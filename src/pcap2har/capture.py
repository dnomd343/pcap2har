"""PyShark capture and PDML helpers."""

import asyncio
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from contextlib import ExitStack
from pathlib import Path

import pyshark
from pyshark.capture.capture import TSharkCrashException
from pyshark.packet.packet import Packet
from pyshark.tshark.output_parser.tshark_xml import TsharkXmlParser
from pyshark.tshark.tshark import TSharkNotFoundException, TSharkVersionException


class XmlPacket(Packet):
    """A PyShark packet retaining the nested PDML tree."""

    def __init__(self, data: bytes) -> None:
        super().__init__()
        self.xml = ET.fromstring(data)


class XmlParser(TsharkXmlParser):
    def _parse_single_packet(self, packet: bytes) -> XmlPacket:
        return XmlPacket(packet)


class Capture(pyshark.FileCapture):
    # Private hook: requires the pinned PyShark version.
    def _setup_tshark_output_parser(self) -> XmlParser:
        return XmlParser()

    async def _cleanup_subprocess(self, process: asyncio.subprocess.Process) -> None:
        # PyShark 0.6 otherwise retries failed processes during close/destruction.
        try:
            await super()._cleanup_subprocess(process)
        finally:
            if process.returncode is not None:
                self._running_processes.discard(process)


def read_packets(pcap: Path, keys: Path, tshark: str | None, *, decompress: bool = True) -> Iterator[ET.Element]:
    """Yield PDML packets without retaining them."""
    prefs = {'tls.keylog_file': str(keys)}
    if not decompress:
        prefs['http.decompress_body'] = 'FALSE'
    try:
        # Close the capture before its event loop, including on failure.
        with ExitStack() as cleanup:
            loop = asyncio.new_event_loop()
            cleanup.callback(loop.close)
            capture = Capture(
                input_file=str(pcap),
                tshark_path=tshark,
                override_prefs=prefs,
                custom_parameters=['-2'],
                keep_packets=False,
                eventloop=loop,
            )
            cleanup.callback(capture.close)
            for parsed in capture:
                yield parsed.xml
    except TSharkNotFoundException as exc:
        raise FileNotFoundError('TShark not found; install it or use --tshark') from exc
    except (TSharkCrashException, TSharkVersionException) as exc:
        detail = str(exc).split('Last error line: ')[-1].splitlines()[0]
        raise RuntimeError(detail) from exc
    except ET.ParseError as exc:
        raise RuntimeError(f'Invalid TShark XML: {exc}') from exc
