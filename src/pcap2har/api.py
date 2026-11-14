"""Public capture-to-HAR API."""

import asyncio
import logging
from os import PathLike
from pathlib import Path

from .har import export_har
from .parser import collect_messages, read_requests


def convert(
    pcap: str | PathLike[str],
    keys: str | PathLike[str],
    output: str | PathLike[str],
    *,
    tshark: str | PathLike[str] | None = None,
) -> Path:
    """Write HAR and return its absolute path. Raise on invalid input or failure.

    Recoverable capture problems are logged; existing output is replaced atomically.
    This is synchronous; async callers should use asyncio.to_thread(convert, ...).
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        pass
    else:
        raise RuntimeError('Use asyncio.to_thread(convert, ...) inside an event loop')
    pcap, keys, output = (Path(p).expanduser().resolve() for p in (pcap, keys, output))
    if not keys.is_file():
        raise FileNotFoundError(f'Key log not found: {keys}')
    if output in (pcap, keys):
        raise ValueError('Output must differ from input files')
    executable = str(tshark) if tshark is not None else None

    rows = read_requests(pcap, keys, executable)
    if not rows:
        logging.getLogger(__name__).warning('No decodable HTTP requests found')
    states, issues = collect_messages(pcap, keys, executable, rows)
    output.parent.mkdir(parents=True, exist_ok=True)
    export_har(output, rows, states, issues)
    return output
