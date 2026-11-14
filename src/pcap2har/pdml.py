"""Read fields from TShark PDML elements."""

from collections.abc import Iterator
from typing import Literal, overload
from xml.etree.ElementTree import Element

from .models import Endpoint


def endpoint(packet: Element, transport: str, side: Literal['src', 'dst'] = 'src') -> Endpoint:
    ip = value(packet, f'ip.{side}') or value(packet, f'ipv6.{side}')
    return Endpoint(ip, number(packet, f'{transport}.{side}port'))


def fields(node: Element, name: str) -> list[Element]:
    return node.findall(f".//field[@name='{name}']")


@overload
def value(node: Element, name: str, default: str) -> str: ...


@overload
def value(node: Element, name: str, default: None = None) -> str | None: ...


def value(node: Element, name: str, default: str | None = None) -> str | None:
    match = node.find(f".//field[@name='{name}']")
    return match.get('show', default) if match is not None else default


def number(node: Element, name: str) -> int | None:
    text = value(node, name)
    return int(text) if text is not None else None


def required(node: Element, name: str) -> str:
    result = value(node, name)
    if result is None:
        raise ValueError(f'Missing PDML field: {name}')
    return result


def raw(node: Element, name: str) -> bytes:
    return b''.join(bytes.fromhex(f.get('value', '')) for f in fields(node, name))


def packet_issues(packet: Element) -> Iterator[str]:
    """Share the same capture checks between both passes."""
    yield from message_issues(packet)
    if packet.find(".//field[@name='tcp.analysis.lost_segment']") is not None:
        yield 'tcp_gap'
    if int(required(packet, 'frame.cap_len')) < int(required(packet, 'frame.len')):
        yield 'truncated'


def message_issues(packet: Element) -> Iterator[str]:
    """Report corruption within a decoded message or stream fragment."""
    malformed = packet.find(".//proto[@name='_ws.malformed']") is not None
    if malformed or packet.find(".//field[@name='_ws.malformed']") is not None:
        yield 'malformed'
    if packet.find(".//field[@name='quic.fragment.overlap.conflict']") is not None:
        yield 'quic_overlap'
