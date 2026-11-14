"""HTTP/1 and HTTP/2 requests and messages decoded by TShark."""

import logging
from collections import defaultdict
from collections.abc import Iterable, Iterator
from xml.etree.ElementTree import Element

from ..models import Endpoint, Header, Message, RequestInfo, States
from ..pdml import endpoint, fields, message_issues, number, raw, required, value
from .http2 import Headers


def units(packet: Element) -> Iterator[tuple[bool, Element]]:
    for proto in packet.findall('proto'):
        match proto.get('name'):
            case 'http':
                yield False, proto
            case 'http2':
                for unit in proto.findall("field[@name='http2.stream']"):
                    yield True, unit


def requests(packet: Element, origins: Headers) -> Iterator[RequestInfo]:
    for http2, unit in units(packet):
        if http2 and not origins.accept(packet, unit):
            continue
        method = value(unit, 'http2.headers.method' if http2 else 'http.request.method')
        if not method:
            continue
        version = 'HTTP/2' if http2 else required(unit, 'http.request.version')
        if version not in ('HTTP/1.0', 'HTTP/1.1', 'HTTP/2'):
            logging.getLogger(__name__).warning('Skipping unsupported HTTP version: %s', version)
            continue
        url = value(unit, 'http2.request.full_uri' if http2 else 'http.request.full_uri')
        path = value(unit, 'http2.headers.path' if http2 else 'http.request.uri')
        authority = value(unit, 'http2.headers.authority' if http2 else 'http.host')
        scheme = value(unit, 'http2.headers.scheme')
        if not http2 and path and path.startswith('/') and authority:
            # TShark's full_uri can refer to another request in the same packet.
            scheme = 'https' if packet.find("proto[@name='tls']") is not None else 'http'
            url = f'{scheme}://{authority}{path}'
        if not url and scheme and authority and path:
            url = f'{scheme}://{authority}{path}'
        yield RequestInfo(
            id='',
            frame=int(required(packet, 'frame.number')),
            timestamp=float(required(packet, 'frame.time_epoch')),
            http_version=version,
            connection=value(packet, 'tcp.stream'),
            stream_id=value(unit, 'http2.streamid') if http2 else None,
            client=endpoint(packet, 'tcp'),
            server=endpoint(packet, 'tcp', 'dst'),
            method=method,
            url=url or path or (authority if method == 'CONNECT' else None),
            headers=read_headers(unit, http2),
        )


class HttpStreams:
    """Associate HTTP/1 request frames and HTTP/2 stream IDs with messages."""

    def __init__(self, rows: list[RequestInfo], states: States) -> None:
        self.states = states
        self.headers = Headers()
        self.frame_times: dict[int, float] = {}
        self.reset_connections: set[str | None] = set()
        self.close_risks: dict[str | None, list[tuple[float, Endpoint]]] = defaultdict(list)
        self.http2 = {(r.connection, r.stream_id): r for r in rows if r.http_version == 'HTTP/2'}
        self.http1: dict[tuple[str | None, str | None], list[RequestInfo]] = defaultdict(list)
        self.connections: dict[str | None, list[RequestInfo]] = defaultdict(list)
        for row in rows:
            if row.http_version in ('HTTP/1.0', 'HTTP/1.1'):
                self.http1[(row.connection, str(row.frame))].append(row)
                self.connections[row.connection].append(row)

    def collect(self, packet: Element, *, damaged: bool) -> None:
        frame = required(packet, 'frame.number')
        timestamp = float(required(packet, 'frame.time_epoch'))
        connection = value(packet, 'tcp.stream')
        # Only HTTP/1 reassembly needs earlier packet timestamps.
        if connection in self.connections:
            self.frame_times[int(frame)] = timestamp
        if connection in self.connections and damaged:
            self.close_risks[connection].append((timestamp, endpoint(packet, 'tcp')))
        request_index = 0
        for http2, unit in units(packet):
            if http2:
                if not self.headers.accept(packet, unit):
                    continue
                row = self.http2.get((connection, value(unit, 'http2.streamid')))
                if row is None:
                    continue
                kind = value(unit, 'http2.type')
                # DATA, HEADERS and CONTINUATION carry message content; control frames do not.
                if kind not in ('0', '1', '9'):
                    continue
                source = endpoint(packet, 'tcp')
                response = source != row.client
            else:
                response = value(unit, 'http.response.code') is not None
                if response:
                    row = self.match_response(connection, value(unit, 'http.request_in'))
                else:
                    if value(unit, 'http.request.method') is None:
                        continue
                    candidates = self.http1.get((connection, frame), [])
                    row = candidates[request_index] if request_index < len(candidates) else None
                    request_index += 1
                if row is None:
                    continue
            exchange = self.states[row.id]
            message = exchange.response if response else exchange.request
            continuation = http2 and value(unit, 'http2.type') == '9'
            if http2:
                unit = self.headers.collect(row.id, response, message, unit, packet)
                if unit is None:
                    continue
            method = value(unit, 'http2.headers.method' if http2 else 'http.request.method')
            status = number(unit, 'http2.headers.status' if http2 else 'http.response.code')
            if method or (status is not None and (status >= 200 or status == 101)):
                message.first_byte = None if continuation else self.first_byte(packet, unit, http2)
            message.issues.update(message_issues(unit))
            collect_fragment(message, unit, http2, response, packet)
        self.collect_close(packet, connection)

    def first_byte(self, packet: Element, unit: Element, http2: bool) -> float | None:
        """Resolve plain HTTP/1 reassembly; avoid guessing across TLS or multiplexed frames."""
        segments = fields(packet, 'tcp.segment')
        tls = packet.find("proto[@name='tls']") is not None
        if fields(packet, 'tls.segment') or (http2 and value(unit, 'http2.type') != '1'):
            return None
        if segments:
            if tls or http2 or len(list(units(packet))) != 1:
                return None
            times = [self.frame_times.get(int(field.get('show', '0'))) for field in segments]
            if any(time is None for time in times):
                return None
            return min(time for time in times if time is not None)
        return float(required(packet, 'frame.time_epoch'))

    def collect_close(self, packet: Element, connection: str | None) -> None:
        """A server FIN delimits the last response; a prior reset prevents this."""
        if connection not in self.connections:
            return
        if value(packet, 'tcp.flags.reset') in ('1', 'True'):
            self.reset_connections.add(connection)
        if connection in self.reset_connections or value(packet, 'tcp.flags.fin') not in ('1', 'True'):
            return
        source = endpoint(packet, 'tcp')
        for row in reversed(self.connections[connection]):
            message = self.states[row.id].response
            if message.status is None:
                continue
            if source != row.server or message.closed_at is not None:
                return
            message.closed_at = float(required(packet, 'frame.time_epoch'))
            # FIN alone cannot prove a close-delimited body survived capture gaps.
            earlier = (r for r in self.connections[connection] if r.frame < row.frame)
            previous = [self.states[r.id].response.end for r in earlier]
            start = max([row.timestamp, *(time for time in previous if time is not None)])
            risks = self.close_risks[connection]
            if any(time >= start and peer == source for time, peer in risks):
                message.closed_at = None
            return

    def match_response(self, connection: str | None, frame: str | None) -> RequestInfo | None:
        """Use TShark's request frame, or HTTP/1 response order for pipelining."""
        candidates = self.http1.get((connection, frame), []) if frame else self.connections.get(connection, [])
        for row in candidates:
            exchange = self.states[row.id]
            if (frame is not None or exchange.request.start is not None) and exchange.response.status is None:
                return row
        return None


def collect_fragment(msg: Message, unit: Element, http2: bool, response: bool, packet: Element) -> None:
    """Collect one decoded HTTP/1 or HTTP/2 message fragment."""
    method = value(unit, 'http2.headers.method' if http2 else 'http.request.method')
    status = value(unit, 'http2.headers.status' if http2 else 'http.response.code')
    frame = int(required(packet, 'frame.number'))
    timestamp = float(required(packet, 'frame.time_epoch'))
    headers = read_headers(unit, http2, response)
    # Informational responses precede the final response; 101 instead completes an upgrade.
    if status and 100 <= int(status) < 200 and int(status) != 101:
        msg.interim.append({'status': int(status), 'headers': headers, 'frame': frame})
        return
    if headers and (method or status):
        msg.headers = headers
    elif headers:
        msg.trailers.extend(headers)
    if status:
        msg.status = int(status)
        msg.status_text = value(unit, 'http.response.phrase', '')
    msg.observe(timestamp)
    if http2:
        retries = ('retransmission', 'fast_retransmission')
        retransmitted = any(fields(packet, f'tcp.analysis.{kind}') for kind in retries)
        if not retransmitted:
            collect_data(msg, unit)
        if value(unit, 'http2.flags.end_stream') in ('1', 'True'):
            msg.ended = True
    else:
        payload = encoded_body(unit)
        if payload is None:
            payload = raw(unit, 'http.file_data') or raw(unit, 'http.chunk_data') or raw(unit, 'data.data')
        msg.chunks.append(payload)
        trailers = raw(unit, 'http.chunked_trailer_part').decode('iso-8859-1')
        msg.trailers.extend(read_header_lines(trailers.splitlines()))
        # A zero-length chunk terminates a chunked HTTP/1 body.
        msg.ended |= any(f.get('show') == '0' for f in fields(unit, 'http.chunk_size'))


def collect_data(message: Message, unit: Element) -> None:
    """Keep encoded bytes; exclude decoded copies."""
    assembled = fields(unit, 'http2.body.reassembled.data')
    if assembled:
        message.chunks = [bytes.fromhex(assembled[0].get('value', ''))]
        return
    encoded = encoded_body(unit)
    if encoded is not None:
        message.chunks = [encoded]
        return
    # Nested DATA may already be decompressed.
    for field in unit.findall("field[@name='http2.data.data']"):
        message.chunks.append(bytes.fromhex(field.get('value', '')))


def encoded_body(unit: Element) -> bytes | None:
    for field in unit.findall('field'):
        if field.get('show', '').startswith('Content-encoded entity body'):
            return bytes.fromhex(field.get('value', ''))
    return None


def read_headers(node: Element, http2: bool, response: bool = False) -> list[Header]:
    if http2:
        return [
            {'name': required(h, 'http2.header.name'), 'value': value(h, 'http2.header.value', '')}
            for h in fields(node, 'http2.header')
            if value(h, 'http2.header.name')
        ]
    lines = (f.get('show', '') for f in fields(node, 'http.response.line' if response else 'http.request.line'))
    return read_header_lines(lines)


def read_header_lines(lines: Iterable[str]) -> list[Header]:
    result: list[Header] = []
    for line in lines:
        line = line.removesuffix('\\r\\n').rstrip('\r\n')
        if ':' in line:
            name, text = line.split(':', 1)
            result.append({'name': name, 'value': text.lstrip()})
    return result
