"""HTTP/3 adapter over TShark's decoded frames; no QUIC/QPACK implementation."""

from collections import defaultdict
from collections.abc import Iterator
from dataclasses import dataclass, field
from xml.etree.ElementTree import Element

from ..models import Endpoint, Header, Issues, Message, RequestInfo, States
from ..pdml import endpoint, fields, message_issues, number, required, value


def frames(packet: Element) -> Iterator[tuple[str, str, Element, Element]]:
    """Associate each HTTP/3 frame with its preceding QUIC packet."""
    quic = None
    fallback = value(packet, 'quic.connection.number')
    for proto in packet.findall('proto'):
        if proto.get('name') == 'quic':
            quic = proto
        elif proto.get('name') == 'http3' and quic is not None:
            connection = value(quic, 'quic.connection.number', fallback)
            if connection is None:
                continue
            for frame in proto.findall(".//field[@name='http3.frame']"):
                stream = value(frame, 'http3.frame_streamid')
                # QUIC's low two stream-ID bits are 00 for client-initiated bidirectional streams.
                if stream is not None and int(stream) % 4 == 0:
                    yield f'quic:{connection}', stream, frame, quic


def read_headers(frame: Element) -> list[Header]:
    return [
        {'name': required(h, 'http3.header.header.name'), 'value': value(h, 'http3.headers.header.value', '')}
        for h in fields(frame, 'http3.headers.header')
        if value(h, 'http3.header.header.name') is not None
    ]


def requests(packet: Element) -> Iterator[RequestInfo]:
    for connection, stream, frame, _ in frames(packet):
        method = value(frame, 'http3.headers.method')
        if not method:
            continue
        authority = value(frame, 'http3.headers.authority')
        path = value(frame, 'http3.headers.path')
        scheme = value(frame, 'http3.headers.scheme', 'https')
        url = value(frame, 'http3.request.full_uri')
        if not url and authority and path:
            url = f'{scheme}://{authority}{path}'
        if not (url or (method == 'CONNECT' and authority)):
            continue
        yield RequestInfo(
            id='',
            frame=int(required(packet, 'frame.number')),
            timestamp=float(required(packet, 'frame.time_epoch')),
            http_version='HTTP/3',
            connection=connection,
            stream_id=stream,
            client=endpoint(packet, 'udp'),
            server=endpoint(packet, 'udp', 'dst'),
            method=method,
            url=url or path or (authority if method == 'CONNECT' else None),
            headers=read_headers(frame),
        )


@dataclass(slots=True)
class StreamCoverage:
    """Captured QUIC byte ranges, including HTTP/3 framing, in one direction."""

    ranges: list[tuple[int, int]] = field(default_factory=list)  # Half-open intervals: [start, end).
    final_size: int | None = None

    def collect(self, frame: Element, msg: Message, diagnostics: set[str]) -> None:
        offset = number(frame, 'quic.stream.offset')
        # With the OFF bit unset, the omitted STREAM offset is zero.
        if offset is None and value(frame, 'quic.stream.off') in ('0', 'False'):
            offset = 0
        length = number(frame, 'quic.stream.length')
        data = fields(frame, 'quic.stream_data')
        captured = sum(len(bytes.fromhex(part.get('value', ''))) for part in data)
        if length is None and data:
            length = captured
        if offset is None or length is None or offset < 0 or length < 0:
            msg.issues.add('unknown_stream_range')
            return
        if captured < length:
            diagnostics.add('truncated_stream')
        if captured > length:
            msg.issues.add('invalid_stream_length')
        if value(frame, 'quic.stream.fin') in ('1', 'True'):
            final_size = offset + length
            if self.final_size is not None and self.final_size != final_size:
                msg.issues.add('conflicting_final_size')
            self.final_size = final_size
        if captured:
            self.ranges.append((offset, offset + min(captured, length)))
            merged: list[tuple[int, int]] = []
            for start, end in sorted(self.ranges):
                if merged and start <= merged[-1][1]:
                    merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
                else:
                    merged.append((start, end))
            self.ranges = merged
        if self.final_size is not None and any(end > self.final_size for _, end in self.ranges):
            msg.issues.add('invalid_final_size')

    @property
    def complete(self) -> bool:
        if self.final_size is None:
            return False
        if self.final_size == 0:
            return not self.ranges
        return self.ranges == [(0, self.final_size)]


class Http3Streams:
    """Use decoded HTTP/3 frames and per-direction QUIC byte coverage."""

    def __init__(self, rows: list[RequestInfo], states: States) -> None:
        self.rows = {(r.connection, r.stream_id): r for r in rows if r.http_version == 'HTTP/3'}
        self.states = states
        self.peers: dict[tuple[str | None, Endpoint], bool] = {}
        self.cids: dict[tuple[str, str | None], bool] = {}
        self.seen: set[tuple] = set()
        self.coverage: dict[tuple[str, bool], StreamCoverage] = defaultdict(StreamCoverage)
        self.skipped = 0
        for (connection, _), row in self.rows.items():
            self.peers[(connection, row.client)] = False
            self.peers[(connection, row.server)] = True

    def direction(self, connection: str, quic: Element, packet: Element) -> bool | None:
        peer = (connection, endpoint(packet, 'udp'))
        role = self.peers.get(peer)
        dcid = value(quic, 'quic.dcid')
        if role is None and (connection, dcid) in self.cids:
            role = not self.cids[(connection, dcid)]
            self.peers[peer] = role
        return role

    def collect(self, packet: Element, issues: Issues) -> None:
        units = list(frames(packet))
        source = endpoint(packet, 'udp')
        # Headers identify roles even after an address change.
        for connection, _, frame, _ in units:
            if value(frame, 'http3.headers.method'):
                self.peers[(connection, source)] = False
            elif value(frame, 'http3.headers.status'):
                self.peers[(connection, source)] = True
        for connection, stream, frame, quic in units:
            self.collect_frame(connection, stream, frame, quic, packet)
        self.collect_control(packet, issues)

    def collect_frame(self, connection: str, stream: str, frame: Element, quic: Element, packet: Element) -> None:
        row = self.rows.get((connection, stream))
        role = self.direction(connection, quic, packet)
        if row is None or role is None:
            self.skipped += 1
            if row is not None:
                self.unknown_direction(row)
            return
        # QUIC packet numbers are unique per direction in the application space.
        packet_number = value(quic, 'quic.packet_number')
        key = (connection, role, packet_number, stream, frame.get('pos'), frame.get('size'))
        if packet_number is not None and key in self.seen:
            return
        if packet_number is not None:
            self.seen.add(key)
        exchange = self.states[row.id]
        msg = exchange.response if role else exchange.request
        msg.issues.update(message_issues(frame))
        headers = read_headers(frame)
        status = value(frame, 'http3.headers.status')
        method = value(frame, 'http3.headers.method')
        frame_id = int(required(packet, 'frame.number'))
        if status and 100 <= int(status) < 200:
            msg.interim.append({'status': int(status), 'headers': headers, 'frame': frame_id})
            return
        if method or status:
            if not fields(quic, 'quic.fragment'):
                msg.first_byte = float(required(packet, 'frame.time_epoch'))
            msg.headers = headers
        elif headers:
            msg.trailers.extend(headers)
        if status:
            msg.status = int(status)
        msg.observe(float(required(packet, 'frame.time_epoch')))
        # These are parsed HTTP/3 DATA payloads, not raw QUIC stream bytes.
        for data in frame.findall("field[@name='http3.data']"):
            msg.chunks.append(bytes.fromhex(data.get('value', '')))

    def finish(self) -> None:
        """Resolve QUIC coverage after retransmissions and out-of-order packets."""
        for row in self.rows.values():
            exchange = self.states[row.id]
            for role, msg in ((False, exchange.request), (True, exchange.response)):
                coverage = self.coverage.get((row.id, role))
                if coverage is None or not coverage.complete:
                    msg.issues.add('incomplete_stream')

    def unknown_direction(self, row: RequestInfo) -> None:
        exchange = self.states[row.id]
        for msg in (exchange.request, exchange.response):
            msg.issues.add('unknown_stream_direction')

    def collect_control(self, packet: Element, issues: Issues) -> None:
        """Track connection IDs, stream coverage, FIN and RESET_STREAM."""
        fallback = value(packet, 'quic.connection.number')
        for quic in packet.findall("proto[@name='quic']"):
            number = value(quic, 'quic.connection.number', fallback)
            if number is None:
                continue
            connection = f'quic:{number}'
            role = self.direction(connection, quic, packet)
            # A sender advertises its own connection IDs (migration support).
            if role is not None:
                for cid in fields(quic, 'quic.scid') + fields(quic, 'quic.nci.connection_id'):
                    self.cids[(connection, cid.get('show'))] = role
            if fields(quic, 'quic.fragment.overlap.conflict'):
                issues[connection].add('quic_overlap')
            for frame in quic.findall("field[@name='quic.frame']"):
                stream = value(frame, 'quic.stream.stream_id')
                stream_id = stream if stream is not None else value(frame, 'quic.rsts.stream_id')
                row = self.rows.get((connection, stream_id))
                if row is None:
                    continue
                if role is None:
                    self.unknown_direction(row)
                    continue
                exchange = self.states[row.id]
                msg = exchange.response if role else exchange.request
                msg.issues.update(message_issues(frame))
                if stream is not None:
                    self.coverage[(row.id, role)].collect(frame, msg, issues[connection])
                if value(frame, 'quic.stream.fin') in ('1', 'True') and not msg.ended:
                    if msg.start is not None:
                        msg.observe(float(required(packet, 'frame.time_epoch')))
                    msg.ended = True
