"""Coordinate request indexing and message collection."""

import logging
from collections import Counter, defaultdict
from itertools import chain
from pathlib import Path

from .capture import read_packets
from .models import Exchange, Issues, RequestInfo, States
from .pdml import packet_issues, required, value
from .protocols import http, http2, http3
from .protocols.message import finalize

logger = logging.getLogger(__name__)


def read_requests(pcap: Path, keys: Path, tshark: str | None) -> list[RequestInfo]:
    """First pass: index requests in capture order and report packet problems."""
    records: dict[tuple, RequestInfo] = {}
    diagnostics: dict[str, list[int]] = defaultdict(list)
    counts: Counter[str] = Counter()
    origins = http2.Headers()
    skipped = 0
    for packet in read_packets(pcap, keys, tshark):
        for issue in packet_issues(packet):
            counts[issue] += 1
            if len(diagnostics[issue]) < 10:
                diagnostics[issue].append(int(required(packet, 'frame.number')))
        for index, row in enumerate(chain(http3.requests(packet), http.requests(packet, origins))):
            if not row.url:
                skipped += 1
                continue
            match row.http_version:
                case 'HTTP/2' | 'HTTP/3':
                    key = (row.connection, row.stream_id)
                case _:
                    key = (row.connection, row.frame, index)
            if key not in records:
                row.id = f'req-{len(records) + 1:04d}'
                records[key] = row
    for issue, frames in diagnostics.items():
        sample = ', '.join(map(str, frames))
        logger.warning('%s: %s packet(s), frames %s', issue, counts[issue], sample)
    if skipped:
        logger.warning('Skipped %s incomplete request headers', skipped)
    return list(records.values())


def collect_messages(pcap: Path, keys: Path, tshark: str | None, rows: list[RequestInfo]) -> tuple[States, Issues]:
    """Second pass: associate decoded fragments and retain encoded body bytes."""
    if not rows:
        return {}, {}
    states: States = {r.id: Exchange() for r in rows}
    issues: Issues = defaultdict(set)
    tcp = http.HttpStreams(rows, states)
    quic = http3.Http3Streams(rows, states)
    for packet in read_packets(pcap, keys, tshark, decompress=False):
        problems = set(packet_issues(packet))
        issues[value(packet, 'tcp.stream')].update(problems)
        connection = value(packet, 'quic.connection.number')
        if connection is not None:
            issues[f'quic:{connection}'].update(problems)
        tcp.collect(packet, damaged=bool(problems))
        quic.collect(packet, issues)
    if quic.skipped:
        logger.warning('%s HTTP/3 frames could not be associated', quic.skipped)
    quic.finish()
    for row in rows:
        finalize(row, states[row.id])
    return states, issues
