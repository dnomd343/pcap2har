"""Export packet-backed HTTP timings, without inventing browser-side phases."""

from datetime import UTC, datetime
from typing import Any

from harfile import Timings

from ..models import Exchange, RequestInfo


def build_timing(row: RequestInfo, exchange: Exchange) -> dict[str, Any]:
    """Use message-level completeness and boundaries, independent of diagnostics."""
    req, res = exchange.request, exchange.response
    start = req.first_byte if req.first_byte is not None else row.timestamp
    sent = req.result.finished_at
    end = res.result.finished_at
    observed = [time for time in (req.start, req.end, res.start, res.end) if time is not None]
    result = {
        'startedDateTime': datetime.fromtimestamp(start, UTC).isoformat(),
        'time': 0,
        '_timingKnown': False,
        '_observedDurationMs': round((max(observed) - min(observed)) * 1000, 3) if observed else None,
        'timings': Timings(send=-1, wait=-1, receive=-1).asdict(),
        'comment': 'Unresolved capture timing; time=0 is a placeholder. Start may be reassembly time.',
    }
    if req.first_byte is None or sent is None or res.first_byte is None or end is None:
        return result
    if not start <= sent <= res.first_byte <= end:
        result['comment'] = 'Overlapping or inconsistent capture timing; time=0 is a placeholder.'
        return result
    # Capture timestamps are seconds; HAR timings use milliseconds.
    send = round((sent - start) * 1000, 3)
    wait = round((res.first_byte - sent) * 1000, 3)
    receive = round((end - res.first_byte) * 1000, 3)
    result.update(
        time=round(send + wait + receive, 3),
        _timingKnown=True,
        timings=Timings(send=send, wait=wait, receive=receive).asdict(),
        comment='Packet-capture timing; excludes browser queueing and connection setup.',
    )
    return result
