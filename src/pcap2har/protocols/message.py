"""Finalize captured message boundaries independently of HAR export."""

from ..models import Exchange, Header, Message, MessageResult, RequestInfo


def header_values(headers: list[Header], name: str) -> list[str]:
    """Keep repeated values in wire order for framing and content decoding."""
    return [h['value'].strip() for h in headers if h['name'].lower() == name]


def finalize(row: RequestInfo, exchange: Exchange) -> None:
    """Assess both directions after collection has resolved all protocol evidence."""
    exchange.request.result = assess(row, exchange.request, response=False)
    exchange.response.result = assess(row, exchange.response, response=True)


def assess(row: RequestInfo, msg: Message, *, response: bool) -> MessageResult:
    """Resolve framing, coding and end time together so they use the same rules."""
    multiplexed = row.http_version in ('HTTP/2', 'HTTP/3')
    status = msg.status or 0
    # 101 switches protocols; 204 and 304 have no body. Successful CONNECT starts a tunnel.
    tunnel = row.method == 'CONNECT' and 200 <= status < 300
    no_body = response and (row.method == 'HEAD' or status in (101, 204, 304) or tunnel)
    encoding = ','.join(header_values(msg.headers, 'transfer-encoding')).lower()
    transfer = [code.strip() for code in encoding.split(',')]
    codings = header_values(msg.headers, 'content-encoding')
    if not multiplexed:
        codings.extend(code for code in transfer if code not in ('', 'chunked'))
    coding = '' if no_body else ','.join(codings).lower()
    try:
        expected = content_length(msg.headers)
    except ValueError:
        return MessageResult(coding=coding)
    size = sum(map(len, msg.chunks))
    finished = msg.end
    if multiplexed:
        complete = msg.ended and (expected is None or size == expected or no_body)
    elif no_body:
        complete = True
    elif any(transfer):
        # Transfer-Encoding takes precedence over Content-Length in HTTP/1.
        if transfer[-1] == 'chunked':
            complete = msg.ended
        else:
            finished = msg.closed_at
            complete = response and finished is not None
    elif expected is not None:
        complete = size == expected
    elif response:
        finished = msg.closed_at
        complete = finished is not None
    else:
        complete = not size
    complete = complete and msg.start is not None and not msg.issues
    if response and status < 200 and status != 101:
        complete = False
    return MessageResult(complete=complete, coding=coding, finished_at=finished if complete else None)


def content_length(headers: list[Header]) -> int | None:
    """Accept repeated lengths only when all decimal values agree."""
    values = [part.strip() for value in header_values(headers, 'content-length') for part in value.split(',')]
    if not values:
        return None
    if any(not value.isascii() or not value.isdecimal() for value in values):
        raise ValueError('Invalid Content-Length')
    lengths = {int(value) for value in values}
    if len(lengths) != 1:
        raise ValueError('Conflicting Content-Length')
    return lengths.pop()
