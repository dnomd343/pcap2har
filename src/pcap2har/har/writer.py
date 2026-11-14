"""Build HAR models and write atomically."""

import logging
import os
import tempfile
from collections.abc import Iterable
from contextlib import ExitStack
from importlib.metadata import version
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

import orjson
from harfile import Content, Creator, PostData, Record, Request, Response

from ..models import Exchange, HttpVersion, Issues, Message, RequestInfo, States
from .content import Body, decode_body, get_header
from .timing import build_timing


def build_entry(row: RequestInfo, exchange: Exchange, warnings: list[str]) -> dict[str, Any]:
    """Build one HAR entry; keep unknown timings explicit."""
    req, res = exchange.request, exchange.response
    request_body = decode_body(req)
    response_body = decode_body(res)
    request = build_request(row, req, request_body, warnings)
    response = build_response(row.http_version, res, response_body)
    for direction, body in (('request', request_body), ('response', response_body)):
        if body.decode_failed:
            logging.getLogger(__name__).warning('%s %s: %s', row.id, direction, body.comment)
    return {
        **build_timing(row, exchange),
        'request': request,
        'response': response,
        'cache': {},
        'serverIPAddress': row.server.ip,
        'connection': row.connection,
        '_requestId': row.id,
        '_requestFrame': row.frame,
        '_streamId': row.stream_id,
        '_captureWarnings': warnings,
    }


def build_request(row: RequestInfo, req: Message, body: Body, warnings: list[str]) -> dict[str, Any]:
    url = row.url or ''
    headers = req.headers or row.headers
    post = None
    has_body = body.captured or get_header(headers, 'content-length', '0') != '0'
    if has_body:
        post = PostData(mimeType=body.mime, text=body.text, comment=body.comment)

    try:
        query = parse_qsl(urlsplit(url).query, keep_blank_values=True)
    except ValueError:
        query = []
        warning = 'Invalid URL; query parameters omitted.'
        warnings.append(warning)
        logging.getLogger(__name__).warning('%s: %s', row.id, warning)

    # Use harfile models; add capture metadata separately.
    request = Request(
        method=row.method,
        url=url,
        httpVersion=row.http_version,
        headers=[Record(**h) for h in headers],
        queryString=[Record(name=k, value=v) for k, v in query],
        bodySize=body.wire_size,
        postData=post,
    ).asdict()
    request['_bodyComplete'] = body.complete
    if req.trailers:
        request['_trailers'] = req.trailers
    if post is not None and body.encoding == 'base64':
        request['postData']['_encoding'] = 'base64'

    return request


def build_response(version: HttpVersion, res: Message, body: Body) -> dict[str, Any]:
    response = Response(
        status=res.status or 0,
        statusText=res.status_text,
        httpVersion=version,
        headers=[Record(**h) for h in res.headers],
        content=Content(
            size=body.size,
            compression=body.compression,
            mimeType=body.mime,
            text=body.text,
            encoding=body.encoding,
            comment=body.comment,
        ),
        redirectURL=get_header(res.headers, 'location'),
        bodySize=body.wire_size,
    ).asdict()
    response['content'].update(_complete=body.complete, _capturedBytes=body.captured)
    if res.trailers:
        response['_trailers'] = res.trailers
    if res.interim:
        response['_informationalResponses'] = res.interim
    return response


def export_har(output: Path, rows: list[RequestInfo], states: States, issues: Issues) -> None:
    entries = (build_entry(row, states[row.id], sorted(issues.get(row.connection, ()))) for row in rows)
    write_har(output, entries)


def write_har(output: Path, entries: Iterable[dict[str, Any]]) -> None:
    """Write one entry at a time; replace the output only after success."""
    creator = Creator(name='pcap2har', version=version('pcap2har'))
    metadata = {'name': creator.name, 'version': creator.version}
    with ExitStack() as cleanup:
        with tempfile.NamedTemporaryFile(
            mode='wb', dir=output.parent, prefix=f'.{output.name}.', suffix='.tmp', delete=False
        ) as stream:
            temporary = Path(stream.name)
            cleanup.callback(temporary.unlink, missing_ok=True)
            stream.write(b'{"log":{"version":"1.2","creator":')
            stream.write(orjson.dumps(metadata))
            stream.write(b',"entries":[')
            for index, entry in enumerate(entries):
                if index:
                    stream.write(b',')
                stream.write(orjson.dumps(entry))
            stream.write(b']}}\n')
        os.replace(temporary, output)
