"""Decode captured bodies and map protocol results into HAR content."""

import base64
import gzip
import re
import zlib
from compression import zstd
from contextlib import suppress
from dataclasses import dataclass

import brotli

from ..models import Header, Message


def get_header(headers: list[Header], name: str, default: str = '') -> str:
    """Read the first matching header for HAR metadata."""
    return next((h['value'].strip() for h in headers if h['name'].lower() == name), default)


@dataclass(slots=True)
class Body:
    """HAR body representation derived from a finalized protocol message.

    Completeness describes captured data, not decoding success: a complete body
    may still be unavailable when its compression cannot be decoded.
    """

    mime: str  # Content-Type, including charset when present.
    captured: int  # Encoded payload bytes; excludes protocol headers and chunk framing.
    complete: bool  # Protocol assessment, unchanged by decompression.
    size: int = -1  # Decoded byte count; -1 when incomplete or decoding failed.
    text: str | None = None  # Decoded text or base64; '' is empty, None is unavailable.
    encoding: str | None = None  # HAR storage encoding ('base64'), not HTTP Content-Encoding.
    compression: int | None = None  # Decoded minus encoded bytes; may be negative.
    comment: str | None = None  # Explanation of unavailable or partial content.
    decode_failed: bool = False  # Requests a warning without changing completeness.

    @property
    def wire_size(self) -> int:
        """HAR bodySize: encoded payload size, or -1 when incomplete."""
        return self.captured if self.complete else -1


def decode_body(msg: Message) -> Body:
    """Decode payload bytes for HAR, preserving the protocol assessment."""
    data = b''.join(msg.chunks)
    complete = msg.result.complete
    coding = msg.result.coding
    decoded = decompress(data, coding)
    body = Body(
        mime=get_header(msg.headers, 'content-type', 'application/octet-stream'),
        captured=len(data),
        complete=complete,
        decode_failed=decoded is None,
    )
    if msg.start is None:
        body.comment = 'No message captured; body unavailable.'
        return body
    if decoded is None:
        reason = 'shared dictionary decoding required' if coding in ('dcb', 'dcz') else 'decompression failed'
        body.comment = f'{coding}: {reason}; body omitted.'
        return body
    body.size = len(decoded) if complete else -1
    body.text, body.encoding = encode_text(decoded, body.mime)
    if not complete:
        detail = f' ({", ".join(sorted(msg.issues))})' if msg.issues else ''
        body.comment = f'Body may be partial{detail}; size unknown.'
    if complete and coding:
        body.compression = len(decoded) - body.captured
    return body


def encode_text(data: bytes, mime: str) -> tuple[str, str | None]:
    """Prefer readable text; preserve binary or invalid text as base64."""
    media_type = mime.partition(';')[0].strip().lower()
    text_formats = ('json', 'xml', 'javascript', 'x-www-form-urlencoded')
    textual = media_type.startswith('text/') or any(kind in media_type for kind in text_formats)
    if textual:
        charset = re.search(r"charset=[\"']?([^;\s\"']+)", mime, re.I)
        with suppress(LookupError, UnicodeDecodeError):
            return data.decode(charset.group(1) if charset else 'utf-8'), None
    return base64.b64encode(data).decode('ascii'), 'base64'


def decompress(data: bytes, coding: str) -> bytes | None:
    """Undo content and transfer codings in reverse order; return None on failure."""
    try:
        for code in reversed(coding.split(',')):
            match code.strip():
                case '' | 'identity':
                    pass
                case 'gzip':
                    data = gzip.decompress(data)
                case 'deflate':
                    try:
                        data = zlib.decompress(data)
                    except zlib.error:
                        # Negative window bits accept raw DEFLATE without a zlib wrapper.
                        data = zlib.decompress(data, -zlib.MAX_WBITS)
                case 'br':
                    data = brotli.decompress(data)
                case 'zstd':
                    data = zstd.decompress(data)
                case _:
                    return None
    except ValueError, OSError, EOFError, zlib.error, brotli.error, zstd.ZstdError:
        return None
    return data
