"""Internal models shared by protocol parsing and HAR export.

The first pass indexes RequestInfo records; the second collects request and
response fragments into Message objects. Missing capture values remain None.
"""

from dataclasses import dataclass, field
from typing import Literal, NamedTuple, TypedDict

type HttpVersion = Literal['HTTP/1.0', 'HTTP/1.1', 'HTTP/2', 'HTTP/3']
type States = dict[str, Exchange]  # Request ID -> captured request/response pair.
type Issues = dict[str | None, set[str]]  # Connection ID -> capture problems; None means unassigned.


class Header(TypedDict):
    """HAR-compatible header; lists preserve order and duplicate names."""

    name: str
    value: str


class InformationalResponse(TypedDict):
    """Interim status and headers, with their capture frame."""

    status: int
    headers: list[Header]
    frame: int


class Endpoint(NamedTuple):
    """An observed IP address and transport port."""

    ip: str | None
    port: int | None


@dataclass(slots=True)
class RequestInfo:
    """First-pass metadata: HTTP/1 matches request frames, HTTP/2 and HTTP/3 match streams."""

    id: str  # Assigned during indexing, e.g. 'req-0001'.
    frame: int  # Capture frame containing the request headers.
    timestamp: float  # Request timestamp in Unix seconds.
    http_version: HttpVersion
    connection: str | None  # TShark TCP stream number or 'quic:<connection number>'.
    stream_id: str | None  # HTTP/2 or HTTP/3 stream ID; None for HTTP/1.
    client: Endpoint
    server: Endpoint
    method: str
    url: str | None  # Full URL when available from decoding or reconstruction.
    headers: list[Header]  # First-pass headers, retained as an export fallback.


@dataclass(frozen=True, slots=True)
class MessageResult:
    """Protocol assessment produced after collection; decoding does not change it."""

    complete: bool = False
    coding: str = ''  # Encodings in application order, excluding chunk framing.
    finished_at: float | None = None  # Confirmed message end in Unix seconds.


@dataclass(slots=True)
class Message:
    """One message: encoded payload, observed boundaries and protocol evidence.

    Collection fills the fields; finalization sets result; HAR export decodes chunks.
    """

    result: MessageResult = field(default_factory=MessageResult)
    headers: list[Header] = field(default_factory=list)
    chunks: list[bytes] = field(default_factory=list)
    issues: set[str] = field(default_factory=set)  # Problems attributable to this message.
    start: float | None = None  # Earliest captured fragment, in Unix seconds.
    end: float | None = None  # Latest captured fragment, in Unix seconds.
    first_byte: float | None = None  # Packet-backed first-byte time; None when ambiguous.
    closed_at: float | None = None  # Confirmed HTTP/1 server FIN, excluding reset or capture gaps.
    ended: bool = False  # Observed end marker; does not alone guarantee a complete body.
    status: int | None = None  # Response status; None for requests or a missing status.
    status_text: str = ''  # HTTP/1 reason phrase; empty for HTTP/2 and HTTP/3.
    interim: list[InformationalResponse] = field(default_factory=list)
    trailers: list[Header] = field(default_factory=list)  # Headers following the body.

    def observe(self, timestamp: float) -> None:
        """Update capture bounds, including out-of-order timestamps."""
        self.start = timestamp if self.start is None else min(self.start, timestamp)
        self.end = timestamp if self.end is None else max(self.end, timestamp)


@dataclass(slots=True)
class Exchange:
    """Request and response state for one indexed request."""

    request: Message = field(default_factory=Message)
    response: Message = field(default_factory=Message)
