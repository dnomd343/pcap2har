"""HTTP/2 header-block origins and continuation assembly.

PDML frame types: 0 = DATA, 1 = HEADERS, 5 = PUSH_PROMISE, 9 = CONTINUATION.
The `eh` flag means END_HEADERS; it is independent of END_STREAM.
"""

from xml.etree.ElementTree import Element

from ..models import Endpoint, Message
from ..pdml import endpoint, message_issues, required, value


class Headers:
    """Track HEADERS versus PUSH_PROMISE across continuations in each direction."""

    def __init__(self) -> None:
        self.blocks: dict[tuple[str, bool], Element] = {}
        self.pending: dict[tuple[str | None, str | None, Endpoint], str] = {}

    def accept(self, packet: Element, unit: Element) -> bool:
        kind = value(unit, 'http2.type')
        if kind not in ('1', '5', '9'):
            return True
        key = (value(packet, 'tcp.stream'), value(unit, 'http2.streamid'), endpoint(packet, 'tcp'))
        origin = self.pending.get(key) if kind == '9' else kind
        if value(unit, 'http2.flags.eh') in ('1', 'True'):
            self.pending.pop(key, None)
        elif origin is not None:
            self.pending[key] = origin
        return origin == '1'

    def collect(self, request_id: str, response: bool, msg: Message, unit: Element, packet: Element) -> Element | None:
        """Combine a HEADERS block before classifying initial headers or trailers."""
        kind = value(unit, 'http2.type')
        key = (request_id, response)
        if kind != '9' and msg.ended:
            return None
        if kind == '0':
            return unit
        msg.observe(float(required(packet, 'frame.time_epoch')))
        msg.issues.update(message_issues(unit))
        if kind == '1':
            if key in self.blocks:
                msg.issues.add('overlapping_headers')
            block = Element('field')
            self.blocks[key] = block
            msg.issues.add('incomplete_headers')
            msg.ended |= value(unit, 'http2.flags.end_stream') in ('1', 'True')
        else:
            block = self.blocks.get(key)
            if block is None:
                msg.issues.add('missing_headers')
                return None
        block.extend(unit)
        if value(unit, 'http2.flags.eh') not in ('1', 'True'):
            return None
        del self.blocks[key]
        msg.issues.discard('incomplete_headers')
        return block
