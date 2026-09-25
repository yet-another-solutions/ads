"""Bounded HTTP/2 message profile with stream-local malformed-message resets.

This is a sans-I/O leg, not an authorization decision or an opaque tunnel.
The owner feeds bounded reads, forwards only authorized events, acknowledges
DATA only after consumption, drains output and owns socket deadlines/closure.

h2 4.4.1's public receive_data closes the CONNECTION for HTTP message errors.
Two version-pinned receive hooks below separate these from connection/frame/
HPACK failures. HPACK is always decoded, including on reset streams. All wire
serialization, frame sequencing, settings and flow windows remain h2-owned.
An h2 upgrade MUST review these hooks and rerun the cross-stream regressions.
"""

from __future__ import annotations

import base64
import logging
import re
from collections.abc import Buffer
from dataclasses import dataclass
from importlib.metadata import version

from h2.config import H2Configuration
from h2.connection import AllowedStreamIDs, ConnectionInputs, H2Connection, _decode_headers
from h2.errors import ErrorCodes
from h2.events import (
    DataReceived,
    Event,
    InformationalResponseReceived,
    PriorityUpdated,
    RemoteSettingsChanged,
    RequestReceived,
    ResponseReceived,
    StreamReset,
    TrailersReceived,
)
from h2.exceptions import InvalidBodyLengthError, ProtocolError, StreamClosedError
from h2.settings import SettingCodes, Settings
from h2.stream import StreamInputs, StreamState
from hpack import NeverIndexedHeaderTuple
from hyperframe.frame import DataFrame, Frame, HeadersFrame, RstStreamFrame

from ads_sandbox_egress.framing import BodyLength, Headers, validate_headers, validate_trailers
from ads_sandbox_egress.policy import RequestDenied, authority, consistent_identity

_LOG = logging.getLogger(__name__)
_METHOD = re.compile(rb"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")


@dataclass(slots=True)
class _Message:
    body: BodyLength


class HTTP2Connection(H2Connection):
    """One terminated leg, with no shared origin/client stream ID assumption."""

    def __init__(self, *, client: bool, maximum_streams: int = 64, websocket: bool = False) -> None:
        if any(
            version(package) != pinned
            for package, pinned in (("h2", "4.4.1"), ("hpack", "4.2.0"), ("hyperframe", "6.1.0"))
        ):
            raise RuntimeError("HTTP/2 adapter dependency review required")
        if type(maximum_streams) is not int or not 1 <= maximum_streams <= 128:
            raise ValueError("bounded HTTP/2 concurrency required")
        super().__init__(
            H2Configuration(
                client_side=client,
                header_encoding=None,
                validate_inbound_headers=False,
                normalize_inbound_headers=False,
                validate_outbound_headers=False,
                normalize_outbound_headers=False,
            )
        )
        self.local_settings = Settings(
            client=client,
            initial_values={
                SettingCodes.MAX_CONCURRENT_STREAMS: maximum_streams,
                SettingCodes.MAX_HEADER_LIST_SIZE: 65536,
                SettingCodes.INITIAL_WINDOW_SIZE: 65535,
                SettingCodes.ENABLE_PUSH: 0,
                SettingCodes.ENABLE_CONNECT_PROTOCOL: int(websocket),
            },
        )
        self.decoder.max_header_list_size = 65536
        self._received: dict[int, _Message] = {}
        self._sent: dict[int, _Message] = {}
        self._methods: dict[int, bytes] = {}
        self._informationals: dict[tuple[bool, int], int] = {}
        self.websocket = websocket

    def upgraded(self, method: bytes, settings: bytes | None = None) -> bytes | None:
        """Seed stream 1 ONLY after the owner's independently authorized h2c.

        The HTTP/1 request has completed; never replay its application bytes.
        Later streams are ordinary new authorization events. This operation
        does not itself parse/authorize an Upgrade request or send a 101.
        """
        if self.streams or _METHOD.fullmatch(method) is None:
            raise RequestDenied("h2_invalid_upgrade_state")
        if not self.config.client_side:
            if (
                settings is None
                or len(settings) > 1024
                or re.fullmatch(rb"[A-Za-z0-9_-]*", settings) is None
            ):
                raise RequestDenied("h2_invalid_upgrade_settings")
            try:
                decoded = base64.b64decode(settings, altchars=b"-_", validate=True)
            except ValueError:
                raise RequestDenied("h2_invalid_upgrade_settings") from None
            if len(decoded) % 6:
                raise RequestDenied("h2_invalid_upgrade_settings")
            identifiers = [decoded[index : index + 2] for index in range(0, len(decoded), 6)]
            if len(set(identifiers)) != len(identifiers):
                raise RequestDenied("h2_duplicate_upgrade_settings")
        elif settings is not None:
            raise RequestDenied("h2_unexpected_upgrade_settings")
        result = super().initiate_upgrade_connection(settings)
        self._methods[1] = method
        self.streams[1].request_method = method
        messages = self._sent if self.config.client_side else self._received
        messages[1] = _Message(BodyLength(0))
        return result

    def _forget_closed(self) -> None:
        for stream_id in set(self._received) | set(self._sent) | set(self._methods):
            stream = self.streams.get(stream_id)
            if stream is None or stream.closed:
                self._received.pop(stream_id, None)
                self._sent.pop(stream_id, None)
                self._methods.pop(stream_id, None)
                self._informationals.pop((True, stream_id), None)
                self._informationals.pop((False, stream_id), None)

    def _headers(self, stream_id: int, values: Headers, *, end: bool, incoming: bool) -> Headers:
        fields = validate_headers(values, h2=True)
        if any(value != value.strip(b" \t") for _, value in fields):
            raise RequestDenied("h2_field_whitespace")
        messages = self._received if incoming else self._sent
        if stream_id in messages:
            fields = validate_trailers(fields, h2=True)
            if not end:
                raise RequestDenied("h2_unterminated_trailers")
            messages[stream_id].body.finish()
            return fields
        pseudo = {name: value for name, value in fields if name.startswith(b":")}
        lengths = [value for name, value in fields if name == b"content-length"]
        expected = int(lengths[0]) if lengths else None
        request = incoming != self.config.client_side
        if request:
            if (
                not {b":method", b":scheme", b":path"} <= pseudo.keys()
                or set(pseudo) - {b":method", b":scheme", b":path", b":authority", b":protocol"}
                or _METHOD.fullmatch(pseudo[b":method"]) is None
                or pseudo[b":scheme"] not in (b"http", b"https")
                or not pseudo[b":path"]
                or any(char <= 32 or char == 127 for char in pseudo[b":path"])
                or not (
                    pseudo[b":path"].startswith(b"/")
                    or pseudo[b":path"] == b"*"
                    and pseudo[b":method"] == b"OPTIONS"
                )
            ):
                raise RequestDenied("h2_request_pseudo_headers")
            if pseudo[b":method"] == b"CONNECT":
                enabled = (
                    self.websocket
                    if incoming
                    else bool(self.remote_settings.enable_connect_protocol)
                )
                if (
                    not enabled
                    or pseudo.get(b":protocol") != b"websocket"
                    or not pseudo.get(b":authority")
                ):
                    raise RequestDenied("h2_unsupported_connect")
            elif b":protocol" in pseudo:
                raise RequestDenied("h2_unexpected_protocol")
            try:
                consistent_identity(
                    tuple(
                        authority(
                            value.decode("ascii"), 443 if pseudo[b":scheme"] == b"https" else 80
                        )
                        for name, value in fields
                        if name in (b":authority", b"host")
                    ),
                    None,
                )
            except UnicodeError:
                raise RequestDenied("h2_non_ascii_authority") from None
            self._methods[stream_id] = pseudo[b":method"]
        else:
            if set(pseudo) != {b":status"} or not re.fullmatch(
                rb"[1-5][0-9]{2}", pseudo[b":status"]
            ):
                raise RequestDenied("h2_response_pseudo_headers")
            status = int(pseudo[b":status"])
            if status < 200:
                key = incoming, stream_id
                count = self._informationals.get(key, 0) + 1
                if status == 101 or end or lengths or count > 16:
                    raise RequestDenied("h2_informational_response")
                self._informationals[key] = count
                return fields
            if status == 204 and lengths:
                raise RequestDenied("h2_no_content_length")
            successful_connect = self._methods.get(stream_id) == b"CONNECT" and 200 <= status < 300
            if successful_connect and lengths:
                raise RequestDenied("h2_connect_content_length")
            if (
                status in (204, 304)
                and not successful_connect
                or self._methods.get(stream_id) == b"HEAD"
            ):
                expected = 0  # HEAD/304 length is metadata, not an incoming body.
        if sum(name == b"host" for name, _ in fields) > 1:
            raise RequestDenied("h2_duplicate_host")
        message = _Message(BodyLength(expected))
        if end:
            message.body.finish()
        messages[stream_id] = message
        return fields

    def _message_reset(self, stream_id: int, reason: str) -> StreamReset:
        # Reasons are only fixed internal labels, never peer header values.
        try:
            _LOG.warning("http2_stream_reset reason=%s", reason)
        except Exception:
            pass
        stream = self.streams[stream_id]
        if stream.state_machine.state == StreamState.IDLE:
            # The peer DID send HEADERS. Advance that wire event, but do not
            # invent valid HTTP headers or expose malformed ones to the owner.
            stream.state_machine.process_input(StreamInputs.RECV_HEADERS)
        if stream.closed:
            # A bad final DATA can close both halves before the additional
            # HTTP semantic check (e.g. forbidden 304 body). RST remains legal.
            frame = RstStreamFrame(stream_id)
            frame.error_code = ErrorCodes.PROTOCOL_ERROR
            self._prepare_for_sending([frame])
        else:
            super().reset_stream(stream_id, ErrorCodes.PROTOCOL_ERROR)
        self._forget_closed()
        return StreamReset(
            stream_id=stream_id, error_code=ErrorCodes.PROTOCOL_ERROR, remote_reset=False
        )

    def _receive_headers_frame(self, frame: HeadersFrame) -> tuple[list[Frame], list[Event]]:
        # This mirrors the pinned library's header dispatch, with the ADS
        # message gate AFTER decompression and stream creation but BEFORE
        # message processing can throw a connection-level ProtocolError.
        if (
            frame.stream_id not in self.streams
            and self.open_inbound_streams >= self.local_settings.max_concurrent_streams
        ):
            raise ProtocolError("HTTP/2 concurrent stream limit")
        headers = _decode_headers(self.decoder, frame.data)
        events = self.state_machine.process_input(ConnectionInputs.RECV_HEADERS)
        stream = self._get_or_create_stream(
            frame.stream_id, AllowedStreamIDs(not self.config.client_side)
        )
        priority_events: list[Event] = []
        if "PRIORITY" in frame.flags:
            _, priority_events = self._receive_priority_frame(frame)
        # Closed/reset-stream semantics belong to h2. It has already consumed
        # the peer's HPACK changes and will retain connection-state accounting.
        if stream.closed:
            return stream.receive_headers(headers, "END_STREAM" in frame.flags, None)
        try:
            fields = self._headers(
                frame.stream_id, tuple(headers), end="END_STREAM" in frame.flags, incoming=True
            )
        except RequestDenied:
            return [], [self._message_reset(frame.stream_id, "message_headers")]
        frames, received = stream.receive_headers(fields, "END_STREAM" in frame.flags, None)
        if priority_events and received and isinstance(priority_events[0], PriorityUpdated):
            event = received[0]
            if isinstance(
                event,
                (
                    RequestReceived,
                    ResponseReceived,
                    TrailersReceived,
                    InformationalResponseReceived,
                ),
            ):
                event.priority_updated = priority_events[0]
        return frames, events + received + priority_events

    def _receive_data_frame(self, frame: DataFrame) -> tuple[list[Frame], list[Event]]:
        try:
            frames, events = super()._receive_data_frame(frame)
        except InvalidBodyLengthError:
            # h2 consumed BOTH flow windows before detecting length mismatch.
            # Reset first, then return only connection credit, not stream credit.
            failure = self._message_reset(frame.stream_id, "message_length")
            self.acknowledge_received_data(frame.flow_controlled_length, frame.stream_id)
            return [], [failure]
        for event in events:
            if isinstance(event, DataReceived):
                try:
                    message = self._received[event.stream_id]
                    message.body.add(len(event.data))
                    if "END_STREAM" in frame.flags:
                        message.body.finish()
                except (KeyError, RequestDenied):
                    failure = self._message_reset(event.stream_id, "message_body")
                    self.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                    return frames, [failure]
        return frames, events

    def receive_data(self, data: Buffer) -> list[Event]:
        if memoryview(data).nbytes > 16384:
            raise ValueError("bounded HTTP/2 read required")
        try:
            events = super().receive_data(data)
            for event in events:
                if isinstance(event, RemoteSettingsChanged):
                    change = event.changed_settings.get(SettingCodes.ENABLE_CONNECT_PROTOCOL)
                    if change is not None and change.original_value == 1 and change.new_value == 0:
                        raise ProtocolError("HTTP/2 extended CONNECT cannot be disabled")
            return events
        finally:
            self._forget_closed()

    def headers(self, stream_id: int, values: Headers, *, end: bool = False) -> None:
        """Safe outbound headers after the owner has authorized the exchange."""
        fields = self._headers(stream_id, values, end=end, incoming=False)
        # With normalization disabled, explicitly retain HPACK's never-index
        # protection instead of letting credentials enter a shared table.
        protected = tuple(
            NeverIndexedHeaderTuple(name, value)
            if name in (b"authorization", b"proxy-authorization", b"cookie", b"set-cookie")
            else (name, value)
            for name, value in fields
        )
        super().send_headers(stream_id, protected, end_stream=end)
        self._forget_closed()

    def data(self, stream_id: int, data: bytes, *, end: bool = False) -> None:
        """One bounded DATA frame; caller waits for window credit before calling."""
        if len(data) > min(16384, self.max_outbound_frame_size):
            raise ValueError("bounded HTTP/2 write required")
        message = self._sent.get(stream_id)
        if message is None:
            raise RequestDenied("h2_data_without_headers")
        # Check window first: a retry after backpressure must not count twice.
        if len(data) > max(0, self.local_flow_control_window(stream_id)):
            raise RequestDenied("h2_send_window_unavailable")
        message.body.add(len(data))
        if end:
            message.body.finish()
        if not data and end:
            # SETTINGS can reduce a stream window below zero. Empty EOS
            # consumes no flow credit; h2's explicit end_stream supports it.
            super().end_stream(stream_id)
        else:
            super().send_data(stream_id, data, end_stream=end)
        self._forget_closed()

    def deny(self, stream_id: int) -> None:
        """Standard stream reset only; never an ADS status/body/header."""
        try:
            super().reset_stream(stream_id, ErrorCodes.CANCEL)
        except StreamClosedError:
            pass
        self._forget_closed()
