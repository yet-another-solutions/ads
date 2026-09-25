"""Bounded two-leg HTTP/2 request owner with separate stream-ID spaces.

Policy, helper and membership are per request. Pending requests hold at most
the advertised receive-window bytes; they cannot emit upstream HTTP headers.
No body is buffered in full, no redirects are followed, and stream failures
cancel only their paired exchange. Socket/HPACK failures end the connection.
"""

from __future__ import annotations

import asyncio
import logging
import math
import time
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from h2.events import (
    ConnectionTerminated,
    DataReceived,
    Event,
    InformationalResponseReceived,
    RequestReceived,
    ResponseReceived,
    StreamEnded,
    StreamReset,
    TrailersReceived,
    WindowUpdated,
)

from ads_sandbox_egress.framing import Headers
from ads_sandbox_egress.http2 import HTTP2Connection
from ads_sandbox_egress.policy import RequestDenied
from ads_sandbox_egress.request_authorization import (
    ConnectionTarget,
    RequestAuthorizer,
    RequestHead,
)
from ads_sandbox_egress.streams import OwnedStream

_LOG = logging.getLogger(__name__)


class _Leg:
    def __init__(
        self,
        stream: OwnedStream,
        *,
        client: bool,
        receive: Callable[[Event], None],
        stop: asyncio.Event,
        maximum_streams: int,
        idle_timeout: float,
        on_eof: Callable[[], None] | None = None,
    ) -> None:
        self.stream, self.receive, self.stop = stream, receive, stop
        self.protocol = HTTP2Connection(client=client, maximum_streams=maximum_streams)
        self.idle_timeout = idle_timeout
        self.write_lock = asyncio.Lock()
        self.window_changed = asyncio.Event()
        self.task: asyncio.Task[None] | None = None
        self.closed = False
        self.last_activity = time.monotonic()
        self.on_eof = on_eof

    async def _flush_locked(self) -> None:
        data = self.protocol.data_to_send()
        if data:
            self.stream.writer.write(data)
            async with asyncio.timeout(self.idle_timeout):
                await self.stream.writer.drain()
            self.last_activity = time.monotonic()

    async def flush(self) -> None:
        async with self.write_lock:
            if self.closed:
                self.protocol.data_to_send()
                return
            await self._flush_locked()

    async def start(self) -> None:
        self.protocol.initiate_connection()
        await self.flush()
        self.task = asyncio.create_task(self._read())

    async def _read(self) -> None:
        normal_eof = False
        try:
            while data := await self.stream.reader.read(16384):
                self.last_activity = time.monotonic()
                for event in self.protocol.receive_data(data):
                    if isinstance(event, ConnectionTerminated):
                        raise RequestDenied("http2_connection_terminated")
                    if isinstance(event, WindowUpdated):
                        self.window_changed.set()
                    self.receive(event)
                await self.flush()
            normal_eof = True
        except asyncio.CancelledError:
            raise
        except Exception:
            # Fixed, redacted outcome. Native exception strings can contain
            # client headers and must not be included in logs or responses.
            pass
        finally:
            self.closed = True
            self.window_changed.set()
            if normal_eof and self.on_eof is not None:
                self.on_eof()
            else:
                self.stop.set()

    def deny(self, stream_id: int) -> None:
        if stream_id in self.protocol.streams and not self.protocol.streams[stream_id].closed:
            self.protocol.deny(stream_id)
        self.window_changed.set()

    def credit(self, count: int, stream_id: int) -> None:
        if count:
            self.protocol.acknowledge_received_data(count, stream_id)

    async def headers(self, stream_id: int, headers: Headers, *, end: bool = False) -> None:
        async with self.write_lock:
            if self.closed:
                raise RequestDenied("http2_leg_closed")
            self.protocol.headers(stream_id, headers, end=end)
            await self._flush_locked()

    async def data(self, stream_id: int, data: bytes, *, end: bool = False) -> None:
        offset = 0
        # Idle bound is renewed only after actual forward progress. Other
        # streams' WINDOW_UPDATE frames cannot extend a stalled stream forever.
        deadline = time.monotonic() + self.idle_timeout
        while offset < len(data) or end:
            self.window_changed.clear()
            async with self.write_lock:
                if self.closed:
                    raise RequestDenied("http2_leg_closed")
                window = self.protocol.local_flow_control_window(stream_id)
                count = min(len(data) - offset, max(0, window), 16384)
                final = end and offset + count == len(data)
                if count or final and offset == len(data):
                    self.protocol.data(stream_id, data[offset : offset + count], end=final)
                    offset += count
                    if final:
                        end = False
                    await self._flush_locked()
                    deadline = time.monotonic() + self.idle_timeout
                    continue
            async with asyncio.timeout(max(0, deadline - time.monotonic())):
                await self.window_changed.wait()

    async def close(self) -> None:
        self.closed = True
        self.window_changed.set()
        self.stream.abort()
        if self.task is not None:
            self.task.cancel()
            await asyncio.gather(self.task, return_exceptions=True)


class _Inbox:
    def __init__(self, leg: _Leg, stream_id: int) -> None:
        self.leg, self.stream_id = leg, stream_id
        self.events: deque[Event] = deque()
        self.ready = asyncio.Event()
        self.closed = False
        self.bytes = 0

    def offer(self, event: Event) -> None:
        if self.closed:
            if isinstance(event, DataReceived):
                self.leg.credit(event.flow_controlled_length, self.stream_id)
            return
        size = event.flow_controlled_length if isinstance(event, DataReceived) else 0
        if len(self.events) >= 128 or self.bytes + size > 65535:
            # This event has already consumed native receive-window credit.
            self.leg.deny(self.stream_id)
            self.leg.credit(size, self.stream_id)
            raise RequestDenied("http2_stream_queue_limit")
        self.events.append(event)
        self.bytes += size
        self.ready.set()

    async def take(self) -> Event:
        async with asyncio.timeout(self.leg.idle_timeout):
            while not self.events:
                if self.closed:
                    raise RequestDenied("http2_stream_stopped")
                self.ready.clear()
                await self.ready.wait()
            event = self.events.popleft()
            if isinstance(event, DataReceived):
                self.bytes -= event.flow_controlled_length
            return event

    def discard(self) -> None:
        self.closed = True
        self.leg.credit(
            sum(
                event.flow_controlled_length
                for event in self.events
                if isinstance(event, DataReceived)
            ),
            self.stream_id,
        )
        self.events.clear()
        self.bytes = 0
        self.ready.set()


@dataclass(slots=True)
class _Exchange:
    frontend_id: int
    headers: Headers
    incoming: _Inbox
    task: asyncio.Task[None] | None = None
    origin_id: int | None = None
    outgoing: _Inbox | None = None
    started: bool = False
    cancelled: bool = False
    retired: bool = False
    response_ended: bool = False
    upload_complete: asyncio.Event = field(default_factory=asyncio.Event)


class HTTP2Proxy:
    def __init__(
        self,
        frontend: OwnedStream,
        authorizer: RequestAuthorizer,
        connect: Callable[[ConnectionTarget], Awaitable[OwnedStream]],
        *,
        maximum_streams: int = 64,
        idle_timeout: float = 30,
        authorization_timeout: float = 10,
    ) -> None:
        if (
            type(maximum_streams) is not int
            or not 1 <= maximum_streams <= 128
            or not all(
                math.isfinite(v) and 0 < v <= 120 for v in (idle_timeout, authorization_timeout)
            )
        ):
            raise ValueError("bounded HTTP/2 ownership required")
        self.authorizer, self.connect = authorizer, connect
        self.maximum_streams = maximum_streams
        self.idle_timeout, self.authorization_timeout = idle_timeout, authorization_timeout
        self.stop = asyncio.Event()
        self.front = _Leg(
            frontend,
            client=False,
            receive=self._frontend_event,
            stop=self.stop,
            maximum_streams=maximum_streams,
            idle_timeout=idle_timeout,
        )
        self.origin: _Leg | None = None
        self._origin_lock = asyncio.Lock()
        self._exchanges: dict[int, _Exchange] = {}
        self._origin_streams: dict[int, _Exchange] = {}
        self._tasks: set[asyncio.Task[None]] = set()
        self._running = False

    def _completed_task(self, task: asyncio.Task[None]) -> None:
        self._tasks.discard(task)
        if not task.cancelled() and task.exception() is not None:
            self.stop.set()

    def _cancel(self, exchange: _Exchange) -> None:
        exchange.cancelled = True
        self.front.deny(exchange.frontend_id)
        exchange.incoming.discard()
        if self.origin is not None and exchange.origin_id is not None:
            self.origin.deny(exchange.origin_id)
        if exchange.outgoing is not None:
            exchange.outgoing.discard()
        # A not-yet-started coroutine must enter its finally rather than be
        # cancelled before it can run any cleanup.
        if exchange.started and exchange.task is not None:
            exchange.task.cancel()

    def _frontend_event(self, event: Event) -> None:
        exchange: _Exchange | None
        if isinstance(event, RequestReceived):
            if len(self._exchanges) >= self.maximum_streams:
                self.front.deny(event.stream_id)
                return
            exchange = _Exchange(
                event.stream_id, tuple(event.headers), _Inbox(self.front, event.stream_id)
            )
            self._exchanges[event.stream_id] = exchange
            exchange.task = asyncio.create_task(self._request(exchange))
            self._tasks.add(exchange.task)
            exchange.task.add_done_callback(self._completed_task)
        elif isinstance(event, (DataReceived, TrailersReceived, StreamEnded, StreamReset)):
            exchange = self._exchanges.get(event.stream_id)
            if exchange is None:
                if isinstance(event, DataReceived):
                    self.front.credit(event.flow_controlled_length, event.stream_id)
                return
            if isinstance(event, StreamReset):
                self._cancel(exchange)
            else:
                try:
                    exchange.incoming.offer(event)
                except RequestDenied:
                    self._cancel(exchange)

    def _origin_event(self, event: Event) -> None:
        if isinstance(
            event,
            (
                ResponseReceived,
                InformationalResponseReceived,
                DataReceived,
                TrailersReceived,
                StreamEnded,
                StreamReset,
            ),
        ):
            exchange = self._origin_streams.get(event.stream_id)
            if exchange is None or exchange.outgoing is None:
                if isinstance(event, DataReceived) and self.origin is not None:
                    self.origin.credit(event.flow_controlled_length, event.stream_id)
                return
            if isinstance(event, StreamReset):
                self._cancel(exchange)
            else:
                if isinstance(event, (StreamEnded, TrailersReceived)):
                    exchange.response_ended = True
                try:
                    exchange.outgoing.offer(event)
                except RequestDenied:
                    self._cancel(exchange)

    def _origin_eof(self) -> None:
        # Complete responses already parsed into bounded queues remain usable.
        # An abrupt EOF cannot turn an incomplete response into successful EOS.
        for exchange in tuple(self._origin_streams.values()):
            if not exchange.response_ended:
                self._cancel(exchange)

    async def _upstream(self) -> _Leg:
        async with self._origin_lock:
            if self.origin is None:
                async with asyncio.timeout(self.authorization_timeout):
                    stream = await self.connect(self.authorizer.connection)
                    origin = _Leg(
                        stream,
                        client=True,
                        receive=self._origin_event,
                        stop=self.stop,
                        maximum_streams=self.maximum_streams,
                        idle_timeout=self.idle_timeout,
                        on_eof=self._origin_eof,
                    )
                    try:
                        await origin.start()
                    except BaseException:
                        await origin.close()
                        raise
                    self.origin = origin
            if self.origin.closed:
                raise RequestDenied("http2_origin_unavailable")
            return self.origin

    async def _upload(self, exchange: _Exchange, origin: _Leg) -> None:
        assert exchange.origin_id is not None
        while True:
            event = await exchange.incoming.take()
            if isinstance(event, DataReceived):
                try:
                    await origin.data(exchange.origin_id, event.data)
                finally:
                    self.front.credit(event.flow_controlled_length, exchange.frontend_id)
                    await self.front.flush()
            elif isinstance(event, TrailersReceived):
                await origin.headers(exchange.origin_id, tuple(event.headers), end=True)
                exchange.upload_complete.set()
                return
            elif isinstance(event, StreamEnded):
                await origin.data(exchange.origin_id, b"", end=True)
                exchange.upload_complete.set()
                return
            else:
                raise RequestDenied("http2_request_body_event")

    async def _response(
        self, exchange: _Exchange, origin: _Leg, upload: asyncio.Task[None]
    ) -> None:
        assert exchange.outgoing is not None and exchange.origin_id is not None
        expects = any(
            name == b"expect" and value.lower() == b"100-continue"
            for name, value in exchange.headers
        )
        continued = False
        while True:
            event = await exchange.outgoing.take()
            if isinstance(event, (ResponseReceived, InformationalResponseReceived)):
                if isinstance(event, InformationalResponseReceived):
                    continued |= (b":status", b"100") in event.headers
                elif expects and not continued and not exchange.upload_complete.is_set():
                    upload.cancel()
                await self.front.headers(exchange.frontend_id, tuple(event.headers))
            elif isinstance(event, DataReceived):
                try:
                    await self.front.data(exchange.frontend_id, event.data)
                finally:
                    origin.credit(event.flow_controlled_length, exchange.origin_id)
                    await origin.flush()
            elif isinstance(event, (TrailersReceived, StreamEnded)):
                if isinstance(event, TrailersReceived):
                    await self.front.headers(exchange.frontend_id, tuple(event.headers), end=True)
                else:
                    await self.front.data(exchange.frontend_id, b"", end=True)
                if not exchange.upload_complete.is_set():
                    upload.cancel()
                return
            else:
                raise RequestDenied("http2_response_event")

    async def _retire(self, exchange: _Exchange, *, complete: bool) -> None:
        if exchange.retired:
            return
        exchange.retired = True
        if not complete:
            self.front.deny(exchange.frontend_id)
            if self.origin is not None and exchange.origin_id is not None:
                self.origin.deny(exchange.origin_id)
        exchange.incoming.discard()
        if exchange.outgoing is not None:
            exchange.outgoing.discard()
        self._exchanges.pop(exchange.frontend_id, None)
        if exchange.origin_id is not None:
            self._origin_streams.pop(exchange.origin_id, None)
        await self.front.flush()
        if self.origin is not None:
            await self.origin.flush()

    async def _request(self, exchange: _Exchange) -> None:
        exchange.started = True
        complete = False
        try:
            if exchange.cancelled:
                return
            head = RequestHead.http2(exchange.headers, self.authorizer.connection)
            if head.upgrade is not None:
                raise RequestDenied("http2_websocket_owner_not_implemented")
            async with asyncio.timeout(self.authorization_timeout):
                await self.authorizer.authorize(head)
            origin = await self._upstream()
            async with origin.write_lock:
                stream_id = origin.protocol.get_next_available_stream_id()
                exchange.origin_id = stream_id
                exchange.outgoing = _Inbox(origin, stream_id)
                self._origin_streams[stream_id] = exchange
                # Mapping exists BEFORE serialization can expose the stream.
                origin.protocol.headers(stream_id, head.headers)
                await origin._flush_locked()
            async with asyncio.TaskGroup() as group:
                upload = group.create_task(self._upload(exchange, origin))
                group.create_task(self._response(exchange, origin, upload))
            complete = exchange.upload_complete.is_set()
        except asyncio.CancelledError:
            raise
        except Exception:
            try:
                _LOG.warning("http2_exchange_reset reason=request_or_upstream")
            except Exception:
                pass
        finally:
            try:
                await self._retire(exchange, complete=complete)
            except Exception:
                self.stop.set()

    async def run(self) -> None:
        if self._running:
            raise RuntimeError("HTTP/2 stream owner cannot be reused")
        self._running = True
        try:
            await self.front.start()
            while not self.stop.is_set():
                legs = (self.front,) if self.origin is None else (self.front, self.origin)
                last_activity = max(leg.last_activity for leg in legs)
                remaining = max(0, last_activity + self.idle_timeout - time.monotonic())
                try:
                    async with asyncio.timeout(remaining):
                        await self.stop.wait()
                except TimeoutError:
                    current = (self.front,) if self.origin is None else (self.front, self.origin)
                    if (
                        time.monotonic() - max(leg.last_activity for leg in current)
                        >= self.idle_timeout
                    ):
                        break
        finally:
            exchanges = tuple(self._exchanges.values())
            for exchange in exchanges:
                self._cancel(exchange)
            tasks = tuple(self._tasks)
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            for exchange in exchanges:
                if not exchange.retired:
                    exchange.incoming.discard()
                    if exchange.outgoing is not None:
                        exchange.outgoing.discard()
            self._exchanges.clear()
            self._origin_streams.clear()
            await self.front.close()
            if self.origin is not None:
                await self.origin.close()
