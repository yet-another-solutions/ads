"""Bounded HTTP/1.1 event I/O and actual reset semantics.

This module is not an opaque forwarding fallback. Protocol transitions are
returned to the owning handler for explicit authorization/implementation.
"""

from __future__ import annotations

import asyncio
import errno
import socket
import struct
from typing import Any, Protocol

import h11

from ads_sandbox_egress.framing import ChunkedWire, raw_http1_headers, validate_trailers
from ads_sandbox_egress.policy import RequestDenied


class ByteReader(Protocol):
    async def read(self, maximum: int) -> bytes: ...


class ByteWriter(Protocol):
    @property
    def transport(self) -> asyncio.WriteTransport: ...
    def get_extra_info(self, name: str, default: Any = None) -> Any: ...
    def write(self, data: bytes) -> None: ...
    async def drain(self) -> None: ...


def reset(writer: ByteWriter) -> None:
    """Abort without TLS close-notify or synthetic HTTP policy response."""
    sock = writer.get_extra_info("socket")
    try:
        if sock is not None:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    except OSError as exc:
        if exc.errno not in (errno.EBADF, errno.ENOTSOCK):
            raise
    finally:
        writer.transport.abort()


class HTTP1Channel:
    """One parser/serializer per terminated leg, with pre-parser header checks.

    Read the next header block separately before feeding it to h11. Body reads
    are bounded, and pipelined trailing bytes are returned to this pre-parser
    gate at each cycle. A peer cannot hide a second request in normalized fields.
    """

    def __init__(
        self,
        reader: ByteReader,
        writer: ByteWriter,
        *,
        client: bool,
        idle_timeout: float = 30,
    ) -> None:
        self.reader, self.writer = reader, writer
        self.connection = h11.Connection(
            h11.CLIENT if client else h11.SERVER, max_incomplete_event_size=65536
        )
        self.idle_timeout = idle_timeout
        self._header = True
        self._pending = bytearray()
        self._eof = False
        self._chunks: ChunkedWire | None = None
        self._detached = False

    async def _receive_headers(self) -> None:
        # Absolute per-header deadline, not extended by arriving bytes.
        async with asyncio.timeout(self.idle_timeout):
            while True:
                end = self._pending.find(b"\r\n\r\n")
                if end >= 0:
                    block = bytes(self._pending[: end + 4])
                    del self._pending[: end + 4]
                    _, headers = raw_http1_headers(block)
                    self._chunks = (
                        ChunkedWire()
                        if (b"transfer-encoding", b"chunked")
                        in tuple((name, value.lower()) for name, value in headers)
                        else None
                    )
                    self.connection.receive_data(block)
                    self._header = False
                    return
                if len(self._pending) > 65536:
                    raise RequestDenied("header_limit")
                chunk = await self.reader.read(16384)
                if not chunk:
                    if self._pending:
                        raise RequestDenied("truncated_headers")
                    self._eof = True
                    self._header = False
                    self.connection.receive_data(b"")
                    return
                self._pending.extend(chunk)

    async def receive(self) -> h11.Event:
        if self._detached:
            raise RequestDenied("http1_ownership_transferred")
        try:
            if self._header:
                await self._receive_headers()
            while True:
                event = self.connection.next_event()
                if event is h11.PAUSED:
                    raise RequestDenied("unexpected_protocol_transition")
                if isinstance(event, h11.Event):
                    if isinstance(event, h11.EndOfMessage):
                        validate_trailers(tuple(event.headers))
                    elif isinstance(event, h11.InformationalResponse) and event.status_code != 101:
                        # h11 expects another header block after each 1xx.
                        self._header = True
                    return event
                if self._pending:
                    data = bytes(self._pending)
                    self._pending.clear()
                elif not self._eof:
                    async with asyncio.timeout(self.idle_timeout):
                        data = await self.reader.read(16384)
                else:
                    raise RequestDenied("unexpected_eof")
                if not data:
                    self._eof = True
                if self._chunks is not None:
                    self._chunks.feed(data)
                self.connection.receive_data(data)
        except (h11.RemoteProtocolError, h11.LocalProtocolError, TimeoutError) as exc:
            raise RequestDenied("http1_protocol_failure") from exc

    async def send(self, event: h11.Event) -> None:
        if self._detached:
            raise RequestDenied("http1_ownership_transferred")
        try:
            data = self.connection.send(event)
            if data:
                self.writer.write(data)
                async with asyncio.timeout(self.idle_timeout):
                    await self.writer.drain()
        except (h11.LocalProtocolError, TimeoutError) as exc:
            raise RequestDenied("http1_serialization_failure") from exc

    def next_cycle(self) -> None:
        if self._detached:
            raise RequestDenied("http1_ownership_transferred")
        trailing, closed = self.connection.trailing_data
        # A fresh parser retains both sides' completed-cycle legality, but h11's
        # own buffer must not parse pipelined headers before the strict raw gate.
        if self.connection.our_state is not h11.DONE or self.connection.their_state is not h11.DONE:
            raise RequestDenied("http1_cycle_not_reusable")
        role = self.connection.our_role
        self.connection = h11.Connection(role, max_incomplete_event_size=65536)
        self._pending[:0] = trailing
        self._eof = closed
        self._header = True
        self._chunks = None

    def take_switched_data(self) -> bytes:
        """Transfer buffered bytes once, only after both peers switched."""
        if (
            self._detached
            or self.connection.our_state is not h11.SWITCHED_PROTOCOL
            or self.connection.their_state is not h11.SWITCHED_PROTOCOL
        ):
            raise RequestDenied("http1_not_switched")
        trailing, _ = self.connection.trailing_data
        data = trailing + bytes(self._pending)
        self._pending.clear()
        self._detached = True
        # Prevent a second transfer or re-entry into the HTTP parser.
        self.connection = h11.Connection(self.connection.our_role)
        return data
