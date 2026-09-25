"""Async socket owner for the public-ABI TLS engine.

The real origin/certificate coordinator is called once, while ClientHello is
paused. It receives the decrypted offers. No generic CONNECT or opaque copy
path exists here; the returned stream still needs HTTP authorization.
"""

from __future__ import annotations

import asyncio
import logging
import math
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from ads_sandbox_egress.http1 import reset
from ads_sandbox_egress.tls import ClientHello, TLSContext, TLSFailure, TLSSession, UnmappableTLS

_LOG = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class FrontendIdentity:
    certificate_chain: tuple[bytes, ...]
    private_key: bytes = field(repr=False)
    selected_alpn: bytes | None = None


class TLSStream:
    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        session: TLSSession,
        *,
        idle_timeout: float,
    ) -> None:
        self.reader, self.writer, self.session = reader, writer, session
        self.idle_timeout = idle_timeout
        self._read_lock = asyncio.Lock()
        self._pending = bytearray()
        self._closed = False

    @classmethod
    async def accept(
        cls,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        context: TLSContext,
        prepare: Callable[[ClientHello], Awaitable[FrontendIdentity]],
        *,
        handshake_timeout: float = 10,
        idle_timeout: float = 30,
    ) -> TLSStream:
        if not all(math.isfinite(v) and v > 0 for v in (handshake_timeout, idle_timeout)):
            reset(writer)
            raise ValueError("finite positive TLS deadlines required")
        session = None
        try:
            session = context.session()
            stream = cls(reader, writer, session, idle_timeout=idle_timeout)
            # Includes origin acquisition and certificate selection. A trickle
            # cannot renew the handshake budget.
            async with asyncio.timeout(handshake_timeout):
                while True:
                    state = session.handshake()
                    await stream.drain()
                    if state == "hello":
                        if session.hello is None:
                            raise TLSFailure("missing_client_hello")
                        identity = await prepare(session.hello)
                        session.resume(
                            identity.certificate_chain,
                            identity.private_key,
                            identity.selected_alpn,
                        )
                    elif state == "complete":
                        return stream
                    elif state == "read":
                        await stream._receive()
                    else:
                        raise TLSFailure("unexpected_memory_bio_backpressure")
        except BaseException as exc:
            if session is not None:
                session.close()
            reset(writer)
            if isinstance(exc, UnmappableTLS):
                # Fixed enum only: no exception repr/traceback, certificate,
                # server name, private key or arbitrary remote text.
                _LOG.warning("unmappable_tls reason=%s", exc.reason.value)
            raise

    @property
    def transport(self) -> asyncio.WriteTransport:
        return self.writer.transport

    def get_extra_info(self, name: str, default: Any = None) -> Any:
        return self.writer.get_extra_info(name, default)

    async def _receive(self) -> None:
        encrypted = await self.reader.read(16384)
        if not encrypted:
            # EOF without close_notify is truncation, not a successful TLS EOF.
            raise TLSFailure("tls_truncated")
        self.session.feed(encrypted)

    async def read(self, maximum: int = 16384) -> bytes:
        if not 1 <= maximum <= 16384 or self._closed:
            raise TLSFailure("tls_stream_read_state")
        try:
            async with self._read_lock, asyncio.timeout(self.idle_timeout):
                while True:
                    data = self.session.read(maximum)
                    await self.drain()
                    if data is not None:
                        return data
                    await self._receive()
        except BaseException:
            self.close()
            raise

    def write(self, data: bytes) -> None:
        # One bounded plaintext queue, drained through TLS before another body
        # chunk is requested from the protocol layer.
        if self._closed or len(self._pending) + len(data) > 65536:
            self.close()
            raise TLSFailure("tls_stream_write_limit")
        self._pending.extend(data)

    async def drain(self) -> None:
        if self._closed:
            raise TLSFailure("closed_tls_stream")
        try:
            # No await between consuming engine output and ordered socket
            # writes. TLS read/write coroutines can safely share this engine.
            encrypted = self.session.drain()
            if encrypted:
                self.writer.write(encrypted)
            while self._pending:
                data = bytes(self._pending[:16384])
                del self._pending[:16384]
                self.session.write(data)
                self.writer.write(self.session.drain())
            async with asyncio.timeout(self.idle_timeout):
                await self.writer.drain()
        except BaseException:
            self.close()
            raise

    async def finish(self) -> None:
        """Normal owner completion, distinct from reset-only rejection."""
        try:
            await self.drain()
            self.session.shutdown()
            await self.drain()
            self._closed = True
            self.session.close()
            self.writer.close()
            async with asyncio.timeout(self.idle_timeout):
                await self.writer.wait_closed()
        except BaseException:
            # wait_closed can itself fail after the native state was freed.
            reset(self.writer)
            self.close()
            raise

    def close(self) -> None:
        """Denial/cancellation aborts TCP without a TLS or HTTP policy message."""
        if not self._closed:
            self._closed = True
            self._pending.clear()
            self.session.close()
            reset(self.writer)
