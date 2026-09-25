"""Explicit byte-stream custody shared by the two inspected protocol owners."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from ads_sandbox_egress.http1 import ByteReader, ByteWriter, reset
from ads_sandbox_egress.tls_transport import TLSStream


class _PrefixedReader:
    def __init__(self, reader: ByteReader, prefix: bytes) -> None:
        if len(prefix) > 131072:
            raise ValueError("bounded parser handoff required")
        self.reader, self.pending = reader, prefix

    async def read(self, maximum: int) -> bytes:
        if not 1 <= maximum <= 16384:
            raise ValueError("bounded stream read required")
        if self.pending:
            result, self.pending = self.pending[:maximum], self.pending[maximum:]
            return result
        return await self.reader.read(maximum)


@dataclass(frozen=True, slots=True)
class OwnedStream:
    reader: ByteReader
    writer: ByteWriter
    abort: Callable[[], None]
    finish: Callable[[], Awaitable[None]]

    def prefixed(self, data: bytes) -> OwnedStream:
        """Transfer ownership to a new protocol without losing parser bytes."""
        return OwnedStream(_PrefixedReader(self.reader, data), self.writer, self.abort, self.finish)

    @classmethod
    def tcp(cls, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> OwnedStream:
        def abort() -> None:
            reset(writer)
            writer.close()

        async def finish() -> None:
            try:
                writer.close()
                async with asyncio.timeout(5):
                    await writer.wait_closed()
            except BaseException:
                abort()
                raise

        return cls(reader, writer, abort, finish)

    @classmethod
    def tls(cls, stream: TLSStream) -> OwnedStream:
        return cls(stream, stream, stream.close, stream.finish)
