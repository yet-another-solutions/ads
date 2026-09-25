"""Explicit byte-stream custody shared by the two inspected protocol owners."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from ads_sandbox_egress.http1 import ByteReader, ByteWriter, reset
from ads_sandbox_egress.tls_transport import TLSStream


@dataclass(frozen=True, slots=True)
class OwnedStream:
    reader: ByteReader
    writer: ByteWriter
    abort: Callable[[], None]
    finish: Callable[[], Awaitable[None]]

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
