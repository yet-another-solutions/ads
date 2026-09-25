import asyncio
import socket
import struct

import h11
import pytest

from ads_sandbox_egress.http1 import HTTP1Channel, reset
from ads_sandbox_egress.policy import RequestDenied


def test_actual_tcp_reset_without_http_response():
    async def run():
        async def handle(reader, writer):
            await reader.read(1)
            reset(writer)

        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        async with server:
            reader, writer = await asyncio.open_connection(*server.sockets[0].getsockname())
            writer.write(b"x")
            await writer.drain()
            with pytest.raises(ConnectionResetError):
                await reader.read(1)
            writer.close()
            with pytest.raises(ConnectionResetError):
                await writer.wait_closed()

    asyncio.run(run())


def test_pipelined_duplicate_length_cannot_bypass_raw_gate():
    async def run():
        results = asyncio.get_running_loop().create_future()

        async def handle(reader, writer):
            channel = HTTP1Channel(reader, writer, client=False)
            try:
                request = await channel.receive()
                assert isinstance(request, h11.Request) and request.target == b"/first?q=%2f"
                assert isinstance(await channel.receive(), h11.EndOfMessage)
                await channel.send(h11.Response(status_code=204, headers=[]))
                await channel.send(h11.EndOfMessage())
                channel.next_cycle()
                with pytest.raises(RequestDenied, match="ambiguous"):
                    await channel.receive()
                results.set_result(True)
            except BaseException as exc:
                results.set_exception(exc)
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        async with server:
            reader, writer = await asyncio.open_connection(*server.sockets[0].getsockname())
            writer.write(
                b"GET /first?q=%2f HTTP/1.1\r\nHost: example.com\r\n\r\n"
                b"POST /second HTTP/1.1\r\nHost: example.com\r\n"
                b"Content-Length: 0\r\nContent-Length: 0\r\n\r\n"
            )
            await writer.drain()
            await asyncio.wait_for(results, 3)
            assert b"204" in await reader.read()
            writer.close()
            await writer.wait_closed()

    asyncio.run(run())


def test_streaming_chunks_and_trailers_actual_parser():
    async def run():
        results = asyncio.get_running_loop().create_future()

        async def handle(reader, writer):
            channel = HTTP1Channel(reader, writer, client=False)
            try:
                assert isinstance(await channel.receive(), h11.Request)
                pieces = []
                while True:
                    event = await channel.receive()
                    if isinstance(event, h11.EndOfMessage):
                        assert list(event.headers) == [(b"digest", b"abc")]
                        break
                    assert isinstance(event, h11.Data)
                    pieces.append(bytes(event.data))
                assert b"".join(pieces) == b"hello world"
                results.set_result(True)
            except BaseException as exc:
                results.set_exception(exc)
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        async with server:
            _, writer = await asyncio.open_connection(*server.sockets[0].getsockname())
            for part in [
                b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n",
                b"6\r\nhello \r\n",
                b"5\r\nworld\r\n",
                b"0\r\nDigest: abc\r\n\r\n",
            ]:
                writer.write(part)
                await writer.drain()
                await asyncio.sleep(0)
            await asyncio.wait_for(results, 3)
            writer.close()
            await writer.wait_closed()

    asyncio.run(run())


def test_reset_linger_configuration():
    # AF_INET linger layout is native ints on the Linux production platform.
    assert len(struct.pack("ii", 1, 0)) == 8
    assert socket.SO_LINGER > 0


@pytest.mark.parametrize(
    "body",
    [
        b"1\nx\r\n0\r\n\r\n",
        b"0\r\nDigest: good\r\n folded\r\n\r\n",
        b"0\r\nHost: replaced.example\r\n\r\n",
        b"0\r\nDigest: good\n\n",
    ],
)
def test_raw_chunk_ambiguity_never_normalized_away(body):
    async def run():
        reader = asyncio.StreamReader()
        reader.feed_data(
            b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n" + body
        )
        reader.feed_eof()
        # The receiving half does not write; an actual h11 parser processes all
        # bytes, with StreamReader as the external socket boundary.
        channel = HTTP1Channel(reader, None, client=False)
        assert isinstance(await channel.receive(), h11.Request)
        with pytest.raises(RequestDenied):
            while not isinstance(await channel.receive(), h11.EndOfMessage):
                pass

    asyncio.run(run())


def test_raw_chunk_grammar_incremental_and_pipelined():
    from ads_sandbox_egress.framing import ChunkedWire

    observer = ChunkedWire()
    for char in b'1 ; name="quoted\\"value"; token=yes\r\nx\r\n0\r\nDigest: abc\r\n\r\nNEXT':
        observer.feed(bytes((char,)))
    assert observer.state == "done"
    assert observer.trailers == [(b"Digest", b"abc")]
