import asyncio
import socket

import h11
import pytest
from websockets.asyncio.client import connect
from websockets.extensions.permessage_deflate import ServerPerMessageDeflateFactory
from websockets.frames import Frame, Opcode
from websockets.http11 import Request
from websockets.server import ServerProtocol

from ads_commons.egress import (
    EgressRule,
    ProjectEgressSettings,
    ProjectEgressSnapshot,
    ProtocolSettings,
)
from ads_sandbox_egress.http1 import HTTP1Channel
from ads_sandbox_egress.policy import RequestDenied
from ads_sandbox_egress.websocket import request_headers, response_headers
from test_http1_proxy import close_client, proxy_lab, settings
from test_normalization import nginx_helper as nginx_helper


@pytest.fixture
def anyio_backend():
    return "asyncio"


FIELDS = (
    (b"host", b"origin.example"),
    (b"upgrade", b"websocket"),
    (b"connection", b"Upgrade"),
    (b"sec-websocket-key", b"dGhlIHNhbXBsZSBub25jZQ=="),
    (b"sec-websocket-version", b"13"),
)
RESPONSE = (
    (b"upgrade", b"websocket"),
    (b"connection", b"Upgrade"),
    (b"sec-websocket-accept", b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
)


def wire(fields=FIELDS, method=b"GET"):
    return (
        method
        + b" /a/%62/../allowed?q=x HTTP/1.1\r\n"
        + b"".join(n + b": " + v + b"\r\n" for n, v in fields)
        + b"\r\n"
    )


def allowed():
    return ProjectEgressSettings(
        (
            EgressRule(
                "origin.example",
                80,
                "http",
                ProtocolSettings(method="GET", upgrades=("websocket",)),
                sub_protocol="http/1.1",
            ),
        )
    )


@pytest.mark.parametrize(
    "fields,method",
    [
        (FIELDS, b"POST"),
        (FIELDS[:-1], b"GET"),
        (FIELDS + ((b"sec-websocket-key", FIELDS[3][1]),), b"GET"),
        (FIELDS[:3] + ((b"sec-websocket-key", b"YWJj"),) + FIELDS[4:], b"GET"),
        (FIELDS[:-1] + ((b"sec-websocket-version", b"12"),), b"GET"),
        (FIELDS + ((b"content-length", b"1"),), b"GET"),
        (FIELDS + ((b"transfer-encoding", b"chunked"),), b"GET"),
        (FIELDS + ((b"expect", b"100-continue"),), b"GET"),
        (FIELDS + ((b"connection", b"sec-websocket-key"),), b"GET"),
        (FIELDS + ((b"connection", b"close"),), b"GET"),
        (FIELDS + ((b"sec-websocket-protocol", b"chat,chat"),), b"GET"),
        (FIELDS + ((b"sec-websocket-extensions", b'deflate; param="not a token"'),), b"GET"),
    ],
)
@pytest.mark.anyio
async def test_bad_opening_request_never_contacts_origin(nginx_helper, fields, method):
    async def unexpected(reader, writer):
        pytest.fail("denied WebSocket request contacted origin")

    async with proxy_lab(nginx_helper, unexpected, allowed()) as lab:
        reader, writer = await asyncio.open_connection(*lab.address)
        try:
            writer.write(wire(fields, method))
            await writer.drain()
            with pytest.raises(ConnectionResetError):
                await reader.read(1)
            assert not lab.connected
        finally:
            await close_client(writer)


@pytest.mark.parametrize(
    "fields",
    [
        RESPONSE[:-1],
        RESPONSE[:-1] + ((b"sec-websocket-accept", b"wrong"),),
        RESPONSE + ((b"sec-websocket-accept", RESPONSE[-1][1]),),
        RESPONSE + ((b"content-length", b"0"),),
        RESPONSE + ((b"sec-websocket-protocol", b"unoffered"),),
        RESPONSE + ((b"sec-websocket-extensions", b"unoffered"),),
        RESPONSE[1:],
        RESPONSE[:1] + RESPONSE[2:],
    ],
)
@pytest.mark.anyio
async def test_invalid_101_is_reset_not_switched_or_repaired(nginx_helper, fields):
    async def origin(reader, writer):
        await reader.readuntil(b"\r\n\r\n")
        writer.write(
            b"HTTP/1.1 101 Switching Protocols\r\n"
            + b"".join(n + b": " + v + b"\r\n" for n, v in fields)
            + b"\r\npayload must not escape"
        )
        await writer.drain()
        await reader.read()

    async with proxy_lab(nginx_helper, origin, allowed()) as lab:
        reader, writer = await asyncio.open_connection(*lab.address)
        try:
            writer.write(wire())
            await writer.drain()
            with pytest.raises(ConnectionResetError):
                await reader.read(1)
        finally:
            await close_client(writer)


@pytest.mark.anyio
async def test_policy_denies_upgrade_before_origin_handshake(nginx_helper):
    async def unexpected(reader, writer):
        pytest.fail("denied transition contacted origin")

    async with proxy_lab(nginx_helper, unexpected, settings()) as lab:
        reader, writer = await asyncio.open_connection(*lab.address)
        try:
            writer.write(wire())
            await writer.drain()
            with pytest.raises(ConnectionResetError):
                await reader.read(1)
            assert not lab.connected
        finally:
            await close_client(writer)


@pytest.mark.anyio
async def test_real_websocket_compression_fragmentation_ping_close_and_policy_update(nginx_helper):
    received = []

    async def origin(reader, writer):
        protocol = ServerProtocol(
            extensions=[ServerPerMessageDeflateFactory()], subprotocols=["chat"]
        )
        while data := await reader.read(16384):
            protocol.receive_data(data)
            for event in protocol.events_received():
                if isinstance(event, Request):
                    received.append(event.path)
                    response = protocol.accept(event)
                    assert response.status_code == 101
                    protocol.send_response(response)
                    protocol.send_binary(b"welcome")  # Coalesced with the 101.
                elif isinstance(event, Frame) and event.opcode in (Opcode.BINARY, Opcode.CONT):
                    protocol.send_frame(event)
                elif isinstance(event, Frame) and event.opcode == Opcode.CLOSE:
                    for output in protocol.data_to_send():
                        if output:
                            writer.write(output)
                    await writer.drain()
                    return
            for output in protocol.data_to_send():
                if output:
                    writer.write(output)
            await writer.drain()

    async with proxy_lab(nginx_helper, origin, allowed()) as lab:
        sock = socket.socket()
        sock.setblocking(False)
        try:
            await asyncio.get_running_loop().sock_connect(sock, lab.address)
            async with connect(
                "ws://origin.example/a/%62/../allowed?q=x",
                sock=sock,
                proxy=None,
                subprotocols=["chat"],
                max_size=2**21,
                ping_interval=None,
                close_timeout=2,
            ) as client:
                assert client.subprotocol == "chat"
                assert client.protocol.extensions
                assert await client.recv() == b"welcome"
                await lab.policies.install(ProjectEgressSnapshot(2, ProjectEgressSettings(())))
                # No policy/content reinspection once this session is admitted.
                await client.send([b"one", b"two", b"three"])
                assert await client.recv() == b"onetwothree"
                pong = await client.ping(b"alive")
                await asyncio.wait_for(pong, 2)
                body = bytes(range(256)) * 4096
                await client.send(body)
                assert await client.recv() == body
            assert received == ["/a/%62/../allowed?q=x"]
        finally:
            sock.close()


@pytest.mark.anyio
async def test_redirect_is_http_response_and_next_request_reauthorizes(nginx_helper):
    received = []

    async def origin(reader, writer):
        received.append(await reader.readuntil(b"\r\n\r\n"))
        writer.write(
            b"HTTP/1.1 302 Found\r\nLocation: http://10.0.0.1/private\r\nContent-Length: 0\r\n\r\n"
        )
        await writer.drain()
        await reader.read()

    async with proxy_lab(nginx_helper, origin, allowed()) as lab:
        reader, writer = await asyncio.open_connection(*lab.address)
        try:
            writer.write(wire())
            await writer.drain()
            response = await reader.readuntil(b"\r\n\r\n")
            assert response.startswith(b"HTTP/1.1 302")
            assert b"10.0.0.1/private" in response
            await lab.policies.install(ProjectEgressSnapshot(2, ProjectEgressSettings(())))
            writer.write(b"GET /allowed HTTP/1.1\r\nHost: origin.example\r\n\r\n")
            await writer.drain()
            with pytest.raises(ConnectionResetError):
                await reader.read(1)
            assert len(received) == 1
        finally:
            await close_client(writer)


def test_extension_and_subprotocol_validation_without_payload_transforms():
    request = FIELDS + (
        (b"sec-websocket-protocol", b"chat, superchat"),
        (b"sec-websocket-extensions", b'permessage-deflate; client_max_window_bits="15"'),
    )
    assert request_headers(b"GET", request)
    assert response_headers(
        request,
        RESPONSE
        + (
            (b"sec-websocket-protocol", b"chat"),
            (b"sec-websocket-extensions", b"permessage-deflate; server_no_context_takeover"),
        ),
    )
    with pytest.raises(RequestDenied):
        response_headers(request, RESPONSE + ((b"sec-websocket-protocol", b"chat, superchat"),))


@pytest.mark.anyio
async def test_websocket_idle_and_cancel_leave_no_orphan_relays(nginx_helper):
    closed = asyncio.Event()

    async def origin(reader, writer):
        await reader.readuntil(b"\r\n\r\n")
        writer.write(
            b"HTTP/1.1 101 Switching Protocols\r\n"
            + b"".join(n + b": " + v + b"\r\n" for n, v in RESPONSE)
            + b"\r\n"
        )
        await writer.drain()
        try:
            await reader.read()
        finally:
            closed.set()

    async with proxy_lab(nginx_helper, origin, allowed()) as lab:
        reader, writer = await asyncio.open_connection(*lab.address)
        try:
            writer.write(wire())
            await writer.drain()
            assert (await reader.readuntil(b"\r\n\r\n")).startswith(b"HTTP/1.1 101")
            with pytest.raises(ConnectionResetError):
                async with asyncio.timeout(3):
                    await reader.read(1)
            await asyncio.wait_for(closed.wait(), 2)
        finally:
            await close_client(writer)
    assert not lab.tasks


@pytest.mark.anyio
async def test_one_direction_websocket_activity_outlasts_idle_budget(nginx_helper):
    frames = b"\x82\x01x"

    async def origin(reader, writer):
        await reader.readuntil(b"\r\n\r\n")
        writer.write(
            b"HTTP/1.1 101 Switching Protocols\r\n"
            + b"".join(n + b": " + v + b"\r\n" for n, v in RESPONSE)
            + b"\r\n"
        )
        await writer.drain()
        for _ in range(8):
            await asyncio.sleep(0.2)
            writer.write(frames)
            await writer.drain()
        await reader.read()

    async with proxy_lab(nginx_helper, origin, allowed()) as lab:
        reader, writer = await asyncio.open_connection(*lab.address)
        try:
            writer.write(wire())
            await writer.drain()
            assert (await reader.readuntil(b"\r\n\r\n")).startswith(b"HTTP/1.1 101")
            assert await asyncio.wait_for(reader.readexactly(len(frames) * 8), 3) == frames * 8
        finally:
            await close_client(writer)


@pytest.mark.anyio
async def test_switched_channel_cannot_reparse_or_transfer_buffer_twice():
    # No fake parser/serializer: seed the actual h11 transition state.
    channel = HTTP1Channel(None, None, client=False)
    channel.connection.receive_data(wire() + b"pending")
    assert isinstance(channel.connection.next_event(), h11.Request)
    assert isinstance(channel.connection.next_event(), h11.EndOfMessage)
    channel.connection.send(h11.InformationalResponse(status_code=101, headers=list(RESPONSE)))
    assert channel.take_switched_data() == b"pending"
    with pytest.raises(RequestDenied):
        channel.take_switched_data()
    with pytest.raises(RequestDenied):
        channel.next_cycle()
    with pytest.raises(RequestDenied):
        await channel.receive()
    with pytest.raises(RequestDenied):
        await channel.send(h11.EndOfMessage())
