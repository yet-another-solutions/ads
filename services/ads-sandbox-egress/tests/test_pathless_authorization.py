"""Real protocol/NGINX regressions for the explicitly approved adapters."""

import asyncio
import ipaddress

import h11
import pytest
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import RequestReceived, StreamEnded

from ads_sandbox_egress.http1 import HTTP1Channel
from ads_sandbox_egress.http2_proxy import HTTP2Proxy
from ads_sandbox_egress.normalization import Normalizer
from ads_sandbox_egress.request_authorization import ConnectionTarget
from test_http1_proxy import close_client, proxy_lab, settings
from test_http2_proxy import Client, Origin, ended, reset
from test_normalization import nginx_helper as nginx_helper


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.anyio
@pytest.mark.parametrize("chunked", [False, True])
async def test_empty_host_upload_preserves_origin_method_target_framing_and_expect(
    nginx_helper, chunked
):
    seen = []

    async def origin(reader, writer):
        channel = HTTP1Channel(reader, writer, client=False)
        request = await channel.receive()
        assert request.method == b"POST" and request.target == b"/a/../upload?raw=%2f"
        assert (b"host", b"") in request.headers
        assert (b"expect", b"100-continue") in request.headers
        assert (
            (b"transfer-encoding", b"chunked") if chunked else (b"content-length", b"4")
        ) in request.headers
        await channel.send(h11.InformationalResponse(status_code=100, headers=[]))
        while not isinstance(event := await channel.receive(), h11.EndOfMessage):
            seen.append(event)
        if chunked:
            assert list(event.headers) == [(b"digest", b"retained")]
        await channel.send(h11.Response(status_code=200, headers=[(b"content-length", b"0")]))
        await channel.send(h11.EndOfMessage())

    async with proxy_lab(nginx_helper, origin, settings("/upload", domain="*")) as lab:
        reader, writer = await asyncio.open_connection(*lab.address)
        try:
            framing = b"Transfer-Encoding: chunked" if chunked else b"Content-Length: 4"
            writer.write(
                b"POST /a/../upload?raw=%2f HTTP/1.1\r\nHost:\r\nExpect: 100-continue\r\n"
                + framing
                + b"\r\nConnection: close\r\n\r\n"
            )
            await writer.drain()
            assert b"100" in await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2)
            assert not seen
            writer.write(b"4\r\nbody\r\n0\r\nDigest: retained\r\n\r\n" if chunked else b"body")
            await writer.drain()
            assert b"200" in await asyncio.wait_for(reader.read(), 2)
            assert b"".join(event.data for event in seen) == b"body"
            assert not lab.resolver.calls
        finally:
            await close_client(writer)


@pytest.mark.anyio
@pytest.mark.parametrize("host", [b"", b"origin.example"])
async def test_options_asterisk_http1_preserves_target_without_inventing_uri(tmp_path, host):
    received = []

    async def origin(reader, writer):
        received.append(await reader.readuntil(b"\r\n\r\n"))
        writer.write(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
        await writer.drain()

    # No helper socket: pathless is an explicit target kind, not fallback on
    # helper failure. The ordinary path failure is tested separately below.
    helper = Normalizer(tmp_path / "not-running.sock")
    async with proxy_lab(helper, origin, settings(domain="*")) as lab:
        reader, writer = await asyncio.open_connection(*lab.address)
        try:
            writer.write(b"OPTIONS * HTTP/1.1\r\nHost: " + host + b"\r\nConnection: close\r\n\r\n")
            await writer.drain()
            assert b"204" in await asyncio.wait_for(reader.read(), 2)
            assert received == [b"OPTIONS * HTTP/1.1\r\nhost: " + host + b"\r\n\r\n"]
            assert lab.resolver.calls == (["origin.example"] if host else [])
        finally:
            await close_client(writer)


@pytest.mark.anyio
@pytest.mark.parametrize(
    "wire",
    [
        b"GET * HTTP/1.1\r\nHost:\r\n\r\n",
        b"OPTIONS * HTTP/1.1\r\n\r\n",
        b"OPTIONS * HTTP/1.1\r\nHost:\r\nHost:\r\n\r\n",
        b"OPTIONS / HTTP/1.1\r\nHost:\r\n\r\n",
    ],
)
async def test_pathless_does_not_bypass_protocol_or_ordinary_helper_failure(tmp_path, wire):
    async def origin(reader, writer):
        pytest.fail("invalid or unnormalized request reached origin")

    async with proxy_lab(
        Normalizer(tmp_path / "not-running.sock"), origin, settings(domain="*")
    ) as lab:
        reader, writer = await asyncio.open_connection(*lab.address)
        try:
            writer.write(wire)
            await writer.drain()
            with pytest.raises(ConnectionResetError):
                await asyncio.wait_for(reader.read(), 2)
            assert not lab.connected
        finally:
            await close_client(writer)


@pytest.mark.anyio
@pytest.mark.parametrize("mode", ["whitelist", "blacklist"])
async def test_http2_asterisk_path_constraint_is_not_a_uri_and_keeps_other_streams(
    nginx_helper, mode
):
    origin = Origin()
    async with proxy_lab(
        nginx_helper, origin.handle, settings("/allowed", mode=mode), proxy_type=HTTP2Proxy
    ) as lab:
        client = await Client.open(lab.address)
        try:
            await client.request(1, b"*", method=b"OPTIONS")
            await client.request(3, b"/allowed")
            await client.until(
                lambda events: (
                    reset(events, 1) and ended(events, 3)
                    if mode == "whitelist"
                    else ended(events, 1) and reset(events, 3)
                )
            )
            assert len(origin.requests) == 1
            fields = dict(next(iter(origin.requests.values())))
            assert fields[b":path"] == (b"/allowed" if mode == "whitelist" else b"*")
            assert fields[b":method"] == (b"GET" if mode == "whitelist" else b"OPTIONS")
        finally:
            await close_client(client.writer)


@pytest.mark.anyio
@pytest.mark.parametrize("authority", [(), ((b":authority", b""),)])
async def test_http2_absent_or_empty_authority_survives_helper_and_wire(nginx_helper, authority):
    received = []

    async def origin(reader, writer):
        # Hyper-h2's default validator forbids missing authority. This fixture
        # accepts the agreed profile to observe actual unmodified wire headers.
        protocol = H2Connection(
            H2Configuration(
                client_side=False, validate_inbound_headers=False, normalize_inbound_headers=False
            )
        )
        protocol.initiate_connection()
        writer.write(protocol.data_to_send())
        await writer.drain()
        while data := await reader.read(16384):
            for event in protocol.receive_data(data):
                if isinstance(event, RequestReceived):
                    received.append(tuple(event.headers))
                elif isinstance(event, StreamEnded):
                    protocol.send_headers(event.stream_id, [(b":status", b"204")], end_stream=True)
            writer.write(protocol.data_to_send())
            await writer.drain()

    async with proxy_lab(
        nginx_helper, origin, settings("/allowed", domain="*"), proxy_type=HTTP2Proxy
    ) as lab:
        client = await Client.open(lab.address)
        client.protocol.config.validate_outbound_headers = False
        original = (
            (b":method", b"GET"),
            (b":scheme", b"http"),
            *authority,
            (b":path", b"/a/../allowed?raw=%2f"),
        )
        try:
            client.protocol.send_headers(1, original, end_stream=True)
            await client.flush()
            await client.until(lambda events: ended(events, 1))
            assert received == [original] and not lab.resolver.calls
        finally:
            await close_client(client.writer)


@pytest.mark.anyio
@pytest.mark.parametrize("tls_name", [None, "origin.example", "other.example"])
async def test_empty_http_authority_preserves_tls_name_policy_and_membership(
    nginx_helper, tls_name
):
    target = ConnectionTarget(ipaddress.ip_address("1.1.1.1"), 443, True, tls_name)

    async def origin(reader, writer):
        block = await reader.readuntil(b"\r\n\r\n")
        assert b"host: \r\n" in block
        writer.write(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
        await writer.drain()

    # Only transport/TLS admission is a fixture here; actual identity enforcement
    # uses the immutable target that the real TLS owner supplies.
    async with proxy_lab(
        nginx_helper, origin, settings(port=443, protocol="https"), target=target
    ) as lab:
        reader, writer = await asyncio.open_connection(*lab.address)
        try:
            writer.write(b"GET / HTTP/1.1\r\nHost:\r\nConnection: close\r\n\r\n")
            await writer.drain()
            if tls_name == "origin.example":
                assert b"204" in await asyncio.wait_for(reader.read(), 2)
                assert lab.resolver.calls == [tls_name]
            else:
                with pytest.raises(ConnectionResetError):
                    await asyncio.wait_for(reader.read(), 2)
                assert not lab.connected
        finally:
            await close_client(writer)


@pytest.mark.anyio
@pytest.mark.parametrize(
    "case",
    ["private", "member", "port", "tls_mismatch", "unnamed_whitelist", "unnamed_blacklist"],
)
async def test_pathless_retains_mandatory_destination_and_identity_gates(nginx_helper, case):
    target = (
        ConnectionTarget(ipaddress.ip_address("10.0.0.1"), 80, False)
        if case == "private"
        else ConnectionTarget(ipaddress.ip_address("1.1.1.1"), 443, True, "other.example")
        if case == "tls_mismatch"
        else None
    )
    configured = settings(
        mode="blacklist" if case == "unnamed_blacklist" else "whitelist",
        port=443 if case == "tls_mismatch" else 80,
        protocol="https" if case == "tls_mismatch" else "http",
    )
    host = (
        b""
        if case.startswith("unnamed")
        else (b"origin.example:81" if case == "port" else b"origin.example")
    )

    async def origin(reader, writer):
        pytest.fail("pathless must not waive mandatory authorization")

    async with proxy_lab(nginx_helper, origin, configured, target=target) as lab:
        if case == "member":
            lab.resolver.addresses = frozenset((ipaddress.ip_address("8.8.8.8"),))
        reader, writer = await asyncio.open_connection(*lab.address)
        try:
            writer.write(b"OPTIONS * HTTP/1.1\r\nHost: " + host + b"\r\n\r\n")
            await writer.drain()
            with pytest.raises(ConnectionResetError):
                await asyncio.wait_for(reader.read(), 2)
            assert not lab.connected
        finally:
            await close_client(writer)


@pytest.mark.anyio
async def test_invalid_h2_asterisk_method_is_stream_local_with_zero_origin_bytes(nginx_helper):
    origin = Origin()
    async with proxy_lab(nginx_helper, origin.handle, settings(), proxy_type=HTTP2Proxy) as lab:
        client = await Client.open(lab.address)
        try:
            await client.request(1, b"*", method=b"GET")
            await client.request(3, b"*", method=b"OPTIONS")
            await client.until(lambda events: reset(events, 1) and ended(events, 3))
            assert len(origin.requests) == 1
            assert dict(origin.requests[1])[b":method"] == b"OPTIONS"
            assert dict(origin.requests[1])[b":path"] == b"*"
        finally:
            await close_client(client.writer)
