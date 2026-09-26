import asyncio
import base64

import pytest
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived, RequestReceived, StreamEnded
from h2.settings import SettingCodes

from ads_commons.egress import (
    EgressPath,
    EgressRule,
    ProjectEgressSettings,
    ProjectEgressSnapshot,
    ProtocolSettings,
)
from test_http1_proxy import close_client, proxy_lab
from test_http2_proxy import Client, ended, reset
from test_normalization import nginx_helper as nginx_helper


@pytest.fixture
def anyio_backend():
    return "asyncio"


def configured():
    return ProjectEgressSettings(
        (
            EgressRule(
                "origin.example",
                80,
                "http",
                ProtocolSettings(
                    method="any", upgrades=("http/2",), paths=(EgressPath("/upgrade"),)
                ),
                sub_protocol="http/1.1",
            ),
            EgressRule(
                "origin.example",
                80,
                "http",
                ProtocolSettings(method="any", upgrades="none", paths=(EgressPath("/allowed"),)),
                sub_protocol="http/2",
            ),
        )
    )


def upgrade_request(settings, *, method=b"GET", body=b""):
    return (
        method + b" /upgrade HTTP/1.1\r\nHost: origin.example\r\n"
        b"Upgrade: h2c\r\nConnection: Upgrade, HTTP2-Settings\r\nHTTP2-Settings: "
        + settings
        + b"\r\nContent-Length: "
        + str(len(body)).encode()
        + b"\r\n\r\n"
        + body
    )


class Origin:
    def __init__(self):
        self.opening = None
        self.requests = {}
        self.body = None
        self.settings = None

    async def handle(self, reader, writer):
        self.opening = await reader.readuntil(b"\r\n\r\n")
        fields = dict(line.lower().split(b": ", 1) for line in self.opening.split(b"\r\n")[1:-2])
        # Settings are case-sensitive base64; recover the original field value.
        encoded = next(
            line.split(b": ", 1)[1]
            for line in self.opening.split(b"\r\n")
            if line.lower().startswith(b"http2-settings:")
        )
        self.settings = encoded
        self.body = await reader.readexactly(int(fields[b"content-length"]))
        protocol = H2Connection(H2Configuration(client_side=False))
        protocol.initiate_upgrade_connection(encoded)
        writer.write(
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n"
        )
        protocol.send_headers(1, [(b":status", b"200"), (b"content-length", b"3")])
        if self.opening.startswith(b"HEAD "):
            protocol.end_stream(1)
        else:
            protocol.send_data(1, b"one", end_stream=True)
        # A coalesced 101, SETTINGS and stream-1 response tests parser custody.
        writer.write(protocol.data_to_send())
        await writer.drain()
        while data := await reader.read(16384):
            for event in protocol.receive_data(data):
                if isinstance(event, RequestReceived):
                    self.requests[event.stream_id] = tuple(event.headers)
                elif isinstance(event, DataReceived):
                    protocol.acknowledge_received_data(
                        event.flow_controlled_length, event.stream_id
                    )
                elif isinstance(event, StreamEnded):
                    protocol.send_headers(event.stream_id, [(b":status", b"200")])
                    protocol.send_data(event.stream_id, b"later", end_stream=True)
            writer.write(protocol.data_to_send())
            await writer.drain()


@pytest.mark.parametrize(
    "method,body", [(b"GET", b""), (b"HEAD", b""), (b"POST", b"complete upload")]
)
@pytest.mark.anyio
async def test_real_h2c_upgrade_one_request_and_independent_later_streams(
    nginx_helper, method, body
):
    origin = Origin()
    async with proxy_lab(nginx_helper, origin.handle, configured()) as lab:
        reader, writer = await asyncio.open_connection(*lab.address)
        client = Client(reader, writer)
        # Native H2 client's local SETTINGS differ from the proxy origin leg.
        client.protocol.local_settings[SettingCodes.INITIAL_WINDOW_SIZE] = 4096
        encoded = client.protocol.initiate_upgrade_connection()
        client.protocol.streams[1].request_method = method
        try:
            writer.write(upgrade_request(encoded, method=method, body=body))
            await writer.drain()
            assert (await reader.readuntil(b"\r\n\r\n")).startswith(b"HTTP/1.1 101")
            await client.flush()
            await client.until(lambda events: ended(events, 1))
            assert origin.body == body
            assert origin.settings != encoded
            assert origin.opening.startswith(method + b" /upgrade HTTP/1.1\r\n")
            assert not origin.requests  # Stream 1 wasn't replayed as HEADERS.
            assert not reset(client.events, 1)
            if method == b"HEAD":
                assert not any(isinstance(e, DataReceived) and e.data for e in client.events)
            await client.request(3, b"/denied")
            await client.request(5, b"/allowed")
            await client.until(lambda events: reset(events, 3) and ended(events, 5))
            assert list(origin.requests) == [3]  # Separate ID spaces after stream 1.
            assert dict(origin.requests[3])[b":path"] == b"/allowed"
            await lab.policies.install(ProjectEgressSnapshot(2, ProjectEgressSettings(())))
            await client.request(7, b"/allowed")
            await client.until(lambda events: reset(events, 7))
            assert len(origin.requests) == 1
        finally:
            await close_client(writer)


@pytest.mark.parametrize(
    "encoded", [b"=", b"!!!!", base64.urlsafe_b64encode(b"\x00\x04\x00\x00\xff\xff" * 2)]
)
@pytest.mark.anyio
async def test_malformed_upgrade_settings_never_open_origin(nginx_helper, encoded):
    async def unexpected(reader, writer):
        pytest.fail("invalid h2c contacted origin")

    async with proxy_lab(nginx_helper, unexpected, configured()) as lab:
        reader, writer = await asyncio.open_connection(*lab.address)
        try:
            writer.write(upgrade_request(encoded))
            await writer.drain()
            with pytest.raises(ConnectionResetError):
                await reader.read(1)
            assert not lab.connected
        finally:
            await close_client(writer)


@pytest.mark.parametrize("upgrade", [b"websocket", b"h2", b"h2c\r\nContent-Length: 0"])
@pytest.mark.anyio
async def test_invalid_origin_switch_does_not_leak_or_switch(nginx_helper, upgrade):
    async def origin(reader, writer):
        await reader.readuntil(b"\r\n\r\n")
        writer.write(
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: "
            + upgrade
            + b"\r\n\r\nbad"
        )
        await writer.drain()
        await reader.read()

    async with proxy_lab(nginx_helper, origin, configured()) as lab:
        reader, writer = await asyncio.open_connection(*lab.address)
        try:
            writer.write(upgrade_request(b""))
            await writer.drain()
            with pytest.raises(ConnectionResetError):
                await reader.read(1)
        finally:
            await close_client(writer)


@pytest.mark.anyio
async def test_denied_h2c_upgrade_never_contacts_origin(nginx_helper):
    async def unexpected(reader, writer):
        pytest.fail("denied h2c contacted origin")

    async with proxy_lab(nginx_helper, unexpected, ProjectEgressSettings(())) as lab:
        reader, writer = await asyncio.open_connection(*lab.address)
        try:
            writer.write(upgrade_request(b""))
            await writer.drain()
            with pytest.raises(ConnectionResetError):
                await reader.read(1)
            assert not lab.connected
        finally:
            await close_client(writer)


@pytest.mark.anyio
async def test_declined_h2c_remains_http_and_reauthorizes_next_request(nginx_helper):
    received = []

    async def origin(reader, writer):
        received.append(await reader.readuntil(b"\r\n\r\n"))
        writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 2\r\n\r\nno")
        await writer.drain()
        await reader.read()

    async with proxy_lab(nginx_helper, origin, configured()) as lab:
        reader, writer = await asyncio.open_connection(*lab.address)
        try:
            writer.write(upgrade_request(b""))
            await writer.drain()
            assert (await reader.readuntil(b"\r\n\r\n")).startswith(b"HTTP/1.1 403")
            assert await reader.readexactly(2) == b"no"
            await lab.policies.install(ProjectEgressSnapshot(2, ProjectEgressSettings(())))
            writer.write(b"GET /upgrade HTTP/1.1\r\nHost: origin.example\r\n\r\n")
            await writer.drain()
            with pytest.raises(ConnectionResetError):
                await reader.read(1)
            assert len(received) == 1
        finally:
            await close_client(writer)
