import asyncio

import pytest
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived, RequestReceived, ResponseReceived, StreamEnded, StreamReset
from h2.settings import SettingCodes, Settings
from websockets.extensions.permessage_deflate import PerMessageDeflate
from websockets.frames import Frame, Opcode
from websockets.protocol import Protocol, Side

from ads_commons.egress import (
    EgressPath,
    EgressRule,
    ProjectEgressSettings,
    ProjectEgressSnapshot,
    ProtocolSettings,
)
from ads_sandbox_egress.http2_proxy import HTTP2Proxy
from test_http1_proxy import close_client, proxy_lab
from test_http2_proxy import Client, ended, headers, reset
from test_normalization import nginx_helper as nginx_helper


@pytest.fixture
def anyio_backend():
    return "asyncio"


def policy(*, method="CONNECT", upgrade=("websocket",)):
    return ProjectEgressSettings(
        (
            EgressRule(
                "origin.example",
                80,
                "http",
                ProtocolSettings(method=method, upgrades=upgrade, paths=(EgressPath("/a/chat"),)),
                sub_protocol="http/2",
            ),
            EgressRule(
                "origin.example",
                80,
                "http",
                ProtocolSettings(method="GET", upgrades="none", paths=(EgressPath("/allowed"),)),
                sub_protocol="http/2",
            ),
        )
    )


def opening(path=b"/a/%62/../chat?q=x"):
    ordinary = headers(path, method=b"CONNECT")
    return ordinary + (
        (b":protocol", b"websocket"),
        (b"sec-websocket-version", b"13"),
        (b"sec-websocket-protocol", b"chat"),
        (b"sec-websocket-extensions", b"permessage-deflate"),
    )


def websocket(side):
    protocol = Protocol(side, max_size=2**21)
    protocol.extensions = [PerMessageDeflate(False, False, 15, 15)]
    return protocol


class Origin:
    def __init__(self, *, enabled=True, status=b"200", bad_protocol=False, hold=False):
        self.enabled, self.status, self.bad_protocol, self.hold = (
            enabled,
            status,
            bad_protocol,
            hold,
        )
        self.requests, self.websockets, self.bytes = {}, {}, {}
        self.resets, self.ends = [], []
        self.protocol = self.writer = None

    async def flush(self):
        self.writer.write(self.protocol.data_to_send())
        await self.writer.drain()

    async def handle(self, reader, writer):
        self.protocol = H2Connection(H2Configuration(client_side=False))
        self.protocol.local_settings = Settings(
            client=False,
            initial_values={
                SettingCodes.ENABLE_CONNECT_PROTOCOL: int(self.enabled),
            },
        )
        self.writer = writer
        self.protocol.initiate_connection()
        await self.flush()
        while data := await reader.read(16384):
            for event in self.protocol.receive_data(data):
                if isinstance(event, RequestReceived):
                    self.requests[event.stream_id] = tuple(event.headers)
                    self.bytes[event.stream_id] = bytearray()
                    if dict(event.headers).get(b":protocol") == b"websocket":
                        self.websockets[event.stream_id] = websocket(Side.SERVER)
                        if not self.hold:
                            if self.status.startswith(b"2"):
                                self.protocol.send_headers(
                                    event.stream_id,
                                    (
                                        (b":status", self.status),
                                        (
                                            b"sec-websocket-protocol",
                                            b"unoffered" if self.bad_protocol else b"chat",
                                        ),
                                        (b"sec-websocket-extensions", b"permessage-deflate"),
                                    ),
                                )
                            else:
                                self.protocol.send_headers(
                                    event.stream_id, ((b":status", self.status),)
                                )
                                self.protocol.send_data(
                                    event.stream_id, b"rejected", end_stream=True
                                )
                elif isinstance(event, DataReceived):
                    self.bytes[event.stream_id].extend(event.data)
                    self.protocol.acknowledge_received_data(
                        event.flow_controlled_length, event.stream_id
                    )
                    if event.stream_id in self.websockets and event.data:
                        ws = self.websockets[event.stream_id]
                        ws.receive_data(event.data)
                        for frame in ws.events_received():
                            if isinstance(frame, Frame) and frame.opcode in (
                                Opcode.BINARY,
                                Opcode.CONT,
                            ):
                                ws.send_frame(frame)
                        for output in ws.data_to_send():
                            if output:
                                for offset in range(0, len(output), 16384):
                                    self.protocol.send_data(
                                        event.stream_id, output[offset : offset + 16384]
                                    )
                            else:
                                self.protocol.end_stream(event.stream_id)
                elif isinstance(event, StreamEnded):
                    self.ends.append(event.stream_id)
                    if event.stream_id not in self.websockets:
                        self.protocol.send_headers(event.stream_id, ((b":status", b"200"),))
                        self.protocol.send_data(event.stream_id, b"ordinary", end_stream=True)
                elif isinstance(event, StreamReset):
                    self.resets.append(event.stream_id)
            await self.flush()


async def start(client, stream=1, fields=None):
    await client.until(lambda _: client.protocol.remote_settings.enable_connect_protocol)
    client.protocol.send_headers(stream, opening() if fields is None else fields)
    await client.flush()


async def send_ws(client, ws, stream=1):
    for output in ws.data_to_send():
        if output:
            for offset in range(0, len(output), 16384):
                client.protocol.send_data(stream, output[offset : offset + 16384])
        else:
            client.protocol.end_stream(stream)
    await client.flush()


class Frames:
    def __init__(self, ws, stream=1):
        self.ws, self.stream = ws, stream
        self.seen = 0
        self.frames = []

    def collect(self, events):
        for event in events[self.seen :]:
            if isinstance(event, DataReceived) and event.stream_id == self.stream:
                self.ws.receive_data(event.data)
                self.frames.extend(self.ws.events_received())
            elif isinstance(event, StreamEnded) and event.stream_id == self.stream:
                self.ws.receive_eof()
        self.seen = len(events)
        return self.frames


@pytest.mark.parametrize("status", [b"200", b"204"])
@pytest.mark.anyio
async def test_extended_connect_real_frames_helper_get_but_policy_and_origin_connect(
    nginx_helper, status
):
    observed = []

    class Recorder:
        async def normalize(self, method, target, fields):
            observed.append((method, target, fields))
            return await nginx_helper.normalize(method, target, fields)

    origin = Origin(status=status)
    async with proxy_lab(Recorder(), origin.handle, policy(), proxy_type=HTTP2Proxy) as lab:
        client = await Client.open(lab.address)
        ws = websocket(Side.CLIENT)
        frames = Frames(ws)
        try:
            await start(client)
            await client.until(lambda events: any(isinstance(e, ResponseReceived) for e in events))
            assert observed[0][0:2] == (b"GET", b"/a/%62/../chat?q=x")
            assert (b"host", b"origin.example") in observed[0][2]
            assert dict(origin.requests[1])[b":method"] == b"CONNECT"
            assert dict(origin.requests[1])[b":protocol"] == b"websocket"
            assert dict(origin.requests[1])[b":path"] == b"/a/%62/../chat?q=x"
            assert not any(
                n in (b"sec-websocket-key", b"sec-websocket-accept") for n, _ in origin.requests[1]
            )
            await lab.policies.install(ProjectEgressSnapshot(2, ProjectEgressSettings(())))
            ws.send_binary(b"first", fin=False)
            ws.send_continuation(b"last", fin=True)
            await send_ws(client, ws)
            await client.until(lambda events: len(frames.collect(events)) >= 2)
            assert b"".join(f.data for f in frames.frames) == b"firstlast"
            ws.send_ping(b"ping")
            await send_ws(client, ws)
            await client.until(
                lambda events: any(f.opcode == Opcode.PONG for f in frames.collect(events))
            )
            body = bytes(range(256)) * 4096
            ws.send_binary(body)
            await send_ws(client, ws)
            await client.until(
                lambda events: any(
                    f.opcode == Opcode.BINARY and f.data == body for f in frames.collect(events)
                )
            )
            await client.request(3)
            await client.until(lambda events: reset(events, 3))
            assert len(origin.requests) == 1  # New HTTP denied, authorized WS alive.
            await lab.policies.install(ProjectEgressSnapshot(3, policy()))
            await client.request(5)
            await client.until(lambda events: ended(events, 5))
            ws.send_close(1000)
            await send_ws(client, ws)
            await client.until(lambda events: ended(events, 1))
            assert any(f.opcode == Opcode.CLOSE for f in frames.collect(client.events))
            await send_ws(client, ws)  # Native client sends its transport END_STREAM.
            async with asyncio.timeout(2):
                while 1 not in origin.ends or 1 in lab.owners[0]._exchanges:
                    await asyncio.sleep(0)
            assert not reset(client.events, 1)
        finally:
            await close_client(client.writer)


@pytest.mark.parametrize("configured", [policy(method="GET"), policy(upgrade="none")])
@pytest.mark.anyio
async def test_helper_get_does_not_change_method_or_upgrade_policy(nginx_helper, configured):
    origin = Origin()
    async with proxy_lab(nginx_helper, origin.handle, configured, proxy_type=HTTP2Proxy) as lab:
        client = await Client.open(lab.address)
        try:
            await start(client)
            await client.until(lambda events: reset(events, 1))
            assert not lab.connected
            await client.request(3)
            await client.until(lambda events: ended(events, 3))
        finally:
            await close_client(client.writer)


@pytest.mark.parametrize("mode", ["disabled", "bad-protocol", "rejection", "timeout"])
@pytest.mark.anyio
async def test_failed_opening_is_stream_local_and_never_forwards_early_data(nginx_helper, mode):
    origin = Origin(
        enabled=mode != "disabled",
        bad_protocol=mode == "bad-protocol",
        status=b"403" if mode == "rejection" else b"200",
        hold=mode == "timeout",
    )
    async with proxy_lab(nginx_helper, origin.handle, policy(), proxy_type=HTTP2Proxy) as lab:
        client = await Client.open(lab.address)
        try:
            await start(client)
            client.protocol.send_data(1, b"early data")
            await client.flush()
            if mode == "rejection":
                await client.until(lambda events: ended(events, 1))
                assert any(
                    isinstance(e, ResponseReceived) and (b":status", b"403") in e.headers
                    for e in client.events
                )
                assert any(
                    isinstance(e, DataReceived) and e.data == b"rejected" for e in client.events
                )
            else:
                await client.until(lambda events: reset(events, 1))
                assert not any(isinstance(e, ResponseReceived) for e in client.events)
            assert not any(origin.bytes.values())
            if mode == "disabled":
                assert not origin.requests
            await client.request(3)
            await client.until(lambda events: ended(events, 3))
        finally:
            await close_client(client.writer)


@pytest.mark.parametrize("case", ["version", "authority", "protocol", "length", "missing-version"])
@pytest.mark.anyio
async def test_invalid_extended_opening_denied_without_origin_contact(nginx_helper, case):
    fields = opening()
    if case == "version":
        fields = tuple((n, b"12" if n == b"sec-websocket-version" else v) for n, v in fields)
    elif case == "authority":
        fields = tuple((n, v) for n, v in fields if n != b":authority")
    elif case == "protocol":
        fields = tuple((n, b"arbitrary" if n == b":protocol" else v) for n, v in fields)
    elif case == "length":
        fields += ((b"content-length", b"0"),)
    else:
        fields = tuple((n, v) for n, v in fields if n != b"sec-websocket-version")
    origin = Origin()
    async with proxy_lab(nginx_helper, origin.handle, policy(), proxy_type=HTTP2Proxy) as lab:
        client = await Client.open(lab.address)
        try:
            if case == "authority":
                # A raw peer can violate pseudo-header requirements. Disable
                # only the TEST endpoint's outbound validation, not ADS.
                client.protocol.config.validate_outbound_headers = False
            await start(client, fields=fields)
            await client.until(lambda events: reset(events, 1))
            assert not lab.connected
            await client.request(3)
            await client.until(lambda events: ended(events, 3))
        finally:
            await close_client(client.writer)


@pytest.mark.anyio
async def test_websocket_reset_is_paired_only(nginx_helper):
    origin = Origin()
    async with proxy_lab(nginx_helper, origin.handle, policy(), proxy_type=HTTP2Proxy) as lab:
        client = await Client.open(lab.address)
        try:
            await start(client)
            await client.until(lambda events: any(isinstance(e, ResponseReceived) for e in events))
            client.protocol.reset_stream(1)
            await client.flush()
            await client.request(3)
            await client.until(lambda events: ended(events, 3))
            assert origin.resets == [1]
            assert not reset(client.events, 3)
        finally:
            await close_client(client.writer)


@pytest.mark.anyio
async def test_one_way_websocket_activity_and_independent_stream_idle(nginx_helper):
    origin = Origin()
    async with proxy_lab(nginx_helper, origin.handle, policy(), proxy_type=HTTP2Proxy) as lab:
        client = await Client.open(lab.address)
        try:
            await start(client)
            await client.until(lambda events: any(isinstance(e, ResponseReceived) for e in events))
            for index in range(8):
                await asyncio.sleep(0.2)
                origin.protocol.send_data(1, b"\x82\x01x")
                await origin.flush()
                await client.until(
                    lambda events, index=index: (
                        sum(isinstance(e, DataReceived) and e.stream_id == 1 for e in events)
                        > index
                    )
                )
            assert not reset(client.events, 1)
            # Other streams keep the connection busy, but cannot renew this
            # WebSocket stream's idle budget.
            for stream in range(3, 17, 2):
                await asyncio.sleep(0.2)
                await client.request(stream)
                await client.until(lambda events, stream=stream: ended(events, stream))
            await client.until(lambda events: reset(events, 1))
            assert not reset(client.events, 15)
        finally:
            await close_client(client.writer)
