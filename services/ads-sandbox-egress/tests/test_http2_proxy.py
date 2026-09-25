import asyncio

import pytest
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived, RequestReceived, ResponseReceived, StreamEnded, StreamReset
from hyperframe.frame import HeadersFrame

from ads_commons.egress import ProjectEgressSnapshot
from ads_sandbox_egress.http2_proxy import HTTP2Proxy, _Leg
from test_http1_proxy import close_client, proxy_lab, settings
from test_normalization import nginx_helper as nginx_helper


@pytest.fixture
def anyio_backend():
    return "asyncio"


def headers(path=b"/allowed", *, method=b"GET", extra=()):
    return (
        (b":method", method),
        (b":scheme", b"http"),
        (b":authority", b"origin.example"),
        (b":path", path),
        *extra,
    )


class Client:
    def __init__(self, reader, writer):
        self.reader, self.writer = reader, writer
        self.protocol = H2Connection()
        self.events = []

    @classmethod
    async def open(cls, address):
        reader, writer = await asyncio.open_connection(*address)
        self = cls(reader, writer)
        self.protocol.initiate_connection()
        await self.flush()
        return self

    async def flush(self):
        self.writer.write(self.protocol.data_to_send())
        await self.writer.drain()

    async def until(self, predicate):
        async with asyncio.timeout(3):
            while not predicate(self.events):
                data = await self.reader.read(16384)
                assert data, "unexpected proxy EOF"
                events = self.protocol.receive_data(data)
                self.events.extend(events)
                for event in events:
                    if isinstance(event, DataReceived):
                        self.protocol.acknowledge_received_data(
                            event.flow_controlled_length, event.stream_id
                        )
                await self.flush()

    async def request(self, stream, path=b"/allowed", *, end=True, method=b"GET", extra=()):
        self.protocol.send_headers(
            stream, headers(path, method=method, extra=extra), end_stream=end
        )
        await self.flush()


class Origin:
    def __init__(self):
        self.requests = {}
        self.counts = {}
        self.resets = []
        self.protocol = None
        self.writer = None
        self.changed = asyncio.Event()

    async def flush(self):
        self.writer.write(self.protocol.data_to_send())
        await self.writer.drain()

    async def handle(self, reader, writer):
        assert self.protocol is None, "unexpected second origin connection"
        self.protocol = H2Connection(H2Configuration(client_side=False))
        self.writer = writer
        self.protocol.initiate_connection()
        await self.flush()
        while data := await reader.read(16384):
            for event in self.protocol.receive_data(data):
                if isinstance(event, RequestReceived):
                    self.requests[event.stream_id] = tuple(event.headers)
                    self.counts[event.stream_id] = 0
                    path = dict(event.headers)[b":path"]
                    if path == b"/early":
                        self.protocol.send_headers(
                            event.stream_id, [(b":status", b"413")], end_stream=True
                        )
                    elif path == b"/duplex":
                        self.protocol.send_headers(event.stream_id, [(b":status", b"200")])
                        self.protocol.send_data(event.stream_id, b"ready")
                elif isinstance(event, DataReceived):
                    self.counts[event.stream_id] += len(event.data)
                    self.protocol.acknowledge_received_data(
                        event.flow_controlled_length, event.stream_id
                    )
                elif isinstance(event, StreamReset):
                    self.resets.append(event.stream_id)
                elif isinstance(event, StreamEnded):
                    path = dict(self.requests[event.stream_id])[b":path"]
                    if path == b"/hold":
                        self.protocol.send_headers(event.stream_id, [(b":status", b"200")])
                        self.protocol.send_data(event.stream_id, b"first")
                    elif path == b"/bad":
                        # Raw malformed origin response; retain real peer HPACK.
                        frame = HeadersFrame(event.stream_id)
                        frame.flags.add("END_HEADERS")
                        frame.flags.add("END_STREAM")
                        frame.data = self.protocol.encoder.encode(
                            [
                                (b":status", b"200"),
                                (b"content-length", b"0"),
                                (b"content-length", b"0"),
                            ]
                        )
                        writer.write(frame.serialize())
                    elif path == b"/reset":
                        self.protocol.reset_stream(event.stream_id)
                    elif path == b"/duplex":
                        self.protocol.send_data(event.stream_id, b"done", end_stream=True)
                    elif path == b"/silent":
                        pass  # Response deliberately controlled by lifecycle tests.
                    elif path != b"/early":
                        self.protocol.send_headers(event.stream_id, [(b":status", b"200")])
                        body = (
                            str(self.counts[event.stream_id]).encode()
                            if path == b"/upload"
                            else b"origin-" + str(event.stream_id).encode()
                        )
                        self.protocol.send_data(event.stream_id, body, end_stream=True)
                self.changed.set()
            await self.flush()


def ended(events, stream):
    return any(isinstance(event, StreamEnded) and event.stream_id == stream for event in events)


def reset(events, stream):
    return any(isinstance(event, StreamReset) and event.stream_id == stream for event in events)


@pytest.mark.anyio
async def test_denied_stream_has_zero_upstream_bytes_and_ids_are_separate(nginx_helper):
    origin = Origin()
    async with proxy_lab(
        nginx_helper, origin.handle, settings("/allowed"), proxy_type=HTTP2Proxy
    ) as lab:
        client = await Client.open(lab.address)
        try:
            await client.request(1, b"/denied")
            await client.request(3)
            await client.until(lambda events: reset(events, 1) and ended(events, 3))
            assert len(lab.connected) == 1
            assert list(origin.requests) == [1]  # Frontend stream 3 -> origin 1.
            assert dict(origin.requests[1])[b":path"] == b"/allowed"
            assert any(
                isinstance(e, DataReceived) and e.stream_id == 3 and e.data == b"origin-1"
                for e in client.events
            )
            assert not any(
                isinstance(e, ResponseReceived) and e.stream_id == 1 for e in client.events
            )
        finally:
            await close_client(client.writer)
    assert all(not owner._tasks and not owner._exchanges for owner in lab.owners)


@pytest.mark.anyio
@pytest.mark.parametrize("bad_path", [b"/bad", b"/reset"])
async def test_upstream_stream_error_does_not_kill_another_exchange(nginx_helper, bad_path):
    origin = Origin()
    async with proxy_lab(nginx_helper, origin.handle, settings(), proxy_type=HTTP2Proxy) as lab:
        client = await Client.open(lab.address)
        try:
            await client.request(1, bad_path)
            await client.request(3)
            await client.until(lambda events: reset(events, 1) and ended(events, 3))
            assert len(origin.requests) == 2 and len(lab.connected) == 1
            assert not any(
                isinstance(e, ResponseReceived) and e.stream_id == 1 for e in client.events
            )
        finally:
            await close_client(client.writer)


@pytest.mark.anyio
async def test_policy_revision_preserves_active_stream_but_denies_new_stream(nginx_helper):
    origin = Origin()
    async with proxy_lab(nginx_helper, origin.handle, settings(), proxy_type=HTTP2Proxy) as lab:
        client = await Client.open(lab.address)
        try:
            await client.request(1, b"/hold")
            await client.until(
                lambda events: any(
                    isinstance(e, DataReceived) and e.data == b"first" for e in events
                )
            )
            await lab.policies.install(ProjectEgressSnapshot(2, settings(mode="blacklist")))
            await client.request(3)
            await client.until(lambda events: reset(events, 3))
            origin.protocol.send_data(1, b"last", end_stream=True)
            await origin.flush()
            await client.until(lambda events: ended(events, 1))
            assert list(origin.requests) == [1]
            assert not reset(client.events, 1)
        finally:
            await close_client(client.writer)


@pytest.mark.anyio
async def test_client_reset_cancels_only_mapped_origin_stream(nginx_helper):
    origin = Origin()
    async with proxy_lab(nginx_helper, origin.handle, settings(), proxy_type=HTTP2Proxy) as lab:
        client = await Client.open(lab.address)
        try:
            await client.request(1, b"/hold")
            await client.until(lambda events: any(isinstance(e, DataReceived) for e in events))
            client.protocol.reset_stream(1)
            await client.flush()
            await client.request(3)
            await client.until(lambda events: ended(events, 3))
            async with asyncio.timeout(2):
                while 1 not in origin.resets:
                    origin.changed.clear()
                    await origin.changed.wait()
            assert 3 not in origin.resets
        finally:
            await close_client(client.writer)


@pytest.mark.anyio
async def test_large_upload_streams_under_flow_control_without_full_body_queue(nginx_helper):
    origin = Origin()
    total = 1024 * 1024
    async with proxy_lab(nginx_helper, origin.handle, settings(), proxy_type=HTTP2Proxy) as lab:
        client = await Client.open(lab.address)
        try:
            await client.request(
                1,
                b"/upload",
                method=b"POST",
                end=False,
                extra=((b"content-length", str(total).encode()),),
            )
            sent = 0
            peak = 0
            while sent < total:
                count = min(16000, total - sent, client.protocol.local_flow_control_window(1))
                if count:
                    client.protocol.send_data(1, b"x" * count, end_stream=sent + count == total)
                    sent += count
                    await client.flush()
                    if lab.owners and lab.owners[0]._exchanges:
                        peak = max(
                            peak, sum(e.incoming.bytes for e in lab.owners[0]._exchanges.values())
                        )
                else:
                    await client.until(lambda _: client.protocol.local_flow_control_window(1) > 0)
            await client.until(lambda events: ended(events, 1))
            assert origin.counts[1] == total
            assert peak <= 65535
            assert any(
                isinstance(e, DataReceived) and e.data == str(total).encode() for e in client.events
            )
        finally:
            await close_client(client.writer)


@pytest.mark.anyio
async def test_duplex_response_headers_do_not_cancel_upload(nginx_helper):
    origin = Origin()
    async with proxy_lab(nginx_helper, origin.handle, settings(), proxy_type=HTTP2Proxy) as lab:
        client = await Client.open(lab.address)
        try:
            await client.request(1, b"/duplex", method=b"POST", end=False)
            await client.until(
                lambda events: any(
                    isinstance(e, DataReceived) and e.data == b"ready" for e in events
                )
            )
            client.protocol.send_data(1, b"body", end_stream=True)
            await client.flush()
            await client.until(lambda events: ended(events, 1))
            assert origin.counts[1] == 4 and not reset(client.events, 1)
        finally:
            await close_client(client.writer)


@pytest.mark.anyio
async def test_early_final_response_is_relayed_without_requesting_upload(nginx_helper):
    origin = Origin()
    async with proxy_lab(nginx_helper, origin.handle, settings(), proxy_type=HTTP2Proxy) as lab:
        client = await Client.open(lab.address)
        try:
            await client.request(
                1, b"/early", method=b"POST", end=False, extra=((b"expect", b"100-continue"),)
            )
            await client.until(lambda events: ended(events, 1))
            response = next(e for e in client.events if isinstance(e, ResponseReceived))
            assert (b":status", b"413") in response.headers
            assert origin.counts[1] == 0
            await client.request(3)
            await client.until(lambda events: ended(events, 3))
        finally:
            await close_client(client.writer)


@pytest.mark.anyio
async def test_reset_before_request_task_starts_cannot_leak_upstream(nginx_helper):
    origin = Origin()
    async with proxy_lab(nginx_helper, origin.handle, settings(), proxy_type=HTTP2Proxy) as lab:
        client = await Client.open(lab.address)
        try:
            client.protocol.send_headers(1, headers(), end_stream=True)
            client.protocol.reset_stream(1)
            await client.flush()
            await client.request(3)
            await client.until(lambda events: ended(events, 3))
            assert list(origin.requests) == [1]
            assert len(lab.connected) == 1
        finally:
            await close_client(client.writer)


@pytest.mark.anyio
async def test_queue_event_flood_is_stream_local_and_releases_credit(nginx_helper):
    origin = Origin()
    async with proxy_lab(nginx_helper, origin.handle, settings(), proxy_type=HTTP2Proxy) as lab:
        client = await Client.open(lab.address)
        try:
            client.protocol.send_headers(1, headers(method=b"POST"))
            for _ in range(160):
                client.protocol.send_data(1, b"x")
            await client.flush()
            await client.until(lambda events: reset(events, 1))
            await client.request(3)
            await client.until(lambda events: ended(events, 3))
            assert list(origin.requests) == [1]
            assert lab.owners[0].front.protocol.inbound_flow_control_window > 0
        finally:
            await close_client(client.writer)
    assert all(not owner._tasks and not owner._exchanges for owner in lab.owners)


@pytest.mark.anyio
async def test_authorization_timeout_does_not_block_another_stream_or_forward_early_body(
    nginx_helper,
):
    pending = asyncio.Event()

    class Delayed:
        async def normalize(self, method, target, fields):
            if target == b"/slow":
                pending.set()
                await asyncio.Event().wait()
            return await nginx_helper.normalize(method, target, fields)

    origin = Origin()
    async with proxy_lab(Delayed(), origin.handle, settings(), proxy_type=HTTP2Proxy) as lab:
        client = await Client.open(lab.address)
        try:
            await client.request(1, b"/slow", method=b"POST", end=False)
            client.protocol.send_data(1, b"early body", end_stream=True)
            await client.flush()
            await asyncio.wait_for(pending.wait(), 2)
            assert not lab.connected
            await client.request(3)
            await client.until(lambda events: ended(events, 3))
            await client.until(lambda events: reset(events, 1))
            assert len(origin.requests) == 1
            assert dict(origin.requests[1])[b":path"] == b"/allowed"
            assert origin.counts[1] == 0
        finally:
            await close_client(client.writer)


@pytest.mark.anyio
async def test_origin_eof_preserves_complete_queued_response_but_resets_truncated_one(nginx_helper):
    async def origin(reader, writer):
        protocol = H2Connection(H2Configuration(client_side=False))
        protocol.initiate_connection()
        writer.write(protocol.data_to_send())
        await writer.drain()
        completed = []
        requests = {}
        while len(completed) < 2:
            for event in protocol.receive_data(await reader.read(16384)):
                if isinstance(event, RequestReceived):
                    requests[dict(event.headers)[b":path"]] = event.stream_id
                if isinstance(event, StreamEnded):
                    completed.append(event.stream_id)
            writer.write(protocol.data_to_send())
            await writer.drain()
        protocol.send_headers(
            requests[b"/truncated"], [(b":status", b"200"), (b"content-length", b"3")]
        )
        protocol.send_data(requests[b"/truncated"], b"x")
        protocol.send_headers(
            requests[b"/complete"], [(b":status", b"200"), (b"content-length", b"2")]
        )
        protocol.send_data(requests[b"/complete"], b"ok", end_stream=True)
        writer.write(protocol.data_to_send())
        await writer.drain()
        # A clean TCP EOF, not an application END_STREAM for the first response.

    async with proxy_lab(nginx_helper, origin, settings(), proxy_type=HTTP2Proxy) as lab:
        client = await Client.open(lab.address)
        try:
            await client.request(1, b"/truncated")
            await client.request(3, b"/complete")
            await client.until(lambda events: reset(events, 1) and ended(events, 3))
            assert any(
                isinstance(e, DataReceived) and e.stream_id == 3 and e.data == b"ok"
                for e in client.events
            )
        finally:
            await close_client(client.writer)


@pytest.mark.anyio
async def test_origin_opened_during_front_start_is_not_mistaken_for_h2c(nginx_helper, monkeypatch):
    actual_start = _Leg.start
    reached = asyncio.Event()
    release = asyncio.Event()

    async def interleaved_start(leg):
        await actual_start(leg)
        if not leg.protocol.config.client_side:
            reached.set()
            await release.wait()

    monkeypatch.setattr(_Leg, "start", interleaved_start)
    origin = Origin()
    async with proxy_lab(nginx_helper, origin.handle, settings(), proxy_type=HTTP2Proxy) as lab:
        client = await Client.open(lab.address)
        try:
            await reached.wait()
            await client.request(1)
            await client.until(lambda events: ended(events, 1))
            release.set()
            await asyncio.sleep(0)
            await client.request(3)
            await client.until(lambda events: ended(events, 3))
            assert len(lab.connected) == 1
            assert list(origin.requests) == [1, 3]
        finally:
            release.set()
            await close_client(client.writer)
