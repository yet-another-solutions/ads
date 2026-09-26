import asyncio

import pytest
from h2.events import DataReceived, StreamReset
from h2.exceptions import ProtocolError
from hyperframe.frame import Frame, GoAwayFrame

from ads_sandbox_egress.http2 import GracefulShutdown
from ads_sandbox_egress.http2_proxy import HTTP2Proxy
from ads_sandbox_egress.policy import RequestDenied
from test_http1_proxy import close_client, proxy_lab, settings
from test_http2 import feed, pair, request
from test_http2_proxy import Client, Origin, ended, reset
from test_normalization import nginx_helper as nginx_helper


@pytest.fixture
def anyio_backend():
    return "asyncio"


class DrainingClient(Client):
    """Independent endpoint shim for stock h2's missing graceful GOAWAY mode.

    The test endpoint decodes GOAWAY directly with hyperframe and keeps its h2
    codec alive for remaining streams. It does not use the ADS codec or owner.
    All other HTTP/frame/HPACK state is the unmodified h2 test client.
    """

    def __init__(self, reader, writer):
        super().__init__(reader, writer)
        self.pending = bytearray()
        self.goaways = []

    async def until(self, predicate):
        async with asyncio.timeout(3):
            while not predicate(self.events):
                data = await self.reader.read(16384)
                assert data, "unexpected proxy EOF"
                self.pending.extend(data)
                while len(self.pending) >= 9:
                    frame, size = Frame.parse_frame_header(memoryview(bytes(self.pending[:9])))
                    if len(self.pending) < 9 + size:
                        break
                    encoded = bytes(self.pending[: 9 + size])
                    del self.pending[: 9 + size]
                    if isinstance(frame, GoAwayFrame):
                        frame.parse_body(memoryview(encoded[9:]))
                        self.goaways.append(frame)
                        continue
                    received = self.protocol.receive_data(encoded)
                    self.events.extend(received)
                    for event in received:
                        if isinstance(event, DataReceived):
                            self.protocol.acknowledge_received_data(
                                event.flow_controlled_length, event.stream_id
                            )
                await self.flush()


@pytest.mark.anyio
async def test_independent_client_empty_flush_after_clean_eof_has_no_write():
    class ClosedWriter:
        def write(self, data):
            raise ConnectionResetError("closed subprocess stdin")

        async def drain(self):
            raise AssertionError("must not drain without outgoing bytes")

    client = DrainingClient(None, ClosedWriter())
    # A decoded GOAWAY has no required ACK. Empty flush must not turn its
    # already-received success into an unrelated subprocess-pipe error.
    await client.flush()
    client.protocol.initiate_connection()
    with pytest.raises(ConnectionResetError):
        await client.flush()  # Real pending frames still propagate errors.


def test_codec_goaway_fences_new_streams_without_discarding_queued_data():
    ads, peer = pair(client=True)
    ads.headers(1, request(), end=True)
    peer.receive_data(ads.data_to_send())
    peer.send_headers(1, [(b":status", b"200")])
    feed(ads, peer.data_to_send())
    shutdown = GoAwayFrame(0, last_stream_id=1, error_code=0, additional_data=b"private debug")
    events = feed(ads, shutdown.serialize())
    assert events == [GracefulShutdown(1)]
    assert not hasattr(events[0], "additional_data")
    with pytest.raises(RequestDenied, match="draining"):
        ads.headers(3, request(), end=True)
    peer.send_data(1, b"finish", end_stream=True)
    assert any(
        isinstance(event, DataReceived) and event.data == b"finish"
        for event in feed(ads, peer.data_to_send())
    )
    with pytest.raises(ProtocolError):
        feed(ads, GoAwayFrame(0, last_stream_id=3, error_code=0).serialize())


def test_late_headers_after_goaway_still_consume_hpack_and_reset_locally():
    ads, peer = pair()
    peer.send_headers(1, request())
    feed(ads, peer.data_to_send())
    ads.begin_shutdown()
    peer.send_headers(3, request((b"x-dynamic", b"compression-state")), end_stream=True)
    events = feed(ads, peer.data_to_send())
    assert any(isinstance(event, StreamReset) and event.stream_id == 3 for event in events)
    assert ads.local_last_stream == 1
    # Native HPACK state is synchronized even though stream 3 wasn't exposed.
    peer.send_headers(1, [(b"x-dynamic", b"compression-state")], end_stream=True)
    assert feed(ads, peer.data_to_send())


@pytest.mark.anyio
async def test_origin_goaway_drains_accepted_stream_and_resets_unprocessed_stream(nginx_helper):
    origin = Origin()
    async with proxy_lab(nginx_helper, origin.handle, settings(), proxy_type=HTTP2Proxy) as lab:
        client = await DrainingClient.open(lab.address)
        try:
            await client.request(1, b"/hold")
            await client.until(lambda events: any(isinstance(e, DataReceived) for e in events))
            await client.request(3, b"/silent")
            async with asyncio.timeout(2):
                while 3 not in origin.requests:
                    await asyncio.sleep(0)
            origin.writer.write(
                GoAwayFrame(
                    0, last_stream_id=1, error_code=0, additional_data=b"secret"
                ).serialize()
            )
            await origin.writer.drain()
            await client.until(lambda events: bool(client.goaways) and reset(events, 3))
            assert client.goaways[0].last_stream_id == 3  # Frontend watermark, not origin ID 1.
            assert client.goaways[0].additional_data == b""
            assert not reset(client.events, 1)
            # Deliberately misbehaving late client: still consume HPACK, never
            # contact origin or expand the already-sent last-stream watermark.
            await client.request(5)
            await client.until(lambda events: reset(events, 5))
            origin.protocol.send_data(1, b"last", end_stream=True)
            await origin.flush()
            await client.until(lambda events: ended(events, 1))
            assert any(isinstance(e, DataReceived) and e.data == b"last" for e in client.events)
            assert await asyncio.wait_for(client.reader.read(), 2) == b""
            assert len(origin.requests) == 2 and lab.owners[0]._graceful
        finally:
            await close_client(client.writer)


@pytest.mark.anyio
async def test_goaway_without_active_streams_finishes_without_reset(nginx_helper):
    origin = Origin()
    async with proxy_lab(nginx_helper, origin.handle, settings(), proxy_type=HTTP2Proxy) as lab:
        client = await DrainingClient.open(lab.address)
        try:
            await client.request(1)
            await client.until(lambda events: ended(events, 1))
            origin.writer.write(GoAwayFrame(0, last_stream_id=1, error_code=0).serialize())
            await origin.writer.drain()
            await client.until(lambda events: bool(client.goaways))
            assert await asyncio.wait_for(client.reader.read(), 2) == b""
            assert lab.owners[0]._graceful
        finally:
            await close_client(client.writer)


@pytest.mark.anyio
@pytest.mark.parametrize("pending_data", [False, True])
async def test_error_goaway_retains_connection_wide_failure(nginx_helper, pending_data):
    origin = Origin()
    async with proxy_lab(nginx_helper, origin.handle, settings(), proxy_type=HTTP2Proxy) as lab:
        client = await DrainingClient.open(lab.address)
        try:
            await client.request(1, b"/hold")
            await client.until(lambda events: any(isinstance(e, DataReceived) for e in events))
            if pending_data:
                origin.protocol.send_data(1, b"buffered but not completed")
                origin.writer.write(origin.protocol.data_to_send())
            origin.writer.write(
                GoAwayFrame(
                    0, last_stream_id=1, error_code=2, additional_data=b"private"
                ).serialize()
            )
            await origin.writer.drain()
            with pytest.raises(ConnectionResetError):
                async with asyncio.timeout(2):
                    await client.reader.read()
            assert not lab.owners[0]._graceful and not client.goaways
        finally:
            await close_client(client.writer)


@pytest.mark.anyio
async def test_client_goaway_allows_existing_response_to_finish(nginx_helper):
    origin = Origin()
    async with proxy_lab(nginx_helper, origin.handle, settings(), proxy_type=HTTP2Proxy) as lab:
        client = await DrainingClient.open(lab.address)
        try:
            await client.request(1, b"/hold")
            await client.until(lambda events: any(isinstance(e, DataReceived) for e in events))
            client.writer.write(GoAwayFrame(0, last_stream_id=0, error_code=0).serialize())
            await client.writer.drain()
            await client.until(lambda events: bool(client.goaways))
            origin.protocol.send_data(1, b"last", end_stream=True)
            await origin.flush()
            await client.until(lambda events: ended(events, 1))
            assert not reset(client.events, 1)
            assert await asyncio.wait_for(client.reader.read(), 2) == b""
        finally:
            await close_client(client.writer)


@pytest.mark.anyio
async def test_drain_deadline_is_not_extended_by_active_response(nginx_helper):
    origin = Origin()
    async with proxy_lab(nginx_helper, origin.handle, settings(), proxy_type=HTTP2Proxy) as lab:
        client = await DrainingClient.open(lab.address)
        try:
            await client.request(1, b"/hold")
            await client.until(lambda events: any(isinstance(e, DataReceived) for e in events))
            origin.writer.write(GoAwayFrame(0, last_stream_id=1, error_code=0).serialize())
            await origin.writer.drain()
            await client.until(lambda events: bool(client.goaways))
            for index in range(3):
                await asyncio.sleep(0.2)
                origin.protocol.send_data(1, b"active")
                await origin.flush()
                await client.until(
                    lambda events, index=index: (
                        sum(isinstance(e, DataReceived) and e.data == b"active" for e in events)
                        > index
                    )
                )
            with pytest.raises(ConnectionResetError):
                async with asyncio.timeout(2):
                    await client.reader.read()
            assert not lab.owners[0]._graceful
        finally:
            await close_client(client.writer)
