import asyncio
import base64
import struct

import pytest
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import (
    ConnectionTerminated,
    DataReceived,
    InformationalResponseReceived,
    RequestReceived,
    ResponseReceived,
    StreamEnded,
    StreamReset,
    TrailersReceived,
)
from h2.exceptions import ProtocolError
from hyperframe.frame import ContinuationFrame, DataFrame, HeadersFrame, SettingsFrame

from ads_sandbox_egress.http2 import HTTP2Connection
from ads_sandbox_egress.policy import RequestDenied


@pytest.fixture
def anyio_backend():
    return "asyncio"


def request(*extra, method=b"GET", path=b"/original%2Ftarget?x=1"):
    return (
        (b":method", method),
        (b":scheme", b"https"),
        (b":authority", b"origin.example"),
        (b":path", path),
        *extra,
    )


def pair(*, client=False, **kwargs):
    ads = HTTP2Connection(client=client, **kwargs)
    peer = H2Connection(
        H2Configuration(
            client_side=not client,
            normalize_outbound_headers=False,
            validate_outbound_headers=False,
        )
    )
    ads.initiate_connection()
    peer.initiate_connection()
    feed(ads, peer.data_to_send())
    peer.receive_data(ads.data_to_send())
    feed(ads, peer.data_to_send())
    return ads, peer


def feed(connection, data):
    events = []
    for offset in range(0, len(data), 16384):
        events.extend(connection.receive_data(data[offset : offset + 16384]))
    return events


def raw_headers(peer, stream, fields, *, end=False):
    frame = HeadersFrame(stream)
    frame.data = peer.encoder.encode(fields)
    frame.flags.add("END_HEADERS")
    if end:
        frame.flags.add("END_STREAM")
    return frame.serialize()


def raw_data(stream, data, *, end=False):
    frame = DataFrame(stream)
    frame.data = data
    if end:
        frame.flags.add("END_STREAM")
    return frame.serialize()


def assert_survivor(ads, peer, stream=3):
    peer.send_headers(stream, request(), end_stream=True)
    events = feed(ads, peer.data_to_send())
    assert any(isinstance(event, RequestReceived) and event.stream_id == stream for event in events)
    ads.headers(stream, ((b":status", b"200"), (b"content-length", b"2")))
    ads.data(stream, b"ok", end=True)
    events = peer.receive_data(ads.data_to_send())
    assert any(isinstance(event, DataReceived) and event.data == b"ok" for event in events)
    assert not any(isinstance(event, ConnectionTerminated) for event in events)


@pytest.mark.parametrize(
    "bad",
    [
        request((b"content-length", b"0"), (b"content-length", b"0")),
        request((b"content-length", b"0,0")),
        request((b"content-length", b"-1")),
        request((b"content-length", b"1"), (b"transfer-encoding", b"chunked")),
        request((b"connection", b"close")),
        request((b"te", b"gzip")),
        request((b"X-UPPER", b"bad")),
        request((b"x", b" leading")),
        request((b"x", b"trailing\t")),
        request((b"x", b"a\rb")),
        request((b":method", b"POST")),
        request((b"x", b"ok"), (b":path", b"/late")),
        request((b":status", b"200")),
        request(path=b""),
        request(path=b"relative"),
        request((b":protocol", b"websocket")),
        request(method=b"CONNECT"),
        request((b"content-length", b"1")),
        request((b"host", b"a"), (b"host", b"a")),
        request((b"host", b"other.example")),
        request((b"host", b"origin.example:80")),
        request((b"host", b"origin.example\xff")),
    ],
)
def test_malformed_request_resets_only_its_stream_and_preserves_hpack(bad):
    ads, peer = pair()
    # One malformed stream and a subsequent stream share the same HPACK state.
    # Raw construction preserves malformed fields instead of peer normalization.
    events = feed(ads, raw_headers(peer, 1, bad, end=True))
    assert len(events) == 1 and isinstance(events[0], StreamReset)
    assert events[0].stream_id == 1 and not events[0].remote_reset
    wire = ads.data_to_send()
    assert wire[3] == 3  # RST_STREAM, not a synthetic HEADERS response or GOAWAY.
    assert_survivor(ads, peer)


@pytest.mark.parametrize("mode", ["over", "short", "trailers", "forbidden-trailer", "open-trailer"])
def test_late_body_failure_is_stream_local(mode):
    ads, peer = pair()
    peer.send_headers(1, request((b"content-length", b"3"), method=b"POST"))
    events = feed(ads, peer.data_to_send())
    assert isinstance(events[0], RequestReceived)
    if mode == "over":
        wire = raw_data(1, b"four", end=True)
    elif mode == "short":
        wire = raw_data(1, b"x", end=True)
    elif mode == "trailers":
        wire = raw_data(1, b"x") + raw_headers(peer, 1, ((b"x-checksum", b"a"),), end=True)
    else:
        wire = raw_data(1, b"abc") + raw_headers(
            peer,
            1,
            ((b"authorization", b"secret"),) if mode == "forbidden-trailer" else ((b"x", b"a"),),
            end=mode != "open-trailer",
        )
    events = feed(ads, wire)
    assert any(isinstance(event, StreamReset) and event.stream_id == 1 for event in events)
    for event in events:
        if isinstance(event, DataReceived):
            ads.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
    reset_events = peer.receive_data(ads.data_to_send())
    assert any(isinstance(event, StreamReset) for event in reset_events)
    assert_survivor(ads, peer)


def test_denial_and_inflight_data_return_connection_credit_without_disturbing_other_streams():
    ads, peer = pair()
    peer.send_headers(1, request(method=b"POST"))
    feed(ads, peer.data_to_send())
    ads.deny(1)
    peer.receive_data(ads.data_to_send())
    # In-flight DATA after cancellation must still consume/release connection
    # flow credit, not be dropped before the frame/connection state machine.
    for _ in range(8):
        feed(ads, raw_data(1, b"x" * 16000))
        ads.data_to_send()
    assert ads.inbound_flow_control_window > 0
    assert_survivor(ads, peer)


def test_body_credit_is_not_returned_until_the_consumer_acknowledges():
    ads, peer = pair()
    peer.send_headers(1, request(method=b"POST"))
    peer.send_data(1, b"x" * 16000)
    events = feed(ads, peer.data_to_send())
    data = next(event for event in events if isinstance(event, DataReceived))
    assert ads.inbound_flow_control_window == 65535 - data.flow_controlled_length
    assert ads.data_to_send() == b""
    ads.acknowledge_received_data(data.flow_controlled_length, data.stream_id)
    # h2 coalesces WINDOW_UPDATEs until enough credit has been consumed.
    assert ads.inbound_flow_control_window <= 65535
    ads.deny(1)
    assert_survivor(ads, peer)


def test_valid_interim_streamed_body_trailers_and_original_target():
    ads, peer = pair()
    original = request((b"expect", b"100-continue"), method=b"POST")
    peer.send_headers(1, original)
    events = feed(ads, peer.data_to_send())
    assert tuple(events[0].headers) == original
    ads.headers(1, ((b":status", b"100"),))
    events = peer.receive_data(ads.data_to_send())
    assert isinstance(events[0], InformationalResponseReceived)
    peer.send_data(1, b"body")
    peer.send_headers(1, ((b"x-checksum", b"abcd"),), end_stream=True)
    events = feed(ads, peer.data_to_send())
    assert any(isinstance(event, TrailersReceived) for event in events)
    assert any(isinstance(event, StreamEnded) for event in events)
    ads.headers(1, ((b":status", b"200"),))
    ads.data(1, b"response")
    ads.headers(1, ((b"x-checksum", b"answer"),), end=True)
    events = peer.receive_data(ads.data_to_send())
    assert any(isinstance(event, TrailersReceived) for event in events)
    assert not ads._received and not ads._sent and not ads._methods


@pytest.mark.parametrize(
    "fields,end",
    [
        (((b":status", b"200"), (b"content-length", b"0"), (b"content-length", b"0")), True),
        (((b":status", b"200"), (b"content-length", b"1")), True),
        (((b":status", b"101"),), False),
        (((b":status", b"100"),), True),
        (((b":status", b"103"), (b"content-length", b"0")), False),
        (((b":status", b"204"), (b"content-length", b"0")), True),
        (((b":status", b"600"),), True),
    ],
)
def test_upstream_bad_response_is_stream_local(fields, end):
    ads, peer = pair(client=True)
    ads.headers(1, request(), end=True)
    ads.headers(3, request(), end=True)
    peer.receive_data(ads.data_to_send())
    events = feed(ads, raw_headers(peer, 1, fields, end=end))
    assert any(isinstance(event, StreamReset) and event.stream_id == 1 for event in events)
    peer.receive_data(ads.data_to_send())
    peer.send_headers(3, [(b":status", b"200")], end_stream=True)
    events = feed(ads, peer.data_to_send())
    assert any(isinstance(event, ResponseReceived) and event.stream_id == 3 for event in events)


@pytest.mark.parametrize("method,status", [(b"HEAD", b"200"), (b"GET", b"304")])
def test_metadata_length_is_not_body_and_illegal_body_resets_stream(method, status):
    ads, peer = pair(client=True)
    ads.headers(1, request(method=method), end=True)
    ads.headers(3, request(method=method), end=True)
    peer.receive_data(ads.data_to_send())
    fields = ((b":status", status), (b"content-length", b"123"))
    events = feed(ads, raw_headers(peer, 1, fields, end=True))
    assert any(isinstance(event, ResponseReceived) for event in events)
    events = feed(ads, raw_headers(peer, 3, fields) + raw_data(3, b"x", end=True))
    assert any(isinstance(event, StreamReset) and event.stream_id == 3 for event in events)


def test_hpack_failure_is_connection_wide_not_a_fabricated_stream_success():
    ads, peer = pair()
    frame = HeadersFrame(1)
    frame.flags.add("END_HEADERS")
    frame.data = b"\xff\xff\xff\xff\x7f"  # Impossible HPACK dynamic index.
    with pytest.raises(ProtocolError):
        feed(ads, frame.serialize())
    events = peer.receive_data(ads.data_to_send())
    assert any(isinstance(event, ConnectionTerminated) for event in events)
    assert not any(isinstance(event, ResponseReceived) for event in events)


def test_limits_and_outbound_strict_profile():
    ads, peer = pair(client=True)
    with pytest.raises(ValueError, match="read"):
        ads.receive_data(b"x" * 16385)
    with pytest.raises(RequestDenied):
        ads.headers(1, request((b"content-length", b"0"), (b"content-length", b"0")))
    ads.headers(1, request((b"content-length", b"3"), method=b"POST"))
    with pytest.raises(ValueError, match="write"):
        ads.data(1, b"x" * 16385)
    with pytest.raises(RequestDenied, match="exceeded"):
        ads.data(1, b"four", end=True)
    ads.deny(1)
    # Only outbound headers and a reset were serialized, never invalid DATA.
    events = peer.receive_data(ads.data_to_send())
    assert any(isinstance(event, StreamReset) for event in events)
    assert not any(isinstance(event, DataReceived) for event in events)


def test_continuation_fragments_preserve_gate_and_hpack_after_denial():
    ads, peer = pair()
    encoded = peer.encoder.encode(request((b"content-length", b"0"), (b"content-length", b"0")))
    first = HeadersFrame(1)
    first.flags.add("END_STREAM")
    first.data = encoded[:3]
    assert feed(ads, first.serialize()) == []
    continuation = ContinuationFrame(1)
    continuation.flags.add("END_HEADERS")
    continuation.data = encoded[3:]
    events = feed(ads, continuation.serialize())
    assert len(events) == 1 and isinstance(events[0], StreamReset)
    ads.data_to_send()
    assert_survivor(ads, peer)


def test_hpack_on_reset_stream_still_updates_table_for_other_streams():
    ads, peer = pair()
    peer.send_headers(1, request(method=b"POST"))
    feed(ads, peer.data_to_send())
    ads.deny(1)
    ads.data_to_send()
    extra = ((b"x-new-entry", b"shared-compression-state"),)
    feed(ads, raw_headers(peer, 1, extra, end=True))
    ads.data_to_send()
    peer.send_headers(3, request(*extra), end_stream=True)
    events = feed(ads, peer.data_to_send())
    request_event = next(event for event in events if isinstance(event, RequestReceived))
    assert extra[0] in request_event.headers
    ads.headers(3, ((b":status", b"204"),), end=True)
    assert not ads._received and not ads._sent and not ads._methods


def test_early_final_response_does_not_invent_continue_or_finish_upload():
    ads, peer = pair(client=True)
    ads.headers(1, request((b"expect", b"100-continue"), method=b"POST"))
    peer.receive_data(ads.data_to_send())
    peer.send_headers(1, [(b":status", b"413")], end_stream=True)
    events = feed(ads, peer.data_to_send())
    assert any(isinstance(event, ResponseReceived) for event in events)
    assert not any(isinstance(event, InformationalResponseReceived) for event in events)
    assert ads.data_to_send() == b""
    ads.deny(1)
    resets = peer.receive_data(ads.data_to_send())
    assert any(isinstance(event, StreamReset) for event in resets)


def test_informational_flood_is_stream_local_and_metadata_is_bounded():
    ads, peer = pair(client=True)
    ads.headers(1, request(), end=True)
    peer.receive_data(ads.data_to_send())
    for _ in range(16):
        events = feed(ads, raw_headers(peer, 1, ((b":status", b"103"),)))
        assert isinstance(events[0], InformationalResponseReceived)
    events = feed(ads, raw_headers(peer, 1, ((b":status", b"103"),)))
    assert isinstance(events[0], StreamReset)
    assert not ads._informationals


def test_outbound_flow_control_retry_does_not_double_count_body():
    ads, peer = pair(client=True)
    settings = SettingsFrame(0)
    settings.settings[4] = 2  # INITIAL_WINDOW_SIZE.
    feed(ads, settings.serialize())
    ads.headers(1, request((b"content-length", b"3"), method=b"POST"))
    with pytest.raises(RequestDenied, match="window"):
        ads.data(1, b"abc", end=True)
    assert ads._sent[1].body.received == 0
    ads.data(1, b"ab")
    events = peer.receive_data(ads.data_to_send())
    data = next(event for event in events if isinstance(event, DataReceived))
    peer.increment_flow_control_window(3, stream_id=1)
    feed(ads, peer.data_to_send())
    ads.data(1, b"c", end=True)
    events = peer.receive_data(ads.data_to_send())
    assert data.data == b"ab"
    assert any(isinstance(event, DataReceived) and event.data == b"c" for event in events)


def test_h2c_seed_preserves_head_and_later_stream_isolation():
    ads = HTTP2Connection(client=False)
    peer = H2Connection()
    settings = peer.initiate_upgrade_connection()
    assert ads.upgraded(b"HEAD", settings) is None
    feed(ads, peer.data_to_send())
    peer.receive_data(ads.data_to_send())
    ads.headers(1, ((b":status", b"200"), (b"content-length", b"123")), end=True)
    events = peer.receive_data(ads.data_to_send())
    assert any(isinstance(event, ResponseReceived) and event.stream_id == 1 for event in events)
    peer.send_headers(3, request(), end_stream=True)
    feed(ads, peer.data_to_send())
    ads.deny(3)
    events = peer.receive_data(ads.data_to_send())
    assert any(isinstance(event, StreamReset) and event.stream_id == 3 for event in events)
    assert_survivor(ads, peer, stream=5)


def test_h2c_client_seed_and_settings_validation():
    ads = HTTP2Connection(client=True)
    peer = H2Connection(H2Configuration(client_side=False))
    settings = ads.upgraded(b"GET")
    peer.initiate_upgrade_connection(settings)
    peer.receive_data(ads.data_to_send())
    feed(ads, peer.data_to_send())
    peer.send_headers(1, [(b":status", b"200")], end_stream=True)
    events = feed(ads, peer.data_to_send())
    assert any(isinstance(event, ResponseReceived) and event.stream_id == 1 for event in events)
    for malformed in (
        None,
        b"!!!",
        b"A",
        base64.urlsafe_b64encode(b"bad"),
        base64.urlsafe_b64encode(struct.pack("!HIHI", 4, 65535, 4, 65535)),
    ):
        server = HTTP2Connection(client=False)
        with pytest.raises(RequestDenied):
            server.upgraded(b"GET", malformed)
        assert server.data_to_send() == b""


def test_h2c_head_response_can_end_with_empty_data():
    ads = HTTP2Connection(client=True)
    peer = H2Connection(H2Configuration(client_side=False))
    settings = ads.upgraded(b"HEAD")
    peer.initiate_upgrade_connection(settings)
    peer.receive_data(ads.data_to_send())
    feed(ads, peer.data_to_send())
    peer.send_headers(1, [(b":status", b"200"), (b"content-length", b"123")])
    peer.send_data(1, b"", end_stream=True)
    events = feed(ads, peer.data_to_send())
    assert any(isinstance(event, StreamEnded) for event in events)
    assert not any(isinstance(event, StreamReset) for event in events)


def test_sensitive_headers_are_preserved_but_never_compression_indexed():
    ads, peer = pair(client=True)
    secret = b"sensitive-fixture"
    fields = request(
        (b"authorization", secret),
        (b"proxy-authorization", secret),
        (b"cookie", secret),
        (b"set-cookie", secret),
    )
    ads.headers(1, fields, end=True)
    events = peer.receive_data(ads.data_to_send())
    headers = next(event.headers for event in events if isinstance(event, RequestReceived))
    assert (b"authorization", secret) in headers
    assert (b"cookie", secret) in headers
    assert all(value != secret for _, value in ads.encoder.header_table.dynamic_entries)
    assert all(value != secret for _, value in peer.decoder.header_table.dynamic_entries)


def test_empty_authority_remains_absent_and_equivalent_host_is_not_rewritten():
    ads, peer = pair()
    fields = tuple(
        (name, b"") if name == b":authority" else (name, value) for name, value in request()
    )
    events = feed(ads, raw_headers(peer, 1, fields, end=True))
    assert (
        tuple(next(event.headers for event in events if isinstance(event, RequestReceived)))
        == fields
    )
    ads.deny(1)
    peer.send_headers(3, request((b"host", b"ORIGIN.EXAMPLE:443")), end_stream=True)
    events = feed(ads, peer.data_to_send())
    headers = next(event.headers for event in events if isinstance(event, RequestReceived))
    assert (b"host", b"ORIGIN.EXAMPLE:443") in headers


def test_extended_websocket_connect_requires_negotiated_setting_but_not_opaque_fallback():
    ads, peer = pair(websocket=True)
    headers = request((b":protocol", b"websocket"), method=b"CONNECT")
    peer.send_headers(1, headers)
    events = feed(ads, peer.data_to_send())
    assert any(isinstance(event, RequestReceived) for event in events)
    # Parsing is not permission: only a separate policy/handshake handler may
    # accept this event. Here it is denied with no synthetic HTTP response.
    ads.deny(1)
    events = peer.receive_data(ads.data_to_send())
    assert any(isinstance(event, StreamReset) for event in events)
    assert_survivor(ads, peer)
    peer.send_headers(5, request((b":protocol", b"arbitrary"), method=b"CONNECT"))
    events = feed(ads, peer.data_to_send())
    assert any(isinstance(event, StreamReset) for event in events)


def test_dependency_gate_and_header_count_limits(monkeypatch):
    import ads_sandbox_egress.http2 as module

    ads, peer = pair()
    headers = request(*((f"x-{index}".encode(), b"v") for index in range(129)))
    events = feed(ads, raw_headers(peer, 1, headers, end=True))
    assert isinstance(events[0], StreamReset)
    monkeypatch.setattr(module, "version", lambda name: "unreviewed")
    with pytest.raises(RuntimeError, match="dependency review"):
        HTTP2Connection(client=False)


@pytest.mark.anyio
async def test_real_socket_stream_denial_leaves_another_exchange_alive():
    done = asyncio.Event()
    errors = []

    async def handle(reader, writer):
        connection = HTTP2Connection(client=False)
        connection.initiate_connection()
        try:
            writer.write(connection.data_to_send())
            await writer.drain()
            async with asyncio.timeout(3):
                while data := await reader.read(16384):
                    for event in connection.receive_data(data):
                        if isinstance(event, RequestReceived):
                            if event.stream_id == 1:
                                connection.deny(1)
                            else:
                                connection.headers(3, ((b":status", b"200"),))
                                connection.data(3, b"survived", end=True)
                    writer.write(connection.data_to_send())
                    await writer.drain()
        except Exception as error:
            errors.append(error)
        finally:
            writer.close()
            await writer.wait_closed()
            done.set()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    address = server.sockets[0].getsockname()
    reader, writer = await asyncio.open_connection(*address)
    peer = H2Connection()
    peer.initiate_connection()
    peer.send_headers(1, request(), end_stream=True)
    peer.send_headers(3, request(), end_stream=True)
    observed = []
    try:
        writer.write(peer.data_to_send())
        await writer.drain()
        async with asyncio.timeout(3):
            while not any(
                isinstance(event, StreamEnded) and event.stream_id == 3 for event in observed
            ):
                observed.extend(peer.receive_data(await reader.read(16384)))
                writer.write(peer.data_to_send())
                await writer.drain()
        assert any(isinstance(event, StreamReset) and event.stream_id == 1 for event in observed)
        assert any(
            isinstance(event, DataReceived) and event.data == b"survived" for event in observed
        )
        assert not any(
            isinstance(event, ResponseReceived) and event.stream_id == 1 for event in observed
        )
        assert not any(isinstance(event, ConnectionTerminated) for event in observed)
    finally:
        writer.close()
        await writer.wait_closed()
        await asyncio.wait_for(done.wait(), 3)
        server.close()
        await server.wait_closed()
    assert not errors
