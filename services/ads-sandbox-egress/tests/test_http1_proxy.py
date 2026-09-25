import asyncio
import ipaddress
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field

import h11
import pytest

from ads_commons.egress import (
    EgressPath,
    EgressRule,
    ProjectEgressSettings,
    ProjectEgressSnapshot,
    ProtocolSettings,
)
from ads_sandbox_egress.configuration import PolicyStore
from ads_sandbox_egress.destinations import DestinationBoundary
from ads_sandbox_egress.http1 import HTTP1Channel
from ads_sandbox_egress.http1_proxy import HTTP1Proxy
from ads_sandbox_egress.membership import ConnectionMembership, ResolutionEvidence
from ads_sandbox_egress.policy import RequestDenied
from ads_sandbox_egress.request_authorization import (
    ConnectionTarget,
    RequestAuthorizer,
    RequestHead,
)
from ads_sandbox_egress.streams import OwnedStream
from test_normalization import nginx_helper as nginx_helper

PUBLIC = ipaddress.ip_address("1.1.1.1")


@pytest.fixture
def anyio_backend():
    return "asyncio"


def settings(*paths, domain="origin.example", mode="whitelist", port=80, protocol="http"):
    return ProjectEgressSettings(
        (
            EgressRule(
                domain,
                port,
                protocol,
                ProtocolSettings(
                    method="any", upgrades="none", paths=tuple(EgressPath(p) for p in paths)
                ),
            ),
        ),
        mode,
    )


class Resolver:
    def __init__(self):
        self.calls = []
        self.addresses = frozenset((PUBLIC,))
        self.authentication = "insecure"
        self.fail = False

    async def resolve(self, name):
        self.calls.append(name)
        if self.fail:
            raise OSError("private resolver detail")
        return ResolutionEvidence(
            name, self.addresses, frozenset(), time.monotonic() + 0.2, True, self.authentication
        )


@dataclass
class Lab:
    policies: PolicyStore
    resolver: Resolver
    address: tuple
    connected: list = field(default_factory=list)
    tasks: set = field(default_factory=set)
    errors: list = field(default_factory=list)
    owners: list = field(default_factory=list)


@asynccontextmanager
async def proxy_lab(
    normalizer, origin_handler, configured=None, target=None, proxy_type=HTTP1Proxy
):
    """Only the admitted socket/connector and DNS acquisition are fixtures.

    The production identity/membership/policy/NGINX/HTTP/framing/stream owners
    run unchanged. Loopback fixture sockets do NOT prove kernel interception
    or production public-peer/interface binding.
    """
    policies = PolicyStore()
    if configured is not None:
        await policies.install(ProjectEgressSnapshot(1, configured))
    resolver = Resolver()
    boundary = DestinationBoundary((ipaddress.ip_network("10.0.0.0/8"),), (), "fixture")
    target = target or ConnectionTarget(PUBLIC, 80, False)
    lab = Lab(policies, resolver, ())
    writers = set()

    async def tracked(handler, reader, writer):
        task = asyncio.current_task()
        lab.tasks.add(task)
        writers.add(writer)
        try:
            await handler(reader, writer)
        except (ConnectionResetError, BrokenPipeError):
            pass
        except Exception as error:
            lab.errors.append(error)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionResetError, BrokenPipeError):
                pass
            writers.discard(writer)
            lab.tasks.discard(task)

    origin = await asyncio.start_server(lambda r, w: tracked(origin_handler, r, w), "127.0.0.1", 0)

    async def connect(original):
        assert original is target
        lab.connected.append(original)
        reader, writer = await asyncio.open_connection(*origin.sockets[0].getsockname())
        return OwnedStream.tcp(reader, writer)

    async def frontend(reader, writer):
        membership = ConnectionMembership(resolver, boundary)
        authorizer = RequestAuthorizer(target, policies, membership, normalizer)
        try:
            proxy = proxy_type(
                OwnedStream.tcp(reader, writer),
                authorizer,
                connect,
                idle_timeout=1,
                authorization_timeout=1,
            )
            lab.owners.append(proxy)
            await proxy.run()
        finally:
            await membership.close()

    front = await asyncio.start_server(lambda r, w: tracked(frontend, r, w), "127.0.0.1", 0)
    lab.address = front.sockets[0].getsockname()
    try:
        yield lab
    finally:
        front.close()
        origin.close()
        for writer in tuple(writers):
            writer.transport.abort()
        for task in tuple(lab.tasks):
            task.cancel()
        await asyncio.gather(*tuple(lab.tasks), return_exceptions=True)
        await front.wait_closed()
        await origin.wait_closed()
    assert not lab.tasks and not lab.errors


async def close_client(writer):
    writer.close()
    try:
        await writer.wait_closed()
    except (ConnectionResetError, BrokenPipeError):
        pass


@pytest.mark.anyio
async def test_real_named_request_normalizes_for_policy_but_forwards_original_target(nginx_helper):
    received = []

    async def origin(reader, writer):
        received.append(await reader.readuntil(b"\r\n\r\n"))
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        await writer.drain()

    async with proxy_lab(nginx_helper, origin, settings("/a/c/D")) as lab:
        reader, writer = await asyncio.open_connection(*lab.address)
        try:
            writer.write(
                b"GET /a/%62/../c//D?q=%2f HTTP/1.1\r\nHost: origin.example\r\n"
                b"Connection: close, x-hop\r\nX-Hop: removed\r\nX-End: retained\r\n\r\n"
            )
            await writer.drain()
            response = await asyncio.wait_for(reader.read(), 2)
            assert response.endswith(b"ok") and b"200" in response
            assert b"/a/%62/../c//D?q=%2f" in received[0]
            assert b"x-end: retained" in received[0]
            assert b"x-hop" not in received[0] and b"connection:" not in received[0]
            assert len(lab.connected) == 1 and lab.resolver.calls == ["origin.example"]
        finally:
            await close_client(writer)


@pytest.mark.anyio
@pytest.mark.parametrize(
    "case",
    [
        "unconfigured",
        "path",
        "private",
        "member",
        "host",
        "absolute",
        "port",
        "connect",
        "upgrade",
        "helper",
    ],
)
async def test_denial_resets_before_any_upstream_socket_or_http_bytes(nginx_helper, case):
    async def origin(reader, writer):
        pytest.fail("denied request reached origin")

    target = (
        ConnectionTarget(ipaddress.ip_address("10.2.3.4"), 80, False) if case == "private" else None
    )
    async with proxy_lab(
        nginx_helper,
        origin,
        None if case == "unconfigured" else settings("/allowed"),
        target=target,
    ) as lab:
        if case == "member":
            lab.resolver.addresses = frozenset((ipaddress.ip_address("8.8.8.8"),))
        request_target = (
            b"/denied"
            if case == "path"
            else b"http://other.example/allowed"
            if case == "absolute"
            else b"/%GG"
            if case == "helper"
            else b"/allowed"
        )
        host = (
            b"other.example"
            if case == "host"
            else b"origin.example:81"
            if case == "port"
            else b"origin.example"
        )
        method = b"CONNECT" if case == "connect" else b"GET"
        extra = b"Connection: upgrade\r\nUpgrade: arbitrary\r\n" if case == "upgrade" else b""
        reader, writer = await asyncio.open_connection(*lab.address)
        try:
            writer.write(
                method
                + b" "
                + request_target
                + b" HTTP/1.1\r\nHost: "
                + host
                + b"\r\n"
                + extra
                + b"\r\n"
            )
            await writer.drain()
            with pytest.raises(ConnectionResetError):
                await asyncio.wait_for(reader.read(), 2)
            assert not lab.connected
        finally:
            await close_client(writer)


@pytest.mark.anyio
async def test_continue_upload_and_trailers_stream_through_both_real_parsers(nginx_helper):
    seen = []

    async def origin(reader, writer):
        channel = HTTP1Channel(reader, writer, client=False)
        request = await channel.receive()
        assert (b"expect", b"100-continue") in request.headers
        await channel.send(h11.InformationalResponse(status_code=100, headers=[]))
        while True:
            event = await channel.receive()
            seen.append(event)
            if isinstance(event, h11.EndOfMessage):
                break
        await channel.send(
            h11.Response(status_code=200, headers=[(b"transfer-encoding", b"chunked")])
        )
        await channel.send(h11.Data(data=b"answer"))
        await channel.send(h11.EndOfMessage(headers=[(b"digest", b"response")]))

    async with proxy_lab(nginx_helper, origin, settings("/upload")) as lab:
        reader, writer = await asyncio.open_connection(*lab.address)
        try:
            writer.write(
                b"POST /upload HTTP/1.1\r\nHost: origin.example\r\n"
                b"Expect: 100-continue\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
            )
            await writer.drain()
            interim = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2)
            assert interim.startswith(b"HTTP/1.1 100")
            assert not seen
            writer.write(b"4\r\nbody\r\n0\r\nDigest: request\r\n\r\n")
            await writer.drain()
            result = await asyncio.wait_for(reader.read(), 2)
            assert b"answer" in result and b"digest: response" in result
            assert (
                b"".join(bytes(event.data) for event in seen if isinstance(event, h11.Data))
                == b"body"
            )
            assert list(seen[-1].headers) == [(b"digest", b"request")]
        finally:
            await close_client(writer)


@pytest.mark.anyio
async def test_early_final_does_not_wait_for_or_solicit_upload(nginx_helper):
    async def origin(reader, writer):
        header = await reader.readuntil(b"\r\n\r\n")
        assert b"expect: 100-continue" in header
        writer.write(b"HTTP/1.1 413 Too Large\r\nContent-Length: 4\r\n\r\nnope")
        await writer.drain()
        try:
            await reader.read()
        except ConnectionResetError:
            pass

    async with proxy_lab(nginx_helper, origin, settings("/upload")) as lab:
        reader, writer = await asyncio.open_connection(*lab.address)
        try:
            writer.write(
                b"POST /upload HTTP/1.1\r\nHost: origin.example\r\n"
                b"Expect: 100-continue\r\nContent-Length: 1000000000000\r\n\r\n"
            )
            await writer.drain()
            result = await asyncio.wait_for(reader.read(), 2)
            assert b"413" in result and result.endswith(b"nope") and b"100 Continue" not in result
        finally:
            await close_client(writer)


@pytest.mark.anyio
async def test_new_request_observes_new_policy_without_retroactively_stopping_response(
    nginx_helper,
):
    response_started = asyncio.Event()
    release = asyncio.Event()
    received = []

    async def origin(reader, writer):
        received.append(await reader.readuntil(b"\r\n\r\n"))
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nabc")
        await writer.drain()
        response_started.set()
        await release.wait()
        writer.write(b"def")
        await writer.drain()
        try:
            received.append(await reader.read())
        except ConnectionResetError:
            pass

    async with proxy_lab(nginx_helper, origin, settings("/allowed")) as lab:
        reader, writer = await asyncio.open_connection(*lab.address)
        try:
            writer.write(b"GET /allowed HTTP/1.1\r\nHost: origin.example\r\n\r\n")
            await writer.drain()
            await asyncio.wait_for(response_started.wait(), 2)
            headers = await reader.readuntil(b"\r\n\r\n")
            assert b"200" in headers and await reader.readexactly(3) == b"abc"
            await lab.policies.install(
                ProjectEgressSnapshot(2, settings("/allowed", mode="blacklist"))
            )
            release.set()
            assert await reader.readexactly(3) == b"def"
            writer.write(b"GET /allowed HTTP/1.1\r\nHost: origin.example\r\n\r\n")
            await writer.drain()
            with pytest.raises(ConnectionResetError):
                await asyncio.wait_for(reader.read(), 2)
            assert len(lab.connected) == 1
            assert all(not data or data.count(b"GET ") == 1 for data in received)
        finally:
            release.set()
            await close_client(writer)


@pytest.mark.anyio
@pytest.mark.parametrize(
    "response",
    [
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nx",
        b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: arbitrary\r\n\r\n",
    ],
)
async def test_invalid_upstream_response_resets_client_without_synthetic_error(
    nginx_helper, response
):
    async def origin(reader, writer):
        await reader.readuntil(b"\r\n\r\n")
        writer.write(response)
        await writer.drain()

    async with proxy_lab(nginx_helper, origin, settings()) as lab:
        reader, writer = await asyncio.open_connection(*lab.address)
        seen = bytearray()
        try:
            writer.write(b"GET / HTTP/1.1\r\nHost: origin.example\r\n\r\n")
            await writer.drain()
            with pytest.raises(ConnectionResetError):
                async with asyncio.timeout(2):
                    while part := await reader.read(16384):
                        seen.extend(part)
            assert b"403" not in seen and b"502" not in seen
        finally:
            await close_client(writer)


@pytest.mark.anyio
async def test_http2_authorization_adapter_uses_original_path_and_current_snapshot(nginx_helper):
    policies, resolver = PolicyStore(), Resolver()
    await policies.install(
        ProjectEgressSnapshot(1, settings("/normal/path", port=443, protocol="https"))
    )
    boundary = DestinationBoundary((ipaddress.ip_network("10.0.0.0/8"),), (), "fixture")
    membership = ConnectionMembership(resolver, boundary)
    target = ConnectionTarget(PUBLIC, 443, True, "origin.example")
    authorizer = RequestAuthorizer(target, policies, membership, nginx_helper)
    fields = (
        (b":method", b"POST"),
        (b":scheme", b"https"),
        (b":authority", b"origin.example"),
        (b":path", b"/normal//path?raw=%2f"),
        (b"content-length", b"1000000000000"),
        (b"expect", b"100-continue"),
    )
    try:
        head = RequestHead.http2(fields, target)
        result = await authorizer.authorize(head)
        assert result.head.headers == fields
        assert result.head.target == b"/normal//path?raw=%2f"
        assert result.normalized_path == b"/normal/path" and result.policy_revision == 1
    finally:
        await membership.close()


@pytest.mark.anyio
async def test_pipeline_reauthorizes_every_request_and_never_follows_redirects(nginx_helper):
    seen = []

    async def origin(reader, writer):
        channel = HTTP1Channel(reader, writer, client=False)
        for index in range(2):
            request = await channel.receive()
            seen.append(request.target)
            assert isinstance(await channel.receive(), h11.EndOfMessage)
            await channel.send(
                h11.Response(
                    status_code=302 if index == 0 else 200,
                    headers=[(b"content-length", b"0"), (b"location", b"http://10.0.0.1/private")],
                )
            )
            await channel.send(h11.EndOfMessage())
            if index == 0:
                channel.next_cycle()

    async with proxy_lab(nginx_helper, origin, settings("/a", "/b")) as lab:
        reader, writer = await asyncio.open_connection(*lab.address)
        try:
            writer.write(
                b"GET /a HTTP/1.1\r\nHost: origin.example\r\n\r\n"
                b"GET /b HTTP/1.1\r\nHost: origin.example\r\nConnection: close\r\n\r\n"
            )
            await writer.drain()
            result = await asyncio.wait_for(reader.read(), 2)
            assert result.count(b"HTTP/1.1 ") == 2
            assert b"302" in result and b"200" in result
            assert b"http://10.0.0.1/private" in result
            assert seen == [b"/a", b"/b"] and len(lab.connected) == 1
            assert lab.resolver.calls == ["origin.example"]
        finally:
            await close_client(writer)


@pytest.mark.anyio
async def test_new_request_after_dns_expiry_never_uses_stale_membership(nginx_helper):
    first = asyncio.Event()
    seen = []

    async def origin(reader, writer):
        seen.append(await reader.readuntil(b"\r\n\r\n"))
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        await writer.drain()
        first.set()
        try:
            remainder = await reader.read()
            assert not remainder
        except ConnectionResetError:
            pass

    async with proxy_lab(nginx_helper, origin, settings()) as lab:
        reader, writer = await asyncio.open_connection(*lab.address)
        try:
            writer.write(b"GET / HTTP/1.1\r\nHost: origin.example\r\n\r\n")
            await writer.drain()
            await first.wait()
            await reader.readuntil(b"\r\n\r\n")
            await asyncio.sleep(0.25)
            lab.resolver.fail = True
            writer.write(b"GET / HTTP/1.1\r\nHost: origin.example\r\n\r\n")
            await writer.drain()
            with pytest.raises(ConnectionResetError):
                await asyncio.wait_for(reader.read(), 2)
            assert len(seen) == 1 and lab.resolver.calls == ["origin.example"] * 2
        finally:
            await close_client(writer)


@pytest.mark.anyio
async def test_policy_change_while_helper_pending_applies_before_authorization(nginx_helper):
    pending, release = asyncio.Event(), asyncio.Event()

    class PausedNormalizer:
        async def normalize(self, method, target, headers):
            result = await nginx_helper.normalize(method, target, headers)
            pending.set()
            await release.wait()
            return result

    async def origin(reader, writer):
        pytest.fail("pending request was not authorized before policy changed")

    async with proxy_lab(PausedNormalizer(), origin, settings("/allowed")) as lab:
        reader, writer = await asyncio.open_connection(*lab.address)
        try:
            writer.write(b"GET /allowed HTTP/1.1\r\nHost: origin.example\r\n\r\n")
            await writer.drain()
            await asyncio.wait_for(pending.wait(), 2)
            await lab.policies.install(
                ProjectEgressSnapshot(2, settings("/allowed", mode="blacklist"))
            )
            release.set()
            with pytest.raises(ConnectionResetError):
                await asyncio.wait_for(reader.read(), 2)
            assert not lab.connected
        finally:
            release.set()
            await close_client(writer)


@pytest.mark.anyio
@pytest.mark.parametrize("status", ["bogus", "indeterminate"])
async def test_dnssec_defect_alone_is_not_extra_proxy_policy(nginx_helper, status):
    async def origin(reader, writer):
        await reader.readuntil(b"\r\n\r\n")
        writer.write(b"HTTP/1.1 204 No Content\r\n\r\n")
        await writer.drain()

    async with proxy_lab(nginx_helper, origin, settings()) as lab:
        lab.resolver.authentication = status
        reader, writer = await asyncio.open_connection(*lab.address)
        try:
            writer.write(b"GET / HTTP/1.1\r\nHost: origin.example\r\nConnection: close\r\n\r\n")
            await writer.drain()
            assert b"204" in await asyncio.wait_for(reader.read(), 2)
            assert len(lab.connected) == 1
        finally:
            await close_client(writer)


@pytest.mark.anyio
async def test_literal_destination_does_not_invent_dns_or_reverse_name(nginx_helper):
    async def origin(reader, writer):
        header = await reader.readuntil(b"\r\n\r\n")
        assert b"host: 1.1.1.1" in header
        writer.write(b"HTTP/1.1 204 No Content\r\n\r\n")
        await writer.drain()

    async with proxy_lab(nginx_helper, origin, settings(domain="*")) as lab:
        reader, writer = await asyncio.open_connection(*lab.address)
        try:
            writer.write(b"GET / HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n")
            await writer.drain()
            assert b"204" in await asyncio.wait_for(reader.read(), 2)
            assert lab.resolver.calls == [] and len(lab.connected) == 1
        finally:
            await close_client(writer)


@pytest.mark.parametrize("protocol", ["http1", "http2"])
def test_conflicting_schemes_and_tls_names_are_not_selectable_hints(protocol):
    target = ConnectionTarget(PUBLIC, 443, True, "origin.example")
    with pytest.raises(RequestDenied):
        if protocol == "http1":
            RequestHead.http1(
                h11.Request(
                    method=b"GET",
                    target=b"http://origin.example/",
                    headers=[(b"host", b"origin.example")],
                ),
                target,
            )
        else:
            RequestHead.http2(
                (
                    (b":method", b"GET"),
                    (b":scheme", b"http"),
                    (b":authority", b"origin.example"),
                    (b":path", b"/"),
                ),
                target,
            )


@pytest.mark.anyio
async def test_empty_host_is_not_repaired_to_make_nginx_pass(nginx_helper):
    # This exposes an unfinished supported case, not successful proxy support:
    # NGINX rejects the legally empty Host. No invented authority/raw-path fallback.
    async def origin(reader, writer):
        pytest.fail("helper rejection must not be repaired")

    async with proxy_lab(nginx_helper, origin, settings(domain="*")) as lab:
        reader, writer = await asyncio.open_connection(*lab.address)
        try:
            writer.write(b"GET / HTTP/1.1\r\nHost:\r\n\r\n")
            await writer.drain()
            with pytest.raises(ConnectionResetError):
                await asyncio.wait_for(reader.read(), 2)
            assert not lab.connected and not lab.resolver.calls
        finally:
            await close_client(writer)


@pytest.mark.anyio
async def test_response_headers_do_not_cancel_an_active_duplex_upload(nginx_helper):
    async def origin(reader, writer):
        await reader.readuntil(b"\r\n\r\n")
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nready")
        await writer.drain()
        assert await reader.readexactly(4) == b"body"
        writer.write(b"!")
        await writer.drain()

    async with proxy_lab(nginx_helper, origin, settings("/duplex")) as lab:
        reader, writer = await asyncio.open_connection(*lab.address)
        try:
            writer.write(
                b"POST /duplex HTTP/1.1\r\nHost: origin.example\r\nContent-Length: 4\r\n"
                b"Connection: close\r\n\r\n"
            )
            await writer.drain()
            assert b"200" in await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2)
            assert await reader.readexactly(5) == b"ready"
            writer.write(b"body")
            await writer.drain()
            assert await asyncio.wait_for(reader.read(), 2) == b"!"
        finally:
            await close_client(writer)
