"""Single owner from admitted original destination to inspected HTTP exchanges.

Only kernel admission supplies the destination. The external socket boundary is
explicit for protocol tests; production uses InterfaceConnector, never a URL,
proxy environment variable, resolver result or HTTP-header-selected endpoint.
"""

from __future__ import annotations

import asyncio
import logging
import re
import socket
from collections.abc import Awaitable, Callable

from ads_sandbox_egress.certificate_mirror import CertificateMirror
from ads_sandbox_egress.certificates import CertificatePairs, PairDestination
from ads_sandbox_egress.configuration import PolicyStore
from ads_sandbox_egress.destinations import Address, DestinationBoundary
from ads_sandbox_egress.ech_lifecycle import ECHLifecycle
from ads_sandbox_egress.http1_proxy import HTTP1Proxy
from ads_sandbox_egress.http2_proxy import HTTP2Proxy
from ads_sandbox_egress.membership import ConnectionMembership, EvidenceResolver
from ads_sandbox_egress.normalization import Normalizer
from ads_sandbox_egress.origin_tls import OriginContext, inspect_origin
from ads_sandbox_egress.policy import RequestDenied
from ads_sandbox_egress.request_authorization import ConnectionTarget, RequestAuthorizer
from ads_sandbox_egress.streams import OwnedStream
from ads_sandbox_egress.tls import ClientHello
from ads_sandbox_egress.tls_transport import FrontendIdentity, TLSStream

_LOG = logging.getLogger(__name__)
_H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
SocketConnector = Callable[
    [Address, int], Awaitable[tuple[asyncio.StreamReader, asyncio.StreamWriter]]
]


class InterfaceConnector:
    """A new nontransparent upstream socket, with exact peer verification."""

    def __init__(self, interface: str, boundary: DestinationBoundary) -> None:
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,15}", interface):
            raise ValueError("explicit upstream interface required")
        self.interface, self.boundary = interface, boundary

    async def __call__(
        self, address: Address, port: int
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        self.boundary.require_public(str(address))
        if type(port) is not int or not 1 <= port <= 65535:
            raise RequestDenied("invalid_original_port")
        stream = socket.socket(
            socket.AF_INET if address.version == 4 else socket.AF_INET6, socket.SOCK_STREAM
        )
        writer = None
        try:
            stream.setsockopt(
                socket.SOL_SOCKET, socket.SO_BINDTODEVICE, self.interface.encode() + b"\0"
            )
            stream.setblocking(False)
            async with asyncio.timeout(10):
                await asyncio.get_running_loop().sock_connect(stream, (str(address), port))
                reader, writer = await asyncio.open_connection(sock=stream, limit=65536)
            peer = writer.get_extra_info("peername")
            if not peer or peer[1] != port:
                raise RequestDenied("upstream_peer_changed")
            self.boundary.require_peer(address, peer[0])
            return reader, writer
        except BaseException:
            if writer is not None:
                OwnedStream.tcp(reader, writer).abort()
            else:
                stream.close()
            raise


class Connections:
    """Bounded admitted-flow owner, sharing the live control PolicyStore."""

    def __init__(
        self,
        policies: PolicyStore,
        boundary: DestinationBoundary,
        resolver: EvidenceResolver,
        normalizer: Normalizer,
        ech: ECHLifecycle,
        origin: OriginContext,
        pairs: CertificatePairs,
        mirror: CertificateMirror,
        connect: SocketConnector,
        *,
        maximum: int = 128,
    ) -> None:
        if not 1 <= maximum <= 128:
            raise ValueError("bounded connection admission required")
        self.policies, self.boundary, self.resolver = policies, boundary, resolver
        self.normalizer, self.ech, self.origin = normalizer, ech, origin
        self.pairs, self.mirror, self.connect = pairs, mirror, connect
        self.maximum = maximum
        self._tasks: set[asyncio.Task[None]] = set()
        self._closed = False

    def accept(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        address: Address,
        port: int,
    ) -> None:
        if self._closed or not self.policies.accepting or len(self._tasks) >= self.maximum:
            OwnedStream.tcp(reader, writer).abort()
            return
        task = asyncio.create_task(self._run(reader, writer, address, port))
        self._tasks.add(task)
        task.add_done_callback(self._completed)

    def _completed(self, task: asyncio.Task[None]) -> None:
        self._tasks.discard(task)
        if not task.cancelled():
            task.exception()

    async def _run(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        address: Address,
        port: int,
    ) -> None:
        raw = OwnedStream.tcp(reader, writer)
        front = raw
        upstream: OwnedStream | None = None
        membership = ConnectionMembership(self.resolver, self.boundary)
        selected: bytes | None = None
        try:
            target = ConnectionTarget(address, port, False)
            self.boundary.require_public(str(address))
            # One nonrenewing classification deadline. Ordinary methods are
            # not delayed while waiting for the length of an HTTP/2 preface.
            prefix = b""
            async with asyncio.timeout(10):
                while _H2_PREFACE.startswith(prefix):
                    byte = await reader.read(1)
                    if not byte:
                        raise RequestDenied("empty_connection")
                    prefix += byte
                    if prefix == _H2_PREFACE:
                        selected = b"h2"
                        break
            front = raw.prefixed(prefix)
            if prefix[0] == 0x16:

                async def prepare(hello: ClientHello) -> FrontendIdentity:
                    nonlocal target, upstream, selected
                    target = ConnectionTarget(address, port, True, hello.server_name)
                    name = hello.server_name or str(address)
                    r, w = await self.connect(address, port)
                    stream, observed = await inspect_origin(
                        r, w, self.origin, name, hello.protocols
                    )
                    upstream = OwnedStream.tls(stream)
                    selected = observed.selected_alpn
                    if selected not in (None, b"http/1.1", b"h2"):
                        raise RequestDenied("unsupported_origin_protocol")
                    destination = PairDestination(address, port, name)
                    return (
                        self.pairs.valid(destination, observed)
                        if observed.verified
                        else self.mirror.mirror(destination, observed)
                    )

                stream = await TLSStream.accept(front.reader, writer, self.ech.context, prepare)
                front = OwnedStream.tls(stream)

            async def adopt(original: ConnectionTarget) -> OwnedStream:
                nonlocal upstream
                if original is not target:
                    raise RequestDenied("original_destination_changed")
                if upstream is None:
                    if target.secure:
                        raise RequestDenied("inspected_origin_absent")
                    r, w = await self.connect(address, port)
                    upstream = OwnedStream.tcp(r, w)
                return upstream

            authorizer = RequestAuthorizer(target, self.policies, membership, self.normalizer)
            if selected == b"h2":
                await HTTP2Proxy(front, authorizer, adopt).run()
            else:
                await HTTP1Proxy(front, authorizer, adopt).run()
        except asyncio.CancelledError:
            raise
        except Exception:
            # Includes incomplete-support failures: no synthetic success. Never
            # log exception text from TLS, HTTP, certificates or DNS responses.
            _LOG.warning("connection denied")
        finally:
            front.abort()
            raw.abort()
            if upstream is not None:
                upstream.abort()
            await membership.close()

    async def close(self) -> None:
        self._closed = True
        tasks = tuple(self._tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self._tasks.clear()
