"""Read-only signed CRL endpoint on an explicitly supplied private listener.

Not a proxy, redirector, control API or general private-address exception.
The bootstrap owner binds/fences the socket to its private interface first.
Only the paired sandbox source and literal local authority are admitted here.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import math
import re
import socket
from datetime import UTC, datetime

import h11

from ads_sandbox_egress.crl import CRLRepository, CRLUnavailable
from ads_sandbox_egress.http1 import HTTP1Channel, reset
from ads_sandbox_egress.identity_store import StateUnavailable
from ads_sandbox_egress.policy import RequestDenied

_LOG = logging.getLogger(__name__)
_PATH = re.compile(rb"/crl/([0-9a-f]{64})\.der")


class LocalCRLService:
    def __init__(
        self,
        repository: CRLRepository,
        sandbox_address: ipaddress.IPv4Address | ipaddress.IPv6Address,
        *,
        maximum_connections: int = 16,
        deadline: float = 5,
    ) -> None:
        if (
            not isinstance(sandbox_address, (ipaddress.IPv4Address, ipaddress.IPv6Address))
            or type(maximum_connections) is not int
            or not 1 <= maximum_connections <= 128
            or not math.isfinite(deadline)
            or not 0 < deadline <= 30
        ):
            raise ValueError("explicit bounded private CRL service required")
        self.repository, self.sandbox_address = repository, sandbox_address
        self.maximum_connections, self.deadline = maximum_connections, deadline
        self._server: asyncio.Server | None = None
        self._tasks: set[asyncio.Task[None]] = set()
        self._writers: set[asyncio.StreamWriter] = set()
        self._closed = False
        self._failed = False
        self._authority = ""
        self._hosts: set[bytes] = set()
        self._legacy_host = b""

    @property
    def healthy(self) -> bool:
        # Socket component only; runtime readiness additionally checks required
        # CRL authorities/current publications and all other enforcement owners.
        return (
            self._server is not None
            and self._server.is_serving()
            and not self._closed
            and not self._failed
        )

    async def start(self, sock: socket.socket) -> None:
        if self._server is not None or self._closed:
            raise RuntimeError("CRL listener already started or closed")
        address = ipaddress.ip_address(sock.getsockname()[0])
        port = sock.getsockname()[1]
        if (
            sock.family not in (socket.AF_INET, socket.AF_INET6)
            or sock.type & socket.SOCK_STREAM != socket.SOCK_STREAM
            or address.is_unspecified
            or address.is_multicast
            or not 1 <= port <= 65535
        ):
            raise ValueError("bound specific private stream listener required")
        host = f"[{address}]" if address.version == 6 else str(address)
        self._authority = f"{host}:{port}"
        self._hosts = {self._authority.encode("ascii")}
        self._legacy_host = host.encode("ascii")
        if port == 80:
            self._hosts.add(host.encode("ascii"))
        self._server = await asyncio.start_server(self._accept, sock=sock, limit=8192)

    def url(self, identity: str) -> str:
        if not self.healthy or re.fullmatch("[0-9a-f]{64}", identity) is None:
            raise CRLUnavailable("crl_listener_unavailable")
        return f"http://{self._authority}/crl/{identity}.der"

    @staticmethod
    def _deny(writer: asyncio.StreamWriter, reason: str) -> None:
        try:
            _LOG.warning("local_crl_denied reason=%s", reason)
        except Exception:
            pass
        finally:
            reset(writer)

    def _accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        if (
            self._closed
            or self._failed
            or len(self._tasks) >= self.maximum_connections
            or peer is None
            or ipaddress.ip_address(peer[0]) != self.sandbox_address
        ):
            self._deny(writer, "source_or_capacity")
            return
        self._writers.add(writer)
        task = asyncio.create_task(self._serve(reader, writer))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        channel = HTTP1Channel(reader, writer, client=False, idle_timeout=self.deadline)
        try:
            async with asyncio.timeout(self.deadline):
                request = await channel.receive()
                if not isinstance(request, h11.Request):
                    raise RequestDenied("crl_request")
                headers = tuple(request.headers)
                hosts = [value for name, value in headers if name == b"host"]
                path = _PATH.fullmatch(request.target)
                if (
                    request.method not in (b"GET", b"HEAD")
                    or request.http_version not in (b"1.0", b"1.1")
                    or len(hosts) != 1
                    or (
                        hosts[0] not in self._hosts
                        and not (request.http_version == b"1.0" and hosts[0] == self._legacy_host)
                    )
                    or path is None
                    or len(headers) > 32
                    or sum(len(name) + len(value) for name, value in headers) > 4096
                    or any(
                        name
                        in (
                            b"transfer-encoding",
                            b"upgrade",
                            b"expect",
                            b"range",
                            b"proxy-connection",
                            b"http2-settings",
                        )
                        for name, _ in headers
                    )
                    or any(name == b"content-length" and value != b"0" for name, value in headers)
                ):
                    raise RequestDenied("crl_request")
                end = await channel.receive()
                if not isinstance(end, h11.EndOfMessage) or end.headers:
                    raise RequestDenied("crl_body")
                now = datetime.now(UTC)
                result = self.repository.get(path[1].decode("ascii"), now=now)
                expiry = result.crl.next_update_utc
                if expiry is None:
                    raise StateUnavailable("missing committed CRL expiry")
                remaining = max(0, int((expiry - now).total_seconds()))
                await channel.send(
                    h11.Response(
                        status_code=200,
                        headers=[
                            (b"content-type", b"application/pkix-crl"),
                            (b"content-length", str(len(result.der)).encode("ascii")),
                            (b"cache-control", f"public, max-age={remaining}".encode("ascii")),
                            (b"connection", b"close"),
                        ],
                    )
                )
                if request.method == b"GET":
                    for offset in range(0, len(result.der), 16384):
                        await channel.send(h11.Data(data=result.der[offset : offset + 16384]))
                await channel.send(h11.EndOfMessage())
                writer.close()
                await writer.wait_closed()
        except asyncio.CancelledError:
            reset(writer)
            raise
        except StateUnavailable:
            self._failed = True
            self._deny(writer, "persistent_state")
        except (RequestDenied, CRLUnavailable, OSError, TimeoutError):
            self._deny(writer, "request_or_publication")
        except Exception:
            self._failed = True
            self._deny(writer, "internal_failure")
        finally:
            self._writers.discard(writer)

    async def close(self) -> None:
        self._closed = True
        if self._server is not None:
            self._server.close()
        for writer in tuple(self._writers):
            reset(writer)
        tasks = tuple(self._tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        if self._server is not None:
            await self._server.wait_closed()
