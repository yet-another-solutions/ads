"""Bounded DNS transport. A validated synthetic view is a mandatory dependency.

This layer never forwards an AcquiredAnswer. The supplied view owns DNSSEC
classification, faithful synthesis, ECH replacement and durable publication.
"""

from __future__ import annotations

import asyncio
import copy
import json
import logging
import math
import time
from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from functools import partial
from typing import Protocol
from uuid import UUID, uuid4

import dns.exception
import dns.flags
import dns.message
import dns.opcode
import dns.rdataclass
import dns.rdatatype

from ads_sandbox_egress.http1 import reset
from ads_sandbox_egress.policy import RequestDenied

_LOG = logging.getLogger(__name__)


class SyntheticView(Protocol):
    async def answer(
        self, query: dns.message.Message, *, deadline: float
    ) -> dns.message.Message: ...


@dataclass(frozen=True, slots=True)
class DNSLimits:
    accepted: int = 128
    executing: int = 32
    connections: int = 8
    outstanding: int = 16
    deadline: float = 10
    frame_deadline: float = 5
    idle_timeout: float = 30

    def __post_init__(self) -> None:
        if not (
            1 <= self.executing <= self.accepted <= 1024
            and 1 <= self.connections <= 128
            and 1 <= self.outstanding <= 128
            and all(
                math.isfinite(v) and 0 < v <= 300
                for v in (self.deadline, self.frame_deadline, self.idle_timeout)
            )
        ):
            raise ValueError("invalid DNS transport limits")


class DNSTransport:
    def __init__(
        self,
        view: SyntheticView,
        *,
        sandbox_id: UUID,
        instance_id: UUID,
        classifier_version: str,
        safe_udp_payload: int,
        limits: DNSLimits | None = None,
    ) -> None:
        if not 512 <= safe_udp_payload <= 1232 or not classifier_version:
            raise ValueError("explicit safe DNS payload and classifier required")
        self.view = view
        self.sandbox_id, self.instance_id = sandbox_id, instance_id
        self.classifier_version = classifier_version[:128]
        self.safe_udp_payload = safe_udp_payload
        self.limits = limits or DNSLimits()
        self._slots = asyncio.Semaphore(self.limits.executing)
        self._accepted = 0
        self._connections = 0
        self._closed = False
        self._udp: asyncio.DatagramTransport | None = None
        self._tcp: asyncio.Server | None = None
        self._tasks: dict[asyncio.Task[None], Callable[[], None]] = {}
        self._writers: set[asyncio.StreamWriter] = set()

    def _warning(
        self,
        reason: str,
        transport: str,
        started: float,
        query: dns.message.Message | None = None,
    ) -> None:
        fields: dict[str, object] = {
            "event": "dns_denied",
            "level": "WARNING",
            "sandbox_id": str(self.sandbox_id),
            "egress_instance_id": str(self.instance_id),
            "request_id": str(uuid4()),
            "transport": transport,
            "action": "drop" if transport == "udp" else "reset",
            "reason": reason[:128],
            "classifier_version": self.classifier_version,
            "elapsed_ms": max(0, int((time.monotonic() - started) * 1000)),
        }
        if query is not None and len(query.question) == 1:
            question = query.question[0]
            fields["query"] = {
                "id": query.id,
                "name": question.name.to_text()[:255],
                "type": dns.rdatatype.to_text(question.rdtype),
            }
        # No raw packets, exception repr, credentials or key material. Logging
        # pipeline availability is not authorization or readiness input.
        try:
            _LOG.warning(json.dumps(fields, ensure_ascii=True, separators=(",", ":")))
        except Exception:
            pass

    def _query(self, wire: bytes, *, udp: bool) -> dns.message.Message:
        if not wire or len(wire) > (1232 if udp else 65535):
            raise RequestDenied("message_size")
        try:
            query = dns.message.from_wire(wire)
        except (dns.exception.DNSException, ValueError):
            raise RequestDenied("malformed_message") from None
        if (
            query.flags & (dns.flags.QR | dns.flags.TC)
            or query.opcode() != dns.opcode.QUERY
            or len(query.question) != 1
            or query.answer
            or query.authority
            or query.additional
            or query.tsig is not None
            or query.edns > 0
            or query.question[0].rdclass != dns.rdataclass.IN
            or query.question[0].rdtype in (dns.rdatatype.AXFR, dns.rdatatype.IXFR)
        ):
            raise RequestDenied("unsupported_query")
        return query

    def _admit(self) -> None:
        if self._closed or self._accepted >= self.limits.accepted:
            raise RequestDenied("query_capacity")
        self._accepted += 1

    async def _answer(self, query: dns.message.Message, started: float, *, udp: bool) -> bytes:
        deadline = started + self.limits.deadline
        try:
            async with asyncio.timeout_at(deadline), self._slots:
                response = await self.view.answer(query, deadline=deadline)
                if (
                    response.id != query.id
                    or response.question != query.question
                    or not response.flags & dns.flags.QR
                    or response.opcode() != dns.opcode.QUERY
                ):
                    raise RequestDenied("invalid_view_response")
                size = 65535
                if udp:
                    advertised = 512 if query.edns < 0 else max(512, query.payload)
                    size = min(advertised, self.safe_udp_payload)
                try:
                    return response.to_wire(max_size=size)
                except dns.exception.TooBig:
                    if not udp:
                        raise RequestDenied("response_unrepresentable") from None
                    # dnspython may omit Additional data without TC by default.
                    # ADS promises a TCP completion path, not a partial result
                    # that pretends every required inspected RRset was included.
                    truncated = copy.copy(response)
                    truncated.flags |= dns.flags.TC
                    return truncated.to_wire(max_size=size, prefer_truncation=True)
        except TimeoutError:
            raise RequestDenied("resolution_deadline") from None
        except (dns.exception.DNSException, ValueError):
            raise RequestDenied("response_unrepresentable") from None

    def _spawn(
        self, coroutine: Coroutine[object, object, None], finished: Callable[[], None]
    ) -> None:
        task = asyncio.create_task(coroutine)
        self._tasks[task] = finished
        task.add_done_callback(self._completed)

    def _completed(self, done: asyncio.Task[None]) -> None:
        finished = self._tasks.pop(done, None)
        if finished is not None:
            finished()
        if not done.cancelled():
            done.exception()

    def _release_query(self) -> None:
        self._accepted -= 1

    async def start(self, host: str, port: int) -> tuple[str, int]:
        """Caller must have established private-only kernel/interface binding."""
        if self._tcp is not None or self._closed:
            raise RuntimeError("DNS transport not startable")
        loop = asyncio.get_running_loop()
        owner = self

        class UDP(asyncio.DatagramProtocol):
            def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
                started = time.monotonic()
                query = None
                try:
                    query = owner._query(data, udp=True)
                    owner._admit()
                except RequestDenied as exc:
                    owner._warning(str(exc), "udp", started, query)
                    return
                owner._spawn(owner._udp_query(query, addr, started), owner._release_query)

        def tcp(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            if self._closed or self._connections >= self.limits.connections:
                self._warning("connection_capacity", "tcp", time.monotonic())
                reset(writer)
                return
            self._connections += 1
            self._writers.add(writer)

            def complete() -> None:
                self._connections -= 1
                self._writers.discard(writer)
                writer.close()

            self._spawn(self._tcp_connection(reader, writer), complete)

        try:
            self._tcp = await asyncio.start_server(tcp, host, port, limit=65536)
            address = self._tcp.sockets[0].getsockname()
            datagram, _ = await loop.create_datagram_endpoint(UDP, local_addr=(host, address[1]))
            self._udp = datagram
            return host, address[1]
        except BaseException:
            await self.close()
            raise

    async def _udp_query(
        self, query: dns.message.Message, address: tuple[str, int], started: float
    ) -> None:
        try:
            wire = await self._answer(query, started, udp=True)
            if self._udp is not None and not self._closed:
                self._udp.sendto(wire, address)
        except RequestDenied as exc:
            self._warning(str(exc), "udp", started, query)
        except Exception:
            self._warning("view_failure", "udp", started, query)

    async def _tcp_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        pending: dict[int, asyncio.Task[None]] = {}
        idle = asyncio.Event()
        idle.set()
        write_lock = asyncio.Lock()
        failed = False

        async def process(query: dns.message.Message, started: float) -> None:
            nonlocal failed
            try:
                wire = await self._answer(query, started, udp=False)
                async with asyncio.timeout_at(started + self.limits.deadline), write_lock:
                    if failed:
                        return
                    writer.write(len(wire).to_bytes(2, "big") + wire)
                    await writer.drain()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                failed = True
                reason = str(exc) if isinstance(exc, RequestDenied) else "view_failure"
                self._warning(reason, "tcp", started, query)
                reset(writer)

        def complete(query_id: int, task: asyncio.Task[None]) -> None:
            if pending.get(query_id) is not task:
                return
            self._release_query()
            pending.pop(query_id, None)
            if not pending:
                idle.set()
            if not task.cancelled():
                task.exception()

        try:
            while not failed and not self._closed:
                first = asyncio.create_task(reader.read(1))
                drained = asyncio.create_task(idle.wait())
                try:
                    if pending:
                        await asyncio.wait((first, drained), return_when=asyncio.FIRST_COMPLETED)
                    async with asyncio.timeout(self.limits.idle_timeout):
                        leading = await first
                finally:
                    for wait_task in (first, drained):
                        if not wait_task.done():
                            wait_task.cancel()
                    await asyncio.gather(first, drained, return_exceptions=True)
                if not leading:
                    break
                started = time.monotonic()
                async with asyncio.timeout(self.limits.frame_deadline):
                    length = int.from_bytes(leading + await reader.readexactly(1), "big")
                    query = self._query(await reader.readexactly(length), udp=False)
                if query.id in pending:
                    raise RequestDenied("duplicate_outstanding_id")
                if len(pending) >= self.limits.outstanding:
                    raise RequestDenied("connection_query_capacity")
                self._admit()
                idle.clear()
                task = asyncio.create_task(process(query, started))
                pending[query.id] = task
                task.add_done_callback(partial(complete, query.id))
        except (RequestDenied, TimeoutError, asyncio.IncompleteReadError) as exc:
            reason = str(exc) if isinstance(exc, RequestDenied) else "frame_or_idle_deadline"
            self._warning(reason, "tcp", time.monotonic())
            reset(writer)
        except OSError:
            pass
        finally:
            outstanding = tuple(pending.items())
            for _, task in outstanding:
                task.cancel()
            await asyncio.gather(*(task for _, task in outstanding), return_exceptions=True)
            for query_id, task in outstanding:
                complete(query_id, task)
            writer.close()
            try:
                async with asyncio.timeout(self.limits.frame_deadline):
                    await writer.wait_closed()
            except (OSError, TimeoutError):
                writer.transport.abort()

    async def close(self) -> None:
        self._closed = True
        if self._udp is not None:
            self._udp.close()
            self._udp = None
        server, self._tcp = self._tcp, None
        if server is not None:
            server.close()
        for writer in tuple(self._writers):
            reset(writer)
        tasks = tuple(self._tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for task in tasks:
            self._completed(task)
        if server is not None:
            # Recent asyncio waits for active transports too. Abort/join them
            # above before waiting; otherwise a client can delay shutdown.
            await server.wait_closed()
