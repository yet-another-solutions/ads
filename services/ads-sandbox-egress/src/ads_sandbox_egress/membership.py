"""Connection-owned DNS evidence. Never a policy or shared resolver cache."""

from __future__ import annotations

import asyncio
import math
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from ads_sandbox_egress.destinations import Address, DestinationBoundary, dns_name
from ads_sandbox_egress.policy import RequestDenied, canonical_host


@dataclass(frozen=True, slots=True)
class ServiceEndpoint:
    """One verified original-service -> target -> independently resolved address."""

    service: str
    target: str
    address: Address
    port: int
    authority_port: int


@dataclass(frozen=True, slots=True)
class ResolutionEvidence:
    name: str
    direct_addresses: frozenset[Address]
    service_endpoints: frozenset[ServiceEndpoint]
    # Absolute monotonic expiry of the shortest-lived required dependency.
    expires_at: float
    complete: bool
    authentication: str  # secure/insecure/bogus/indeterminate, never an allow bit


class EvidenceResolver(Protocol):
    async def resolve(
        self, name: str, *, authority_port: int, protocol: str
    ) -> ResolutionEvidence: ...


class ConnectionMembership:
    def __init__(
        self,
        resolver: EvidenceResolver,
        boundary: DestinationBoundary,
        *,
        ttl_cap: float = 10,
        max_names: int = 128,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not math.isfinite(ttl_cap) or not 5 <= ttl_cap <= 10 or not 1 <= max_names <= 1024:
            raise ValueError("invalid connection evidence bounds")
        self.resolver, self.boundary = resolver, boundary
        self.cap, self.maximum, self.clock = ttl_cap, max_names, clock
        self._cache: dict[tuple[str, int, str], tuple[ResolutionEvidence, float]] = {}
        self._inflight: dict[tuple[str, int, str], asyncio.Task[ResolutionEvidence]] = {}
        self._closed = False

    async def _lookup(self, key: tuple[str, int, str]) -> ResolutionEvidence:
        name, authority_port, protocol = key
        result = await self.resolver.resolve(name, authority_port=authority_port, protocol=protocol)
        if (
            not result.complete
            or result.name != name
            or not math.isfinite(result.expires_at)
            or result.authentication not in ("secure", "insecure", "bogus", "indeterminate")
        ):
            raise RequestDenied("incomplete_membership")
        for address in result.direct_addresses:
            self.boundary.require_public(str(address))
        for endpoint in result.service_endpoints:
            if endpoint.service != name or not (
                1 <= endpoint.port <= 65535 and endpoint.authority_port == authority_port
            ):
                raise RequestDenied("invalid_service_evidence")
            dns_name(endpoint.target)
            self.boundary.require_public(str(endpoint.address))
        now = self.clock()
        if not self._closed and result.expires_at > now:
            self._cache[key] = (result, min(result.expires_at, now + self.cap))
        return result

    async def require(
        self,
        name: str,
        original: Address,
        original_port: int,
        authority_port: int,
        *,
        protocol: str,
    ) -> None:
        if self._closed:
            raise RequestDenied("connection_closed")
        name = canonical_host(name)
        if protocol not in ("http", "https") or not all(
            type(port) is int and 1 <= port <= 65535 for port in (original_port, authority_port)
        ):
            raise RequestDenied("invalid_membership_scope")
        key = (name, authority_port, protocol)
        self.boundary.require_public(str(original))
        now = self.clock()
        self._cache = {k: v for k, v in self._cache.items() if v[1] > now}
        cached = self._cache.get(key)
        if cached is not None:
            result = cached[0]
        else:
            task = self._inflight.get(key)
            if task is None:
                if len(set(self._cache) | set(self._inflight)) >= self.maximum:
                    raise RequestDenied("connection_evidence_capacity")
                task = asyncio.create_task(self._lookup(key))
                self._inflight[key] = task

                def finished(done: asyncio.Task[ResolutionEvidence]) -> None:
                    if self._inflight.get(key) is done:
                        del self._inflight[key]
                    # Consume detached exceptions if the last waiter was cancelled.
                    if not done.cancelled():
                        done.exception()

                task.add_done_callback(finished)
            result = await asyncio.shield(task)
        if self._closed:
            raise RequestDenied("connection_closed")
        if original_port == authority_port and original in result.direct_addresses:
            return
        if any(
            e.service == name
            and e.address == original
            and e.port == original_port
            and e.authority_port == authority_port
            for e in result.service_endpoints
        ):
            return
        raise RequestDenied("destination_not_member")

    async def close(self) -> None:
        self._closed = True
        tasks = tuple(self._inflight.values())
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self._inflight.clear()
        self._cache.clear()
