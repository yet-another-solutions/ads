from __future__ import annotations

import asyncio
import math
from dataclasses import dataclass
from typing import Protocol
from uuid import UUID, uuid4

import msgspec

from ads_commons.egress import (
    EgressApplied,
    EgressApply,
    EgressPing,
    ProjectEgressSnapshot,
    canonical_settings,
)
from ads_commons.security import AccessDenied, SecurityContextHolder, ensure_caller


@dataclass(frozen=True, slots=True)
class PairIdentity:
    """Trusted immutable deployment inputs, never taken from sandbox traffic."""

    project_id: UUID
    sandbox_id: UUID
    ipc_service_subject: UUID
    health_timeout_seconds: float = 2

    def __post_init__(self) -> None:
        if not all(
            isinstance(value, UUID)
            for value in (self.project_id, self.sandbox_id, self.ipc_service_subject)
        ):
            raise ValueError("pair identity requires UUIDs")
        if not math.isfinite(self.health_timeout_seconds) or self.health_timeout_seconds <= 0:
            raise ValueError("health timeout must be finite and positive")


class LocalHealth(Protocol):
    """Runtime must prove local enforcement/helper responsiveness, not Internet reachability."""

    async def healthy(self) -> bool: ...


class StaleConfiguration(Exception):
    def __init__(self, received: int, applied: int) -> None:
        super().__init__("stale revision")
        self.received, self.applied = received, applied


class RevisionConflict(Exception):
    pass


class ConfigurationUnavailable(Exception):
    pass


class PolicyStore:
    """One atomic immutable snapshot reference shared by control and enforcement.

    New processes start with None, meaning unconfigured/deny-all. Request handlers
    capture the reference once; replacing it cannot mutate an active exchange.
    The boot UUID and settings are process state, not durable DNSSEC/ECH identity.
    """

    def __init__(self) -> None:
        self.instance_id = uuid4()
        self._snapshot: ProjectEgressSnapshot | None = None
        self._lock = asyncio.Lock()
        self.accepting = True

    def capture(self) -> ProjectEgressSnapshot | None:
        return self._snapshot

    async def install(self, snapshot: ProjectEgressSnapshot) -> EgressApplied:
        # Canonicalization is structural only, never ruleset lint or target-rule synthesis.
        snapshot = msgspec.json.decode(msgspec.json.encode(snapshot), type=ProjectEgressSnapshot)
        canonical = ProjectEgressSnapshot(snapshot.revision, canonical_settings(snapshot.settings))
        async with self._lock:
            if not self.accepting:
                raise ConfigurationUnavailable()
            previous = self._snapshot
            if previous is not None:
                if canonical.revision < previous.revision:
                    raise StaleConfiguration(canonical.revision, previous.revision)
                if canonical.revision == previous.revision:
                    if canonical.settings != previous.settings:
                        raise RevisionConflict()
                    return EgressApplied(self.instance_id, previous.revision)
            # No await, external side effect or incremental mutation inside this swap.
            self._snapshot = canonical
            return EgressApplied(self.instance_id, canonical.revision)

    async def close(self) -> None:
        async with self._lock:
            self.accepting = False


class ConfigurationService:
    def __init__(self, pair: PairIdentity, store: PolicyStore, health: LocalHealth) -> None:
        self.pair, self.store, self.health = pair, store, health

    async def apply(self, body: EgressApply) -> EgressApplied:
        context = SecurityContextHolder.require()
        ensure_caller(context, "ads-sandbox-ipc")
        if context.user_id != self.pair.ipc_service_subject:
            raise AccessDenied("expected IPC service identity")
        if body.project_id != self.pair.project_id:
            raise AccessDenied("paired project mismatch")
        return await self.store.install(body.snapshot)

    async def ping(self) -> EgressPing:
        healthy = False
        if self.store.accepting:
            try:
                async with asyncio.timeout(self.pair.health_timeout_seconds):
                    healthy = await self.health.healthy()
            except asyncio.CancelledError:
                raise
            except Exception:
                healthy = False
        return EgressPing(self.store.instance_id, healthy and self.store.accepting)
