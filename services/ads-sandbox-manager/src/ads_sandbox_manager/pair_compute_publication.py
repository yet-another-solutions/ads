"""Internal publication of implemented compute members, never pair readiness."""

from __future__ import annotations

import asyncio
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ads_sandbox_manager.config import Settings
from ads_sandbox_manager.pair_compute import PrivateGuestRuntime, RelayRuntime
from ads_sandbox_manager.pair_compute_inputs import (
    PUBLISHED_COMPUTE_ROLES,
    compute_manifest,
    guest_payload,
    relay_payload,
)
from ads_sandbox_manager.pair_compute_kube import PairComputeAdapter
from ads_sandbox_manager.pair_store import PairClaimLost, PairIntent, PairIntentRepository
from ads_sandbox_manager.store import SandboxSession


class PairComputePublication:
    def __init__(
        self,
        settings: Settings,
        sessions: async_sessionmaker[AsyncSession],
        repository: PairIntentRepository,
        kube: PairComputeAdapter,
    ) -> None:
        self.settings, self.sessions = settings, sessions
        self.repository, self.kube = repository, kube
        self._dispatches: set[asyncio.Task[str]] = set()

    def _configuration(self, intent: PairIntent) -> None:
        wanted = (self.settings.namespace, self.settings.golden_version)
        if (intent.namespace, intent.golden_version) != wanted or (
            self.kube.namespace,
            self.kube.golden_version,
        ) != wanted:
            raise RuntimeError("pair compute configuration changed")

    def _finished(self, task: asyncio.Task[str]) -> None:
        self._dispatches.discard(task)
        if not task.cancelled():
            task.exception()

    async def _dispatch(self, intent: PairIntent, role: str) -> str:
        self._configuration(intent)
        # Egress also repeats custody, two CA clones and all controls after the
        # Pod observation. Every SDK call retains its own timeout.
        calls = 45 if role == "egress" else 24
        async with asyncio.timeout(calls * self.settings.control_seconds):
            uid = await self.kube.create(
                intent.binding(), role, intent.compute_payloads[role], intent.control_uids
            )
        async with asyncio.timeout(self.settings.control_seconds), self.sessions.begin() as db:
            self._configuration(intent)
            await self.repository.settle_compute(db, intent, role)
        return uid

    async def drain(self) -> None:
        if self._dispatches:
            async with asyncio.timeout(self.settings.control_seconds):
                await asyncio.wait(tuple(self._dispatches))

    async def dispatch_reserved(self, intent: PairIntent, role: str) -> str:
        """Only the caller holding the just-committed sole reservation calls this."""
        if (
            intent.compute_dispatch[f"Pod/{role}"] != "inflight"
            or intent.compute_uids[f"Pod/{role}"]
        ):
            raise RuntimeError("original unbound compute reservation required")
        operation = asyncio.create_task(self._dispatch(intent, role), name="pair-compute-dispatch")
        self._dispatches.add(operation)
        operation.add_done_callback(self._finished)
        await asyncio.wait((operation,))
        return operation.result()

    async def prepare(
        self,
        row: SandboxSession,
        generation: UUID,
        guest: PrivateGuestRuntime,
        relay: RelayRuntime,
    ) -> PairIntent:
        config = self.settings.session_objects
        if config is None or row.claimed_by is None:
            raise PairClaimLost("a configured provisioning claim is required")
        if guest.transport_mtu != relay.transport_mtu:
            raise ValueError("guest and relay transport MTU must match")
        owner = row.claimed_by
        async with asyncio.timeout(config.create_seconds):
            for role in PUBLISHED_COMPUTE_ROLES:
                async with (
                    asyncio.timeout(self.settings.control_seconds),
                    self.sessions.begin() as db,
                ):
                    intent = await self.repository.owned(db, row, owner, generation)
                    self._configuration(intent)
                    current = await db.get(SandboxSession, row.session_id)
                    assert current is not None
                    payload = (
                        guest_payload(current, guest) if role == "guest" else relay_payload(relay)
                    )
                    payload["control_uids"] = dict(intent.control_uids)
                    payload["manifest"] = compute_manifest(
                        self.settings, intent.binding(), role, payload
                    )
                    intent, dispatch = await self.repository.reserve_compute(
                        db, row, owner, generation, role, payload
                    )
                if dispatch:
                    uid = await self.dispatch_reserved(intent, role)
                else:
                    uid = None
                    while uid is None:
                        async with (
                            asyncio.timeout(self.settings.control_seconds),
                            self.sessions.begin() as db,
                        ):
                            intent = await self.repository.owned(db, row, owner, generation)
                            self._configuration(intent)
                        uid = await self.kube.observe(
                            intent.binding(),
                            role,
                            payload,
                            intent.control_uids,
                            intent.compute_uids[f"Pod/{role}"],
                        )
                        if uid is None:
                            await asyncio.sleep(0.05)
                assert uid is not None
                async with (
                    asyncio.timeout(self.settings.control_seconds),
                    self.sessions.begin() as db,
                ):
                    self._configuration(intent)
                    intent = await self.repository.bind_compute(
                        db, row, owner, generation, role, uid
                    )
            return intent
