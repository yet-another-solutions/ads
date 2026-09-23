"""One-shot stateful egress Pod publication, not readiness or runtime bootstrap."""

from __future__ import annotations

import asyncio
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ads_sandbox_manager.config import Settings
from ads_sandbox_manager.egress_compute import EgressRuntime
from ads_sandbox_manager.egress_compute_inputs import egress_payload
from ads_sandbox_manager.egress_state_store import EgressStateRepository
from ads_sandbox_manager.pair_compute_inputs import compute_manifest
from ads_sandbox_manager.pair_compute_kube import PairComputeAdapter
from ads_sandbox_manager.pair_compute_publication import PairComputePublication
from ads_sandbox_manager.pair_store import PairClaimLost, PairIntent, PairIntentRepository
from ads_sandbox_manager.store import SandboxSession


class EgressComputePublication:
    def __init__(
        self,
        settings: Settings,
        sessions: async_sessionmaker[AsyncSession],
        repository: PairIntentRepository,
        kube: PairComputeAdapter,
    ) -> None:
        self.settings, self.sessions, self.repository, self.kube = (
            settings,
            sessions,
            repository,
            kube,
        )
        self.states = EgressStateRepository(repository)
        self.writes = PairComputePublication(settings, sessions, repository, kube)

    async def drain(self) -> None:
        await self.writes.drain()

    async def prepare(
        self, row: SandboxSession, generation: UUID, runtime: EgressRuntime
    ) -> PairIntent:
        config = self.settings.session_objects
        if config is None or row.claimed_by is None:
            raise PairClaimLost("a configured provisioning claim is required")
        owner = row.claimed_by
        async with asyncio.timeout(config.create_seconds):
            async with asyncio.timeout(self.settings.control_seconds), self.sessions.begin() as db:
                intent = await self.repository.owned(db, row, owner, generation)
                self.writes._configuration(intent)
                if intent.egress_state_id is None:
                    raise PairClaimLost("committed egress state anchor required")
                state = await self.states.owned(db, row, owner, generation, intent.egress_state_id)
                current = await db.get(SandboxSession, row.session_id)
                assert current is not None
                payload = egress_payload(current, state, runtime)
                payload["control_uids"] = dict(intent.control_uids)
                payload["manifest"] = compute_manifest(
                    self.settings, intent.binding(), "egress", payload
                )
                intent, dispatch = await self.repository.reserve_compute(
                    db, row, owner, generation, "egress", payload
                )
            if dispatch:
                uid = await self.writes.dispatch_reserved(intent, "egress")
            else:
                uid = None
                while uid is None:
                    async with (
                        asyncio.timeout(self.settings.control_seconds),
                        self.sessions.begin() as db,
                    ):
                        intent = await self.repository.owned(db, row, owner, generation)
                        self.writes._configuration(intent)
                        # Revalidate SQL ownership/dependencies even while an old
                        # original invocation has not made its write observable.
                        intent, duplicate = await self.repository.reserve_compute(
                            db, row, owner, generation, "egress", payload
                        )
                        if duplicate:
                            raise RuntimeError("egress reservation disappeared")
                    uid = await self.kube.observe(
                        intent.binding(),
                        "egress",
                        payload,
                        intent.control_uids,
                        intent.compute_uids["Pod/egress"],
                    )
                    if uid is None:
                        await asyncio.sleep(0.05)
            assert uid is not None
            async with asyncio.timeout(self.settings.control_seconds), self.sessions.begin() as db:
                self.writes._configuration(intent)
                return await self.repository.bind_compute(db, row, owner, generation, "egress", uid)
