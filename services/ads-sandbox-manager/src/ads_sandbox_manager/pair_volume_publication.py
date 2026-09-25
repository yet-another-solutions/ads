"""Internal fresh workspace/CA publication under an existing creating claim."""

from __future__ import annotations

import asyncio
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ads_sandbox_manager.config import Settings
from ads_sandbox_manager.pair_store import PairClaimLost, PairIntent
from ads_sandbox_manager.pair_volume_inputs import VOLUME_ROLES, volume_manifest
from ads_sandbox_manager.pair_volume_kube import PairVolumeAdapter
from ads_sandbox_manager.pair_volume_store import PairVolumeRepository
from ads_sandbox_manager.store import SandboxSession, SessionPVC


class PairVolumePublication:
    def __init__(
        self,
        settings: Settings,
        sessions: async_sessionmaker[AsyncSession],
        repository: PairVolumeRepository,
        kube: PairVolumeAdapter,
    ) -> None:
        self.settings, self.sessions, self.repository, self.kube = (
            settings,
            sessions,
            repository,
            kube,
        )
        self._dispatches: set[asyncio.Task[str]] = set()

    def _configuration(self, intent: PairIntent) -> None:
        self.kube.configuration(intent)
        if (intent.namespace, intent.golden_version) != (
            self.settings.namespace,
            self.settings.golden_version,
        ):
            raise RuntimeError("paired clone publisher configuration changed")

    def _finished(self, task: asyncio.Task[str]) -> None:
        self._dispatches.discard(task)
        if not task.cancelled():
            task.exception()

    async def drain(self) -> None:
        if self._dispatches:
            async with asyncio.timeout(self.settings.control_seconds):
                await asyncio.wait(tuple(self._dispatches))

    async def _dispatch(self, intent: PairIntent, role: str) -> str:
        config = self.settings.session_objects
        assert config is not None
        self._configuration(intent)
        async with asyncio.timeout(config.create_seconds):
            uid = await self.kube.create(intent, role)
        async with asyncio.timeout(self.settings.control_seconds), self.sessions.begin() as db:
            self._configuration(intent)
            await self.repository.settle(db, intent, role)
        return uid

    async def prepare(self, row: SandboxSession, generation: UUID) -> PairIntent:
        config = self.settings.session_objects
        if config is None or row.claimed_by is None or row.pvc_id is None:
            raise PairClaimLost("configured fresh workspace claim required")
        owner = row.claimed_by
        async with asyncio.timeout(config.create_seconds):
            for role in VOLUME_ROLES:
                async with (
                    asyncio.timeout(self.settings.control_seconds),
                    self.sessions.begin() as db,
                ):
                    intent = await self.repository.pairs.owned(db, row, owner, generation)
                    self._configuration(intent)
                if role == "workspace" and intent.retained_from is not None:
                    retained_uid = await self.kube.observe_retained(intent)
                    async with (
                        asyncio.timeout(self.settings.control_seconds),
                        self.sessions.begin() as db,
                    ):
                        intent = await self.repository.pairs.owned(db, row, owner, generation)
                        if intent.volume_resources["workspace"]["uid"] != retained_uid:
                            raise PairClaimLost("retained workspace UID changed")
                    continue
                # Shared source services retain their own Job/PVC locks and release
                # checks. No session SQL transaction crosses their network work.
                sources = await self.kube.sources(role)
                async with (
                    asyncio.timeout(self.settings.control_seconds),
                    self.sessions.begin() as db,
                ):
                    intent = await self.repository.pairs.owned(db, row, owner, generation)
                    self._configuration(intent)
                    pvc = await db.get(SessionPVC, row.pvc_id, with_for_update=True)
                    if pvc is None:
                        raise PairClaimLost("workspace lifetime missing")
                    prior = intent.volume_resources[role]["payload"]
                    payload = {
                        "pvc_id": str(row.pvc_id),
                        "pvc_changed": prior["pvc_changed"]
                        if prior is not None
                        else pvc.last_state_change.isoformat(),
                        "sources": sources,
                    }
                    payload["manifest"] = volume_manifest(
                        self.settings, intent.binding(), role, payload
                    )
                    intent, dispatch = await self.repository.reserve(
                        db, row, owner, generation, role, payload
                    )
                if dispatch:
                    task = asyncio.create_task(
                        self._dispatch(intent, role), name="pair-clone-dispatch"
                    )
                    self._dispatches.add(task)
                    task.add_done_callback(self._finished)
                    await asyncio.wait((task,))
                    uid = task.result()
                else:
                    uid = None
                    while uid is None:
                        async with (
                            asyncio.timeout(self.settings.control_seconds),
                            self.sessions.begin() as db,
                        ):
                            intent, duplicate = await self.repository.reserve(
                                db, row, owner, generation, role, payload
                            )
                            self._configuration(intent)
                            if duplicate:
                                raise RuntimeError("paired clone reservation disappeared")
                        uid = await self.kube.observe(intent, role)
                        if uid is None:
                            await asyncio.sleep(0.05)
                assert uid is not None
                async with (
                    asyncio.timeout(self.settings.control_seconds),
                    self.sessions.begin() as db,
                ):
                    self._configuration(intent)
                    intent = await self.repository.bind(db, row, owner, generation, role, uid)
            return intent
