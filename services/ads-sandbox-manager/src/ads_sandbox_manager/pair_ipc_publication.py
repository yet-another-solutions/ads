"""Internal one-shot paired IPC publication, without a ready transition."""

from __future__ import annotations

import asyncio
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ads_sandbox_manager.config import Settings
from ads_sandbox_manager.pair_ipc_inputs import IPC_ROLES, ipc_manifest
from ads_sandbox_manager.pair_ipc_kube import PairIpcAdapter
from ads_sandbox_manager.pair_ipc_store import PairIpcRepository
from ads_sandbox_manager.pair_store import PairClaimLost, PairIntent
from ads_sandbox_manager.store import SandboxSession


class PairIpcPublication:
    def __init__(
        self,
        settings: Settings,
        sessions: async_sessionmaker[AsyncSession],
        repository: PairIpcRepository,
        kube: PairIpcAdapter,
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
            raise RuntimeError("paired IPC publisher configuration changed")

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

    async def prepare(
        self, row: SandboxSession, generation: UUID, ads_service_subject: UUID
    ) -> PairIntent:
        config = self.settings.session_objects
        if config is None or row.claimed_by is None:
            raise PairClaimLost("a configured provisioning claim is required")
        if not isinstance(ads_service_subject, UUID):
            raise ValueError("trusted ADS native service subject required")
        owner = row.claimed_by
        async with asyncio.timeout(config.create_seconds):
            for role in IPC_ROLES:
                async with (
                    asyncio.timeout(self.settings.control_seconds),
                    self.sessions.begin() as db,
                ):
                    intent = await self.repository.pairs.owned(db, row, owner, generation)
                    self._configuration(intent)
                    payload = self.repository.dependencies(intent)
                    if role == "deployment":
                        payload["volume_uid"] = intent.ipc_resources["volume"]["uid"]
                        payload["ads_service_subject"] = str(ads_service_subject)
                    payload["manifest"] = ipc_manifest(
                        self.settings, intent.binding(), role, payload
                    )
                    intent, dispatch = await self.repository.reserve(
                        db, row, owner, generation, role, payload
                    )
                if dispatch:
                    task = asyncio.create_task(
                        self._dispatch(intent, role), name="pair-ipc-dispatch"
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
                                raise RuntimeError("paired IPC reservation disappeared")
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
