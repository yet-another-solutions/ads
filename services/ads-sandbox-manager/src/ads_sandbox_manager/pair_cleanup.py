"""Read-only pair ownership capture under the existing claim, not retirement."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Protocol, cast

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ads_sandbox_manager.config import Settings
from ads_sandbox_manager.lifecycle_store import CleanupWork, LifecycleRepository
from ads_sandbox_manager.pair_kube import ControlKind
from ads_sandbox_manager.pair_objects import PairBinding
from ads_sandbox_manager.pair_store import (
    COMPUTE_ROLES,
    CONTROL_RESOURCES,
    compute_key,
    resource_key,
)
from ads_sandbox_manager.store import SandboxSession


class PairCleanupKubernetes(Protocol):
    @property
    def namespace(self) -> str: ...
    @property
    def golden_version(self) -> str: ...
    async def observe(
        self, pair: PairBinding, kind: ControlKind, role: str, uid: str | None = None
    ) -> str | None: ...
    async def observe_compute(
        self, pair: PairBinding, role: str, uid: str | None = None
    ) -> str | None: ...


class PairCleanupCapture:
    """No creates, deletes, node calls or completion verdict.

    Known UIDs are never forgotten after absence. Unknown UIDs stay unknown
    until observed; they never become an absence bit that would hide a late
    create. Each successful capture commits before the next external read.
    """

    def __init__(
        self,
        settings: Settings,
        sessions: async_sessionmaker[AsyncSession],
        repository: LifecycleRepository,
        kube: PairCleanupKubernetes,
    ) -> None:
        self.settings, self.sessions = settings, sessions
        self.repository, self.kube = repository, kube

    def _configuration(self, work: CleanupWork) -> None:
        assert work.pair_snapshot is not None
        wanted = (self.settings.namespace, self.settings.golden_version)
        if (self.kube.namespace, self.kube.golden_version) != wanted or (
            work.pair_snapshot["namespace"],
            work.pair_snapshot["golden_version"],
        ) != wanted:
            raise RuntimeError("pair cleanup builder configuration changed")

    async def capture(self, work: CleanupWork, *, recovery: SandboxSession | None = None) -> None:
        async with asyncio.timeout(self.settings.cleanup_seconds):
            for kind, role in (*CONTROL_RESOURCES, *(("Pod", role) for role in COMPUTE_ROLES)):
                async with (
                    asyncio.timeout(self.settings.control_seconds),
                    self.sessions.begin() as db,
                ):
                    work = await self.repository.owned_pair_cleanup(
                        db,
                        work,
                        datetime.now(UTC),
                        recovery=recovery,
                        recovery_seconds=self.settings.recovery_seconds,
                    )
                    self._configuration(work)
                    await self.repository.fence_pair_creators(db, work)
                    pair = self.repository.cleanup_pair(work)
                assert work.pair_snapshot is not None
                if kind == "Pod":
                    uid = await self.kube.observe_compute(
                        pair, role, work.pair_snapshot["compute_uids"][compute_key(role)]
                    )
                else:
                    uid = await self.kube.observe(
                        pair,
                        cast(ControlKind, kind),
                        role,
                        work.pair_snapshot["control_uids"][resource_key(kind, role)],
                    )
                async with (
                    asyncio.timeout(self.settings.control_seconds),
                    self.sessions.begin() as db,
                ):
                    self._configuration(work)
                    if kind == "Pod":
                        work = await self.repository.record_pair_compute(
                            db,
                            work,
                            role,
                            uid,
                            datetime.now(UTC),
                            recovery=recovery,
                            recovery_seconds=self.settings.recovery_seconds,
                        )
                    else:
                        work = await self.repository.record_pair_control(
                            db,
                            work,
                            kind,
                            role,
                            uid,
                            datetime.now(UTC),
                            recovery=recovery,
                            recovery_seconds=self.settings.recovery_seconds,
                        )
