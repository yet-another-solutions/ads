"""Read-only pair ownership capture under the existing claim, not retirement."""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Protocol, cast

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ads_sandbox_manager.config import Settings
from ads_sandbox_manager.lifecycle_store import CleanupWork, LifecycleRepository
from ads_sandbox_manager.pair_ipc_inputs import IPC_ROLES
from ads_sandbox_manager.pair_ipc_store import PairIpcRepository
from ads_sandbox_manager.pair_kube import ControlKind
from ads_sandbox_manager.pair_objects import PairBinding
from ads_sandbox_manager.pair_store import (
    COMPUTE_ROLES,
    CONTROL_RESOURCES,
    PairIntent,
    PairIntentRepository,
    compute_key,
    resource_key,
)
from ads_sandbox_manager.pair_volume_inputs import VOLUME_ROLES, volume_manifest
from ads_sandbox_manager.pair_volume_store import PairVolumeRepository
from ads_sandbox_manager.relay_inputs import INPUT_ROLES
from ads_sandbox_manager.session_objects import ipc_name
from ads_sandbox_manager.store import SandboxSession

log = logging.getLogger(__name__)


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
    async def observe_relay_custody(self, pair: PairBinding, uid: str | None) -> str | None: ...
    async def observe_relay_input(
        self, pair: PairBinding, role: str, uid: str | None
    ) -> str | None: ...
    async def observe_egress_state(
        self, snapshot: dict[str, object], role: str, uid: str | None
    ) -> str | None: ...
    async def observe_ipc(self, pair: PairBinding, role: str, uid: str | None) -> str | None: ...
    async def observe_clone(
        self, pair: PairBinding, role: str, payload: dict[str, object], uid: str | None
    ) -> str | None: ...
    async def release_evidence(self, name: str, uid: str | None) -> dict[str, object] | None: ...
    async def delete(self, pair: PairBinding, kind: ControlKind, role: str, uid: str) -> bool: ...
    async def dispose_secret(
        self,
        pair: PairBinding,
        key: str,
        uid: str,
        *,
        persistent: dict[str, object] | None = None,
        retain: bool = False,
    ) -> bool: ...


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
        pairs = PairIntentRepository()
        self.volumes = PairVolumeRepository(pairs)
        self.ipcs = PairIpcRepository(pairs)

    def _configuration(self, work: CleanupWork) -> None:
        assert work.pair_snapshot is not None
        wanted = (self.settings.namespace, self.settings.golden_version)
        if (self.kube.namespace, self.kube.golden_version) != wanted or (
            work.pair_snapshot["namespace"],
            work.pair_snapshot["golden_version"],
        ) != wanted:
            raise RuntimeError("pair cleanup builder configuration changed")

    async def capture_ready(self, row: SandboxSession) -> None:
        """Persist release evidence for one live ready pair under its owner.

        Read-only kube reads plus fenced first-wins writes. A changed claim
        loses its fence and leaves stored evidence untouched. Missing evidence
        for a live claim stays missing (fail closed) and is retried next pass.
        """
        async with (
            asyncio.timeout(self.settings.control_seconds),
            self.sessions.begin() as db,
        ):
            current = await db.get(SandboxSession, row.session_id)
            if current is None or current.status != "ready" or current.claimed_by is None:
                return
            owner = current.claimed_by
            generation = await db.scalar(
                select(PairIntent.generation)
                .where(PairIntent.session_id == row.session_id)
                .where(PairIntent.retired_at.is_(None))
            )
        if generation is None:
            return
        pairs = PairIntentRepository()
        for role in VOLUME_ROLES:
            async with (
                asyncio.timeout(self.settings.control_seconds),
                self.sessions.begin() as db,
            ):
                intent = await pairs.owned(db, row, owner, generation)
                entry = intent.volume_resources[role]
                if entry["dispatch"] == "unissued" or not entry["uid"]:
                    continue
                if entry.get("release") is not None:
                    continue
                desired = volume_manifest(self.settings, intent.binding(), role, entry["payload"])
                evidence = await self.kube.release_evidence(
                    desired["metadata"]["name"], entry["uid"]
                )
                if evidence is None:
                    log.warning(
                        "paired clone release evidence unavailable: %s %s",
                        desired["metadata"]["name"],
                        row.sandbox_id,
                    )
                    continue
                await self.volumes.record_release(db, row, owner, generation, role, evidence)
        for role in IPC_ROLES:
            async with (
                asyncio.timeout(self.settings.control_seconds),
                self.sessions.begin() as db,
            ):
                intent = await pairs.owned(db, row, owner, generation)
                entry = intent.ipc_resources[role]
                if role != "volume" or entry["dispatch"] == "unissued" or not entry["uid"]:
                    continue
                if entry.get("release") is not None:
                    continue
                evidence = await self.kube.release_evidence(ipc_name(row.sandbox_id), entry["uid"])
                if evidence is None:
                    log.warning(
                        "paired IPC volume release evidence unavailable: %s",
                        row.sandbox_id,
                    )
                    continue
                await self.ipcs.record_release(db, row, owner, generation, role, evidence)

    async def capture(self, work: CleanupWork, *, recovery: SandboxSession | None = None) -> bool:
        async with asyncio.timeout(self.settings.cleanup_seconds):
            for role in VOLUME_ROLES:
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
                entry = work.pair_snapshot["volume_resources"][role]
                if entry["dispatch"] == "unissued":
                    continue
                uid = await self.kube.observe_clone(pair, role, entry["payload"], entry["uid"])
                release = None
                if uid is not None:
                    desired = volume_manifest(self.settings, pair, role, entry["payload"])
                    release = await self.kube.release_evidence(desired["metadata"]["name"], uid)
                async with (
                    asyncio.timeout(self.settings.control_seconds),
                    self.sessions.begin() as db,
                ):
                    work = await self.repository.record_clone(
                        db,
                        work,
                        role,
                        uid,
                        datetime.now(UTC),
                        recovery=recovery,
                        recovery_seconds=self.settings.recovery_seconds,
                    )
                    work = await self.repository.record_pair_release(
                        db,
                        work,
                        "volume_resources",
                        role,
                        release,
                        datetime.now(UTC),
                        recovery=recovery,
                        recovery_seconds=self.settings.recovery_seconds,
                    )
            for role in IPC_ROLES:
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
                entry = work.pair_snapshot["ipc_resources"][role]
                if entry["dispatch"] == "unissued":
                    continue
                uid = await self.kube.observe_ipc(pair, role, entry["uid"])
                release = None
                if role == "volume" and uid is not None:
                    release = await self.kube.release_evidence(ipc_name(pair.sandbox_id), uid)
                async with (
                    asyncio.timeout(self.settings.control_seconds),
                    self.sessions.begin() as db,
                ):
                    work = await self.repository.record_ipc_resource(
                        db,
                        work,
                        role,
                        uid,
                        datetime.now(UTC),
                        recovery=recovery,
                        recovery_seconds=self.settings.recovery_seconds,
                    )
                    work = await self.repository.record_pair_release(
                        db,
                        work,
                        "ipc_resources",
                        role,
                        release,
                        datetime.now(UTC),
                        recovery=recovery,
                        recovery_seconds=self.settings.recovery_seconds,
                    )
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
            assert work.pair_snapshot is not None
            if work.pair_snapshot["relay_custody"]["public_keys"] is not None:
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
                uid = await self.kube.observe_relay_custody(
                    pair, work.pair_snapshot["relay_custody"]["uid"]
                )
                async with (
                    asyncio.timeout(self.settings.control_seconds),
                    self.sessions.begin() as db,
                ):
                    self._configuration(work)
                    work = await self.repository.record_relay_custody(
                        db,
                        work,
                        uid,
                        datetime.now(UTC),
                        recovery=recovery,
                        recovery_seconds=self.settings.recovery_seconds,
                    )
            for role in INPUT_ROLES:
                assert work.pair_snapshot is not None
                if work.pair_snapshot["relay_inputs"][role]["payload"] is None:
                    continue
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
                uid = await self.kube.observe_relay_input(
                    pair, role, work.pair_snapshot["relay_inputs"][role]["uid"]
                )
                async with (
                    asyncio.timeout(self.settings.control_seconds),
                    self.sessions.begin() as db,
                ):
                    self._configuration(work)
                    work = await self.repository.record_relay_input(
                        db,
                        work,
                        role,
                        uid,
                        datetime.now(UTC),
                        recovery=recovery,
                        recovery_seconds=self.settings.recovery_seconds,
                    )
            for role in ("key", "volume"):
                assert work.pair_snapshot is not None
                persistent = work.pair_snapshot["egress_state"]
                if persistent is None or persistent[f"{role}_dispatch"] == "unissued":
                    continue
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
                assert work.pair_snapshot is not None
                persistent = work.pair_snapshot["egress_state"]
                assert persistent is not None
                uid = await self.kube.observe_egress_state(
                    persistent, role, persistent[f"{role}_uid"]
                )
                release = None
                if role == "volume" and uid is not None:
                    release = await self.kube.release_evidence(
                        f"ads-egress-volume-{persistent['state_id']}", uid
                    )
                async with (
                    asyncio.timeout(self.settings.control_seconds),
                    self.sessions.begin() as db,
                ):
                    self._configuration(work)
                    work = await self.repository.record_egress_state(
                        db,
                        work,
                        role,
                        uid,
                        datetime.now(UTC),
                        recovery=recovery,
                        recovery_seconds=self.settings.recovery_seconds,
                    )
                    if role == "volume" and release is not None:
                        await self.repository.record_state_release(
                            db,
                            work,
                            release,
                            datetime.now(UTC),
                            recovery=recovery,
                            recovery_seconds=self.settings.recovery_seconds,
                        )
            async with (
                asyncio.timeout(self.settings.control_seconds),
                self.sessions.begin() as db,
            ):
                self._configuration(work)
                return await self.repository.seal_pair_cleanup(
                    db,
                    work,
                    datetime.now(UTC),
                    recovery=recovery,
                    recovery_seconds=self.settings.recovery_seconds,
                )
