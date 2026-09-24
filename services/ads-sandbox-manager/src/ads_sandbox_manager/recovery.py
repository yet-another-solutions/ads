from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime, timedelta
from functools import partial
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ads_sandbox_manager.config import Settings
from ads_sandbox_manager.lifecycle import RECOVER, LifecycleService, Signal
from ads_sandbox_manager.lifecycle_store import CleanupWork
from ads_sandbox_manager.objects import Object
from ads_sandbox_manager.pair_store import PairClaimLost
from ads_sandbox_manager.session_objects import session_name
from ads_sandbox_manager.sessions import SessionProvisioner, TopicPreparation
from ads_sandbox_manager.store import SandboxSession, SessionPVC, SessionRepository, advance

log = logging.getLogger(__name__)


class RecoveryService:
    """Resume committed recovery intent without replaying Kafka or storing credentials."""

    def __init__(
        self,
        settings: Settings,
        sessions: async_sessionmaker[AsyncSession],
        repository: SessionRepository,
        lifecycle: LifecycleService,
        provisioner: SessionProvisioner,
        topics: TopicPreparation,
    ) -> None:
        self.settings, self.sessions, self.repository = settings, sessions, repository
        self.lifecycle, self.provisioner, self.topics = lifecycle, provisioner, topics
        self._task: asyncio.Task[None] | None = None

    async def _owned(self, db: AsyncSession, observed: SandboxSession) -> SandboxSession | None:
        row = await db.get(SandboxSession, observed.session_id, with_for_update=True)
        if row is None or (
            row.sandbox_id,
            row.status,
            row.status_changed_at,
        ) != (observed.sandbox_id, "recovering", observed.status_changed_at):
            return None
        return row

    async def _save(self, row: SandboxSession, work: CleanupWork, targets: list[Object]) -> bool:
        async with self.sessions.begin() as db:
            if await self._owned(db, row) is None:
                return False
            current = await db.get(CleanupWork, work.work_id)
            if current is None or current.kind != "recovery":
                return False
            current.targets = targets
        work.targets = targets
        return True

    async def execute(self, session_id: UUID) -> None:
        async with self.sessions.begin() as db:
            row = await db.get(SandboxSession, session_id)
            if row is None or row.status != "recovering":
                return
            works = list(
                await db.scalars(
                    select(CleanupWork)
                    .where(CleanupWork.session_id == session_id, CleanupWork.kind == "recovery")
                    .order_by(CleanupWork.state_changed)
                )
            )
        remaining = (
            row.status_changed_at
            + timedelta(seconds=self.settings.recovery_seconds)
            - datetime.now(UTC)
        ).total_seconds()
        try:
            if remaining <= 0:
                raise TimeoutError
            async with asyncio.timeout(remaining):
                await self._execute(row, works)
        except PairClaimLost:
            # Capture is read-only. Losing its claim must not fail a replacement
            # session or reinterpret stale evidence as a recovery verdict.
            log.warning("paired recovery capture claim lost; evidence retained")
        except Exception:
            # A failed executor leaves all targets/evidence intact. The next authenticated
            # signal rotates the boundary again; stale workers cannot fail the replacement.
            async with self.sessions.begin() as db:
                current = await self._owned(db, row)
                if current is None:
                    return
                current.status = "failed"
                current.status_changed_at = advance(current.status_changed_at, datetime.now(UTC))
            await self.lifecycle.emit(RECOVER, Signal(row.session_id, row.sandbox_id))
            log.warning("manager recovery failed; exact targets retained")

    async def _execute(self, row: SandboxSession, works: list[CleanupWork]) -> None:
        if not works:
            raise RuntimeError("recovery has no durable intent")
        if any(work.pair_snapshot is not None for work in works):
            for work in works:
                if work.pair_snapshot is not None:
                    if not await self.lifecycle.pair_capture.capture(work, recovery=row):
                        log.warning("paired recovery writers unresolved; evidence retained")
                        return
                    runtime = self.lifecycle.pair_runtime
                    if runtime is None or not await runtime.release(work, recovery=row):
                        log.warning("paired recovery requires runtime-release proof")
                        return
            # Do not delete control policies, storage or old-generation evidence
            # through the legacy guest/IPC-only recovery path.
            log.warning("paired recovery resource retirement pending: %s", row.session_id)
            return
        if any(obj.get("retain") for work in works for obj in work.targets):
            # Older versions converted idle timeouts into destructive recovery.
            # Do not silently turn their retained workspace into a delete target.
            log.error("recovery blocked by retained workspace intent: %s", row.session_id)
            return
        kube = self.lifecycle.kube
        for sandbox_id in {w.sandbox_id for w in works}:
            async with self.sessions.begin() as db:
                if await self._owned(db, row) is None:
                    return
            async with asyncio.timeout(self.settings.control_seconds):
                if not await self.topics.remove(sandbox_id):
                    return

        # Merge repeated captures of the same exact target. A prior idle/reap capture
        # can be the only evidence left after deletion. Never overwrite it with absence.
        evidence: dict[tuple[str, str, str | None], Object] = {}
        for work in works:
            for obj in work.targets:
                key = (obj["kind"], obj["name"], obj["uid"])
                if obj.get("captured") or obj.get("cleaned"):
                    evidence[key] = {**evidence.get(key, {}), **obj}
        for work in works:
            captured = []
            for obj in work.targets:
                obj = {
                    **obj,
                    **evidence.get((obj["kind"], obj["name"], obj["uid"]), {}),
                }
                if not obj.get("captured") and not obj.get("cleaned"):
                    if obj["uid"] is None:
                        observed = await kube.observe(obj)
                        if observed is None:
                            # No committed UID and no object: nothing known to reclaim.
                            # An in-flight stale create can appear later; orphan scans own it.
                            obj = {**obj, "cleaned": True}
                        else:
                            signal = self.lifecycle.object_signal(observed)
                            if signal is None or (signal.session_id, signal.sandbox_id) != (
                                row.session_id,
                                work.sandbox_id,
                            ):
                                raise RuntimeError("unbound cleanup object has foreign identity")
                            obj = {**obj, "uid": signal.uid}
                    if not obj.get("cleaned"):
                        obj = await kube.capture(obj)
                captured.append(obj)
            if not await self._save(row, work, captured):
                return

        # Stop all old compute before releasing dependent storage, across every carried
        # generation. Kubernetes foreground deletion and storage evidence remain mandatory.
        for kind in ("Deployment", "PersistentVolumeClaim"):
            compute_pending = False
            for work in works:
                for index, obj in enumerate(work.targets):
                    if obj["kind"] != kind or obj.get("cleaned"):
                        continue
                    async with self.sessions.begin() as db:
                        if await self._owned(db, row) is None:
                            return
                    observed = await kube.observe(obj)
                    if observed is None:
                        log.warning(
                            "recovery exact target missing: %s uid=%s", obj["name"], obj["uid"]
                        )
                    if kind == "PersistentVolumeClaim" and not await kube.released(obj):
                        return
                    await kube.delete(obj)
                    observed = await kube.observe(obj)
                    if observed is not None and observed["metadata"]["uid"] == obj["uid"]:
                        if kind == "Deployment":
                            compute_pending = True
                            continue
                        return
                    if (
                        kind == "PersistentVolumeClaim"
                        and not obj["name"].startswith("ads-sandbox-ipc-")
                        and not await kube.reclaimed(obj)
                    ):
                        return
                    targets = list(work.targets)
                    targets[index] = {**obj, "cleaned": True}
                    if not await self._save(row, work, targets):
                        return
            if compute_pending:
                return

        # Delete records only after proven reclamation. The fresh PVC and creating claim
        # commit together; ordinary requests never see stopped or claim this boundary.
        async with self.sessions.begin() as db:
            current = await self._owned(db, row)
            if current is None:
                return
            for pvc in await db.scalars(
                select(SessionPVC).where(SessionPVC.session_id == row.session_id).with_for_update()
            ):
                if not any(
                    obj["kind"] == "PersistentVolumeClaim"
                    and obj["name"] == session_name(pvc.pvc_id)
                    and (pvc.uid is None or obj["uid"] == pvc.uid)
                    and obj.get("cleaned")
                    for work in works
                    for obj in work.targets
                ):
                    raise RuntimeError("PVC record has no proven cleanup")
                await db.delete(pvc)
            for work in works:
                stored = await db.get(CleanupWork, work.work_id)
                if stored is not None:
                    await db.delete(stored)
            current.pvc_id = current.pvc_uid = None
            current.guest_deployment_uid = current.ipc_deployment_uid = current.ipc_pvc_uid = None
            current.ca_attempt = current.ca_sources = current.ca_clones = None
            current.status = "stopped"
            current.status_changed_at = advance(current.status_changed_at, datetime.now(UTC))
            await db.flush()
            claimed = await self.repository.claim(db, current, uuid4(), datetime.now(UTC))
            if claimed is None:
                raise RuntimeError("rebuild claim lost")
        # Crash here leaves creating, covered by the watchdog; never replay an execution.
        await self.provisioner.build(claimed, resume=False)

    async def run_once(self) -> None:
        async with self.sessions.begin() as db:
            ids = list(
                await db.scalars(
                    select(SandboxSession.session_id)
                    .where(SandboxSession.status == "recovering")
                    .order_by(SandboxSession.status_changed_at)
                    .limit(self.settings.lifecycle_batch)
                )
            )
        for session_id in ids:
            await self.lifecycle._locked(
                f"manager-recovery-{session_id}", partial(self.execute, session_id)
            )

    async def _run(self) -> None:
        while True:
            try:
                await self.run_once()
            except Exception:
                log.warning("manager recovery pass unavailable")
            await asyncio.sleep(self.settings.poll_seconds)

    async def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._run(), name="manager-recovery")

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
            self._task = None
