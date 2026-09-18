from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import DateTime, ForeignKey, delete, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column

from ads_sandbox_manager.session_objects import ipc_name, session_name
from ads_sandbox_manager.store import Base, PingProbe, SandboxSession, SessionPVC, advance


class CleanupWork(Base):
    """Restart-safe intent and captured targets. Never contains JWTs or execution data."""

    __tablename__ = "cleanup_work"

    work_id: Mapped[UUID] = mapped_column(primary_key=True)
    session_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("sandbox_session.session_id", ondelete="CASCADE"), index=True
    )
    sandbox_id: Mapped[UUID]
    pvc_id: Mapped[UUID | None]
    kind: Mapped[str]
    state_changed: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    pvc_changed: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deadline: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    acknowledged: Mapped[bool] = mapped_column(default=False)
    targets: Mapped[list[dict[str, Any]]] = mapped_column(JSONB)


def target(kind: str, name: str, uid: str | None, *, retain: bool = False) -> dict[str, Any]:
    return {"kind": kind, "name": name, "uid": uid, "retain": retain}


def sandbox_targets(row: SandboxSession, *, retain: bool) -> list[dict[str, Any]]:
    objects = [
        target("Deployment", ipc_name(row.sandbox_id), row.ipc_deployment_uid),
        target("PersistentVolumeClaim", ipc_name(row.sandbox_id), row.ipc_pvc_uid),
        target("Deployment", session_name(row.sandbox_id), row.guest_deployment_uid),
    ]
    if row.pvc_id:
        objects.append(
            target("PersistentVolumeClaim", session_name(row.pvc_id), row.pvc_uid, retain=retain)
        )
    return objects


class LifecycleRepository:
    """All joint mutations lock sandbox then its PVC. External work follows commit."""

    async def locked(
        self,
        db: AsyncSession,
        session_id: UUID,
        sandbox_id: UUID,
    ) -> tuple[SandboxSession | None, SessionPVC | None]:
        row = await db.get(SandboxSession, session_id, with_for_update=True)
        if row is None or row.sandbox_id != sandbox_id:
            return None, None
        pvc = await db.get(SessionPVC, row.pvc_id, with_for_update=True) if row.pvc_id else None
        return row, pvc

    def work(
        self,
        db: AsyncSession,
        row: SandboxSession,
        pvc: SessionPVC | None,
        kind: str,
        now: datetime,
        timeout: float,
        targets: list[dict[str, Any]],
    ) -> CleanupWork:
        work = CleanupWork(
            work_id=uuid4(),
            session_id=row.session_id,
            sandbox_id=row.sandbox_id,
            pvc_id=pvc.pvc_id if pvc else None,
            kind=kind,
            state_changed=row.status_changed_at,
            pvc_changed=pvc.last_state_change if pvc else None,
            deadline=now + timedelta(seconds=timeout),
            targets=targets,
            acknowledged=False,
        )
        db.add(work)
        return work

    async def idle(
        self,
        db: AsyncSession,
        session_id: UUID,
        sandbox_id: UUID,
        now: datetime,
        inactivity: float,
        timeout: float,
    ) -> CleanupWork | None:
        row, pvc = await self.locked(db, session_id, sandbox_id)
        cutoff = now - timedelta(seconds=inactivity)
        if (
            row is None
            or row.status != "ready"
            or row.last_execution_at > cutoff
            or pvc is None
            or pvc.state != "attached"
            or pvc.last_execution > cutoff
        ):
            return None
        row.status = "shutting_down"
        row.status_changed_at = advance(row.status_changed_at, now)
        pvc.state = "detaching"
        pvc.last_state_change = advance(pvc.last_state_change, now)
        return self.work(db, row, pvc, "idle", now, timeout, sandbox_targets(row, retain=True))

    async def reap(
        self,
        db: AsyncSession,
        session_id: UUID,
        sandbox_id: UUID,
        pvc_id: UUID,
        now: datetime,
        inactivity: float,
        detached: float,
        timeout: float,
    ) -> CleanupWork | None:
        row, pvc = await self.locked(db, session_id, sandbox_id)
        if (
            row is None
            or row.status != "stopped"
            or pvc is None
            or pvc.pvc_id != pvc_id
            or pvc.state != "detached"
            or pvc.last_execution > now - timedelta(seconds=inactivity)
            or row.last_execution_at > now - timedelta(seconds=inactivity)
            or pvc.last_state_change > now - timedelta(seconds=detached)
        ):
            return None
        pvc.state = "destroying"
        pvc.last_state_change = advance(pvc.last_state_change, now)
        return self.work(
            db,
            row,
            pvc,
            "reap",
            now,
            timeout,
            [
                {
                    **(pvc.release_evidence or {}),
                    **target("PersistentVolumeClaim", session_name(pvc_id), pvc.uid),
                }
            ],
        )

    async def service(
        self,
        db: AsyncSession,
        session_id: UUID,
        sandbox_id: UUID,
        now: datetime,
        timeout: float,
        targets: list[dict[str, Any]],
    ) -> CleanupWork | None:
        row, pvc = await self.locked(db, session_id, sandbox_id)
        if row is None or row.status != "stopped" or (pvc is not None and pvc.state != "detached"):
            return None
        row.status = "service"
        row.status_changed_at = advance(row.status_changed_at, now)
        row.service_deadline = now + timedelta(seconds=timeout)
        return self.work(db, row, pvc, "service", now, timeout, targets)

    async def owns(self, db: AsyncSession, work: CleanupWork) -> bool:
        if work.kind == "orphan":
            return True  # Each exact object is independently revalidated before deletion.
        if work.session_id is None:
            return False
        row, pvc = await self.locked(db, work.session_id, work.sandbox_id)
        state = {"idle": "shutting_down", "reap": "stopped", "service": "service"}.get(work.kind)
        return (
            row is not None
            and row.status == state
            and row.status_changed_at == work.state_changed
            and row.pvc_id == work.pvc_id
            and (
                (pvc is None and work.pvc_id is None)
                or (
                    pvc is not None
                    and pvc.last_state_change == work.pvc_changed
                    and pvc.state
                    == {"idle": "detaching", "reap": "destroying", "service": "detached"}[work.kind]
                )
            )
        )

    async def complete(self, db: AsyncSession, work: CleanupWork, now: datetime) -> bool:
        if not await self.owns(db, work):
            return False
        if work.session_id is not None:
            row, pvc = await self.locked(db, work.session_id, work.sandbox_id)
            assert row is not None
            if work.kind == "reap":
                assert pvc is not None
                row.pvc_id = None
                row.pvc_uid = None
                await db.delete(pvc)
            else:
                row.status = "stopped"
                row.status_changed_at = advance(row.status_changed_at, now)
                row.service_deadline = None
                row.guest_deployment_uid = row.ipc_deployment_uid = row.ipc_pvc_uid = None
                if work.kind == "idle":
                    assert pvc is not None
                    pvc.state = "detached"
                    pvc.last_state_change = advance(pvc.last_state_change, now)
                    pvc.release_evidence = next(t for t in work.targets if t.get("retain"))
        stored = await db.get(CleanupWork, work.work_id)
        if stored is not None:
            await db.delete(stored)
        return True

    async def recover(
        self,
        db: AsyncSession,
        session_id: UUID,
        sandbox_id: UUID,
        now: datetime,
        timeout: float,
    ) -> bool:
        """Published verdicts win over late success; active recovery duplicates do not."""
        row, pvc = await self.locked(db, session_id, sandbox_id)
        if row is None:
            return False
        if row.status == "recovering":
            if row.status_changed_at > now - timedelta(seconds=timeout):
                return False
            row.status = "failed"
        old = self.work(db, row, pvc, "recovery", now, timeout, sandbox_targets(row, retain=False))
        if pvc and pvc.release_evidence:
            old.targets = [
                {**pvc.release_evidence, **obj} if obj["name"] == session_name(pvc.pvc_id) else obj
                for obj in old.targets
            ]
        # Preserve prior evidence and every unfinished generation, rather than replace it.
        previous = list(
            await db.scalars(select(CleanupWork).where(CleanupWork.session_id == session_id))
        )
        for work in previous:
            work.kind = "recovery"
        old.kind = "recovery"
        row.sandbox_id = uuid4()
        row.status = "recovering"
        row.status_changed_at = advance(row.status_changed_at, now)
        row.service_deadline = None
        row.claimed_by = None
        row.pvc_id = row.pvc_uid = None
        row.guest_deployment_uid = row.ipc_deployment_uid = row.ipc_pvc_uid = None
        row.last_ping_at = row.last_ping_sent_at = None
        await db.execute(delete(PingProbe).where(PingProbe.sandbox_id == sandbox_id))
        if pvc:
            pvc.state = "failed"
            pvc.last_state_change = advance(pvc.last_state_change, now)
        return True
