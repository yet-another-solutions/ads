from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, select, update
from sqlalchemy.dialects.postgresql import JSONB, insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class SandboxSession(Base):
    """Durable identity/lifecycle only. No tokens, execution buffers, or output."""

    __tablename__ = "sandbox_session"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending','creating','ready','shutting_down',"
            "'stopped','service','failed','recovering')",
            name="sandbox_session_status",
        ),
    )

    session_id: Mapped[UUID] = mapped_column(primary_key=True)
    sandbox_id: Mapped[UUID] = mapped_column(unique=True)
    status: Mapped[str]
    golden_version: Mapped[str]
    pvc_uid: Mapped[str | None]
    pvc_id: Mapped[UUID | None]
    service_deadline: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    guest_deployment_uid: Mapped[str | None]
    ipc_deployment_uid: Mapped[str | None]
    ipc_pvc_uid: Mapped[str | None]
    claimed_by: Mapped[UUID | None]
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    status_changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_execution_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_ping_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class SessionPVC(Base):
    """A disk lifetime, not a session alias. Old targets never follow a new mapping."""

    __tablename__ = "session_pvc"
    __table_args__ = (
        CheckConstraint(
            "state IN ('detached','attaching','attached','detaching','destroying','failed')",
            name="session_pvc_state",
        ),
    )

    pvc_id: Mapped[UUID] = mapped_column(primary_key=True)
    session_id: Mapped[UUID] = mapped_column(
        ForeignKey("sandbox_session.session_id", ondelete="CASCADE"), index=True
    )
    sandbox_id: Mapped[UUID]
    uid: Mapped[str | None]
    release_evidence: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    state: Mapped[str]
    last_execution: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_state_change: Mapped[datetime] = mapped_column(DateTime(timezone=True))


def advance(previous: datetime, now: datetime) -> datetime:
    """PostgreSQL microsecond precision, including two claims in the same clock tick."""
    return max(now, previous + timedelta(microseconds=1))


class SessionRepository:
    """Data methods require a caller-owned transaction; never call Kubernetes here."""

    async def by_sandbox(self, db: AsyncSession, sandbox_id: UUID) -> SandboxSession | None:
        result: SandboxSession | None = await db.scalar(
            select(SandboxSession).where(SandboxSession.sandbox_id == sandbox_id)
        )
        return result

    async def mark_ready(
        self, db: AsyncSession, sandbox_id: UUID, now: datetime, expected: datetime
    ) -> bool:
        row = await db.scalar(
            select(SandboxSession)
            .where(SandboxSession.sandbox_id == sandbox_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if row is None or row.pvc_id is None or row.status_changed_at != expected:
            return False
        pvc = await db.get(SessionPVC, row.pvc_id, with_for_update=True)
        if pvc is None or pvc.state != "attaching":
            return False
        result = await db.scalar(
            update(SandboxSession)
            .where(
                SandboxSession.sandbox_id == sandbox_id,
                SandboxSession.status == "creating",
                SandboxSession.pvc_uid.is_not(None),
                SandboxSession.ipc_pvc_uid.is_not(None),
                SandboxSession.guest_deployment_uid.is_not(None),
                SandboxSession.ipc_deployment_uid.is_not(None),
            )
            .values(
                status="ready",
                status_changed_at=advance(row.status_changed_at, now),
                last_execution_at=now,
                last_ping_at=now,
            )
            .returning(SandboxSession.session_id)
        )
        if result is not None:
            pvc.state = "attached"
            pvc.last_state_change = advance(pvc.last_state_change, now)
            pvc.last_execution = now
        return result is not None

    async def stamp_result(self, db: AsyncSession, sandbox_id: UUID, now: datetime) -> None:
        row = await db.scalar(
            select(SandboxSession).where(SandboxSession.sandbox_id == sandbox_id).with_for_update()
        )
        if row is not None:
            row.last_execution_at = max(row.last_execution_at, now)
            pvc = await db.get(SessionPVC, row.pvc_id, with_for_update=True) if row.pvc_id else None
            if pvc is not None:
                pvc.last_execution = max(pvc.last_execution, now)

    async def admit(
        self, db: AsyncSession, session_id: UUID, now: datetime
    ) -> SandboxSession | None:
        row = await db.get(SandboxSession, session_id, with_for_update=True)
        if row is None or row.status != "ready" or row.pvc_id is None:
            return None
        pvc = await db.get(SessionPVC, row.pvc_id, with_for_update=True)
        if pvc is None or pvc.state != "attached":
            return None
        row.last_execution_at = max(row.last_execution_at, now)
        pvc.last_execution = max(pvc.last_execution, now)
        return row

    async def get(self, db: AsyncSession, session_id: UUID) -> SandboxSession | None:
        result: SandboxSession | None = await db.scalar(
            select(SandboxSession)
            .where(SandboxSession.session_id == session_id)
            .execution_options(populate_existing=True)
        )
        return result

    async def insert_pending(
        self,
        db: AsyncSession,
        session_id: UUID,
        sandbox_id: UUID,
        version: str,
        now: datetime,
    ) -> bool:
        result = await db.scalar(
            insert(SandboxSession)
            .values(
                session_id=session_id,
                sandbox_id=sandbox_id,
                status="pending",
                golden_version=version,
                created_at=now,
                status_changed_at=now,
                last_execution_at=now,
            )
            .on_conflict_do_nothing(index_elements=[SandboxSession.session_id])
            .returning(
                SandboxSession.session_id,
            )
        )
        return result is not None

    async def claim(
        self,
        db: AsyncSession,
        row: SandboxSession,
        owner: UUID,
        now: datetime,
    ) -> SandboxSession | None:
        # Always lock sandbox before PVC, shared by admission/idle/reap/service/recovery.
        expected = (row.sandbox_id, row.status, row.status_changed_at, row.pvc_id)
        current = await db.scalar(
            select(SandboxSession)
            .where(SandboxSession.session_id == row.session_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if current is None or current.status not in ("pending", "stopped"):
            return None
        if (
            current.sandbox_id,
            current.status,
            current.status_changed_at,
            current.pvc_id,
        ) != expected:
            return None
        pvc = (
            await db.get(SessionPVC, current.pvc_id, with_for_update=True)
            if current.pvc_id
            else None
        )
        if pvc is not None and pvc.state != "detached":
            return None
        if pvc is None:
            if current.pvc_id is not None:
                return None  # A missing record is not permission to silently replace contents.
            pvc = SessionPVC(
                pvc_id=uuid4(),
                session_id=current.session_id,
                sandbox_id=current.sandbox_id,
                uid=None,
                state="attaching",
                last_execution=now,
                last_state_change=now,
            )
            db.add(pvc)
            current.pvc_id = pvc.pvc_id
            current.pvc_uid = None
        else:
            pvc.state = "attaching"
            pvc.last_state_change = advance(pvc.last_state_change, now)
        await db.flush()
        # A pending loser may not take over a winner's insertion/claim gap.
        # Pending claims are invoked only by the INSERT winner; stopped is CAS.
        result: SandboxSession | None = await db.scalar(
            update(SandboxSession)
            .where(
                SandboxSession.session_id == row.session_id,
                SandboxSession.sandbox_id == row.sandbox_id,
                SandboxSession.status == row.status,
                SandboxSession.status.in_(("pending", "stopped")),
            )
            .values(
                status="creating",
                claimed_by=owner,
                status_changed_at=advance(current.status_changed_at, now),
                guest_deployment_uid=None,
                ipc_deployment_uid=None,
                ipc_pvc_uid=None,
            )
            .returning(SandboxSession)
            .execution_options(populate_existing=True)
        )
        return result

    async def owned(
        self,
        db: AsyncSession,
        row: SandboxSession,
        owner: UUID,
    ) -> SandboxSession | None:
        result: SandboxSession | None = await db.scalar(
            select(SandboxSession)
            .where(
                SandboxSession.session_id == row.session_id,
                SandboxSession.sandbox_id == row.sandbox_id,
                SandboxSession.claimed_by == owner,
                SandboxSession.status == "creating",
                SandboxSession.status_changed_at == row.status_changed_at,
            )
            .with_for_update()
        )
        return result

    async def record(
        self,
        db: AsyncSession,
        row: SandboxSession,
        owner: UUID,
        **values: object,
    ) -> SandboxSession | None:
        current = await self.owned(db, row, owner)
        if current is None:
            return None
        changed = values.get("status_changed_at")
        if isinstance(changed, datetime):
            values["status_changed_at"] = advance(current.status_changed_at, changed)
        if row.pvc_id is not None:
            pvc = await db.get(SessionPVC, row.pvc_id, with_for_update=True)
            if pvc is not None:
                if "pvc_uid" in values:
                    pvc.uid = str(values["pvc_uid"])
                if values.get("status") == "failed":
                    pvc.state = "failed"
                    pvc.last_state_change = advance(pvc.last_state_change, row.status_changed_at)
        result: SandboxSession | None = await db.scalar(
            update(SandboxSession)
            .where(
                SandboxSession.session_id == row.session_id,
                SandboxSession.sandbox_id == row.sandbox_id,
                SandboxSession.claimed_by == owner,
                SandboxSession.status == "creating",
                SandboxSession.status_changed_at == row.status_changed_at,
            )
            .values(**values)
            .returning(SandboxSession)
            .execution_options(populate_existing=True)
        )
        return result
