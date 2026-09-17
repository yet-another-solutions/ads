from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import CheckConstraint, DateTime, select, update
from sqlalchemy.dialects.postgresql import insert
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
            "'stopped','failed','recovering')",
            name="sandbox_session_status",
        ),
    )

    session_id: Mapped[UUID] = mapped_column(primary_key=True)
    sandbox_id: Mapped[UUID] = mapped_column(unique=True)
    status: Mapped[str]
    golden_version: Mapped[str]
    pvc_uid: Mapped[str | None]
    guest_deployment_uid: Mapped[str | None]
    ipc_deployment_uid: Mapped[str | None]
    ipc_pvc_uid: Mapped[str | None]
    claimed_by: Mapped[UUID | None]
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    status_changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_execution_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_ping_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class SessionRepository:
    """Data methods require a caller-owned transaction; never call Kubernetes here."""

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
                status_changed_at=now,
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
            select(SandboxSession).where(
                SandboxSession.session_id == row.session_id,
                SandboxSession.sandbox_id == row.sandbox_id,
                SandboxSession.claimed_by == owner,
                SandboxSession.status == "creating",
            )
        )
        return result

    async def record(
        self,
        db: AsyncSession,
        row: SandboxSession,
        owner: UUID,
        **values: object,
    ) -> SandboxSession | None:
        result: SandboxSession | None = await db.scalar(
            update(SandboxSession)
            .where(
                SandboxSession.session_id == row.session_id,
                SandboxSession.sandbox_id == row.sandbox_id,
                SandboxSession.claimed_by == owner,
                SandboxSession.status == "creating",
            )
            .values(**values)
            .returning(SandboxSession)
            .execution_options(populate_existing=True)
        )
        return result
