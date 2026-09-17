from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class InFlight(Base):
    """Correlation and handshake state only. Never credentials, output, or replica identity."""

    __tablename__ = "sandbox_execution"

    execution_id: Mapped[UUID] = mapped_column(primary_key=True)
    session_id: Mapped[UUID]
    message_id: Mapped[UUID]
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    deadline: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    timed_out: Mapped[bool] = mapped_column(default=False)
    ack_replied: Mapped[bool] = mapped_column(default=False)


class InFlightRepository:
    """Data operations require a caller-owned transaction."""

    async def insert(self, session: AsyncSession, row: InFlight) -> None:
        session.add(row)
        await session.flush()

    async def locked(self, session: AsyncSession, execution_id: UUID) -> InFlight | None:
        row: InFlight | None = await session.scalar(
            select(InFlight).where(InFlight.execution_id == execution_id).with_for_update()
        )
        return row

    async def remove(self, session: AsyncSession, row: InFlight) -> None:
        await session.delete(row)

    async def collect(self, session: AsyncSession, before: datetime) -> None:
        await session.execute(delete(InFlight).where(InFlight.created_at < before))
