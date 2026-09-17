from __future__ import annotations

import asyncio
import uuid

from sqlalchemy import String, create_engine, delete
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from sqlalchemy.pool import StaticPool

from ads_engine.config import Settings


class Base(DeclarativeBase):
    pass


class ActiveSessionRow(Base):
    __tablename__ = "active_sessions"

    session_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    message_id: Mapped[str] = mapped_column(String(36), nullable=False)


class ConversationRunRow(Base):
    __tablename__ = "conversation_runs"

    session_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(64), nullable=False)


def _create_engine(database_url: str) -> Engine:
    if database_url.startswith("sqlite"):
        connect_args = {"check_same_thread": False}
        if ":memory:" in database_url:
            return create_engine(
                database_url,
                connect_args=connect_args,
                poolclass=StaticPool,
            )
        return create_engine(database_url, connect_args=connect_args)
    return create_engine(database_url)


class ActiveSessionStore:
    def __init__(self, settings: Settings) -> None:
        self._engine = _create_engine(settings.database_url)
        Base.metadata.create_all(self._engine)
        self._sessions = sessionmaker(bind=self._engine, expire_on_commit=False)
        self._lock = asyncio.Lock()

    async def run_of_conversation(self, session_id: uuid.UUID) -> str | None:
        async with self._lock:
            with self._sessions() as session:
                row = session.get(ConversationRunRow, str(session_id))
                return None if row is None else row.run_id

    async def remember_run_of_conversation(self, session_id: uuid.UUID, run_id: str) -> None:
        async with self._lock:
            with self._sessions() as session:
                session.merge(ConversationRunRow(session_id=str(session_id), run_id=run_id))
                session.commit()

    async def reset(self) -> None:
        async with self._lock:
            with self._sessions() as session:
                session.execute(delete(ActiveSessionRow))
                session.commit()

    async def claim(self, session_id: uuid.UUID, message_id: uuid.UUID) -> bool:
        async with self._lock:
            with self._sessions() as session:
                try:
                    session.add(
                        ActiveSessionRow(
                            session_id=str(session_id),
                            message_id=str(message_id),
                        )
                    )
                    session.commit()
                except IntegrityError:
                    session.rollback()
                    return False
                return True

    async def release(self, session_id: uuid.UUID) -> None:
        async with self._lock:
            with self._sessions() as session:
                session.execute(
                    delete(ActiveSessionRow).where(ActiveSessionRow.session_id == str(session_id))
                )
                session.commit()
