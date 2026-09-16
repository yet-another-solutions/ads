from __future__ import annotations

import uuid

from advanced_alchemy.repository import SQLAlchemySyncRepository
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ads.models import (
    IN_FLIGHT_STATUSES,
    ChatSession,
    Project,
    SessionEntry,
    SessionRun,
    SessionRunBuffer,
)


class ProjectRepository(SQLAlchemySyncRepository[Project]):
    """Data layer. Requires an open transaction and never begins one."""

    model_type = Project

    def __init__(self, session: Session) -> None:
        super().__init__(session=session)

    def list_for_user(self, user_id: uuid.UUID) -> list[Project]:
        statement = (
            select(Project)
            .where(Project.user_id == user_id)
            .order_by(Project.name.asc(), Project.id.asc())
        )
        return list(self.session.scalars(statement).all())

    def get_for_user(self, user_id: uuid.UUID, project_id: uuid.UUID) -> Project | None:
        statement = select(Project).where(Project.user_id == user_id, Project.id == project_id)
        return self.session.scalars(statement).first()

    def insert(self, row: Project) -> Project:
        self.session.add(row)
        self.session.flush()
        return row


class SessionRepository(SQLAlchemySyncRepository[ChatSession]):
    """Data layer. Requires an open transaction and never begins one."""

    model_type = ChatSession

    def __init__(self, session: Session) -> None:
        super().__init__(session=session)

    def list_for_project(self, user_id: uuid.UUID, project_id: uuid.UUID) -> list[ChatSession]:
        statement = (
            select(ChatSession)
            .where(ChatSession.user_id == user_id, ChatSession.project_id == project_id)
            .order_by(ChatSession.created_at.asc(), ChatSession.id.asc())
        )
        return list(self.session.scalars(statement).all())

    def get_for_user(self, user_id: uuid.UUID, session_id: uuid.UUID) -> ChatSession | None:
        statement = select(ChatSession).where(
            ChatSession.user_id == user_id, ChatSession.id == session_id
        )
        return self.session.scalars(statement).first()

    def get_any(self, session_id: uuid.UUID) -> ChatSession | None:
        return self.session.scalars(select(ChatSession).where(ChatSession.id == session_id)).first()

    def insert(self, row: ChatSession) -> ChatSession:
        self.session.add(row)
        self.session.flush()
        return row


class SessionEntryRepository(SQLAlchemySyncRepository[SessionEntry]):
    """Data layer. Requires an open transaction and never begins one."""

    model_type = SessionEntry

    def __init__(self, session: Session) -> None:
        super().__init__(session=session)

    def insert(self, row: SessionEntry) -> SessionEntry:
        self.session.add(row)
        self.session.flush()
        return row

    def get_entry(self, entry_id: uuid.UUID) -> SessionEntry | None:
        return self.session.scalars(select(SessionEntry).where(SessionEntry.id == entry_id)).first()

    def list_for_session(self, session_id: uuid.UUID) -> list[SessionEntry]:
        statement = select(SessionEntry).where(SessionEntry.session_id == session_id)
        return list(self.session.scalars(statement).all())

    def walk(self, session: ChatSession) -> list[SessionEntry]:
        """Head-to-tail order: follow ``prev`` from ``latest``, then read it back."""
        rows = {row.id: row for row in self.list_for_session(session.id)}
        chain: list[SessionEntry] = []
        cursor = session.latest_entry_id
        seen: set[uuid.UUID] = set()
        while cursor is not None and cursor in rows and cursor not in seen:
            seen.add(cursor)
            row = rows[cursor]
            chain.append(row)
            cursor = row.prev_id
        chain.reverse()
        return chain

    def delete_for_run(self, session_id: uuid.UUID, run_id: uuid.UUID) -> None:
        rows = list(
            self.session.scalars(
                select(SessionEntry).where(
                    SessionEntry.session_id == session_id,
                    SessionEntry.run_id == run_id,
                )
            ).all()
        )
        for row in rows:
            row.prev_id = None
            row.next_id = None
        self.session.flush()
        for row in rows:
            self.session.delete(row)
        self.session.flush()

    def delete_entry(self, row: SessionEntry) -> None:
        row.prev_id = None
        row.next_id = None
        self.session.flush()
        self.session.delete(row)
        self.session.flush()


class SessionRunRepository(SQLAlchemySyncRepository[SessionRun]):
    """Data layer. Requires an open transaction and never begins one."""

    model_type = SessionRun

    def __init__(self, session: Session) -> None:
        super().__init__(session=session)

    def insert(self, row: SessionRun) -> SessionRun:
        self.session.add(row)
        self.session.flush()
        return row

    def in_flight_for_session(self, session_id: uuid.UUID) -> SessionRun | None:
        statement = select(SessionRun).where(
            SessionRun.session_id == session_id,
            SessionRun.status.in_(IN_FLIGHT_STATUSES),
        )
        return self.session.scalars(statement).first()

    def in_flight_sessions(self, session_ids: list[uuid.UUID]) -> set[uuid.UUID]:
        if not session_ids:
            return set()
        statement = select(SessionRun.session_id).where(
            SessionRun.session_id.in_(session_ids),
            SessionRun.status.in_(IN_FLIGHT_STATUSES),
        )
        return set(self.session.scalars(statement).all())

    def all_in_flight(self) -> list[SessionRun]:
        statement = select(SessionRun).where(SessionRun.status.in_(IN_FLIGHT_STATUSES))
        return list(self.session.scalars(statement).all())

    def get_run(self, run_id: uuid.UUID) -> SessionRun | None:
        return self.session.scalars(select(SessionRun).where(SessionRun.id == run_id)).first()

    def delete_run(self, row: SessionRun) -> None:
        self.session.delete(row)
        self.session.flush()


class SessionRunBufferRepository(SQLAlchemySyncRepository[SessionRunBuffer]):
    """Data layer. Requires an open transaction and never begins one."""

    model_type = SessionRunBuffer

    def __init__(self, session: Session) -> None:
        super().__init__(session=session)

    def get_delta(self, run_id: uuid.UUID, order_no: int) -> SessionRunBuffer | None:
        statement = select(SessionRunBuffer).where(
            SessionRunBuffer.run_id == run_id,
            SessionRunBuffer.order_no == order_no,
        )
        return self.session.scalars(statement).first()

    def insert(self, row: SessionRunBuffer) -> SessionRunBuffer:
        self.session.add(row)
        self.session.flush()
        return row

    def orders(self, run_id: uuid.UUID) -> set[int]:
        statement = select(SessionRunBuffer.order_no).where(SessionRunBuffer.run_id == run_id)
        return set(self.session.scalars(statement).all())

    def list_after(self, run_id: uuid.UUID, order_no: int) -> list[SessionRunBuffer]:
        statement = (
            select(SessionRunBuffer)
            .where(SessionRunBuffer.run_id == run_id, SessionRunBuffer.order_no > order_no)
            .order_by(SessionRunBuffer.order_no.asc())
        )
        return list(self.session.scalars(statement).all())

    def delete_for_run(self, run_id: uuid.UUID) -> None:
        self.session.execute(delete(SessionRunBuffer).where(SessionRunBuffer.run_id == run_id))
        self.session.flush()
