from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from ads.domain import turns_from_entries, utc_now
from ads.exceptions import InvalidInput, NotFound, SessionForbidden
from ads.models import (
    STATUS_FINISHED,
    ChatSession,
    SessionEntry,
    assistant_part_kind,
    assistant_part_role,
)
from ads.repository import (
    ProjectRepository,
    SessionEntryRepository,
    SessionRepository,
    SessionRunBufferRepository,
    SessionRunRepository,
)
from ads.views import PartView, RunView, SessionView, TranscriptView
from ads_commons.security import SecurityContextHolder, require_role


def _require_text(value: str, field: str) -> str:
    if not value.strip():
        raise InvalidInput(f"{field} must be non-empty")
    return value.strip()


class SessionService:
    """Sessions and their transcripts. Other users' rows are 403, missing rows 404."""

    def __init__(
        self,
        session: Session,
        projects: ProjectRepository,
        sessions: SessionRepository,
        entries: SessionEntryRepository,
        runs: SessionRunRepository,
        buffer: SessionRunBufferRepository,
    ) -> None:
        self._session = session
        self._projects = projects
        self._sessions = sessions
        self._entries = entries
        self._runs = runs
        self._buffer = buffer

    @require_role("user")
    async def create(self, project_id: uuid.UUID, name: str, description: str) -> SessionView:
        user_id = SecurityContextHolder.require().user_id
        clean_name = _require_text(name, "Session name")
        clean_description = _require_text(description, "Session description")
        now = utc_now()
        with self._session.begin():
            project = self._projects.get_for_user(user_id, project_id)
            if project is None:
                raise NotFound("no such project")
            row = ChatSession(
                id=uuid.uuid4(),
                project_id=project.id,
                user_id=user_id,
                name=clean_name,
                description=clean_description,
                latest_entry_id=None,
                created_at=now,
                updated_at=now,
            )
            stored = self._sessions.insert(row)
            return SessionView(
                id=stored.id,
                project_id=stored.project_id,
                name=stored.name,
                description=stored.description,
                running=False,
            )

    def _load_owned(self, session_id: uuid.UUID) -> ChatSession:
        user_id = SecurityContextHolder.require().user_id
        row = self._sessions.get_any(session_id)
        if row is None:
            raise NotFound("no such session")
        if row.user_id != user_id:
            raise SessionForbidden("session belongs to another user")
        return row

    async def get(self, session_id: uuid.UUID) -> SessionView:
        with self._session.begin():
            row = self._load_owned(session_id)
            running = self._runs.in_flight_for_session(row.id) is not None
            return SessionView(
                id=row.id,
                project_id=row.project_id,
                name=row.name,
                description=row.description,
                running=running,
            )

    async def entries(self, session_id: uuid.UUID) -> list[SessionEntry]:
        with self._session.begin():
            row = self._load_owned(session_id)
            return self._entries.walk(row)

    async def transcript(self, session_id: uuid.UUID) -> TranscriptView:
        """Committed entries plus buffer rows above the watermark, for a clean reconnect."""
        with self._session.begin():
            row = self._load_owned(session_id)
            project = self._projects.get_for_user(row.user_id, row.project_id)
            committed = self._entries.walk(row)
            run = self._runs.in_flight_for_session(row.id)
            live: list[PartView] = []
            run_view: RunView | None = None
            if run is not None and run.status != STATUS_FINISHED:
                run_view = RunView(status=run.status, message_id=run.message_id)
                for delta in self._buffer.list_after(run.id, run.watermark):
                    live.append(
                        PartView(
                            kind=assistant_part_kind(delta.kind),
                            role=assistant_part_role(delta.kind),
                            text=delta.text,
                            live=True,
                        )
                    )
            return TranscriptView(
                session=SessionView(
                    id=row.id,
                    project_id=row.project_id,
                    name=row.name,
                    description=row.description,
                    running=run_view is not None,
                ),
                project_name=project.name if project is not None else "",
                turns=turns_from_entries(committed, live),
                run=run_view,
            )
