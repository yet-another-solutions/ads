from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from ads.config import Settings
from ads.domain import part_from_stored, turns_from_entries, utc_now
from ads.exceptions import InvalidInput, NotFound, SessionForbidden
from ads.models import (
    KIND_MESSAGE,
    KIND_TOMBSTONE,
    ROLE_ASSISTANT,
    STATUS_FINISHED,
    ChatSession,
    SessionEntry,
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
from ads_policy.audit import BufferedAuditSink
from ads_policy.contract import AuditEvent, Effect

AUDITOR_READ_RULE = "auditor.read"


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
        settings: Settings,
        audit: BufferedAuditSink,
    ) -> None:
        self._session = session
        self._projects = projects
        self._sessions = sessions
        self._entries = entries
        self._runs = runs
        self._buffer = buffer
        self._auditor_role = settings.keycloak_auditor_role
        self._audit = audit

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

    def _load_for_reading(self, session_id: uuid.UUID) -> ChatSession:
        context = SecurityContextHolder.require()
        row = self._sessions.get_any(session_id)
        if row is None:
            raise NotFound("no such session")
        if row.user_id == context.user_id:
            return row
        if self._auditor_role and context.has_role(self._auditor_role):
            self._journal_the_reading(context.subject, row)
            return row
        raise SessionForbidden("session belongs to another user")

    def _journal_the_reading(self, auditor: str, row: ChatSession) -> None:
        self._audit.enqueue(
            AuditEvent(
                run_id="",
                subject=auditor,
                capability=None,
                resource=str(row.id),
                effect=Effect.ALLOW,
                rule_id=AUDITOR_READ_RULE,
                weight=0,
                policy_hash="",
                conversation=str(row.id),
            )
        )

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
            row = self._load_for_reading(session_id)
            project = self._projects.get_for_user(row.user_id, row.project_id)
            committed = self._entries.walk(row)
            run = self._runs.in_flight_for_session(row.id)
            live: list[PartView] = []
            run_view: RunView | None = None
            if run is not None and run.status != STATUS_FINISHED:
                run_view = RunView(
                    status=run.status,
                    message_id=run.message_id,
                    total_context=run.total_context,
                    used_context=run.used_context,
                )
                for delta in self._buffer.list_after(run.id, run.watermark):
                    if delta.kind == KIND_TOMBSTONE:
                        continue
                    live.append(
                        part_from_stored(
                            delta.kind,
                            delta.text,
                            ROLE_ASSISTANT if delta.kind == KIND_MESSAGE else None,
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
                selected_model_id=self._runs.last_model_for_session(row.id),
            )
