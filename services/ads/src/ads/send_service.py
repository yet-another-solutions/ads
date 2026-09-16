from __future__ import annotations

import uuid

import structlog
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ads.abort_subjects import AbortSubjects
from ads.config import Settings
from ads.domain import append_entry, history_from_entries, utc_now
from ads.exceptions import (
    ComposerRejected,
    Conflict,
    NotFound,
    ProducerFailed,
    SessionForbidden,
)
from ads.kafka import EngineRequests
from ads.models import (
    KIND_MESSAGE,
    ROLE_USER,
    STATUS_PENDING,
    ChatSession,
    SessionRun,
)
from ads.repository import (
    SessionEntryRepository,
    SessionRepository,
    SessionRunRepository,
)
from ads.tokens import TokenMinter
from ads_commons.engine import (
    Authorization,
    EngineRequest,
    HistoryTurn,
    OpenAiStreamModel,
)
from ads_commons.preferences import ModelInfo, PreferencesApi
from ads_commons.security import SecurityContextHolder, require_role

log = structlog.get_logger("ads.send")

EMPTY_INPUT = "Type a message before sending."
NO_MODEL = "Pick a model before sending."
UNKNOWN_MODEL = "No such model for this user."


class SendService:
    """ads-v1 §5. One unit of work per step; produce is outside the insert transaction."""

    def __init__(
        self,
        session: Session,
        sessions: SessionRepository,
        entries: SessionEntryRepository,
        runs: SessionRunRepository,
        preferences: PreferencesApi,
        kafka: EngineRequests,
        tokens: TokenMinter,
        settings: Settings,
        subjects: AbortSubjects,
    ) -> None:
        self._session = session
        self._sessions = sessions
        self._entries = entries
        self._runs = runs
        self._preferences = preferences
        self._kafka = kafka
        self._tokens = tokens
        self._settings = settings
        self._subjects = subjects

    def _load_owned(self, session_id: uuid.UUID) -> ChatSession:
        user_id = SecurityContextHolder.require().user_id
        row = self._sessions.get_any(session_id)
        if row is None:
            raise NotFound("no such session")
        if row.user_id != user_id:
            raise SessionForbidden("session belongs to another user")
        return row

    @require_role("user")
    async def send(
        self,
        session_id: uuid.UUID,
        user_input: str,
        model_id: uuid.UUID | None,
    ) -> uuid.UUID:
        """Append the user turn, claim the session, then produce. Returns the run message id."""
        SecurityContextHolder.require()
        with self._session.begin():
            self._load_owned(session_id)
        text = user_input.strip()
        if not text:
            raise ComposerRejected(EMPTY_INPUT)
        if model_id is None:
            raise ComposerRejected(NO_MODEL)
        model = await self._load_model(model_id)

        now = utc_now()
        message_id = uuid.uuid4()
        run_id = uuid.uuid4()
        history: list[HistoryTurn] = []
        try:
            with self._session.begin():
                session_row = self._load_owned(session_id)
                if self._runs.in_flight_for_session(session_row.id) is not None:
                    raise Conflict()
                history = history_from_entries(self._entries.walk(session_row))
                user_entry = append_entry(
                    self._entries,
                    session_row,
                    kind=KIND_MESSAGE,
                    role=ROLE_USER,
                    text=text,
                    run_id=None,
                    now=now,
                )
                self._runs.insert(
                    SessionRun(
                        id=run_id,
                        session_id=session_row.id,
                        message_id=message_id,
                        user_entry_id=user_entry.id,
                        model_id=model_id,
                        status=STATUS_PENDING,
                        watermark=-1,
                        last_order=None,
                        last_event_at=now,
                        finish_at=None,
                        error_text=None,
                        created_at=now,
                        updated_at=now,
                    )
                )
        except IntegrityError as exc:
            raise Conflict() from exc

        # Watchdog abort has no holder. Keep the user JWT in memory for STE.
        self._subjects.remember(session_id, SecurityContextHolder.require().access_token)

        request = EngineRequest(
            session_id=session_id,
            message_id=message_id,
            history=history,
            user_input=text,
            instructions="",
            model=OpenAiStreamModel(
                url=model.url,
                authentication=model.authentication,
                options=model.options,
            ),
            authorization=Authorization(
                token=self._tokens.exchange(self._settings.engine_audience),
            ),
        )
        try:
            await self._kafka.produce_request(request)
        except Exception as exc:
            # Leave the run pending: the watchdog kills it after ping death. No rollback.
            log.warning("engine_request_produce_failed", session_id=str(session_id))
            raise ProducerFailed() from exc
        with self._session.begin():
            run = self._runs.get_run(run_id)
            if run is not None:
                run.last_event_at = utc_now()
                run.updated_at = run.last_event_at
        return message_id

    async def _load_model(self, model_id: uuid.UUID) -> ModelInfo:
        """Server-side only: the bearer stays here and goes onto Kafka, never into HTML."""
        try:
            return await self._preferences.get_model(model_id)
        except NotFound as exc:
            raise ComposerRejected(UNKNOWN_MODEL) from exc
