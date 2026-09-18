"""One service for every engine output. The Kafka listener only maps a DTO to one call."""

from __future__ import annotations

import uuid
from collections.abc import Callable
from contextlib import AbstractContextManager
from datetime import datetime

import structlog
from sqlalchemy.orm import Session

from ads.abort_subjects import AbortSubjects
from ads.config import Settings
from ads.domain import append_entry, detached_context, utc_now
from ads.kafka import EngineRequests
from ads.live import LiveHub
from ads.models import (
    KIND_MESSAGE,
    KIND_REASONING,
    ROLE_ASSISTANT,
    STATUS_FINISHED,
    STATUS_FINISHING,
    STATUS_PENDING,
    STATUS_RUNNING,
    ChatSession,
    SessionRun,
    SessionRunBuffer,
)
from ads.repository import (
    SessionEntryRepository,
    SessionRepository,
    SessionRunBufferRepository,
    SessionRunRepository,
)
from ads.tokens import TokenAuthenticator, TokenMinter
from ads_commons.engine import Abort, AckResponse
from ads_commons.security import (
    AccessDenied,
    InvalidAccessToken,
    SecurityContext,
    SecurityContextHolder,
    ensure_caller,
)

log = structlog.get_logger("ads.engine_output")

SessionFactory = Callable[[], Session]


class EngineOutputService:
    """Persist first, then notify. Never produce abort except on ping death."""

    def __init__(
        self,
        session_factory: SessionFactory,
        kafka: EngineRequests,
        hub: LiveHub,
        tokens: TokenMinter,
        authenticator: TokenAuthenticator,
        settings: Settings,
        subjects: AbortSubjects,
    ) -> None:
        self._session_factory = session_factory
        self._kafka = kafka
        self._hub = hub
        self._tokens = tokens
        self._authenticator = authenticator
        self._settings = settings
        self._subjects = subjects

    # ------------------------------------------------------------------ output

    async def acknowledge(
        self,
        session_id: uuid.UUID,
        message_id: uuid.UUID,
        token: str | None,
    ) -> None:
        if token is None:
            log.info("acknowledge_without_authorization", session_id=str(session_id))
            return
        try:
            context = self._authenticator.authenticate(
                token, audience=self._settings.keycloak_audience
            )
            ensure_caller(context, self._settings.engine_allowed_azp)
        except (InvalidAccessToken, AccessDenied):
            log.info("acknowledge_rejected", session_id=str(session_id))
            return
        session = self._session_factory()
        try:
            with session.begin():
                run = _in_flight(session, session_id)
                if run is None or run.status != STATUS_PENDING or run.message_id != message_id:
                    return
            try:
                exchanged = self._tokens.exchange(self._settings.engine_audience, token)
            except Exception:
                log.info("acknowledge_exchange_failed", session_id=str(session_id))
                return
            self._subjects.remember(session_id, token)
            with session.begin():
                run = _in_flight(session, session_id)
                if run is None or run.status != STATUS_PENDING or run.message_id != message_id:
                    return
                now = utc_now()
                run.status = STATUS_RUNNING
                run.last_event_at = now
                run.updated_at = now
        finally:
            session.close()
        await self._hub.notify(session_id)
        await self._kafka.produce_ack_response(
            AckResponse(session_id=session_id, message_id=message_id),
            exchanged,
        )

    async def partial_response(
        self,
        session_id: uuid.UUID,
        order: int,
        kind: str,
        text: str,
    ) -> None:
        session = self._session_factory()
        notify = False
        try:
            with session.begin():
                run = _in_flight(session, session_id)
                if run is None:
                    return
                if order < 0:
                    return
                if run.last_order is not None and order > run.last_order:
                    return
                buffer = SessionRunBufferRepository(session=session)
                if buffer.get_delta(run.id, order) is not None:
                    log.warning(
                        "duplicate_partial_order",
                        session_id=str(session_id),
                        order=order,
                    )
                    return
                buffer.insert(SessionRunBuffer(run_id=run.id, order_no=order, kind=kind, text=text))
                now = utc_now()
                run.last_event_at = now
                run.updated_at = now
                with self._bound(session, run):
                    self._promote(session, run, now)
                notify = True
        finally:
            session.close()
        if notify:
            await self._hub.notify(session_id)

    async def ping(self, session_id: uuid.UUID) -> None:
        session = self._session_factory()
        try:
            with session.begin():
                run = _in_flight(session, session_id)
                if run is None or run.status == STATUS_FINISHING:
                    return
                now = utc_now()
                run.last_event_at = now
                run.updated_at = now
        finally:
            session.close()

    async def finish(self, session_id: uuid.UUID, last_order: int | None) -> None:
        session = self._session_factory()
        broken = False
        notify = False
        try:
            with session.begin():
                run = _in_flight(session, session_id)
                if run is None:
                    return
                now = utc_now()
                run.last_event_at = now
                run.updated_at = now
                if last_order is None or last_order < 0 or last_order < run.watermark:
                    log.info(
                        "finish_invalid",
                        session_id=str(session_id),
                        last_order=last_order,
                        watermark=run.watermark,
                    )
                    with self._bound(session, run):
                        self._break_run(session, run)
                    broken = True
                else:
                    if run.last_order is None:
                        run.last_order = last_order
                    if run.watermark >= run.last_order:
                        run.status = STATUS_FINISHED
                        run.finish_at = None
                    elif run.status != STATUS_FINISHING:
                        run.status = STATUS_FINISHING
                        run.finish_at = now
                    notify = True
        finally:
            session.close()
        if broken or notify:
            await self._hub.notify(session_id)

    async def error(self, session_id: uuid.UUID, message_id: uuid.UUID, text: str) -> None:
        session = self._session_factory()
        broken = False
        try:
            with session.begin():
                run = _in_flight(session, session_id)
                if run is None:
                    return
                if run.message_id != message_id:
                    # Duplicate / rejected request id. The active run keeps going.
                    log.info("engine_error_other_message", session_id=str(session_id))
                    return
                run.error_text = text
                with self._bound(session, run):
                    self._break_run(session, run)
                broken = True
        finally:
            session.close()
        if broken:
            await self._hub.notify(session_id)

    # -------------------------------------------------------------- ping death

    async def abort_and_break(self, run_id: uuid.UUID) -> None:
        """Ping death of pending/running: produce abort, then unwind locally either way."""
        session = self._session_factory()
        try:
            with session.begin():
                run = SessionRunRepository(session=session).get_run(run_id)
                if run is None:
                    return
                session_id = run.session_id
                message_id = run.message_id
            try:
                subject = self._subjects.get(session_id)
                token = self._tokens.exchange(self._settings.engine_audience, subject)
                await self._kafka.produce_abort(
                    Abort(session_id=session_id, message_id=message_id),
                    token,
                )
            except Exception:
                # Abort produce failure must not skip the local unwind.
                log.warning("abort_produce_failed", session_id=str(session_id))
            with session.begin():
                run = SessionRunRepository(session=session).get_run(run_id)
                if run is None:
                    return
                run.error_text = "ping death"
                with self._bound(session, run):
                    self._break_run(session, run)
        finally:
            session.close()
        await self._hub.notify(session_id)

    async def break_run(self, run_id: uuid.UUID, reason: str) -> None:
        """Broken without abort: engine error, invalid finish, or a gapped finish timeout."""
        session = self._session_factory()
        try:
            with session.begin():
                run = SessionRunRepository(session=session).get_run(run_id)
                if run is None:
                    return
                session_id = run.session_id
                run.error_text = reason
                with self._bound(session, run):
                    self._break_run(session, run)
        finally:
            session.close()
        await self._hub.notify(session_id)

    # ------------------------------------------------------------------ shared

    def _bound(self, session: Session, run: SessionRun) -> AbstractContextManager[SecurityContext]:
        """Bind the holder from the run's session owner. Detached work has no access token."""
        owner = SessionRepository(session=session).get_any(run.session_id)
        user_id = owner.user_id if owner is not None else uuid.uuid4()
        return SecurityContextHolder.bound(detached_context(user_id))

    def _promote(self, session: Session, run: SessionRun, now: datetime) -> None:
        """Advance the watermark, then append the newly continuous deltas as entries."""
        buffer = SessionRunBufferRepository(session=session)
        entries = SessionEntryRepository(session=session)
        sessions = SessionRepository(session=session)
        chat = sessions.get_any(run.session_id)
        if chat is None:
            return
        orders = buffer.orders(run.id)
        watermark = run.watermark
        while watermark + 1 in orders:
            watermark += 1
        if watermark == run.watermark:
            return
        for order_no in range(run.watermark + 1, watermark + 1):
            delta = buffer.get_delta(run.id, order_no)
            if delta is None:  # pragma: no cover - orders came from the same table
                continue
            self._append_delta(entries, chat, run, delta, now)
        run.watermark = watermark
        run.updated_at = now
        if run.last_order is not None and run.watermark >= run.last_order:
            run.status = STATUS_FINISHED
            run.finish_at = None

    def _append_delta(
        self,
        entries: SessionEntryRepository,
        chat: ChatSession,
        run: SessionRun,
        delta: SessionRunBuffer,
        now: datetime,
    ) -> None:
        kind = delta.kind
        if kind in {KIND_MESSAGE, KIND_REASONING}:
            tail = (
                entries.get_entry(chat.latest_entry_id)
                if chat.latest_entry_id is not None
                else None
            )
            if tail is not None and tail.run_id == run.id and tail.kind == kind:
                tail.text = tail.text + delta.text
                return
            append_entry(
                entries,
                chat,
                kind=kind,
                role=None if kind == KIND_REASONING else ROLE_ASSISTANT,
                text=delta.text,
                run_id=run.id,
                now=now,
            )
            return
        append_entry(
            entries,
            chat,
            kind=kind,
            role=None,
            text=delta.text,
            run_id=run.id,
            now=now,
        )

    def _break_run(self, session: Session, run: SessionRun) -> None:
        """FK order with no ON DELETE: unlink, buffer, run, entries."""
        entries = SessionEntryRepository(session=session)
        buffer = SessionRunBufferRepository(session=session)
        runs = SessionRunRepository(session=session)
        sessions = SessionRepository(session=session)
        chat = sessions.get_any(run.session_id)
        user_entry = entries.get_entry(run.user_entry_id)
        if chat is not None:
            previous_id = user_entry.prev_id if user_entry is not None else None
            chat.latest_entry_id = previous_id
            if previous_id is not None:
                previous = entries.get_entry(previous_id)
                if previous is not None:
                    previous.next_id = None
            chat.updated_at = utc_now()
        if user_entry is not None:
            user_entry.prev_id = None
            user_entry.next_id = None
        session.flush()
        buffer.delete_for_run(run.id)
        runs.delete_run(run)
        entries.delete_for_run(run.session_id, run.id)
        if user_entry is not None:
            entries.delete_entry(user_entry)
        self._subjects.forget(run.session_id)


def _in_flight(session: Session, session_id: uuid.UUID) -> SessionRun | None:
    return SessionRunRepository(session=session).in_flight_for_session(session_id)
