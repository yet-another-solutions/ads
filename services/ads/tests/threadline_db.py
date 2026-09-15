"""Direct DB reads for assertions, plus engine output and watchdog drivers."""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timedelta
from typing import Any

from litestar import Litestar
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from ads.config import Settings
from ads.domain import utc_now
from ads.ioc import session_factory_for
from ads.models import ChatSession, SessionEntry, SessionRun, SessionRunBuffer
from ads.repository import (
    SessionEntryRepository,
    SessionRepository,
    SessionRunBufferRepository,
    SessionRunRepository,
)
from ads.watchdog import Watchdog
from ads_commons.engine import EngineOutput


def emit(app: Litestar, output: EngineOutput, headers: Any = None) -> None:
    controller = app.state.engine_output_controller
    asyncio.run(controller.dispatch(output, headers))


def emit_raw(app: Litestar, raw: bytes, headers: Any = None) -> None:
    controller = app.state.engine_output_controller
    asyncio.run(controller.on_record(raw, headers))


def tick(app: Litestar, engine: Engine, settings: Settings, at: datetime) -> None:
    watchdog = Watchdog(
        session_factory_for(engine),
        app.state.engine_output,
        settings,
        clock=lambda: at,
    )
    asyncio.run(watchdog.tick(now=at))


def later(seconds: float) -> datetime:
    return utc_now() + timedelta(seconds=seconds)


def run_of(engine: Engine, session_id: uuid.UUID) -> SessionRun | None:
    with Session(engine) as session, session.begin():
        run = SessionRunRepository(session=session).in_flight_for_session(session_id)
        if run is None:
            return None
        session.expunge_all()
        return run


def runs_of(engine: Engine, session_id: uuid.UUID) -> list[SessionRun]:
    with Session(engine) as session, session.begin():
        rows = list(session.query(SessionRun).filter(SessionRun.session_id == session_id).all())
        session.expunge_all()
        return rows


def chat_of(engine: Engine, session_id: uuid.UUID) -> ChatSession:
    with Session(engine) as session, session.begin():
        row = SessionRepository(session=session).get_any(session_id)
        assert row is not None
        session.expunge_all()
        return row


def entries_of(engine: Engine, session_id: uuid.UUID) -> list[SessionEntry]:
    with Session(engine) as session, session.begin():
        chat = SessionRepository(session=session).get_any(session_id)
        assert chat is not None
        rows = SessionEntryRepository(session=session).walk(chat)
        session.expunge_all()
        return rows


def parts_of(engine: Engine, session_id: uuid.UUID) -> list[tuple[str, str | None, str]]:
    return [(row.kind, row.role, row.text) for row in entries_of(engine, session_id)]


def buffer_of(engine: Engine, run_id: uuid.UUID) -> list[SessionRunBuffer]:
    with Session(engine) as session, session.begin():
        rows = SessionRunBufferRepository(session=session).list_after(run_id, -1)
        session.expunge_all()
        return rows
