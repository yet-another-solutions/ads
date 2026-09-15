from __future__ import annotations

import asyncio
import uuid
from datetime import timedelta

from aiokafka.abc import ConsumerRebalanceListener
from litestar import Litestar
from litestar.testing import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from ads.config import Settings
from ads.domain import utc_now
from ads.ioc import session_factory_for
from ads.kafka import SeekToEndListener, seek_assigned_to_end
from ads.models import STATUS_PENDING
from ads.repository import SessionRunRepository
from ads.watchdog import Watchdog
from ads_commons.engine import AssistantMessage, PartialResponse, Ping, encode_output
from tests.threadline_db import emit_raw, parts_of, run_of, runs_of
from tests.threadline_fakes import FakePreferences, RecordingKafka, login
from tests.threadline_flows import create_project, create_session, send


class _FakeConsumer:
    def __init__(self) -> None:
        self.seeks: list[tuple[str, int]] = []

    async def end_offsets(self, partitions: list[object]) -> dict[object, int]:
        return {partition: 42 for partition in partitions}

    def seek(self, partition: object, offset: int) -> None:
        self.seeks.append((str(partition), offset))


def test_output_consumer_seeks_assigned_partitions_to_end() -> None:
    consumer = _FakeConsumer()
    listener = SeekToEndListener(consumer)
    assert isinstance(listener, ConsumerRebalanceListener)
    asyncio.run(listener.on_partitions_assigned(["p0", "p1"]))
    assert sorted(consumer.seeks) == [("p0", 42), ("p1", 42)]
    asyncio.run(seek_assigned_to_end(consumer, []))
    assert len(consumer.seeks) == 2
    asyncio.run(SeekToEndListener(consumer).on_partitions_revoked(["p0"]))


def test_partial_for_an_unknown_session_is_dropped(app: Litestar, db_engine: Engine) -> None:
    stranger = uuid.uuid4()
    emit_raw(
        app,
        encode_output(
            PartialResponse(session_id=stranger, order=0, message=AssistantMessage(text="x"))
        ),
    )
    emit_raw(app, encode_output(Ping(session_id=stranger)))
    assert runs_of(db_engine, stranger) == []


def test_partial_without_a_primitive_is_ignored(
    client: TestClient,
    app: Litestar,
    db_engine: Engine,
    preferences: FakePreferences,
) -> None:
    model = preferences.seed()
    login(client)
    project = create_project(client)
    session_id = create_session(client, project)
    send(client, project, session_id, "hi", model.id)
    emit_raw(app, encode_output(PartialResponse(session_id=session_id, order=0)))
    run = run_of(db_engine, session_id)
    assert run is not None and run.watermark == -1
    assert parts_of(db_engine, session_id) == [("message", "user", "hi")]


def test_garbage_output_is_dropped(app: Litestar) -> None:
    emit_raw(app, b"not-json")
    emit_raw(app, b'{"type": "finish"}')
    emit_raw(app, b'{"type": "finish", "session_id": "not-a-uuid"}')


def test_watchdog_start_sweeps_stale_rows_then_stops(
    client: TestClient,
    app: Litestar,
    db_engine: Engine,
    settings: Settings,
    kafka: RecordingKafka,
    preferences: FakePreferences,
) -> None:
    model = preferences.seed()
    login(client)
    project = create_project(client)
    session_id = create_session(client, project)
    send(client, project, session_id, "hi", model.id)
    _age(db_engine, session_id, seconds=45)

    watchdog = Watchdog(session_factory_for(db_engine), app.state.engine_output, settings)

    async def _cycle() -> None:
        await watchdog.start()
        await watchdog.stop()

    asyncio.run(_cycle())
    assert len(kafka.aborts) == 1
    assert runs_of(db_engine, session_id) == []
    assert parts_of(db_engine, session_id) == []


def _age(engine: Engine, session_id: uuid.UUID, seconds: float) -> None:
    with Session(engine) as session, session.begin():
        run = SessionRunRepository(session=session).in_flight_for_session(session_id)
        assert run is not None
        assert run.status == STATUS_PENDING
        run.last_event_at = utc_now() - timedelta(seconds=seconds)
