"""Deterministic runtime, not the prompt: ping death and the gapped-finish deadline."""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import structlog
from sqlalchemy.orm import Session

from ads.config import Settings
from ads.domain import utc_now
from ads.engine_output_service import EngineOutputService
from ads.models import STATUS_FINISHING, STATUS_PENDING, STATUS_RUNNING
from ads.repository import SessionRunRepository

log = structlog.get_logger("ads.watchdog")

SessionFactory = Callable[[], Session]
Clock = Callable[[], datetime]


class Watchdog:
    """1s tick. Aborts ping death, kills a gapped finish that never filled."""

    def __init__(
        self,
        session_factory: SessionFactory,
        service: EngineOutputService,
        settings: Settings,
        clock: Clock = utc_now,
    ) -> None:
        self._session_factory = session_factory
        self._service = service
        self._settings = settings
        self._clock = clock
        self._task: asyncio.Task[None] | None = None

    async def tick(self, now: datetime | None = None) -> None:
        moment = now if now is not None else self._clock()
        dead, gapped = self._due(moment)
        for run_id in dead:
            await self._service.abort_and_break(run_id)
        for run_id in gapped:
            await self._service.break_run(run_id, "gapped finish timed out")

    def _due(self, now: datetime) -> tuple[list[uuid.UUID], list[uuid.UUID]]:
        ping_deadline = timedelta(seconds=self._settings.ping_death_seconds)
        finish_deadline = timedelta(seconds=self._settings.finish_gap_seconds)
        dead: list[uuid.UUID] = []
        gapped: list[uuid.UUID] = []
        session = self._session_factory()
        try:
            with session.begin():
                for run in SessionRunRepository(session=session).all_in_flight():
                    if run.status in (STATUS_PENDING, STATUS_RUNNING):
                        if _aware(run.last_event_at) + ping_deadline <= now:
                            dead.append(run.id)
                        continue
                    if run.status != STATUS_FINISHING or run.finish_at is None:
                        continue
                    complete = run.last_order is not None and run.watermark >= run.last_order
                    if not complete and _aware(run.finish_at) + finish_deadline <= now:
                        gapped.append(run.id)
        finally:
            session.close()
        return dead, gapped

    async def run_forever(self) -> None:
        while True:
            await asyncio.sleep(self._settings.watchdog_tick_seconds)
            try:
                await self.tick()
            except Exception as exc:  # a tick must never kill the loop
                log.warning("watchdog_tick_failed", error=str(exc))

    async def start(self) -> None:
        """Process start also sweeps stale pending/running and gapped finishing rows."""
        if self._task is not None:
            return
        try:
            await self.tick()
        except Exception as exc:  # pragma: no cover - startup sweep is best effort
            log.warning("watchdog_start_failed", error=str(exc))
        self._task = asyncio.create_task(self.run_forever())

    async def stop(self) -> None:
        task = self._task
        self._task = None
        if task is None:
            return
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            return


def _aware(value: datetime) -> datetime:
    """SQLite hands back naive datetimes; compare in UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value
