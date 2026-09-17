from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import anyio
import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from ads_sandbox_mcp.config import Settings
from ads_sandbox_mcp.store import InFlightRepository

log = structlog.get_logger("ads_sandbox_mcp")
GC_LOCK = 0x4144534D4350


class ClusterScheduler:
    """One pod holds the PostgreSQL advisory lock; failover follows connection loss."""

    def __init__(
        self, engine: AsyncEngine, repository: InFlightRepository, settings: Settings
    ) -> None:
        self._engine = engine
        self._repository = repository
        self._settings = settings
        self._task: asyncio.Task[None] | None = None

    async def tick(self, session: AsyncSession) -> None:
        await self._repository.collect(
            session,
            datetime.now(UTC) - timedelta(seconds=2 * self._settings.timeout_seconds),
        )

    async def run(self) -> None:
        while True:
            try:
                async with self._engine.connect() as connection:
                    leader = await connection.scalar(
                        text("SELECT pg_try_advisory_lock(:key)"), {"key": GC_LOCK}
                    )
                    await connection.commit()
                    if leader:
                        try:
                            while True:
                                await asyncio.sleep(self._settings.timeout_seconds)
                                async with AsyncSession(bind=connection) as session:
                                    async with session.begin():
                                        await self.tick(session)
                        finally:
                            with anyio.CancelScope(shield=True):
                                try:
                                    await connection.execute(
                                        text("SELECT pg_advisory_unlock(:key)"), {"key": GC_LOCK}
                                    )
                                    await connection.commit()
                                except BaseException:
                                    # Never return a session-locked connection to the pool.
                                    await connection.invalidate()
                                    raise
            except Exception:
                log.warning("gc_failed")
            await asyncio.sleep(self._settings.timeout_seconds)

    async def start(self) -> None:
        self._task = asyncio.create_task(self.run())

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
