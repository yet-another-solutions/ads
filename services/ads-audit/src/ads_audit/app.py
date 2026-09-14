from __future__ import annotations

import asyncio
import contextlib

import structlog
from aio_pika.abc import AbstractRobustConnection
from dishka import AsyncContainer, make_async_container
from dishka.integrations.litestar import LitestarProvider, setup_dishka
from litestar import Litestar
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from ads_audit.api import AuditController
from ads_audit.config import Settings
from ads_audit.consumer import AuditConsumer
from ads_audit.health import live, ready
from ads_audit.ioc import AppProvider
from ads_audit.logconfig import configure_logging
from ads_audit.repository import AuditRepository, fixed_unit_of_work, sql_unit_of_work
from ads_audit.schema import ensure_schema

logger = structlog.get_logger("ads.audit")


def create_app(
    settings: Settings,
    repository: AuditRepository | None = None,
    connection: AbstractRobustConnection | None = None,
) -> Litestar:
    """``repository`` and ``connection`` let a caller bring their own, as tests do."""
    configure_logging()
    container = make_async_container(
        AppProvider(settings, repository, connection), LitestarProvider()
    )

    keeper: list[asyncio.Task[None]] = []

    async def _prepare(app: Litestar) -> None:
        del app
        await _open_journal(container, settings, repository)
        if repository is None:
            keeper.append(asyncio.create_task(_keep_partitions(container, settings)))

    async def _stop(app: Litestar) -> None:
        del app
        for task in keeper:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        await container.close()

    app = Litestar(
        route_handlers=[AuditController, live, ready],
        state=None,
        on_startup=[_prepare],
        on_shutdown=[_stop],
    )
    app.state.api_token = settings.api_token
    setup_dishka(container, app)
    return app


async def _open_journal(
    container: AsyncContainer, settings: Settings, repository: AuditRepository | None
) -> None:
    if repository is None:
        engine = await container.get(AsyncEngine)
        async with engine.begin() as migration:
            await ensure_schema(migration, settings.partitions_ahead)
        sessions = await container.get(async_sessionmaker[AsyncSession])
        unit_of_work = sql_unit_of_work(sessions)
    else:
        unit_of_work = fixed_unit_of_work(repository)
    broker = await container.get(AbstractRobustConnection)
    await AuditConsumer(
        broker, unit_of_work, settings.prefetch, settings.nack_pause_seconds
    ).start()


async def _keep_partitions(container: AsyncContainer, settings: Settings) -> None:
    """Rows land in a partition or not at all, so the next ones are made in advance."""
    engine = await container.get(AsyncEngine)
    while True:
        await asyncio.sleep(settings.partition_check_seconds)
        try:
            async with engine.begin() as connection:
                await ensure_schema(connection, settings.partitions_ahead)
        except Exception:
            logger.exception("audit partitions not extended")
