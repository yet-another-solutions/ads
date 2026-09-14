from __future__ import annotations

import asyncio
import contextlib

import anyio.to_thread
import structlog
from dishka import AsyncContainer, make_async_container
from dishka.integrations.litestar import LitestarProvider, setup_dishka
from litestar import Litestar

from ads_policy.audit import AuditSink, BufferedAuditSink
from ads_policy.client import PolicyClient
from ads_supervisor.api import SupervisorController
from ads_supervisor.config import Settings
from ads_supervisor.health import live, ready
from ads_supervisor.ioc import AppProvider
from ads_supervisor.logconfig import configure_logging
from ads_supervisor.supervisor import Supervisor

logger = structlog.get_logger("ads.supervisor")


def create_app(
    settings: Settings,
    client: PolicyClient | None = None,
    sink: AuditSink | None = None,
) -> Litestar:
    """``client`` and ``sink`` let a caller bring their own, as tests do."""
    configure_logging()
    container = make_async_container(AppProvider(settings, client, sink), LitestarProvider())
    flusher: list[asyncio.Task[None]] = []

    async def _start(app: Litestar) -> None:
        del app
        supervisor = await container.get(Supervisor)
        await anyio.to_thread.run_sync(supervisor.open)
        flusher.append(asyncio.create_task(_publish_audit(container, settings)))

    async def _stop(app: Litestar) -> None:
        del app
        for task in flusher:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        await (await container.get(BufferedAuditSink)).drain()
        await container.close()

    app = Litestar(
        route_handlers=[SupervisorController, live, ready],
        state=None,
        on_startup=[_start],
        on_shutdown=[_stop],
    )
    app.state.api_token = settings.api_token
    setup_dishka(container, app)
    return app


async def _publish_audit(container: AsyncContainer, settings: Settings) -> None:
    audit = await container.get(BufferedAuditSink)
    while True:
        await asyncio.sleep(settings.audit_flush_seconds)
        try:
            await audit.drain()
        except Exception:
            logger.exception("audit backlog not drained", pending=len(audit.pending))
