from __future__ import annotations

import asyncio
import contextlib

import structlog
from dishka import AsyncContainer, make_async_container
from dishka.integrations.litestar import LitestarProvider, setup_dishka
from litestar import Litestar
from redis.asyncio import Redis

from ads_policy.api import PolicyController
from ads_policy.audit import AuditSink, BufferedAuditSink
from ads_policy.config import Settings, policy_document_path
from ads_policy.health import live, ready
from ads_policy.ioc import AppProvider
from ads_policy.logconfig import configure_logging
from ads_policy.pdp import PolicyDecisionPoint
from ads_policy.policy import reload_policy

logger = structlog.get_logger("ads.policy")


def create_app(
    settings: Settings, redis: Redis | None = None, sink: AuditSink | None = None
) -> Litestar:
    configure_logging()
    container = make_async_container(AppProvider(settings, redis, sink), LitestarProvider())
    flusher: list[asyncio.Task[None]] = []

    async def _start(app: Litestar) -> None:
        del app
        flusher.append(asyncio.create_task(_publish_audit(container, settings)))
        flusher.append(asyncio.create_task(_watch_policy(container, settings)))

    async def _stop(app: Litestar) -> None:
        del app
        for task in flusher:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        await (await container.get(BufferedAuditSink)).drain()
        await container.close()

    app = Litestar(
        route_handlers=[PolicyController, live, ready],
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
        if audit.lost:
            logger.warning(
                "decisions made without a journal entry",
                lost=audit.lost,
                pending=len(audit.pending),
            )


async def _watch_policy(container: AsyncContainer, settings: Settings) -> None:
    pdp = await container.get(PolicyDecisionPoint)
    while True:
        await asyncio.sleep(settings.policy_reload_seconds)
        try:
            published = await asyncio.to_thread(
                reload_policy, pdp, policy_document_path(settings), settings.policy_defaults
            )
        except Exception:
            logger.exception("delivered policy not readable, keeping the current version")
            continue
        if published is not None:
            logger.info("policy reloaded", policy_hash=published, version=pdp.policy.version)
