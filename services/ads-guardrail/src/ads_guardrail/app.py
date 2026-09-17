from __future__ import annotations

import asyncio
import contextlib

import structlog
from dishka import AsyncContainer, make_async_container
from dishka.integrations.litestar import LitestarProvider, setup_dishka
from litestar import Litestar

from ads_commons.security import AccessTokenVerifier
from ads_guardrail.api import GuardrailController, McpController
from ads_guardrail.config import Settings
from ads_guardrail.health import live, ready
from ads_guardrail.ioc import AppProvider
from ads_guardrail.logconfig import configure_logging
from ads_guardrail.proxy import Proxy
from ads_policy.audit import AuditSink, BufferedAuditSink
from ads_policy.client import PolicyClient

logger = structlog.get_logger("ads.guardrail")


def create_app(
    settings: Settings,
    client: PolicyClient | None = None,
    sink: AuditSink | None = None,
    person_token_verifier: AccessTokenVerifier | None = None,
) -> Litestar:
    configure_logging()
    container = make_async_container(
        AppProvider(settings, client, sink, person_token_verifier), LitestarProvider()
    )
    flusher: list[asyncio.Task[None]] = []

    async def _start(app: Litestar) -> None:
        del app
        await _fail_fast_if_keycloak_is_unreachable(container)
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
        route_handlers=[McpController, GuardrailController, live, ready],
        state=None,
        on_startup=[_start],
        on_shutdown=[_stop],
    )
    app.state.api_token = settings.api_token
    setup_dishka(container, app)
    return app


async def _fail_fast_if_keycloak_is_unreachable(container: AsyncContainer) -> None:
    await container.get(Proxy)


async def _publish_audit(container: AsyncContainer, settings: Settings) -> None:
    audit = await container.get(BufferedAuditSink)
    while True:
        await asyncio.sleep(settings.audit_flush_seconds)
        try:
            await audit.drain()
        except Exception:
            logger.exception("audit backlog not drained", pending=len(audit.pending))
