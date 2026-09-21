from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from dishka import Provider, make_async_container
from litestar import Litestar, Request, get
from litestar.response import Response

from ads_commons_beans import CommonsBeansProvider
from ads_sandbox_ipc.config import Settings
from ads_sandbox_ipc.ioc import AppProvider
from ads_sandbox_ipc.kafka import KafkaRuntime
from ads_sandbox_ipc.service import IpcService


@get("/health/live", sync_to_thread=False)
def live() -> dict[str, str]:
    return {"status": "live"}


@get("/health/ready", sync_to_thread=False)
def ready(request: Request[Any, Any, Any]) -> Response[dict[str, str]]:
    ipc = request.app.state.ipc
    healthy = ipc.http_ready and not ipc.failed and (ipc.egress is None or not ipc.egress.failed)
    return Response(
        {"status": "ready" if healthy else "not-ready"}, status_code=200 if healthy else 503
    )


def create_app(settings: Settings, *, overrides: tuple[Provider, ...] = ()) -> Litestar:
    container = make_async_container(AppProvider(settings), CommonsBeansProvider(), *overrides)

    @asynccontextmanager
    async def lifecycle(app: Litestar) -> AsyncIterator[None]:
        try:
            runtime = await container.get(KafkaRuntime)
            app.state.ipc = await container.get(IpcService)
            await runtime.start()
            try:
                yield
            finally:
                await runtime.stop()
        finally:
            await container.close()

    return Litestar(route_handlers=[live, ready], lifespan=[lifecycle])
