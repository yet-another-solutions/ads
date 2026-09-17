from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from dishka import Provider, make_async_container
from litestar import Litestar, Request, get
from litestar.response import Response

from ads_commons_beans import CommonsBeansProvider
from ads_sandbox_manager.config import Settings
from ads_sandbox_manager.ioc import AppProvider
from ads_sandbox_manager.runtime import ManagerRuntime


@get("/health/live", sync_to_thread=False)
def live() -> dict[str, str]:
    return {"status": "live"}


@get("/health/ready", sync_to_thread=False)
def ready(request: Request[Any, Any, Any]) -> Response[dict[str, str]]:
    healthy = request.app.state.manager.ready
    return Response(
        {"status": "ready" if healthy else "not-ready"}, status_code=200 if healthy else 503
    )


def create_app(settings: Settings, *, overrides: tuple[Provider, ...] = ()) -> Litestar:
    container = make_async_container(CommonsBeansProvider(), AppProvider(settings), *overrides)

    @asynccontextmanager
    async def lifecycle(app: Litestar) -> AsyncIterator[None]:
        try:
            runtime = await container.get(ManagerRuntime)
            app.state.manager = runtime
            await runtime.start()  # Never block HTTPS probes waiting for a bake.
            try:
                yield
            finally:
                await runtime.stop()
        finally:
            await container.close()

    return Litestar(route_handlers=[live, ready], lifespan=[lifecycle], openapi_config=None)
