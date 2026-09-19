from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from dishka import Provider, make_async_container
from litestar import Litestar

from ads_commons_beans import CommonsBeansProvider, JwtVerifier
from ads_sandbox_mcp.config import Settings
from ads_sandbox_mcp.http import AdsAuthentication, live, mcp_endpoint, ready
from ads_sandbox_mcp.ioc import AppProvider
from ads_sandbox_mcp.runtime import McpRuntime


def create_app(settings: Settings, *, overrides: tuple[Provider, ...] = ()) -> Litestar:
    container = make_async_container(CommonsBeansProvider(), AppProvider(settings), *overrides)
    verifier = container.get_sync(JwtVerifier)

    @asynccontextmanager
    async def lifespan(app: Litestar) -> AsyncIterator[None]:
        try:
            # Resolve loop-bound resources at startup, never during main-thread assembly.
            runtime = await container.get(McpRuntime)
            app.state.runtime = runtime
            async with runtime.run():
                yield
        finally:
            await container.close()

    return Litestar(
        route_handlers=[live, ready, mcp_endpoint],
        lifespan=[lifespan],
        middleware=[lambda app: AdsAuthentication(app, verifier, settings.allowed_callers)],
        openapi_config=None,
    )
