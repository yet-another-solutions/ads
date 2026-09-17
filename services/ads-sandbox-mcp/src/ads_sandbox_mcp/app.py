from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any
from uuid import UUID

import anyio
from dishka import Provider, make_container
from litestar import Litestar, Request, Response, asgi, get
from litestar.enums import ScopeType
from litestar.types import ASGIApp, Receive, Scope, Send
from mcp.server import Server
from mcp.server.transport_security import TransportSecuritySettings
from sqlalchemy.ext.asyncio import AsyncEngine

from ads_commons.security import (
    AccessDenied,
    InvalidAccessToken,
    SecurityContextHolder,
    ensure_caller,
)
from ads_commons_beans import CommonsBeansProvider, JwtVerifier
from ads_sandbox_mcp.config import Settings
from ads_sandbox_mcp.controller import ToolController
from ads_sandbox_mcp.ioc import AppProvider
from ads_sandbox_mcp.kafka import KafkaRuntime
from ads_sandbox_mcp.scheduler import ClusterScheduler


class AdsAuthentication:
    def __init__(self, app: ASGIApp, verifier: JwtVerifier) -> None:
        self.app = app
        self._verifier = verifier

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != ScopeType.HTTP or scope["path"] in ("/health/live", "/health/ready"):
            await self.app(scope, receive, send)
            return
        headers = {k.decode().lower(): v.decode("latin1") for k, v in scope["headers"]}

        async def reject(status: int, detail: str) -> None:
            response = Response({"detail": detail}, status_code=status).to_asgi_response(
                None, Request(scope=scope, receive=receive, send=send)
            )
            await response(scope, receive, send)

        scheme, _, token = headers.get("authorization", "").partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            await reject(401, "unauthorized")
            return
        try:
            context = await asyncio.to_thread(self._verifier.authenticate, token.strip())
        except InvalidAccessToken:
            await reject(401, "unauthorized")
            return
        try:
            ensure_caller(context, "ads-engine")
        except AccessDenied:
            await reject(403, "forbidden")
            return
        with SecurityContextHolder.bound(context):
            try:
                session_id = UUID(headers.get("x-ads-session-id", ""))
                message_id = UUID(headers.get("x-ads-message-id", ""))
            except ValueError:
                await reject(400, "ADS session and message UUID headers are required")
                return
            # Deployment-level version gate only. MCP body validation and dispatch stay SDK-owned.
            if headers.get("mcp-protocol-version") != "2026-07-28":
                await reject(400, "MCP-Protocol-Version must be 2026-07-28")
                return
            with SecurityContextHolder.bound(
                context.with_attributes(session_id=session_id, message_id=message_id)
            ):
                await self.app(scope, receive, send)


@get("/health/live", sync_to_thread=False)
def live() -> dict[str, str]:
    return {"status": "ok"}


@get("/health/ready", sync_to_thread=False)
def ready(request: Request[Any, Any, Any]) -> Response[dict[str, str]]:
    healthy = request.app.state.kafka.ready()
    return Response(
        {"status": "ok" if healthy else "unavailable"}, status_code=200 if healthy else 503
    )


def create_app(settings: Settings, *, overrides: tuple[Provider, ...] = ()) -> Litestar:
    container = make_container(CommonsBeansProvider(), AppProvider(settings), *overrides)
    # Resolve Kafka beans inside the ASGI event loop, not on the main thread.
    verifier = container.get(JwtVerifier)

    @asynccontextmanager
    async def lifespan(app: Litestar) -> AsyncIterator[None]:
        tools = container.get(ToolController)
        sdk: Server[Any] = Server(
            "ads-sandbox-mcp",
            version="0.0.1",
            on_list_tools=tools.list_tools,
            on_call_tool=tools.call_tool,
        )
        sdk.streamable_http_app(
            json_response=True,
            stateless_http=True,
            max_request_body_size=max(4194304, settings.input_bytes * 6 + 65536),
            transport_security=TransportSecuritySettings(
                allowed_hosts=list(settings.allowed_hosts),
                allowed_origins=list(settings.allowed_origins),
            ),
        )
        app.state.sdk = sdk
        kafka = container.get(KafkaRuntime)
        scheduler = container.get(ClusterScheduler)
        app.state.kafka = kafka
        try:
            await kafka.start()
            try:
                await scheduler.start()
                async with sdk.session_manager.run():
                    yield
            finally:
                await scheduler.stop()
                await kafka.stop()
        finally:
            await container.get(AsyncEngine).dispose()
            container.close()

    @asgi("/mcp", copy_scope=True)
    async def mcp_endpoint(scope: Scope, receive: Receive, send: Send) -> None:
        # ASGI types differ between frameworks, but both implement the ASGI specification.
        sdk = scope["app"].state.sdk
        # SDK 2.2.0 watches disconnects on SSE, but not on its JSON-response path.
        # Forward ASGI events unchanged; never read/interpret the MCP body here.
        sender, receiver = anyio.create_memory_object_stream[Any](0)
        async with sender, receiver, anyio.create_task_group() as tasks:

            async def forward_connection() -> None:
                while True:
                    event = await receive()
                    if event["type"] == "http.disconnect":
                        tasks.cancel_scope.cancel()
                        return
                    await sender.send(event)

            tasks.start_soon(forward_connection)
            try:
                await sdk.session_manager.handle_request(scope, receiver.receive, send)
            finally:
                tasks.cancel_scope.cancel()

    return Litestar(
        route_handlers=[live, ready, mcp_endpoint],
        lifespan=[lifespan],
        middleware=[lambda app: AdsAuthentication(app, verifier)],
        openapi_config=None,
    )
