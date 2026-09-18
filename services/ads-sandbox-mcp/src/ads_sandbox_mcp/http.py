"""ADS HTTP authentication and transparent SDK/disconnect adaptation."""

from __future__ import annotations

import asyncio
from typing import Any, cast
from uuid import UUID

import anyio
from litestar import Request, Response, asgi, get
from litestar.enums import ScopeType
from litestar.types import ASGIApp, Receive, Scope, Send

from ads_commons.security import (
    AccessDenied,
    InvalidAccessToken,
    SecurityContextHolder,
    ensure_caller,
)
from ads_commons_beans import JwtVerifier
from ads_sandbox_mcp.runtime import McpRuntime


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
    runtime = cast(McpRuntime, request.app.state.runtime)
    healthy = runtime.ready()
    return Response(
        {"status": "ok" if healthy else "unavailable"}, status_code=200 if healthy else 503
    )


@asgi("/mcp", copy_scope=True)
async def mcp_endpoint(scope: Scope, receive: Receive, send: Send) -> None:
    runtime = cast(McpRuntime, scope["app"].state.runtime)
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
            # Both frameworks implement ASGI; the SDK owns protocol dispatch.
            handle_request = cast(ASGIApp, runtime.sdk.session_manager.handle_request)
            await handle_request(scope, receiver.receive, send)
        finally:
            tasks.cancel_scope.cancel()
