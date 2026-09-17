from __future__ import annotations

import secrets
from typing import Any

import anyio.to_thread
import msgspec
from dishka.integrations.litestar import FromDishka, inject
from litestar import Controller, HttpMethod, Request, Response, get, post, route
from litestar.connection import ASGIConnection
from litestar.exceptions import (
    ClientException,
    HTTPException,
    NotAuthorizedException,
    NotFoundException,
    ServiceUnavailableException,
)
from litestar.handlers import BaseRouteHandler
from litestar.response import Stream

from ads_guardrail.contract import Opening
from ads_guardrail.guardrail import Guardrail, NotAPerson, RunNotOpen
from ads_guardrail.proxy import Proxy, UnknownServer, UpstreamUnavailable
from ads_policy.contract import PolicyDecision, Run, Site

BEARER_PREFIX = "Bearer "
MCP_PATH = "/mcp"
MCP_SOURCE_PREFIX = "mcp:"


class PermissionRequest(msgspec.Struct, frozen=True):
    run_id: str
    source: str
    tool: str
    arguments: dict[str, str]


def require_api_token(connection: ASGIConnection[Any, Any, Any, Any], _: BaseRouteHandler) -> None:
    expected = str(connection.app.state.api_token)
    header = connection.headers.get("authorization", "")
    if not header.startswith(BEARER_PREFIX):
        raise NotAuthorizedException(detail="bearer token required")
    if not secrets.compare_digest(header[len(BEARER_PREFIX) :], expected):
        raise NotAuthorizedException(detail="bearer token required")


class McpController(Controller):
    path = MCP_PATH

    @route(
        "/{server:str}",
        http_method=[HttpMethod.GET, HttpMethod.POST, HttpMethod.DELETE],
        status_code=200,
    )
    @inject
    async def relay(
        self, server: str, request: Request[Any, Any, Any], proxy: FromDishka[Proxy]
    ) -> Response[Any]:
        body = await request.body() if request.method == HttpMethod.POST else b""
        try:
            relayed = await proxy.handle(request.method, server, body, dict(request.headers))
        except UnknownServer as exc:
            raise NotFoundException(detail=f"no MCP server named {server!r}") from exc
        except UpstreamUnavailable as exc:
            raise HTTPException(
                status_code=502, detail=f"MCP server {server!r} did not answer"
            ) from exc
        headers = {k: v for k, v in relayed.headers.items() if k != "content-type"}
        if isinstance(relayed.body, bytes):
            return Response(
                content=relayed.body,
                status_code=relayed.status,
                headers=headers,
                media_type=relayed.media_type,
            )
        return Stream(
            relayed.body,
            status_code=relayed.status,
            headers=headers,
            media_type=relayed.media_type,
        )


class GuardrailController(Controller):
    path = "/guardrail"
    guards = [require_api_token]

    @post("/runs")
    @inject
    async def open_run(self, data: Opening, guardrail: FromDishka[Guardrail]) -> Run:
        try:
            return await anyio.to_thread.run_sync(guardrail.open_run, data)
        except NotAPerson as exc:
            raise ClientException(detail=str(exc)) from exc

    @get("/runs/{run_id:str}")
    @inject
    async def run(self, run_id: str, guardrail: FromDishka[Guardrail]) -> Run:
        try:
            found = await anyio.to_thread.run_sync(guardrail.find_run, run_id)
        except RunNotOpen as exc:
            raise ServiceUnavailableException(detail=str(exc)) from exc
        if found is None:
            raise NotFoundException(detail="no such run")
        return found

    @post("/runs/{run_id:str}/finish", status_code=200)
    @inject
    async def finish_run(self, run_id: str, guardrail: FromDishka[Guardrail]) -> Run:
        try:
            finished = await anyio.to_thread.run_sync(guardrail.finish_run, run_id)
        except RunNotOpen as exc:
            raise ServiceUnavailableException(detail=str(exc)) from exc
        if finished is None:
            raise NotFoundException(detail="no such run")
        return finished

    @post("/permissions")
    @inject
    async def permission(
        self, data: PermissionRequest, guardrail: FromDishka[Guardrail]
    ) -> PolicyDecision:
        try:
            return await anyio.to_thread.run_sync(_decide_permission_request, guardrail, data)
        except RunNotOpen as exc:
            raise ServiceUnavailableException(detail=str(exc)) from exc


def _decide_permission_request(guardrail: Guardrail, data: PermissionRequest) -> PolicyDecision:
    run = guardrail.get_run(data.run_id)
    site = _site_of_source(guardrail, data.source)
    return guardrail.decide_tool_call(run, data.source, data.tool, data.arguments, site=site)


def _site_of_source(guardrail: Guardrail, source: str) -> Site | None:
    if not source.startswith(MCP_SOURCE_PREFIX):
        return None
    server_name = source.removeprefix(MCP_SOURCE_PREFIX)
    for server in guardrail.settings.mcp_servers:
        if server.name == server_name:
            return server.site
    return None


__all__ = ["MCP_PATH", "GuardrailController", "McpController", "Opening", "PermissionRequest"]
