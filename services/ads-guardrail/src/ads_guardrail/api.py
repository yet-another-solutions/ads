from __future__ import annotations

import secrets
from typing import Any

import anyio.to_thread
import msgspec
from dishka.integrations.litestar import FromDishka, inject
from litestar import Controller, HttpMethod, Request, Response, post, route
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

from ads_guardrail.contract import Opening, Sandbox
from ads_guardrail.guardrail import Guardrail, NotAPerson, RunNotOpen
from ads_guardrail.proxy import Proxy, UnknownServer, UpstreamUnavailable
from ads_policy.contract import PolicyDecision, Run

BEARER = "Bearer "

#: Where an agent's MCP clients are pointed, one ``/mcp/<name>`` per server.
MCP_PATH = "/mcp"


class PermissionRequest(msgspec.Struct, frozen=True):
    """A tool call asked about directly, for an agent with no HTTP to intercept.

    The proxy is the usual way in. This exists for a caller that reaches the PEP by
    hand — a loop that dispatches its tools in-process, where there is no request to
    stand in front of.

    No capability here: naming it would mean this side translating, and the binding
    that does the translating is policy, versioned with the run.
    """

    run_id: str
    source: str
    tool: str
    arguments: dict[str, str]


def require_api_token(connection: ASGIConnection[Any, Any, Any, Any], _: BaseRouteHandler) -> None:
    expected = str(connection.app.state.api_token)
    header = connection.headers.get("authorization", "")
    if not header.startswith(BEARER):
        raise NotAuthorizedException(detail="bearer token required")
    if not secrets.compare_digest(header[len(BEARER) :], expected):
        raise NotAuthorizedException(detail="bearer token required")


class McpController(Controller):
    """Stands where the MCP servers used to be. An agent knows only the URL."""

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
        """The three methods of MCP's Streamable HTTP transport, on one path."""
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
    """The decision API, for callers that ask rather than being proxied."""

    path = "/guardrail"
    guards = [require_api_token]

    @post("/runs")
    @inject
    async def open_run(self, data: Opening, guardrail: FromDishka[Guardrail]) -> Run:
        """Whoever creates an agent's sandbox opens a run for each task put in it.

        The API token is what makes the placement believable: the agent must not hold
        it, or it could open a run somewhere it is not. Who the run is for comes from
        the person's own token, which has to verify.
        """
        try:
            return await anyio.to_thread.run_sync(guardrail.open, data)
        except NotAPerson as exc:
            raise ClientException(detail=str(exc)) from exc

    @post("/runs/{run_id:str}/finish", status_code=200)
    @inject
    async def finish_run(self, run_id: str, guardrail: FromDishka[Guardrail]) -> Run:
        """The task is over. Without this a run lingers until its lifetime ends, and the
        next task on the same credentials would find two."""
        try:
            finished = await anyio.to_thread.run_sync(guardrail.finish, run_id)
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
            # The policy client is synchronous, and a hung policy service must not
            # take the event loop down with it — health probes answer from here too.
            return await anyio.to_thread.run_sync(_permit, guardrail, data)
        except RunNotOpen as exc:
            raise ServiceUnavailableException(detail=str(exc)) from exc


def _permit(guardrail: Guardrail, data: PermissionRequest) -> PolicyDecision:
    run = guardrail.run(data.run_id)
    return guardrail.permit(run, data.source, data.tool, data.arguments)


__all__ = [
    "MCP_PATH",
    "GuardrailController",
    "McpController",
    "Opening",
    "PermissionRequest",
    "Sandbox",
]
