from __future__ import annotations

import secrets
from typing import Any

import anyio.to_thread
import msgspec
from dishka.integrations.litestar import FromDishka, inject
from litestar import Controller, get, post
from litestar.connection import ASGIConnection
from litestar.exceptions import NotAuthorizedException, ServiceUnavailableException
from litestar.handlers import BaseRouteHandler

from ads_policy.contract import PolicyDecision, Run
from ads_supervisor.supervisor import RunNotOpen, Supervisor

BEARER = "Bearer "


class PermissionRequest(msgspec.Struct, frozen=True):
    """What an agent asks before it executes a tool, in the agent's own words.

    No capability here: naming it would mean this side translating, and the binding
    that does the translating is policy, versioned with the run.

    ``arguments`` is required and may be empty: a call that sends nothing outbound
    says so, rather than leaving "not checked" and "nothing to check" the same state.
    """

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


class SupervisorController(Controller):
    """The only door through the boundary, and the agent is on the other side of it."""

    path = "/supervisor"
    guards = [require_api_token]

    @get("/run")
    @inject
    async def current_run(self, supervisor: FromDishka[Supervisor]) -> Run:
        if supervisor.run is None:
            raise ServiceUnavailableException(detail="no run has been opened")
        return supervisor.run

    @post("/permissions")
    @inject
    async def permission(
        self, data: PermissionRequest, supervisor: FromDishka[Supervisor]
    ) -> PolicyDecision:
        try:
            # The policy client is synchronous, and a hung policy service must not
            # take the event loop down with it — health probes answer from here too.
            return await anyio.to_thread.run_sync(
                supervisor.permit, data.source, data.tool, data.arguments
            )
        except RunNotOpen as exc:
            raise ServiceUnavailableException(detail=str(exc)) from exc
