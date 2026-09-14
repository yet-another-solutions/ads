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

from ads_policy.contract import Capability, PolicyDecision, Run
from ads_supervisor.supervisor import RunNotOpen, Supervisor

BEARER = "Bearer "


class PermissionRequest(msgspec.Struct, frozen=True):
    """What opencode asks before it executes a tool, named in our own vocabulary."""

    capability: Capability
    resource: str


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
            return await anyio.to_thread.run_sync(supervisor.permit, data.capability, data.resource)
        except RunNotOpen as exc:
            raise ServiceUnavailableException(detail=str(exc)) from exc
