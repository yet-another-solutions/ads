from __future__ import annotations

import secrets
from typing import Any

from dishka.integrations.litestar import FromDishka, inject
from litestar import Controller, get, post
from litestar.connection import ASGIConnection
from litestar.exceptions import ClientException, NotAuthorizedException, NotFoundException
from litestar.handlers import BaseRouteHandler

from ads_policy.contract import (
    DecisionRequest,
    PolicyDecision,
    Run,
    RunRequest,
    ToolCallRequest,
)
from ads_policy.isolation import UnknownPlacement
from ads_policy.service import PolicyService

BEARER = "Bearer "


def require_api_token(connection: ASGIConnection[Any, Any, Any, Any], _: BaseRouteHandler) -> None:
    expected = str(connection.app.state.api_token)
    header = connection.headers.get("authorization", "")
    if not header.startswith(BEARER):
        raise NotAuthorizedException(detail="bearer token required")
    if not secrets.compare_digest(header[len(BEARER) :], expected):
        raise NotAuthorizedException(detail="bearer token required")


class PolicyController(Controller):
    path = "/policy"
    guards = [require_api_token]

    @post("/runs")
    @inject
    async def start_run(self, data: RunRequest, service: FromDishka[PolicyService]) -> Run:
        try:
            return await service.start(data)
        except UnknownPlacement as exc:
            raise ClientException(detail=f"placement not confirmed: {exc}") from exc

    @get("/runs")
    @inject
    async def held_runs(self, holder: str, service: FromDishka[PolicyService]) -> list[Run]:
        if not holder:
            raise ClientException(detail="a holder is required")
        return await service.held_by(holder)

    @get("/runs/{run_id:str}")
    @inject
    async def run(self, run_id: str, service: FromDishka[PolicyService]) -> Run:
        found = await service.run(run_id)
        if found is None:
            raise NotFoundException(detail="no such run")
        return found

    @post("/runs/{run_id:str}/revoke")
    @inject
    async def revoke_run(self, run_id: str, service: FromDishka[PolicyService]) -> Run:
        run = await service.revoke(run_id)
        if run is None:
            raise NotFoundException(detail="no such run")
        return run

    @post("/runs/{run_id:str}/finish")
    @inject
    async def finish_run(self, run_id: str, service: FromDishka[PolicyService]) -> Run:
        run = await service.finish(run_id)
        if run is None:
            raise NotFoundException(detail="no such run")
        return run

    @post("/decide")
    @inject
    async def decide(
        self, data: DecisionRequest, service: FromDishka[PolicyService]
    ) -> PolicyDecision:
        return await service.decide(data)

    @post("/calls")
    @inject
    async def decide_call(
        self, data: ToolCallRequest, service: FromDishka[PolicyService]
    ) -> PolicyDecision:
        return await service.decide_call(data)

    @get("/version")
    @inject
    async def version(self, service: FromDishka[PolicyService]) -> dict[str, str]:
        return service.version()
