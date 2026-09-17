from __future__ import annotations

import secrets
from collections.abc import Sequence
from typing import Any

from dishka.integrations.litestar import FromDishka, inject
from litestar import Controller, get
from litestar.connection import ASGIConnection
from litestar.exceptions import ClientException, NotAuthorizedException
from litestar.handlers import BaseRouteHandler

from ads_audit.repository import Page
from ads_audit.service import AuditService
from ads_policy.contract import AuditEvent

BEARER = "Bearer "


def require_api_token(connection: ASGIConnection[Any, Any, Any, Any], _: BaseRouteHandler) -> None:
    expected = str(connection.app.state.api_token)
    header = connection.headers.get("authorization", "")
    if not header.startswith(BEARER):
        raise NotAuthorizedException(detail="bearer token required")
    if not secrets.compare_digest(header[len(BEARER) :], expected):
        raise NotAuthorizedException(detail="bearer token required")


class AuditController(Controller):
    path = "/audit"
    guards = [require_api_token]

    @get("/events")
    @inject
    async def journal(
        self,
        service: FromDishka[AuditService],
        limit: int = 100,
        cursor: str | None = None,
    ) -> Page:
        try:
            return await service.journal(limit, cursor)
        except ValueError as exc:
            raise ClientException(detail=f"unreadable cursor: {exc}") from exc

    @get("/runs/{run_id:str}")
    @inject
    async def run_events(
        self, run_id: str, service: FromDishka[AuditService]
    ) -> Sequence[AuditEvent]:
        return await service.for_run(run_id)

    @get("/subjects/{subject:str}")
    @inject
    async def subject_events(
        self, subject: str, service: FromDishka[AuditService]
    ) -> Sequence[AuditEvent]:
        return await service.for_subject(subject)

    @get("/runs/{run_id:str}/budget")
    @inject
    async def run_budget(self, run_id: str, service: FromDishka[AuditService]) -> dict[str, object]:
        return {"run_id": run_id, "budget": await service.budget_for_run(run_id)}

    @get("/subjects/{subject:str}/budget")
    @inject
    async def subject_budget(
        self, subject: str, service: FromDishka[AuditService]
    ) -> dict[str, object]:
        return {"subject": subject, "budget": await service.budget_for_subject(subject)}
