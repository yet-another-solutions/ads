from __future__ import annotations

import dataclasses
import secrets
from collections.abc import Awaitable, Sequence
from datetime import datetime, tzinfo
from typing import Any
from zoneinfo import ZoneInfo

import msgspec
from dishka.integrations.litestar import FromDishka, inject
from litestar import Controller, delete, get
from litestar.connection import ASGIConnection
from litestar.exceptions import ClientException, NotAuthorizedException, NotFoundException
from litestar.handlers import BaseRouteHandler

from ads_audit.blocking import ConversationGuard
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


def requested_zone(name: str | None) -> tzinfo | None:
    if name is None:
        return None
    try:
        return ZoneInfo(name)
    except (KeyError, ValueError) as exc:
        raise ClientException(detail=f"unknown time zone: {name}") from exc


def shown_in(zone: tzinfo | None, events: Sequence[AuditEvent]) -> tuple[AuditEvent, ...]:
    if zone is None:
        return tuple(events)
    return tuple(
        msgspec.structs.replace(event, recorded_at=event.recorded_at.astimezone(zone))
        for event in events
    )


def moment_in(zone: tzinfo | None, moment: datetime | None) -> str | None:
    if moment is None:
        return None
    return moment.isoformat() if zone is None else moment.astimezone(zone).isoformat()


async def _paged(page: Awaitable[Page]) -> Page:
    try:
        return await page
    except ValueError as exc:
        raise ClientException(detail=f"unreadable cursor: {exc}") from exc


def _page_shown_in(zone: tzinfo | None, page: Page) -> Page:
    return dataclasses.replace(page, events=shown_in(zone, page.events))


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
        tz: str | None = None,
    ) -> Page:
        zone = requested_zone(tz)
        return _page_shown_in(zone, await _paged(service.journal(limit, cursor)))

    @get("/runs/{run_id:str}")
    @inject
    async def run_events(
        self,
        run_id: str,
        service: FromDishka[AuditService],
        limit: int = 100,
        cursor: str | None = None,
        tz: str | None = None,
    ) -> Page:
        zone = requested_zone(tz)
        return _page_shown_in(zone, await _paged(service.for_run(run_id, limit, cursor)))

    @get("/subjects/{subject:str}")
    @inject
    async def subject_events(
        self,
        subject: str,
        service: FromDishka[AuditService],
        limit: int = 100,
        cursor: str | None = None,
        tz: str | None = None,
    ) -> Page:
        zone = requested_zone(tz)
        return _page_shown_in(zone, await _paged(service.for_subject(subject, limit, cursor)))

    @get("/conversations/{conversation:str}")
    @inject
    async def conversation_events(
        self,
        conversation: str,
        service: FromDishka[AuditService],
        limit: int = 100,
        cursor: str | None = None,
        tz: str | None = None,
    ) -> Page:
        zone = requested_zone(tz)
        return _page_shown_in(
            zone, await _paged(service.for_conversation(conversation, limit, cursor))
        )

    @get("/conversations/{conversation:str}/budget")
    @inject
    async def conversation_budget(
        self, conversation: str, service: FromDishka[AuditService], tz: str | None = None
    ) -> dict[str, object]:
        zone = requested_zone(tz)
        block = await service.conversation_block(conversation)
        standing = block if block is not None and block.in_force else None
        return {
            "conversation": conversation,
            "budget": await service.budget_for_conversation(conversation),
            "blocked_at": None if standing is None else moment_in(zone, standing.blocked_at),
            "lifted_at": None if block is None else moment_in(zone, block.lifted_at),
            "lifted_by": "" if block is None else block.lifted_by,
        }

    @delete("/conversations/{conversation:str}/block", status_code=200)
    @inject
    async def lift_conversation_block(
        self,
        conversation: str,
        by: str,
        service: FromDishka[AuditService],
        guard: FromDishka[ConversationGuard],
        tz: str | None = None,
    ) -> dict[str, object]:
        if not by.strip():
            raise ClientException(detail="who lifts the block is required")
        zone = requested_zone(tz)
        lifted = await service.lift_conversation_block(conversation, by.strip())
        if lifted is None:
            raise NotFoundException(detail="no block to lift")
        await guard.tell_policy_to_lift(lifted)
        return {
            "conversation": lifted.conversation,
            "blocked_at": moment_in(zone, lifted.blocked_at),
            "lifted_at": moment_in(zone, lifted.lifted_at),
            "lifted_by": lifted.lifted_by,
            "budget": lifted.lifted_budget,
        }

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
