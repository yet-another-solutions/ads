from __future__ import annotations

import asyncio
from collections.abc import Sequence
from typing import Any
from uuid import UUID

import msgspec
import structlog
from dishka.integrations.litestar import FromDishka
from litestar import Controller, Request, get

from ads.egress import EgressRequestService, SessionProjectService
from ads.inject import inject
from ads.tokens import TokenAuthenticator
from ads_commons.egress import EgressConfigMessage, EgressConfigRequest, SessionProjectBinding
from ads_commons.engine import authorization_token
from ads_commons.security import AuthenticationRequired, InvalidAccessToken, SecurityContextHolder

log = structlog.get_logger("ads.egress")


class EgressRequestController:
    def __init__(self, verifier: TokenAuthenticator, service: EgressRequestService) -> None:
        self.verifier, self.service = verifier, service

    async def on_record(
        self, raw: bytes, headers: Sequence[tuple[str | bytes, bytes | None]] | None
    ) -> None:
        try:
            message = msgspec.json.decode(raw, type=EgressConfigMessage)
            if not isinstance(message, EgressConfigRequest):
                return
            token = authorization_token(headers)
            if token is None:
                return
            context = await asyncio.to_thread(self.verifier.authenticate, token)
            with SecurityContextHolder.bound(context):
                await self.service.request(message)
        except Exception:
            log.warning("egress_configuration_request_rejected")


@inject
class SessionProjectController(Controller):
    path = "/internal/sessions"
    verifier: FromDishka[TokenAuthenticator]
    projects: FromDishka[SessionProjectService]

    @get("/{session_id:uuid}/project")
    async def session_project(
        self, request: Request[Any, Any, Any], session_id: UUID
    ) -> SessionProjectBinding:
        authorization = request.headers.get("authorization", "")
        if not authorization.startswith("Bearer ") or not authorization[7:].strip():
            raise AuthenticationRequired()
        try:
            context = await asyncio.to_thread(self.verifier.authenticate, authorization[7:])
        except InvalidAccessToken as exc:
            raise AuthenticationRequired() from exc
        with SecurityContextHolder.bound(context):
            return await self.projects.for_manager(session_id)
