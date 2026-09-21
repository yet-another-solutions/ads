from __future__ import annotations

import uuid
from typing import Any

from dishka.integrations.litestar import FromDishka
from litestar import Controller, Request, get

from ads.config import Settings
from ads.session_service import SessionService
from ads.tokens import TokenAuthenticator
from ads.views import TranscriptView
from ads_commons.security import AuthenticationRequired, InvalidAccessToken, ensure_caller
from ads_commons_web.authenticated import AUTH_EXCEPTION_HANDLERS
from ads_commons_web.inject import inject
from ads_commons_web.security_holder import SecurityContextHolder

BEARER = "Bearer "


@inject
class AuditorController(Controller):
    """A chat read for the auditor's pages, with the auditor's own exchanged token."""

    path = "/auditor/sessions"
    exception_handlers = AUTH_EXCEPTION_HANDLERS
    sessions: FromDishka[SessionService]
    authenticator: FromDishka[TokenAuthenticator]
    settings: FromDishka[Settings]

    @get("/{session_id:uuid}/transcript")
    async def transcript(
        self, request: Request[Any, Any, Any], session_id: uuid.UUID
    ) -> TranscriptView:
        header = request.headers.get("authorization", "")
        if not header.startswith(BEARER):
            raise AuthenticationRequired("bearer token required")
        try:
            auditor = self.authenticator.authenticate(
                header[len(BEARER) :], audience=self.settings.keycloak_audience
            )
        except InvalidAccessToken as exc:
            raise AuthenticationRequired("invalid bearer token") from exc
        ensure_caller(auditor, self.settings.auditor_allowed_azp)
        with SecurityContextHolder.bound(auditor):
            return await self.sessions.transcript_for_auditor(session_id)
