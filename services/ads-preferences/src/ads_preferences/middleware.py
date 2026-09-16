from __future__ import annotations

import json
from typing import Any

from litestar.enums import ScopeType
from litestar.types import (
    ASGIApp,
    HTTPResponseBodyEvent,
    HTTPResponseStartEvent,
    Receive,
    Scope,
    Send,
)

from ads_commons.security import (
    AccessDenied,
    InvalidAccessToken,
    SecurityContextHolder,
    ensure_caller,
)
from ads_commons_beans import JwtVerifier
from ads_preferences.config import Settings


def _header_map(scope: Scope) -> dict[str, str]:
    headers: dict[str, str] = {}
    for key, value in scope.get("headers", []):
        headers[key.decode("latin1").lower()] = value.decode("latin1")
    return headers


async def _send_json(send: Send, status: int, detail: str) -> None:
    body = json.dumps({"status_code": status, "detail": detail}).encode()
    start: HTTPResponseStartEvent = {
        "type": "http.response.start",
        "status": status,
        "headers": [(b"content-type", b"application/json")],
    }
    payload: HTTPResponseBodyEvent = {
        "type": "http.response.body",
        "body": body,
        "more_body": False,
    }
    await send(start)
    await send(payload)


class JwtCallerMiddleware:
    """Verify JWT, require caller azp, then bind. Health paths skip auth."""

    def __init__(
        self,
        app: ASGIApp,
        settings: Settings,
        verifier: JwtVerifier,
    ) -> None:
        self.app = app
        self._settings = settings
        self._verifier = verifier

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != ScopeType.HTTP:
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        if path.startswith("/health/"):
            await self.app(scope, receive, send)
            return
        authorization = _header_map(scope).get("authorization", "")
        scheme, _, remainder = authorization.partition(" ")
        token = remainder.strip()
        if scheme.lower() != "bearer" or not token:
            await _send_json(send, 401, "unauthorized")
            return
        try:
            context = self._verifier.authenticate(token)
        except InvalidAccessToken:
            await _send_json(send, 401, "unauthorized")
            return
        try:
            ensure_caller(context, *self._settings.allowed_callers)
        except AccessDenied:
            await _send_json(send, 403, "forbidden")
            return
        bound = SecurityContextHolder.set(context)
        try:
            await self.app(scope, receive, send)
        finally:
            SecurityContextHolder.reset(bound)


def jwt_caller_middleware(settings: Settings, verifier: JwtVerifier) -> Any:
    def factory(app: ASGIApp) -> JwtCallerMiddleware:
        return JwtCallerMiddleware(app, settings=settings, verifier=verifier)

    return factory
