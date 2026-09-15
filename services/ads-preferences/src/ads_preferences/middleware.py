from __future__ import annotations

import json
import ssl
from typing import Any

from jwt import PyJWKClient
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
    jwks_uri_from_well_known,
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
        verifier: JwtVerifier | None = None,
    ) -> None:
        self.app = app
        self._settings = settings
        self._verifier = verifier
        self._loaded: JwtVerifier | None = None

    def _jwks_ssl_context(self) -> ssl.SSLContext | None:
        if self._settings.tls_ca_bundle is None:
            return None
        return ssl.create_default_context(cafile=str(self._settings.tls_ca_bundle))

    def verifier(self) -> JwtVerifier:
        if self._verifier is not None:
            return self._verifier
        if self._loaded is None:
            ssl_context = self._jwks_ssl_context()
            jwks_uri = jwks_uri_from_well_known(
                self._settings.keycloak_well_known_url,
                ssl_context=ssl_context,
            )
            self._loaded = JwtVerifier(
                issuer=self._settings.keycloak_issuer,
                audience=self._settings.keycloak_audience,
                client_id=self._settings.keycloak_client_id,
                jwks_client=PyJWKClient(jwks_uri, ssl_context=ssl_context),
            )
        return self._loaded

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
            context = self.verifier().authenticate(token)
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


def jwt_caller_middleware(settings: Settings, verifier: JwtVerifier | None = None) -> Any:
    def factory(app: ASGIApp) -> JwtCallerMiddleware:
        return JwtCallerMiddleware(app, settings=settings, verifier=verifier)

    return factory
