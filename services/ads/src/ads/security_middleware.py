from __future__ import annotations

from collections.abc import Mapping

from litestar.enums import ScopeType
from litestar.types import ASGIApp, Receive, Scope, Send

from ads.identity import security_context_from_session
from ads.security_holder import SecurityContextHolder

_BOUND_SCOPES = frozenset({ScopeType.HTTP, ScopeType.WEBSOCKET})


class SecurityContextMiddleware:
    """Bind SecurityContextHolder from the cookie session for HTTP and WebSocket work."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in _BOUND_SCOPES:
            await self.app(scope, receive, send)
            return
        session = scope.get("session")
        context = security_context_from_session(session) if isinstance(session, Mapping) else None
        token = SecurityContextHolder.set(context)
        try:
            await self.app(scope, receive, send)
        finally:
            SecurityContextHolder.reset(token)
