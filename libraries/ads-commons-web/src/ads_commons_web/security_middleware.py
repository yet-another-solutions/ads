from __future__ import annotations

from collections.abc import MutableMapping

from litestar.enums import ScopeType
from litestar.types import ASGIApp, Receive, Scope, Send

from ads_commons.security import SecurityContext
from ads_commons_web.security_holder import SecurityContextHolder
from ads_commons_web.session_binder import SessionBinder

_BOUND_SCOPES = frozenset({ScopeType.HTTP, ScopeType.WEBSOCKET})


class SecurityContextMiddleware:
    """Bind SecurityContextHolder from the cookie access token for HTTP and WebSocket work."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in _BOUND_SCOPES:
            await self.app(scope, receive, send)
            return
        session = scope.get("session")
        context: SecurityContext | None = None
        binder = await self._binder(scope)
        if binder is not None and isinstance(session, MutableMapping):
            context = await binder.bind(session)
        token = SecurityContextHolder.set(context)
        try:
            await self.app(scope, receive, send)
        finally:
            SecurityContextHolder.reset(token)

    async def _binder(self, scope: Scope) -> SessionBinder | None:
        app = scope["app"]
        existing = getattr(app.state, "session_binder", None)
        if isinstance(existing, SessionBinder):
            return existing
        container = getattr(app.state, "dishka_container", None)
        if container is None:
            return None
        binder = await container.get(SessionBinder)
        if not isinstance(binder, SessionBinder):
            return None
        app.state.session_binder = binder
        return binder
