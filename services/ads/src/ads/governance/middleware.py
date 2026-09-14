from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from litestar.enums import ScopeType
from litestar.types import ASGIApp, Receive, Scope, Send

from ads.governance.enforcement import Enforcer, EnforcerHolder


@dataclass(frozen=True, slots=True, eq=False)
class PolicyEnforcementMiddleware:
    """Bind an Enforcer for the request, then clear it."""

    app: ASGIApp
    provider: Callable[[Scope], Enforcer | None]

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != ScopeType.HTTP:
            await self.app(scope, receive, send)
            return
        token = EnforcerHolder.set(self.provider(scope))
        try:
            await self.app(scope, receive, send)
        finally:
            EnforcerHolder.reset(token)
