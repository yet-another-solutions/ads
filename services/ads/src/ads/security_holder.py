from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from contextvars import Token
from typing import Any

from ads.identity import identity_from_session, security_context_from_identity
from ads_commons.security import AuthenticationRequired, SecurityContext
from ads_commons.security import SecurityContextHolder as CommonsHolder


class SecurityContextHolder:
    """HTTP-facing holder. Capture may fall back to the session identity."""

    @staticmethod
    def get() -> SecurityContext | None:
        return CommonsHolder.get()

    @staticmethod
    def require() -> SecurityContext:
        return CommonsHolder.require()

    @staticmethod
    def set(context: SecurityContext | None) -> Token[SecurityContext | None]:
        return CommonsHolder.set(context)

    @staticmethod
    def reset(token: Token[SecurityContext | None]) -> None:
        CommonsHolder.reset(token)

    @staticmethod
    @contextmanager
    def bound(context: SecurityContext) -> Iterator[SecurityContext]:
        with CommonsHolder.bound(context) as bound_context:
            yield bound_context

    @staticmethod
    def capture(session: Mapping[str, Any] | None = None) -> SecurityContext:
        """Snapshot the holder, or session identity if the holder is empty."""
        context = CommonsHolder.get()
        if context is not None:
            return context
        if session is not None:
            identity = identity_from_session(session)
            if identity is not None:
                return security_context_from_identity(identity)
        raise AuthenticationRequired()

    @staticmethod
    @contextmanager
    def detached(session: Mapping[str, Any] | None = None) -> Iterator[SecurityContext]:
        """Fork: pick context while the HTTP session is alive, bind it for detached work."""
        with CommonsHolder.bound(SecurityContextHolder.capture(session)) as context:
            yield context
