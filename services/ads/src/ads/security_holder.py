from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar, Token
from typing import Any

from litestar.exceptions import NotAuthorizedException

from ads.identity import identity_from_session, security_context_from_identity
from ads.security_context import SecurityContext

_current: ContextVar[SecurityContext | None] = ContextVar("ads_security_context", default=None)


class SecurityContextHolder:
    """Current SecurityContext for this HTTP request or detached work."""

    @staticmethod
    def get() -> SecurityContext | None:
        return _current.get()

    @staticmethod
    def require() -> SecurityContext:
        context = _current.get()
        if context is None:
            raise NotAuthorizedException(detail="authentication required")
        return context

    @staticmethod
    def set(context: SecurityContext | None) -> Token[SecurityContext | None]:
        return _current.set(context)

    @staticmethod
    def reset(token: Token[SecurityContext | None]) -> None:
        _current.reset(token)

    @staticmethod
    @contextmanager
    def bound(context: SecurityContext) -> Iterator[SecurityContext]:
        token = _current.set(context)
        try:
            yield context
        finally:
            _current.reset(token)

    @staticmethod
    def capture(session: Mapping[str, Any] | None = None) -> SecurityContext:
        """Snapshot the holder, or the live session if the holder is empty."""
        context = _current.get()
        if context is not None:
            return context
        if session is not None:
            identity = identity_from_session(session)
            if identity is not None:
                return security_context_from_identity(identity)
        raise NotAuthorizedException(detail="authentication required")

    @staticmethod
    @contextmanager
    def detached(session: Mapping[str, Any] | None = None) -> Iterator[SecurityContext]:
        """Fork: pick context while the session is alive, bind it for detached work."""
        with SecurityContextHolder.bound(SecurityContextHolder.capture(session)) as context:
            yield context
