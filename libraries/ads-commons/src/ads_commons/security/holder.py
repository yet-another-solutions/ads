from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar, Token

from ads_commons.security.context import SecurityContext

_current: ContextVar[SecurityContext | None] = ContextVar("ads_security_context", default=None)


class AuthenticationRequired(Exception):
    """No SecurityContext is bound to the current work."""

    def __init__(self, detail: str = "authentication required") -> None:
        super().__init__(detail)
        self.detail = detail


class SecurityContextHolder:
    """Current SecurityContext for this request or detached work."""

    @staticmethod
    def get() -> SecurityContext | None:
        return _current.get()

    @staticmethod
    def require() -> SecurityContext:
        context = _current.get()
        if context is None:
            raise AuthenticationRequired()
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
    def capture() -> SecurityContext:
        """Snapshot the holder. Forked work must capture while the session is alive."""
        context = _current.get()
        if context is None:
            raise AuthenticationRequired()
        return context

    @staticmethod
    @contextmanager
    def detached() -> Iterator[SecurityContext]:
        """Fork: pick context while the session is alive, bind it for detached work."""
        with SecurityContextHolder.bound(SecurityContextHolder.capture()) as context:
            yield context
