from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import Token

from ads_commons.security import SecurityContext
from ads_commons.security import SecurityContextHolder as CommonsHolder


class SecurityContextHolder:
    """HTTP-facing holder. Identity is derived at bind, not read from the session cookie."""

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
    def capture() -> SecurityContext:
        return CommonsHolder.capture()

    @staticmethod
    @contextmanager
    def detached() -> Iterator[SecurityContext]:
        with CommonsHolder.detached() as context:
            yield context
