from __future__ import annotations

import functools
import inspect
from collections.abc import Callable, Collection
from typing import Any, TypeVar

from ads_commons.security.context import SecurityContext
from ads_commons.security.holder import AccessDenied, SecurityContextHolder

F = TypeVar("F", bound=Callable[..., Any])


def ensure_caller(context: SecurityContext, *allowed: str) -> None:
    """Raise AccessDenied unless ``context`` was issued for an allowed caller."""
    if not allowed or not context.has_caller(*allowed):
        raise AccessDenied("caller is not allowed")


def check_caller(*allowed: str) -> SecurityContext:
    """Require a bound SecurityContext whose authorized party is allowed."""
    context = SecurityContextHolder.require()
    ensure_caller(context, *allowed)
    return context


def require_caller(*allowed: str) -> Callable[[F], F]:
    """Deny the call unless the bound caller is in ``allowed``.

    With no arguments, ``instance.allowed_callers`` is the allowlist.
    """

    def decorator(fn: F) -> F:
        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                _enforce_caller(args, allowed)
                return await fn(*args, **kwargs)

            return async_wrapper  # type: ignore[return-value]

        @functools.wraps(fn)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            _enforce_caller(args, allowed)
            return fn(*args, **kwargs)

        return sync_wrapper  # type: ignore[return-value]

    return decorator


def _enforce_caller(args: tuple[Any, ...], allowed: tuple[str, ...]) -> None:
    parties: Collection[str] = allowed
    if not parties:
        instance = args[0] if args else None
        configured = getattr(instance, "allowed_callers", None)
        if not configured:
            raise AccessDenied("no allowed callers configured")
        parties = configured
    check_caller(*parties)
