from __future__ import annotations

import functools
import inspect
from collections.abc import Callable
from typing import Any, TypeVar

from ads_commons.security.context import SecurityContext
from ads_commons.security.holder import AccessDenied, SecurityContextHolder

F = TypeVar("F", bound=Callable[..., Any])


def ensure_role(context: SecurityContext, role: str) -> None:
    """Raise AccessDenied unless ``context`` has ``role``."""
    if not context.has_role(role):
        raise AccessDenied(f"role {role} required")


def check_role(role: str) -> SecurityContext:
    """Require a bound SecurityContext that has ``role``."""
    context = SecurityContextHolder.require()
    ensure_role(context, role)
    return context


def require_role(role: str) -> Callable[[F], F]:
    """Deny the call unless the bound identity has ``role``."""

    def decorator(fn: F) -> F:
        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                check_role(role)
                return await fn(*args, **kwargs)

            return async_wrapper  # type: ignore[return-value]

        @functools.wraps(fn)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            check_role(role)
            return fn(*args, **kwargs)

        return sync_wrapper  # type: ignore[return-value]

    return decorator
