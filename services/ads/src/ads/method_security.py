from __future__ import annotations

from collections.abc import Callable
from typing import Any, TypeVar

import wrapt

from ads.security_holder import SecurityContextHolder
from ads_commons.security import AccessDenied

F = TypeVar("F", bound=Callable[..., Any])


def require_role(role: str) -> Callable[[F], F]:
    """wrapt advice: SecurityContextHolder must have ``role``."""

    @wrapt.decorator
    def wrapper(
        wrapped: Callable[..., Any],
        instance: Any,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> Any:
        del instance
        context = SecurityContextHolder.require()
        if not context.has_role(role):
            raise AccessDenied(f"role {role} required")
        return wrapped(*args, **kwargs)

    return wrapper  # type: ignore[return-value]
