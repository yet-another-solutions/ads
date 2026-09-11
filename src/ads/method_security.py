from __future__ import annotations

from collections.abc import Callable
from typing import Any, TypeVar

import wrapt
from litestar.exceptions import NotAuthorizedException, PermissionDeniedException

from ads.security_context import SecurityContext

F = TypeVar("F", bound=Callable[..., Any])


def _security_context_from_call(
    args: tuple[Any, ...], kwargs: dict[str, Any]
) -> SecurityContext | None:
    for value in kwargs.values():
        if isinstance(value, SecurityContext):
            return value
    for value in args:
        if isinstance(value, SecurityContext):
            return value
    return None


def require_role(role: str) -> Callable[[F], F]:
    """wrapt advice: the call must include a SecurityContext that has ``role``."""

    @wrapt.decorator
    def wrapper(
        wrapped: Callable[..., Any],
        instance: Any,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> Any:
        context = _security_context_from_call(args, kwargs)
        if context is None:
            raise NotAuthorizedException(detail="authentication required")
        if not context.has_role(role):
            raise PermissionDeniedException(detail=f"role {role} required")
        return wrapped(*args, **kwargs)

    return wrapper  # type: ignore[return-value]
