from __future__ import annotations

from typing import Any

from litestar import Controller, Request
from litestar.connection import ASGIConnection
from litestar.di import Provide
from litestar.handlers import BaseRouteHandler
from litestar.response import Response
from litestar.types import ExceptionHandlersMap

from ads_commons.security import AccessDenied, AuthenticationRequired
from ads_commons_web.identity import Identity, identity_from_security_context
from ads_commons_web.security_context import SecurityContext
from ads_commons_web.security_holder import SecurityContextHolder


def _bound_context() -> SecurityContext:
    context = SecurityContextHolder.get()
    if context is None or not context.access_token:
        raise AuthenticationRequired()
    return context


def require_authenticated(
    connection: ASGIConnection[Any, Any, Any, Any], _: BaseRouteHandler
) -> None:
    del connection
    _bound_context()


def provide_identity() -> Identity:
    return identity_from_security_context(_bound_context())


def provide_security_context() -> SecurityContext:
    return _bound_context()


def handle_authentication_required(
    request: Request[Any, Any, Any], exc: Exception
) -> Response[Any]:
    del request
    detail = exc.detail if isinstance(exc, AuthenticationRequired) else "authentication required"
    return Response(content={"status_code": 401, "detail": detail}, status_code=401)


def handle_access_denied(request: Request[Any, Any, Any], exc: Exception) -> Response[Any]:
    del request
    detail = exc.detail if isinstance(exc, AccessDenied) else "access denied"
    return Response(content={"status_code": 403, "detail": detail}, status_code=403)


AUTH_EXCEPTION_HANDLERS: ExceptionHandlersMap = {
    AuthenticationRequired: handle_authentication_required,
    AccessDenied: handle_access_denied,
}


class AuthenticatedController(Controller):
    """Backend (frontend-to-backend). 401 if not authenticated. Services may raise 403."""

    guards = [require_authenticated]
    exception_handlers = AUTH_EXCEPTION_HANDLERS
    dependencies = {
        "identity": Provide(provide_identity, sync_to_thread=False),
        "security_context": Provide(provide_security_context, sync_to_thread=False),
    }
