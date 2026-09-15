from __future__ import annotations

from typing import Any

from litestar import Controller, Request
from litestar.connection import ASGIConnection
from litestar.di import NamedDependency, Provide
from litestar.handlers import BaseRouteHandler
from litestar.response import Response
from litestar.types import ExceptionHandlersMap

from ads.identity import Identity, identity_from_session, security_context_from_identity
from ads.security_context import SecurityContext
from ads_commons.security import AccessDenied, AuthenticationRequired


def require_authenticated(
    connection: ASGIConnection[Any, Any, Any, Any], _: BaseRouteHandler
) -> None:
    if identity_from_session(connection.session) is None:
        raise AuthenticationRequired()


def provide_identity(request: Request[Any, Any, Any]) -> Identity:
    identity = identity_from_session(request.session)
    if identity is None:
        raise AuthenticationRequired()
    return identity


def provide_security_context(identity: NamedDependency[Identity]) -> SecurityContext:
    return security_context_from_identity(identity)


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
