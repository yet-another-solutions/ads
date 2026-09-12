from __future__ import annotations

from typing import Any

from litestar import Controller, Request
from litestar.connection import ASGIConnection
from litestar.di import NamedDependency, Provide
from litestar.exceptions import NotAuthorizedException
from litestar.handlers import BaseRouteHandler

from ads.identity import Identity, identity_from_session, security_context_from_identity
from ads.security_context import SecurityContext


def require_authenticated(
    connection: ASGIConnection[Any, Any, Any, Any], _: BaseRouteHandler
) -> None:
    if identity_from_session(connection.session) is None:
        raise NotAuthorizedException(detail="authentication required")


def provide_identity(request: Request[Any, Any, Any]) -> Identity:
    identity = identity_from_session(request.session)
    if identity is None:
        raise NotAuthorizedException(detail="authentication required")
    return identity


def provide_security_context(identity: NamedDependency[Identity]) -> SecurityContext:
    return security_context_from_identity(identity)


class AuthenticatedController(Controller):
    """Backend (frontend-to-backend). 401 if not authenticated. Services may raise 403."""

    guards = [require_authenticated]
    dependencies = {
        "identity": Provide(provide_identity, sync_to_thread=False),
        "security_context": Provide(provide_security_context, sync_to_thread=False),
    }
