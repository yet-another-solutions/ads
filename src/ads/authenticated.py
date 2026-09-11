from __future__ import annotations

from typing import Any

from litestar import Controller, Request
from litestar.connection import ASGIConnection
from litestar.di import NamedDependency, Provide
from litestar.handlers import BaseRouteHandler
from litestar.response import Redirect

from ads.identity import Identity, identity_from_session, security_context_from_identity
from ads.security_context import SecurityContext


class LoginRequired(Exception):
    """No session identity; the request layer redirects to /login."""


def handle_login_required(_request: Request[Any, Any, Any], _exc: LoginRequired) -> Redirect:
    return Redirect("/login")


def require_login(connection: ASGIConnection[Any, Any, Any, Any], _: BaseRouteHandler) -> None:
    if identity_from_session(connection.session) is None:
        raise LoginRequired


def provide_identity(request: Request[Any, Any, Any]) -> Identity:
    identity = identity_from_session(request.session)
    if identity is None:
        raise LoginRequired
    return identity


def provide_security_context(identity: NamedDependency[Identity]) -> SecurityContext:
    return security_context_from_identity(identity)


class AuthenticatedController(Controller):
    """Subclass this so handlers receive identity and security_context as arguments."""

    guards = [require_login]
    dependencies = {
        "identity": Provide(provide_identity, sync_to_thread=False),
        "security_context": Provide(provide_security_context, sync_to_thread=False),
    }
