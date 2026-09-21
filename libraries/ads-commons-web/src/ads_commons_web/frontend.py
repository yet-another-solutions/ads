from __future__ import annotations

from collections.abc import MutableMapping
from typing import Any

from litestar import Controller, Request
from litestar.connection import ASGIConnection
from litestar.di import Provide
from litestar.exceptions import MethodNotAllowedException
from litestar.handlers import BaseRouteHandler
from litestar.response import Redirect

from ads_commons_web.authenticated import provide_identity, provide_security_context
from ads_commons_web.security_holder import SecurityContextHolder

RETURN_TO_SESSION_KEY = "return_to"
_BLOCKED_RETURN_PATHS = frozenset({"/login", "/auth/callback", "/logout"})
_FRONTEND_METHODS = frozenset({"GET", "HEAD"})


class LoginRequired(Exception):
    """No bound access token; the frontend redirects to /login."""


def safe_return_to(value: object) -> str:
    if not isinstance(value, str):
        return "/"
    path = value.split("?", 1)[0]
    if (
        not value.startswith("/")
        or value.startswith("//")
        or "\\" in value
        or "://" in value
        or path in _BLOCKED_RETURN_PATHS
    ):
        return "/"
    return value


def return_to_from_request(request: Request[Any, Any, Any]) -> str:
    if request.method != "GET":
        return "/"
    path = request.url.path or "/"
    query = request.url.query
    candidate = f"{path}?{query}" if query else path
    return safe_return_to(candidate)


def pop_return_to(session: MutableMapping[str, Any]) -> str:
    return safe_return_to(session.pop(RETURN_TO_SESSION_KEY, None))


def handle_login_required(request: Request[Any, Any, Any], _exc: LoginRequired) -> Redirect:
    request.scope.setdefault("session", {})
    request.session[RETURN_TO_SESSION_KEY] = return_to_from_request(request)
    return Redirect("/login")


def require_frontend_login(
    connection: ASGIConnection[Any, Any, Any, Any], _: BaseRouteHandler
) -> None:
    method = str(connection.scope.get("method", ""))
    if method not in _FRONTEND_METHODS:
        raise MethodNotAllowedException()
    context = SecurityContextHolder.get()
    if context is None or not context.access_token:
        raise LoginRequired


class FrontendController(Controller):
    """HTML GET pages. Redirect to login, then back to the same URL. Never POST."""

    guards = [require_frontend_login]
    dependencies = {
        "identity": Provide(provide_identity, sync_to_thread=False),
        "security_context": Provide(provide_security_context, sync_to_thread=False),
    }
