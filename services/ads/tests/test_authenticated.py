from __future__ import annotations

import pytest
from litestar import Litestar, get, post
from litestar.testing import RequestFactory, TestClient

from ads.app import build_session_config
from ads.authenticated import (
    AUTH_EXCEPTION_HANDLERS,
    AuthenticatedController,
    handle_access_denied,
    handle_authentication_required,
    provide_identity,
    provide_security_context,
)
from ads.config import Settings
from ads.identity import Identity
from ads.security_middleware import SecurityContextMiddleware
from ads_commons.security import AccessDenied, AuthenticationRequired, require_role


class _ProbeController(AuthenticatedController):
    path = "/api"

    @get("/ping")
    async def ping(self) -> dict[str, bool]:
        return {"ok": True}


class _DenyService:
    @require_role("nobody")
    def deny(self) -> str:
        return "unreachable"


class _DenyController(AuthenticatedController):
    path = "/api"

    @post("/deny")
    async def deny(self) -> dict[str, str]:
        return {"result": _DenyService().deny()}


def test_missing_session_identity_is_unauthorized() -> None:
    request = RequestFactory().get("/")
    request.scope["session"] = {}
    with pytest.raises(AuthenticationRequired):
        provide_identity(request)


def test_provide_identity_and_security_context_from_session() -> None:
    request = RequestFactory().get("/")
    request.scope["session"] = {
        "identity": {
            "sub": "alice",
            "name": "Alice",
            "roles": ["user"],
            "email": "alice@example.com",
        }
    }
    identity = provide_identity(request)
    assert identity == Identity(
        sub="alice",
        name="Alice",
        roles=("user",),
        email="alice@example.com",
    )
    context = provide_security_context(identity, request)
    assert context.subject == "alice"
    assert context.has_role("user")
    assert context.access_token is None
    request.session["access_token"] = "user-access-token"
    with_token = provide_security_context(identity, request)
    assert with_token.access_token == "user-access-token"


def test_authenticated_controller_returns_401_without_session(settings: Settings) -> None:
    session_config = build_session_config(settings)
    app = Litestar(
        route_handlers=[_ProbeController],
        middleware=[session_config.middleware],
        exception_handlers=AUTH_EXCEPTION_HANDLERS,
    )
    with TestClient(app=app, session_config=session_config) as client:
        response = client.get("/api/ping")
        assert response.status_code == 401


def test_authenticated_controller_returns_401_without_access_token(settings: Settings) -> None:
    session_config = build_session_config(settings)
    app = Litestar(
        route_handlers=[_ProbeController],
        middleware=[session_config.middleware],
        exception_handlers=AUTH_EXCEPTION_HANDLERS,
    )
    with TestClient(app=app, session_config=session_config) as client:
        client.set_session_data(
            {
                "identity": {
                    "sub": "alice",
                    "name": "Alice",
                    "roles": ["user"],
                    "email": "alice@example.com",
                }
            }
        )
        response = client.get("/api/ping")
        assert response.status_code == 401


def test_authenticated_controller_returns_body_when_logged_in(settings: Settings) -> None:
    session_config = build_session_config(settings)
    app = Litestar(route_handlers=[_ProbeController], middleware=[session_config.middleware])
    with TestClient(app=app, session_config=session_config) as client:
        client.set_session_data(
            {
                "identity": {
                    "sub": "alice",
                    "name": "Alice",
                    "roles": ["user"],
                    "email": "alice@example.com",
                },
                "access_token": "user-access-token",
            }
        )
        response = client.get("/api/ping")
        assert response.status_code == 200
        assert response.json() == {"ok": True}


def test_access_denied_handler_maps_bound_role_failure(settings: Settings) -> None:
    session_config = build_session_config(settings)
    app = Litestar(
        route_handlers=[_DenyController],
        middleware=[session_config.middleware, SecurityContextMiddleware],
        exception_handlers=AUTH_EXCEPTION_HANDLERS,
    )
    with TestClient(app=app, session_config=session_config) as client:
        client.set_session_data(
            {
                "identity": {
                    "sub": "alice",
                    "name": "Alice",
                    "roles": ["user"],
                    "email": "alice@example.com",
                },
                "access_token": "user-access-token",
            }
        )
        response = client.post("/api/deny")
        assert response.status_code == 403
        assert response.json()["detail"] == "role nobody required"


def test_handle_authentication_required_returns_401() -> None:
    request = RequestFactory().get("/")
    response = handle_authentication_required(request, AuthenticationRequired())
    assert response.status_code == 401


def test_handle_access_denied_returns_403() -> None:
    request = RequestFactory().get("/")
    response = handle_access_denied(request, AccessDenied("role user required"))
    assert response.status_code == 403
