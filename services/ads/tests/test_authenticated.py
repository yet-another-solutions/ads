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
from ads.security_context import SecurityContext
from ads.security_holder import SecurityContextHolder
from ads.security_middleware import SecurityContextMiddleware
from ads_commons.security import AccessDenied, AuthenticationRequired, require_role
from tests.threadline_fakes import USER_ACCESS_TOKEN, USER_ID, attach_fake_session_binder, login


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


def test_missing_bound_context_is_unauthorized() -> None:
    with pytest.raises(AuthenticationRequired):
        provide_identity()


def test_provide_identity_and_security_context_from_holder() -> None:
    context = SecurityContext(
        subject=str(USER_ID),
        name="Alice Operator",
        roles=frozenset({"user"}),
        email="alice@example.com",
        authorized_party="ads",
        access_token=USER_ACCESS_TOKEN,
    )
    with SecurityContextHolder.bound(context):
        identity = provide_identity()
        assert identity == Identity(
            sub=str(USER_ID),
            name="Alice Operator",
            roles=("user",),
            email="alice@example.com",
            azp="ads",
        )
        bound = provide_security_context()
        assert bound is context
        assert bound.access_token == USER_ACCESS_TOKEN


def test_provide_security_context_without_token_is_unauthorized() -> None:
    context = SecurityContext(
        subject=str(USER_ID),
        name="Alice",
        roles=frozenset({"user"}),
    )
    with SecurityContextHolder.bound(context):
        with pytest.raises(AuthenticationRequired):
            provide_security_context()


def test_authenticated_controller_returns_401_without_session(settings: Settings) -> None:
    session_config = build_session_config(settings)
    app = Litestar(
        route_handlers=[_ProbeController],
        middleware=[session_config.middleware, SecurityContextMiddleware],
        exception_handlers=AUTH_EXCEPTION_HANDLERS,
    )
    attach_fake_session_binder(app)
    with TestClient(app=app, session_config=session_config) as client:
        response = client.get("/api/ping")
        assert response.status_code == 401


def test_authenticated_controller_returns_401_without_access_token(settings: Settings) -> None:
    session_config = build_session_config(settings)
    app = Litestar(
        route_handlers=[_ProbeController],
        middleware=[session_config.middleware, SecurityContextMiddleware],
        exception_handlers=AUTH_EXCEPTION_HANDLERS,
    )
    attach_fake_session_binder(app)
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
    app = Litestar(
        route_handlers=[_ProbeController],
        middleware=[session_config.middleware, SecurityContextMiddleware],
    )
    attach_fake_session_binder(app)
    with TestClient(app=app, session_config=session_config) as client:
        login(client)
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
    attach_fake_session_binder(app)
    with TestClient(app=app, session_config=session_config) as client:
        login(client)
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
