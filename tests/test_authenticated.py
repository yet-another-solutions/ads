from __future__ import annotations

import pytest
from litestar import Litestar, get
from litestar.exceptions import NotAuthorizedException
from litestar.testing import RequestFactory, TestClient

from ads.app import build_session_config
from ads.authenticated import (
    AuthenticatedController,
    provide_identity,
    provide_security_context,
)
from ads.config import Settings
from ads.identity import Identity


class _ProbeController(AuthenticatedController):
    path = "/api"

    @get("/ping")
    async def ping(self) -> dict[str, bool]:
        return {"ok": True}


def test_missing_session_identity_is_unauthorized() -> None:
    request = RequestFactory().get("/")
    request.scope["session"] = {}
    with pytest.raises(NotAuthorizedException):
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
    context = provide_security_context(identity)
    assert context.subject == "alice"
    assert context.has_role("user")


def test_authenticated_controller_returns_401_without_session(settings: Settings) -> None:
    session_config = build_session_config(settings)
    app = Litestar(route_handlers=[_ProbeController], middleware=[session_config.middleware])
    with TestClient(app=app, session_config=session_config) as client:
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
                }
            }
        )
        response = client.get("/api/ping")
        assert response.status_code == 200
        assert response.json() == {"ok": True}
