from __future__ import annotations

import pytest
from litestar import Litestar, get, post
from litestar.exceptions import MethodNotAllowedException
from litestar.testing import RequestFactory, TestClient

from ads.app import build_session_config
from ads.config import Settings
from ads.frontend import (
    RETURN_TO_SESSION_KEY,
    FrontendController,
    LoginRequired,
    handle_login_required,
    pop_return_to,
    require_frontend_login,
    safe_return_to,
)


class _PageController(FrontendController):
    path = "/page"

    @get("/")
    async def page(self) -> dict[str, bool]:
        return {"ok": True}

    @post("/submit")
    async def submit(self) -> dict[str, bool]:
        return {"ok": True}


def test_login_required_handler_redirects_to_login_and_stores_return_to() -> None:
    request = RequestFactory().get("/")
    request.scope["session"] = {}
    response = handle_login_required(request, LoginRequired())
    assert response.status_code == 302
    assert str(response.url).endswith("/login")
    assert request.session[RETURN_TO_SESSION_KEY] == "/"


def test_login_required_handler_stores_path_and_query_for_get() -> None:
    request = RequestFactory().get("/hello?tab=1")
    request.scope["session"] = {}
    handle_login_required(request, LoginRequired())
    assert request.session[RETURN_TO_SESSION_KEY] == "/hello?tab=1"


def test_login_required_handler_does_not_store_post_path() -> None:
    request = RequestFactory().post("/hello/press")
    request.scope["session"] = {}
    handle_login_required(request, LoginRequired())
    assert request.session[RETURN_TO_SESSION_KEY] == "/"


def test_safe_return_to_rejects_open_redirects() -> None:
    assert safe_return_to("https://evil.example/") == "/"
    assert safe_return_to("//evil.example/") == "/"
    assert safe_return_to("/login") == "/"
    assert safe_return_to("/auth/callback") == "/"
    assert safe_return_to("/ok") == "/ok"
    assert safe_return_to("/ok?x=1") == "/ok?x=1"


def test_pop_return_to_defaults_to_root() -> None:
    assert pop_return_to({}) == "/"
    session = {RETURN_TO_SESSION_KEY: "/hello"}
    assert pop_return_to(session) == "/hello"
    assert RETURN_TO_SESSION_KEY not in session


def test_unauthenticated_root_stores_return_to(client: TestClient) -> None:
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["location"].endswith("/login")
    assert client.get_session_data().get(RETURN_TO_SESSION_KEY) == "/"


def test_require_frontend_login_rejects_post() -> None:
    request = RequestFactory().post("/")
    request.scope["session"] = {
        "identity": {
            "sub": "alice",
            "name": "Alice",
            "roles": ["user"],
            "email": "alice@example.com",
        }
    }
    with pytest.raises(MethodNotAllowedException):
        require_frontend_login(request, None)  # type: ignore[arg-type]


def test_frontend_controller_rejects_post_even_when_logged_in(settings: Settings) -> None:
    session_config = build_session_config(settings)
    app = Litestar(
        route_handlers=[_PageController],
        middleware=[session_config.middleware],
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
        denied = client.post("/page/submit")
        assert denied.status_code == 405
        allowed = client.get("/page/")
        assert allowed.status_code == 200
        assert allowed.json() == {"ok": True}


def test_frontend_controller_post_is_method_not_allowed_without_session(
    settings: Settings,
) -> None:
    session_config = build_session_config(settings)
    app = Litestar(
        route_handlers=[_PageController],
        middleware=[session_config.middleware],
    )
    with TestClient(app=app, session_config=session_config) as client:
        response = client.post("/page/submit")
        assert response.status_code == 405
