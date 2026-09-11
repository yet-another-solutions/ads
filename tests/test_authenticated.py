from __future__ import annotations

import pytest
from litestar.testing import RequestFactory

from ads.authenticated import (
    LoginRequired,
    handle_login_required,
    provide_identity,
    provide_security_context,
)
from ads.identity import Identity


def test_missing_session_identity_raises_login_required() -> None:
    request = RequestFactory().get("/")
    request.scope["session"] = {}
    with pytest.raises(LoginRequired):
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


def test_login_required_handler_redirects_to_login() -> None:
    request = RequestFactory().get("/")
    response = handle_login_required(request, LoginRequired())
    assert response.status_code == 302
    assert str(response.url).endswith("/login")
