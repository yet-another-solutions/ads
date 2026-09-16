from __future__ import annotations

import pytest
from litestar.testing import TestClient

from ads.security_context import SecurityContext
from ads.security_holder import SecurityContextHolder
from ads_commons.security import AuthenticationRequired, require_role
from ads_commons.security import SecurityContextHolder as CommonsHolder
from tests.threadline_fakes import USER_ACCESS_TOKEN, USER_ID, login


class _MutatingService:
    """Stand-in for any ads service that mutates on behalf of a user."""

    @require_role("user")
    def touch(self) -> str:
        return "touched"


def _ctx(*roles: str) -> SecurityContext:
    return SecurityContext(
        subject=str(USER_ID),
        name="Alice",
        roles=frozenset(roles),
        access_token=USER_ACCESS_TOKEN,
    )


def test_require_without_bind_is_unauthorized() -> None:
    with pytest.raises(AuthenticationRequired):
        SecurityContextHolder.require()


def test_bound_context_is_current() -> None:
    with SecurityContextHolder.bound(_ctx("user")) as context:
        assert SecurityContextHolder.require() is context
        assert SecurityContextHolder.get() is context
    assert SecurityContextHolder.get() is None


def test_capture_without_holder_raises_even_if_session_has_token() -> None:
    with pytest.raises(AuthenticationRequired):
        SecurityContextHolder.capture()


def test_capture_returns_bound_context() -> None:
    holder_ctx = _ctx("user")
    with SecurityContextHolder.bound(holder_ctx):
        assert SecurityContextHolder.capture() is holder_ctx
        assert SecurityContextHolder.capture().access_token == USER_ACCESS_TOKEN


def test_detached_without_holder_is_unauthorized() -> None:
    with pytest.raises(AuthenticationRequired):
        with SecurityContextHolder.detached():
            raise AssertionError("must not enter")


def test_detached_copies_bound_context() -> None:
    context = _ctx("user")
    with SecurityContextHolder.bound(context):
        with SecurityContextHolder.detached() as detached:
            assert SecurityContextHolder.require() is detached
            assert detached == context
            assert _MutatingService().touch() == "touched"
    assert SecurityContextHolder.get() is None


def test_identity_only_bound_context_is_not_a_session_source() -> None:
    session = {
        "identity": {
            "sub": str(USER_ID),
            "name": "Alice",
            "roles": ["user"],
            "email": "alice@example.com",
        }
    }
    del session
    with pytest.raises(AuthenticationRequired):
        with SecurityContextHolder.detached():
            raise AssertionError("must not enter")


def test_ads_holder_shares_commons_context_var() -> None:
    context = _ctx("user")
    with CommonsHolder.bound(context):
        assert SecurityContextHolder.get() is context
        assert SecurityContextHolder.require() is context
    assert SecurityContextHolder.get() is None


def test_http_request_binds_access_token(client: TestClient) -> None:
    login(client)
    response = client.get("/")
    assert response.status_code == 200


def test_identity_only_session_is_unauthorized(client: TestClient) -> None:
    client.set_session_data(
        {
            "identity": {
                "sub": str(USER_ID),
                "name": "Alice",
                "roles": ["user"],
                "email": "alice@example.com",
            }
        }
    )
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["location"].startswith("/login")
