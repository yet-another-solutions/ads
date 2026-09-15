from __future__ import annotations

import pytest

from ads.hello.service import HelloService
from ads.security_context import SecurityContext
from ads.security_holder import SecurityContextHolder
from ads_commons.security import AuthenticationRequired
from ads_commons.security import SecurityContextHolder as CommonsHolder


def _ctx(*roles: str) -> SecurityContext:
    return SecurityContext(subject="alice", name="Alice", roles=frozenset(roles))


def test_require_without_bind_is_unauthorized() -> None:
    with pytest.raises(AuthenticationRequired):
        SecurityContextHolder.require()


def test_bound_context_is_current() -> None:
    with SecurityContextHolder.bound(_ctx("user")) as context:
        assert SecurityContextHolder.require() is context
        assert SecurityContextHolder.get() is context
    assert SecurityContextHolder.get() is None


def test_capture_from_live_session_when_holder_empty() -> None:
    session = {
        "identity": {
            "sub": "alice",
            "name": "Alice",
            "roles": ["user"],
            "email": "alice@example.com",
        },
        "access_token": "user-access-token",
    }
    captured = SecurityContextHolder.capture(session)
    assert captured.subject == "alice"
    assert captured.has_role("user")
    assert captured.access_token == "user-access-token"


def test_capture_prefers_holder_over_session() -> None:
    holder_ctx = _ctx("user")
    session = {
        "identity": {
            "sub": "bob",
            "name": "Bob",
            "roles": ["user"],
            "email": "bob@example.com",
        }
    }
    with SecurityContextHolder.bound(holder_ctx):
        assert SecurityContextHolder.capture(session) is holder_ctx


def test_detached_picks_session_and_stores_in_work_context() -> None:
    session = {
        "identity": {
            "sub": "alice",
            "name": "Alice",
            "roles": ["user"],
            "email": "alice@example.com",
        }
    }
    with SecurityContextHolder.detached(session) as context:
        assert SecurityContextHolder.require() is context
        assert HelloService().press_button() == "button was pressed"
    assert SecurityContextHolder.get() is None


def test_detached_without_session_or_holder_is_unauthorized() -> None:
    with pytest.raises(AuthenticationRequired):
        with SecurityContextHolder.detached():
            raise AssertionError("must not enter")


def test_ads_holder_shares_commons_context_var() -> None:
    context = _ctx("user")
    with CommonsHolder.bound(context):
        assert SecurityContextHolder.get() is context
        assert SecurityContextHolder.require() is context
    assert SecurityContextHolder.get() is None
