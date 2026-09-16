from __future__ import annotations

import uuid

import pytest

from ads_commons.security import AuthenticationRequired, SecurityContext, SecurityContextHolder


def _ctx(*roles: str, access_token: str | None = None) -> SecurityContext:
    return SecurityContext(
        subject="alice",
        name="Alice",
        roles=frozenset(roles),
        access_token=access_token,
    )


def test_require_without_bind_raises_authentication_required() -> None:
    with pytest.raises(AuthenticationRequired):
        SecurityContextHolder.require()


def test_bound_context_is_current() -> None:
    with SecurityContextHolder.bound(_ctx("user")) as context:
        assert SecurityContextHolder.require() is context
        assert SecurityContextHolder.get() is context
    assert SecurityContextHolder.get() is None


def test_capture_requires_bound_context() -> None:
    with pytest.raises(AuthenticationRequired):
        SecurityContextHolder.capture()
    with SecurityContextHolder.bound(_ctx("user")) as context:
        assert SecurityContextHolder.capture() is context


def test_detached_rebinds_captured_context() -> None:
    with SecurityContextHolder.bound(_ctx("user")):
        with SecurityContextHolder.detached() as context:
            assert SecurityContextHolder.require() is context
            assert context.subject == "alice"
    assert SecurityContextHolder.get() is None


def test_detached_without_holder_raises() -> None:
    with pytest.raises(AuthenticationRequired):
        with SecurityContextHolder.detached():
            raise AssertionError("must not enter")


def test_attributes_survive_capture_and_detach() -> None:
    session_id = uuid.uuid4()
    message_id = uuid.uuid4()
    bound = _ctx("user").with_attributes(session_id=session_id, message_id=message_id)
    with SecurityContextHolder.bound(bound):
        captured = SecurityContextHolder.capture()
        assert captured.attribute("session_id") == session_id
        assert captured.attribute("message_id") == message_id
        with SecurityContextHolder.detached() as context:
            assert context.attribute("session_id") == session_id
            assert SecurityContextHolder.require().attribute("message_id") == message_id
    assert SecurityContextHolder.get() is None


def test_with_access_token_mints_new_context() -> None:
    original = _ctx("user")
    minted = original.with_access_token("secret-token")
    assert minted is not original
    assert minted.subject == original.subject
    assert minted.roles == original.roles
    assert minted.access_token == "secret-token"
    assert original.access_token is None
    assert "secret-token" not in repr(minted)
    with pytest.raises(ValueError, match="access token"):
        original.with_access_token("  ")
