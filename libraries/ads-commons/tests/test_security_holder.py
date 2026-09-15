from __future__ import annotations

import pytest

from ads_commons.security import AuthenticationRequired, SecurityContext, SecurityContextHolder


def _ctx(*roles: str) -> SecurityContext:
    return SecurityContext(subject="alice", name="Alice", roles=frozenset(roles))


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
