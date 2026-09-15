from __future__ import annotations

import pytest

from ads_commons.security import (
    AccessDenied,
    AuthenticationRequired,
    SecurityContext,
    SecurityContextHolder,
    require_role,
)
from ads_preferences.service import PreferencesService


def _ctx(*, roles: frozenset[str] | None = None) -> SecurityContext:
    return SecurityContext(
        subject="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        name="Alice",
        roles=roles if roles is not None else frozenset({"user"}),
        authorized_party="ads",
    )


@require_role("user")
def _guarded() -> str:
    return "ok"


def test_require_role_needs_bound_user() -> None:
    with pytest.raises(AuthenticationRequired):
        _guarded()
    with SecurityContextHolder.bound(_ctx()):
        assert _guarded() == "ok"
    with SecurityContextHolder.bound(_ctx(roles=frozenset())):
        with pytest.raises(AccessDenied, match="role user required"):
            _guarded()


def test_unbound_holder_require_raises() -> None:
    with pytest.raises(AuthenticationRequired):
        SecurityContextHolder.require()


def test_service_is_preferences_api() -> None:
    from ads_commons.preferences import PreferencesApi

    assert issubclass(PreferencesService, PreferencesApi)
