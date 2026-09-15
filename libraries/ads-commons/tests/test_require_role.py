from __future__ import annotations

import asyncio

import pytest

from ads_commons.security import (
    AccessDenied,
    AuthenticationRequired,
    SecurityContext,
    SecurityContextHolder,
    check_role,
    ensure_role,
    require_role,
)


def _ctx(*, roles: frozenset[str] | None = None) -> SecurityContext:
    return SecurityContext(
        subject="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        name="Alice",
        roles=roles if roles is not None else frozenset({"user"}),
        authorized_party="ads",
    )


def test_ensure_role_rejects_missing_role() -> None:
    ensure_role(_ctx(), "user")
    with pytest.raises(AccessDenied, match="role user required"):
        ensure_role(_ctx(roles=frozenset()), "user")
    with pytest.raises(AccessDenied, match="role user required"):
        ensure_role(_ctx(roles=frozenset({"other"})), "user")


def test_check_role_requires_bound_user() -> None:
    with pytest.raises(AuthenticationRequired):
        check_role("user")
    with SecurityContextHolder.bound(_ctx()):
        assert check_role("user").has_role("user")
    with SecurityContextHolder.bound(_ctx(roles=frozenset())):
        with pytest.raises(AccessDenied, match="role user required"):
            check_role("user")


@require_role("user")
def _guarded() -> str:
    return "ok"


@require_role("user")
async def _guarded_async() -> str:
    return "ok"


def test_require_role_allows_user_and_denies_other() -> None:
    with pytest.raises(AuthenticationRequired):
        _guarded()
    with SecurityContextHolder.bound(_ctx()):
        assert _guarded() == "ok"
    with SecurityContextHolder.bound(_ctx(roles=frozenset())):
        with pytest.raises(AccessDenied, match="role user required"):
            _guarded()


def test_require_role_wraps_async_functions() -> None:
    async def _body() -> None:
        with SecurityContextHolder.bound(_ctx()):
            assert await _guarded_async() == "ok"

    asyncio.run(_body())
