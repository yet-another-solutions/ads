from __future__ import annotations

import asyncio

import pytest

from ads_commons.security import (
    AccessDenied,
    AuthenticationRequired,
    SecurityContext,
    SecurityContextHolder,
    check_caller,
    ensure_caller,
    require_caller,
)


def _ctx(*, caller: str | None = "ads") -> SecurityContext:
    return SecurityContext(
        subject="alice",
        name="Alice",
        roles=frozenset({"user"}),
        authorized_party=caller,
    )


def test_ensure_caller_rejects_missing_or_other_azp() -> None:
    ensure_caller(_ctx(caller="ads"), "ads")
    with pytest.raises(AccessDenied, match="caller is not allowed"):
        ensure_caller(_ctx(caller="other"), "ads")
    with pytest.raises(AccessDenied, match="caller is not allowed"):
        ensure_caller(_ctx(caller=None), "ads")


def test_check_caller_requires_bound_allowed_party() -> None:
    with pytest.raises(AuthenticationRequired):
        check_caller("ads")
    with SecurityContextHolder.bound(_ctx(caller="ads")):
        assert check_caller("ads").authorized_party == "ads"
    with SecurityContextHolder.bound(_ctx(caller="other")):
        with pytest.raises(AccessDenied):
            check_caller("ads")


@require_caller("ads")
def _guarded() -> str:
    return "ok"


@require_caller("ads")
async def _guarded_async() -> str:
    return "ok"


class _Service:
    allowed_callers = frozenset({"ads"})

    @require_caller()
    def run(self) -> str:
        return "ok"


def test_require_caller_allows_ads_and_denies_other() -> None:
    with pytest.raises(AuthenticationRequired):
        _guarded()
    with SecurityContextHolder.bound(_ctx(caller="ads")):
        assert _guarded() == "ok"
    with SecurityContextHolder.bound(_ctx(caller="other")):
        with pytest.raises(AccessDenied):
            _guarded()


def test_require_caller_reads_instance_allowed_callers() -> None:
    service = _Service()
    with SecurityContextHolder.bound(_ctx(caller="ads")):
        assert service.run() == "ok"
    with SecurityContextHolder.bound(_ctx(caller="other")):
        with pytest.raises(AccessDenied):
            service.run()


def test_require_caller_wraps_async_functions() -> None:
    async def _body() -> None:
        with SecurityContextHolder.bound(_ctx(caller="ads")):
            assert await _guarded_async() == "ok"

    asyncio.run(_body())
