from __future__ import annotations

import logging

import pytest
from litestar.exceptions import NotAuthorizedException, PermissionDeniedException

from ads.hello.service import HelloService
from ads.security_context import SecurityContext


def _ctx(*roles: str) -> SecurityContext:
    return SecurityContext(subject="alice", name="Alice", roles=frozenset(roles))


def test_greet_returns_hello_world() -> None:
    assert HelloService().greet(security_context=_ctx()) == "hello world"


def test_press_button_requires_security_context() -> None:
    with pytest.raises(NotAuthorizedException):
        HelloService().press_button()  # type: ignore[call-arg]


def test_press_button_requires_user_role() -> None:
    with pytest.raises(PermissionDeniedException):
        HelloService().press_button(security_context=_ctx("other"))


def test_press_button_logs_when_user_role_present(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.INFO):
        result = HelloService().press_button(security_context=_ctx("user"))
    assert result == "button was pressed"
    assert "button was pressed" in caplog.text
