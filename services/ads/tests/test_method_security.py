from __future__ import annotations

import logging

import pytest

from ads.hello.service import HelloService
from ads.security_context import SecurityContext
from ads.security_holder import SecurityContextHolder
from ads_commons.security import AccessDenied, AuthenticationRequired


def _ctx(*roles: str) -> SecurityContext:
    return SecurityContext(subject="alice", name="Alice", roles=frozenset(roles))


def test_greet_returns_hello_world() -> None:
    assert HelloService().greet() == "hello world"


def test_press_button_requires_security_context() -> None:
    with pytest.raises(AuthenticationRequired):
        HelloService().press_button()


def test_press_button_requires_user_role() -> None:
    with pytest.raises(AccessDenied, match="role user required"):
        with SecurityContextHolder.bound(_ctx("other")):
            HelloService().press_button()


def test_press_button_logs_when_user_role_present(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.INFO), SecurityContextHolder.bound(_ctx("user")):
        result = HelloService().press_button()
    assert result == "button was pressed"
    assert "button was pressed" in caplog.text
