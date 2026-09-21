from __future__ import annotations

import pytest

from ads_commons_web.session import cookie_session


def test_session_secret_must_be_at_least_16_bytes() -> None:
    with pytest.raises(RuntimeError, match="16 bytes"):
        cookie_session("short", "https://testserver")


def test_an_empty_session_secret_is_refused() -> None:
    with pytest.raises(RuntimeError, match="non-empty"):
        cookie_session("   ", "https://testserver")


def test_cookie_secure_follows_public_https_url() -> None:
    assert cookie_session("test-session-secret-32b!", "http://testserver").secure is False
    assert cookie_session("test-session-secret-32b!", "https://ads.example").secure is True
