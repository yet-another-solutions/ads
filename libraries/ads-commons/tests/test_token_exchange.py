from __future__ import annotations

import json
from typing import Any
from urllib.parse import parse_qs

import pytest

from ads_commons.security import (
    AuthenticationRequired,
    SecurityContext,
    SecurityContextHolder,
    TokenExchange,
    TokenExchangeError,
    token_endpoint_from_well_known,
)
from jwt_support import encode_token, new_rsa_key, verifier

INBOUND = "inbound-user-token"
EXCHANGED_SUBJECT = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
TOKEN_URL = "https://kc/realms/ads/protocol/openid-connect/token"
WELL_KNOWN = "https://kc/.well-known/openid-configuration"


class _Response:
    def __init__(self, payload: dict[str, object] | bytes) -> None:
        self._body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *args: object) -> None:
        return None


def _exchanger(key: Any) -> TokenExchange:
    return TokenExchange(
        token_endpoint=TOKEN_URL,
        client_id="ads",
        client_secret="ads-secret",
        verifier=verifier(key),
    )


def _bound(token: str | None = INBOUND, **kwargs: Any) -> SecurityContext:
    return SecurityContext(
        subject="alice",
        name="Alice",
        roles=frozenset({"user"}),
        access_token=token,
        **kwargs,
    )


def test_exchange_posts_ste_v2_and_returns_access_token(monkeypatch: pytest.MonkeyPatch) -> None:
    key = new_rsa_key()
    captured: list[Any] = []

    def _urlopen(request: Any, context: Any = None, timeout: int = 10) -> _Response:
        captured.append(request)
        return _Response({"access_token": "exchanged-token"})

    monkeypatch.setattr("ads_commons.security.token_exchange.urlopen", _urlopen)
    with SecurityContextHolder.bound(_bound()):
        token = _exchanger(key).exchange("ads-preferences")
    assert token == "exchanged-token"
    assert len(captured) == 1
    request = captured[0]
    assert request.full_url == TOKEN_URL
    assert request.get_method() == "POST"
    form = parse_qs(request.data.decode())
    assert form["grant_type"] == ["urn:ietf:params:oauth:grant-type:token-exchange"]
    assert form["client_id"] == ["ads"]
    assert form["client_secret"] == ["ads-secret"]
    assert form["subject_token"] == [INBOUND]
    assert form["subject_token_type"] == ["urn:ietf:params:oauth:token-type:access_token"]
    assert form["requested_token_type"] == ["urn:ietf:params:oauth:token-type:access_token"]
    assert form["audience"] == ["ads-preferences"]


def test_exchange_accepts_explicit_subject_token(monkeypatch: pytest.MonkeyPatch) -> None:
    key = new_rsa_key()
    captured: list[Any] = []

    def _urlopen(request: Any, context: Any = None, timeout: int = 10) -> _Response:
        captured.append(request)
        return _Response({"access_token": "exchanged-token"})

    monkeypatch.setattr("ads_commons.security.token_exchange.urlopen", _urlopen)
    token = _exchanger(key).exchange("ads-engine", "acknowledge-header-jwt")
    assert token == "exchanged-token"
    form = parse_qs(captured[0].data.decode())
    assert form["subject_token"] == ["acknowledge-header-jwt"]
    assert form["audience"] == ["ads-engine"]


def test_exchange_is_not_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    key = new_rsa_key()
    calls = {"n": 0}

    def _urlopen(request: Any, context: Any = None, timeout: int = 10) -> _Response:
        calls["n"] += 1
        return _Response({"access_token": f"token-{calls['n']}"})

    monkeypatch.setattr("ads_commons.security.token_exchange.urlopen", _urlopen)
    exchanger = _exchanger(key)
    with SecurityContextHolder.bound(_bound()):
        first = exchanger.exchange("ads-engine")
        second = exchanger.exchange("ads-engine")
    assert first == "token-1"
    assert second == "token-2"
    assert calls["n"] == 2


def test_helper_does_not_keep_tokens(monkeypatch: pytest.MonkeyPatch) -> None:
    key = new_rsa_key()

    def _urlopen(request: Any, context: Any = None, timeout: int = 10) -> _Response:
        return _Response({"access_token": "exchanged-token"})

    monkeypatch.setattr("ads_commons.security.token_exchange.urlopen", _urlopen)
    exchanger = _exchanger(key)
    with SecurityContextHolder.bound(_bound()):
        exchanger.exchange("ads-preferences")
    stored = " ".join(str(value) for value in vars(exchanger).values())
    assert INBOUND not in stored
    assert "exchanged-token" not in stored
    assert INBOUND not in repr(exchanger)


def test_mint_builds_context_from_exchanged_token(monkeypatch: pytest.MonkeyPatch) -> None:
    key = new_rsa_key()
    exchanged = encode_token(
        key,
        sub=EXCHANGED_SUBJECT,
        aud="ads-preferences",
        azp="ads",
        name="FromToken",
        realm_access={"roles": ["admin"]},
    )

    def _urlopen(request: Any, context: Any = None, timeout: int = 10) -> _Response:
        return _Response({"access_token": exchanged})

    monkeypatch.setattr("ads_commons.security.token_exchange.urlopen", _urlopen)
    original = _bound()
    with SecurityContextHolder.bound(original):
        minted = _exchanger(key).mint("ads-preferences")
        assert SecurityContextHolder.require() is original
        assert original.subject == "alice"
        assert original.has_role("user")
        assert original.access_token == INBOUND
    assert minted.subject == EXCHANGED_SUBJECT
    assert minted.name == "FromToken"
    assert minted.has_role("admin")
    assert not minted.has_role("user")
    assert minted.authorized_party == "ads"
    assert minted.access_token == exchanged
    assert minted.subject != original.subject


def test_mint_rejects_invalid_exchanged_token(monkeypatch: pytest.MonkeyPatch) -> None:
    key = new_rsa_key()

    def _urlopen(request: Any, context: Any = None, timeout: int = 10) -> _Response:
        return _Response({"access_token": "not-a-jwt"})

    monkeypatch.setattr("ads_commons.security.token_exchange.urlopen", _urlopen)
    with SecurityContextHolder.bound(_bound()):
        with pytest.raises(TokenExchangeError, match="invalid"):
            _exchanger(key).mint("ads-preferences")


def test_exchange_requires_bound_access_token() -> None:
    key = new_rsa_key()
    with pytest.raises(AuthenticationRequired):
        _exchanger(key).exchange("ads-preferences")
    with SecurityContextHolder.bound(_bound(token=None)):
        with pytest.raises(AuthenticationRequired, match="access token"):
            _exchanger(key).exchange("ads-preferences")


def test_exchange_requires_audience() -> None:
    key = new_rsa_key()
    with SecurityContextHolder.bound(_bound()):
        with pytest.raises(TokenExchangeError, match="audience"):
            _exchanger(key).exchange("  ")


def test_token_endpoint_error_does_not_include_token(monkeypatch: pytest.MonkeyPatch) -> None:
    key = new_rsa_key()

    def _urlopen(request: Any, context: Any = None, timeout: int = 10) -> _Response:
        raise TimeoutError("slow")

    monkeypatch.setattr("ads_commons.security.token_exchange.urlopen", _urlopen)
    with SecurityContextHolder.bound(_bound()):
        with pytest.raises(TokenExchangeError, match="token exchange failed") as caught:
            _exchanger(key).exchange("ads-preferences")
    assert INBOUND not in str(caught.value)
    assert INBOUND not in repr(caught.value)


def test_missing_access_token_in_response(monkeypatch: pytest.MonkeyPatch) -> None:
    key = new_rsa_key()

    def _urlopen(request: Any, context: Any = None, timeout: int = 10) -> _Response:
        return _Response({"token_type": "Bearer"})

    monkeypatch.setattr("ads_commons.security.token_exchange.urlopen", _urlopen)
    with SecurityContextHolder.bound(_bound()):
        with pytest.raises(TokenExchangeError, match="no access_token"):
            _exchanger(key).exchange("ads-preferences")


def test_token_endpoint_from_well_known(monkeypatch: pytest.MonkeyPatch) -> None:
    def _urlopen(url: str, context: Any = None, timeout: int = 10) -> _Response:
        assert url == WELL_KNOWN
        return _Response({"token_endpoint": TOKEN_URL})

    monkeypatch.setattr("ads_commons.security.token_exchange.urlopen", _urlopen)
    assert token_endpoint_from_well_known(WELL_KNOWN) == TOKEN_URL
