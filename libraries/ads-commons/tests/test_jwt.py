from __future__ import annotations

import json
import time
from typing import Any

import pytest

from ads_commons.security import InvalidAccessToken, jwks_uri_from_well_known
from jwt_support import encode_token, new_rsa_key, verifier


def test_valid_access_token_authenticates() -> None:
    key = new_rsa_key()
    token = encode_token(key)
    context = verifier(key).authenticate(token)
    assert context.subject == "alice"
    assert context.has_role("user")


def test_garbage_token_is_rejected() -> None:
    key = new_rsa_key()
    with pytest.raises(InvalidAccessToken):
        verifier(key).authenticate("not-a-jwt")


def test_empty_token_is_rejected() -> None:
    key = new_rsa_key()
    with pytest.raises(InvalidAccessToken, match="required"):
        verifier(key).authenticate("   ")


def test_wrong_audience_is_rejected() -> None:
    key = new_rsa_key()
    token = encode_token(key, aud="other")
    with pytest.raises(InvalidAccessToken):
        verifier(key).authenticate(token)


def test_expired_token_is_rejected() -> None:
    key = new_rsa_key()
    token = encode_token(key, exp=int(time.time()) - 10)
    with pytest.raises(InvalidAccessToken):
        verifier(key).authenticate(token)


def test_wrong_azp_is_rejected() -> None:
    key = new_rsa_key()
    token = encode_token(key, azp="other-client")
    with pytest.raises(InvalidAccessToken, match="azp"):
        verifier(key).authenticate(token)


def test_id_token_nonce_must_match() -> None:
    key = new_rsa_key()
    token = encode_token(key, nonce="expected")
    identity = verifier(key).decode(token, nonce="expected")
    assert identity.sub == "alice"
    with pytest.raises(InvalidAccessToken, match="nonce"):
        verifier(key).decode(token, nonce="other")


def test_jwks_uri_from_well_known(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Response:
        def read(self) -> bytes:
            return json.dumps({"jwks_uri": "https://kc/jwks"}).encode()

        def __enter__(self) -> _Response:
            return self

        def __exit__(self, *args: object) -> None:
            return None

    def _urlopen(url: str, context: Any = None, timeout: int = 10) -> _Response:
        assert url == "https://kc/.well-known/openid-configuration"
        return _Response()

    monkeypatch.setattr("ads_commons.security.jwt.urlopen", _urlopen)
    uri = jwks_uri_from_well_known("https://kc/.well-known/openid-configuration")
    assert uri == "https://kc/jwks"
