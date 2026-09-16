from __future__ import annotations

import time

import pytest

from ads_commons.security import InvalidAccessToken
from jwt_support import SUBJECT, encode_token, new_rsa_key, verifier


def test_valid_access_token_authenticates() -> None:
    key = new_rsa_key()
    token = encode_token(key)
    context = verifier(key).authenticate(token)
    assert context.subject == SUBJECT
    assert context.has_role("user")
    assert context.authorized_party == "ads"
    assert context.access_token == token
    assert token not in repr(context)


def test_authenticate_uses_explicit_audience() -> None:
    key = new_rsa_key()
    token = encode_token(key, aud="ads-preferences")
    context = verifier(key).authenticate(token, audience="ads-preferences")
    assert context.subject == SUBJECT
    assert context.access_token == token
    with pytest.raises(InvalidAccessToken):
        verifier(key).authenticate(token)


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


def test_expired_token_claims_can_skip_exp() -> None:
    key = new_rsa_key()
    token = encode_token(key, exp=int(time.time()) - 10)
    claims = verifier(key).verified_claims(token, verify_exp=False)
    assert claims["sub"] == SUBJECT
    with pytest.raises(InvalidAccessToken):
        verifier(key).verified_claims(token)


def test_non_uuid_sub_is_rejected() -> None:
    key = new_rsa_key()
    token = encode_token(key, sub="alice")
    with pytest.raises(InvalidAccessToken, match="UUID"):
        verifier(key).authenticate(token)


def test_wrong_azp_is_kept_for_caller_check() -> None:
    key = new_rsa_key()
    token = encode_token(key, azp="other-client")
    context = verifier(key).authenticate(token)
    assert context.authorized_party == "other-client"


def test_id_token_nonce_must_match() -> None:
    key = new_rsa_key()
    token = encode_token(key, nonce="expected")
    identity = verifier(key).decode(token, nonce="expected")
    assert identity.sub == SUBJECT
    with pytest.raises(InvalidAccessToken, match="nonce"):
        verifier(key).decode(token, nonce="other")
