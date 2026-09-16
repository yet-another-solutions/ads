from __future__ import annotations

import time
from types import SimpleNamespace
from typing import Any
from uuid import UUID

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from ads_commons_beans import JwtVerifier, JwtVerifierSettings

ISSUER = "https://keycloak.test/realms/ads"
AUDIENCE = "ads-preferences"
CLIENT_ID = "ads"
USER_ID = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
OTHER_USER_ID = UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")


def new_rsa_key() -> RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


class StaticJwks:
    def __init__(self, private_key: RSAPrivateKey) -> None:
        self._key = private_key

    def get_signing_key_from_jwt(self, token: str) -> SimpleNamespace:
        return SimpleNamespace(key=self._key.public_key())


def encode_token(private_key: RSAPrivateKey, **claims: Any) -> str:
    now = int(time.time())
    payload: dict[str, Any] = {
        "sub": str(USER_ID),
        "name": "Alice",
        "iss": ISSUER,
        "aud": AUDIENCE,
        "azp": CLIENT_ID,
        "exp": now + 3600,
        "iat": now,
        "realm_access": {"roles": ["user"]},
    }
    payload.update(claims)
    return jwt.encode(payload, private_key, algorithm="RS256")


def make_verifier(private_key: RSAPrivateKey) -> JwtVerifier:
    return JwtVerifier(
        JwtVerifierSettings(
            issuer=ISSUER,
            audience=AUDIENCE,
            client_id=CLIENT_ID,
            jwks_uri="https://unused.test/certs",
            ssl_context=None,
        ),
        StaticJwks(private_key),
    )
