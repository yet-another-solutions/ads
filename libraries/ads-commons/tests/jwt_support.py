from __future__ import annotations

import time
from types import SimpleNamespace
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from ads_commons.security import JwtVerifier

ISSUER = "https://keycloak.test/realms/ads"
AUDIENCE = "ads"
CLIENT_ID = "ads"


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
        "sub": "alice",
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


def verifier(private_key: RSAPrivateKey, **kwargs: Any) -> JwtVerifier:
    return JwtVerifier(
        issuer=kwargs.get("issuer", ISSUER),
        audience=kwargs.get("audience", AUDIENCE),
        client_id=kwargs.get("client_id", CLIENT_ID),
        jwks_client=StaticJwks(private_key),
    )
