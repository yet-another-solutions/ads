from __future__ import annotations

import ssl
from dataclasses import dataclass
from typing import Any, Protocol

import jwt

from ads_commons.security import (
    Identity,
    InvalidAccessToken,
    SecurityContext,
    identity_from_claims,
    security_context_from_identity,
)

_REQUIRED_CLAIMS = ["exp", "iat", "iss", "aud", "sub"]


class SigningKeySource(Protocol):
    def get_signing_key_from_jwt(self, token: str) -> Any: ...


@dataclass(frozen=True)
class JwtVerifierSettings:
    issuer: str
    audience: str
    client_id: str
    jwks_uri: str
    ssl_context: ssl.SSLContext | None


class JwtVerifier:
    """Verify RS256 Keycloak JWTs against JWKS (iss / aud / exp / signature)."""

    def __init__(
        self,
        settings: JwtVerifierSettings,
        jwks_client: SigningKeySource,
    ) -> None:
        self._issuer = settings.issuer
        self._audience = settings.audience
        self._client_id = settings.client_id
        self._jwks_client = jwks_client

    def verified_claims(
        self,
        token: str,
        *,
        nonce: str | None = None,
        audience: str | None = None,
        verify_exp: bool = True,
    ) -> dict[str, Any]:
        if not token.strip():
            raise InvalidAccessToken("token is required")
        try:
            signing_key = self._jwks_client.get_signing_key_from_jwt(token)
            payload = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=self._audience if audience is None else audience,
                issuer=self._issuer,
                options={"require": _REQUIRED_CLAIMS, "verify_exp": verify_exp},
            )
        except InvalidAccessToken:
            raise
        except Exception as exc:
            raise InvalidAccessToken(str(exc)) from exc
        if nonce is not None and payload.get("nonce") != nonce:
            raise InvalidAccessToken("nonce mismatch")
        if not isinstance(payload, dict):
            raise InvalidAccessToken("JWT payload is not an object")
        return payload

    def decode(
        self,
        token: str,
        *,
        nonce: str | None = None,
        audience: str | None = None,
    ) -> Identity:
        try:
            return identity_from_claims(
                self.verified_claims(token, nonce=nonce, audience=audience),
                self._client_id,
            )
        except ValueError as exc:
            raise InvalidAccessToken(str(exc)) from exc

    def authenticate(self, token: str, *, audience: str | None = None) -> SecurityContext:
        return security_context_from_identity(
            self.decode(token, audience=audience)
        ).with_access_token(token)
