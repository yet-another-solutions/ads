from __future__ import annotations

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


class JwtVerifier:
    """Verify RS256 Keycloak JWTs against JWKS (iss / aud / exp / signature)."""

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        client_id: str,
        jwks_client: SigningKeySource,
    ) -> None:
        self._issuer = issuer
        self._audience = audience
        self._client_id = client_id
        self._jwks_client = jwks_client

    def decode(
        self,
        token: str,
        *,
        nonce: str | None = None,
        audience: str | None = None,
    ) -> Identity:
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
                options={"require": _REQUIRED_CLAIMS},
            )
        except InvalidAccessToken:
            raise
        except Exception as exc:
            raise InvalidAccessToken(str(exc)) from exc
        if nonce is not None and payload.get("nonce") != nonce:
            raise InvalidAccessToken("nonce mismatch")
        try:
            return identity_from_claims(payload, self._client_id)
        except ValueError as exc:
            raise InvalidAccessToken(str(exc)) from exc

    def authenticate(self, token: str, *, audience: str | None = None) -> SecurityContext:
        return security_context_from_identity(
            self.decode(token, audience=audience)
        ).with_access_token(token)
