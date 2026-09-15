from __future__ import annotations

import json
import ssl
from typing import Any, Protocol
from urllib.request import urlopen

import jwt
from jwt import PyJWKClient

from ads_commons.security.context import SecurityContext
from ads_commons.security.identity import (
    Identity,
    identity_from_claims,
    security_context_from_identity,
)

_REQUIRED_CLAIMS = ["exp", "iat", "iss", "aud", "sub"]


class InvalidAccessToken(Exception):
    """JWT failed resource-server verification."""

    def __init__(self, detail: str = "invalid token") -> None:
        super().__init__(detail)
        self.detail = detail


class SigningKeySource(Protocol):
    def get_signing_key_from_jwt(self, token: str) -> Any: ...


def jwks_uri_from_well_known(url: str, ssl_context: ssl.SSLContext | None = None) -> str:
    try:
        with urlopen(url, context=ssl_context, timeout=10) as response:
            payload = json.loads(response.read())
    except (OSError, ValueError, TypeError) as exc:
        raise InvalidAccessToken("openid configuration could not be loaded") from exc
    if not isinstance(payload, dict):
        raise InvalidAccessToken("openid configuration is not an object")
    jwks_uri = payload.get("jwks_uri")
    if not isinstance(jwks_uri, str) or not jwks_uri.strip():
        raise InvalidAccessToken("openid configuration missing jwks_uri")
    return jwks_uri


class JwtVerifier:
    """Verify RS256 Keycloak JWTs against JWKS (iss / aud / exp / azp)."""

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        client_id: str,
        ssl_context: ssl.SSLContext | None = None,
        jwks_uri: str | None = None,
        jwks_client: SigningKeySource | None = None,
    ) -> None:
        self._issuer = issuer
        self._audience = audience
        self._client_id = client_id
        self._ssl_context = ssl_context
        self._jwks_uri = jwks_uri
        self._jwks_client = jwks_client
        if self._jwks_client is None and jwks_uri is not None:
            self._jwks_client = PyJWKClient(jwks_uri, ssl_context=ssl_context)

    def use_jwks_uri(self, jwks_uri: str) -> None:
        if self._jwks_client is not None and self._jwks_uri == jwks_uri:
            return
        self._jwks_uri = jwks_uri
        self._jwks_client = PyJWKClient(jwks_uri, ssl_context=self._ssl_context)

    def decode(self, token: str, *, nonce: str | None = None) -> Identity:
        if not token.strip():
            raise InvalidAccessToken("token is required")
        client = self._jwks_client
        if client is None:
            raise InvalidAccessToken("JWKS is not configured")
        try:
            signing_key = client.get_signing_key_from_jwt(token)
            payload = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=self._audience,
                issuer=self._issuer,
                options={"require": _REQUIRED_CLAIMS},
            )
        except InvalidAccessToken:
            raise
        except Exception as exc:
            raise InvalidAccessToken(str(exc)) from exc
        azp = payload.get("azp")
        if azp is not None and azp != self._client_id:
            raise InvalidAccessToken("azp does not match client id")
        if nonce is not None and payload.get("nonce") != nonce:
            raise InvalidAccessToken("nonce mismatch")
        try:
            return identity_from_claims(payload, self._client_id)
        except ValueError as exc:
            raise InvalidAccessToken(str(exc)) from exc

    def authenticate(self, token: str) -> SecurityContext:
        return security_context_from_identity(self.decode(token))
