from __future__ import annotations

from typing import Any
from urllib.parse import urlencode

import httpx
import jwt
import stamina
from authlib.integrations.httpx_client import AsyncOAuth2Client
from jwt import PyJWKClient

from ads.config import Settings
from ads.identity import Identity, identity_from_claims


class OidcClient:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._metadata: dict[str, Any] | None = None
        self._jwks_client: PyJWKClient | None = None
        self._jwks_uri: str | None = None

    @stamina.retry(on=httpx.HTTPError, attempts=5, wait_initial=0.2)
    async def _get_json(self, url: str) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(url)
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict):
                raise ValueError(f"expected JSON object from {url}")
            return payload

    async def metadata(self) -> dict[str, Any]:
        if self._metadata is None:
            self._metadata = await self._get_json(self._settings.keycloak_well_known_url)
        return self._metadata

    def redirect_uri(self) -> str:
        return f"{self._settings.public_base_url}/auth/callback"

    async def authorization_url(self, *, state: str, nonce: str) -> str:
        metadata = await self.metadata()
        endpoint = metadata["authorization_endpoint"]
        query = urlencode(
            {
                "response_type": "code",
                "client_id": self._settings.keycloak_client_id,
                "redirect_uri": self.redirect_uri(),
                "scope": "openid profile email",
                "state": state,
                "nonce": nonce,
            }
        )
        return f"{endpoint}?{query}"

    async def exchange_code(self, code: str) -> dict[str, Any]:
        metadata = await self.metadata()
        async with AsyncOAuth2Client(
            client_id=self._settings.keycloak_client_id,
            client_secret=self._settings.keycloak_client_secret,
            token_endpoint_auth_method="client_secret_post",
        ) as client:
            token = await client.fetch_token(
                metadata["token_endpoint"],
                grant_type="authorization_code",
                code=code,
                redirect_uri=self.redirect_uri(),
            )
        if not isinstance(token, dict):
            raise ValueError("token endpoint returned a non-object")
        return token

    def decode_id_token(self, id_token: str, *, nonce: str) -> Identity:
        if self._metadata is None:
            raise RuntimeError("OIDC metadata has not been loaded")
        jwks_uri = str(self._metadata["jwks_uri"])
        if self._jwks_client is None or self._jwks_uri != jwks_uri:
            self._jwks_client = PyJWKClient(jwks_uri)
            self._jwks_uri = jwks_uri
        signing_key = self._jwks_client.get_signing_key_from_jwt(id_token)
        payload = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=["RS256"],
            audience=self._settings.keycloak_audience,
            issuer=self._settings.keycloak_issuer,
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
        azp = payload.get("azp")
        if azp is not None and azp != self._settings.keycloak_client_id:
            raise jwt.InvalidTokenError("azp does not match client id")
        if payload.get("nonce") != nonce:
            raise jwt.InvalidTokenError("nonce mismatch")
        return identity_from_claims(payload, self._settings.keycloak_client_id)
