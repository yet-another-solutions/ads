from __future__ import annotations

import ssl
from typing import Any
from urllib.parse import urlencode

import httpx2
import stamina
from authlib.integrations.httpx_client import AsyncOAuth2Client

from ads.config import Settings
from ads.identity import Identity
from ads_commons_beans import JwtVerifier


class OidcClient:
    def __init__(self, settings: Settings, verifier: JwtVerifier) -> None:
        self._settings = settings
        self._metadata: dict[str, Any] | None = None
        self._verifier = verifier

    def _ssl_context(self) -> ssl.SSLContext | None:
        if self._settings.tls_ca_bundle is None:
            return None
        return ssl.create_default_context(cafile=str(self._settings.tls_ca_bundle))

    def _verify(self) -> ssl.SSLContext | bool:
        context = self._ssl_context()
        if context is None:
            return True
        return context

    @stamina.retry(on=httpx2.HTTPError, attempts=5, wait_initial=0.2)
    async def _get_json(self, url: str) -> dict[str, Any]:
        async with httpx2.AsyncClient(timeout=10.0, verify=self._verify()) as client:
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
            verify=self._verify(),
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
        return self._verifier.decode(id_token, nonce=nonce)
