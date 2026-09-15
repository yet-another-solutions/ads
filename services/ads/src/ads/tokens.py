"""Standard Token Exchange V2 access for ads. Tokens stay in memory, never persisted."""

from __future__ import annotations

import ssl
from typing import Protocol

from jwt import PyJWKClient

from ads.config import Settings
from ads_commons.security import (
    SecurityContext,
    TokenExchange,
    jwks_uri_from_well_known,
    token_endpoint_from_well_known,
)
from ads_commons_beans import JwtVerifier


class TokenMinter(Protocol):
    """Exchange for an audience. ``subject_token`` overrides the bound holder token."""

    def exchange(self, audience: str, subject_token: str | None = None) -> str: ...

    def mint(self, audience: str, subject_token: str | None = None) -> SecurityContext: ...


class TokenAuthenticator(Protocol):
    def authenticate(self, token: str, *, audience: str | None = None) -> SecurityContext: ...


def ssl_context_for(settings: Settings) -> ssl.SSLContext | None:
    if settings.tls_ca_bundle is None:
        return None
    return ssl.create_default_context(cafile=str(settings.tls_ca_bundle))


class KeycloakJwtVerifier:
    """Lazy JwtVerifier: the JWKS URI is discovered on first use, not at import."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._verifier: JwtVerifier | None = None

    def verifier(self) -> JwtVerifier:
        if self._verifier is None:
            ssl_context = ssl_context_for(self._settings)
            self._verifier = JwtVerifier(
                issuer=self._settings.keycloak_issuer,
                audience=self._settings.keycloak_audience,
                client_id=self._settings.keycloak_client_id,
                jwks_client=PyJWKClient(
                    jwks_uri_from_well_known(
                        self._settings.keycloak_well_known_url,
                        ssl_context=ssl_context,
                    ),
                    ssl_context=ssl_context,
                ),
            )
        return self._verifier

    def authenticate(self, token: str, *, audience: str | None = None) -> SecurityContext:
        return self.verifier().authenticate(token, audience=audience)


class KeycloakTokenExchange:
    """Lazy TokenExchange: the token endpoint is discovered on first use."""

    def __init__(self, settings: Settings, authenticator: KeycloakJwtVerifier) -> None:
        self._settings = settings
        self._authenticator = authenticator
        self._exchange: TokenExchange | None = None

    def _delegate(self) -> TokenExchange:
        if self._exchange is None:
            ssl_context = ssl_context_for(self._settings)
            self._exchange = TokenExchange(
                token_endpoint=token_endpoint_from_well_known(
                    self._settings.keycloak_well_known_url,
                    ssl_context,
                ),
                client_id=self._settings.keycloak_client_id,
                client_secret=self._settings.keycloak_client_secret,
                verifier=self._authenticator.verifier(),
                ssl_context=ssl_context,
            )
        return self._exchange

    def exchange(self, audience: str, subject_token: str | None = None) -> str:
        return self._delegate().exchange(audience, subject_token)

    def mint(self, audience: str, subject_token: str | None = None) -> SecurityContext:
        return self._delegate().mint(audience, subject_token)
