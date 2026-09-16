from __future__ import annotations

import ssl
from dataclasses import dataclass

from dishka import Provider, Scope, provide
from jwt import PyJWKClient

from ads_commons_beans.jwt import JwtVerifier, JwtVerifierSettings, SigningKeySource
from ads_commons_beans.token_exchange import TokenExchange


@dataclass(frozen=True)
class TokenExchangeSettings:
    token_endpoint: str
    client_id: str
    client_secret: str
    ssl_context: ssl.SSLContext | None


class CommonsBeansProvider(Provider):
    """Shared ADS beans. Owning modules include this provider."""

    @provide(scope=Scope.APP, provides=SigningKeySource)
    def signing_key_source(self, settings: JwtVerifierSettings) -> SigningKeySource:
        return PyJWKClient(settings.jwks_uri, ssl_context=settings.ssl_context)

    jwt_verifier = provide(JwtVerifier, scope=Scope.APP)

    @provide(scope=Scope.APP)
    def token_exchange(
        self,
        settings: TokenExchangeSettings,
        verifier: JwtVerifier,
    ) -> TokenExchange:
        return TokenExchange(
            token_endpoint=settings.token_endpoint,
            client_id=settings.client_id,
            client_secret=settings.client_secret,
            verifier=verifier,
            ssl_context=settings.ssl_context,
        )
