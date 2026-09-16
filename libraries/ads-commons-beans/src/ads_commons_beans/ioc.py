from __future__ import annotations

from dishka import Provider, Scope, provide
from jwt import PyJWKClient

from ads_commons.security import AccessTokenVerifier
from ads_commons_beans.jwt import JwtVerifier, JwtVerifierSettings, SigningKeySource
from ads_commons_beans.token_exchange import TokenExchange


class CommonsBeansProvider(Provider):
    """Shared ADS beans. Owning modules include this provider."""

    @provide(scope=Scope.APP, provides=SigningKeySource)
    def signing_key_source(self, settings: JwtVerifierSettings) -> SigningKeySource:
        return PyJWKClient(settings.jwks_uri, ssl_context=settings.ssl_context)

    jwt_verifier = provide(JwtVerifier, scope=Scope.APP)

    @provide(scope=Scope.APP)
    def access_token_verifier(self, verifier: JwtVerifier) -> AccessTokenVerifier:
        return verifier

    token_exchange = provide(TokenExchange, scope=Scope.APP)
