from __future__ import annotations

import asyncio

from dishka import Provider, Scope, make_async_container, provide
from sqlalchemy import Engine

from ads.config import Settings
from ads.ioc import AppProvider
from ads.oidc import OidcClient
from ads.tokens import TokenAuthenticator, TokenMinter
from ads_commons_beans import (
    CommonsBeansProvider,
    JwtVerifier,
    JwtVerifierSettings,
    TokenExchange,
    TokenExchangeSettings,
)


class _OfflineSecurity(Provider):
    @provide(scope=Scope.APP)
    def jwt_verifier_settings(self) -> JwtVerifierSettings:
        return JwtVerifierSettings(
            issuer="https://iss.test",
            audience="ads",
            client_id="ads",
            jwks_uri="https://iss.test/jwks",
            ssl_context=None,
        )

    @provide(scope=Scope.APP)
    def token_exchange_settings(self) -> TokenExchangeSettings:
        return TokenExchangeSettings(
            token_endpoint="https://iss.test/token",
            client_id="ads",
            client_secret="secret",
            ssl_context=None,
        )


def test_oidc_and_authenticator_share_one_jwt_verifier(
    settings: Settings, db_engine: Engine
) -> None:
    container = make_async_container(
        AppProvider(settings, db_engine),
        CommonsBeansProvider(),
        _OfflineSecurity(),
    )
    try:
        verifier = container.get_sync(JwtVerifier)
        authenticator = container.get_sync(TokenAuthenticator)
        oidc = container.get_sync(OidcClient)
        minter = container.get_sync(TokenMinter)
        assert authenticator is verifier
        assert oidc._verifier is verifier
        assert isinstance(minter, TokenExchange)
        assert minter._verifier is verifier
    finally:
        asyncio.run(container.close())
