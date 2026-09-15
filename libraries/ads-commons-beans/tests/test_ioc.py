from dishka import Provider, Scope, make_container, provide

from ads_commons_beans import (
    CommonsBeansProvider,
    JwtVerifier,
    JwtVerifierSettings,
    TokenExchange,
    TokenExchangeSettings,
)


class _SettingsProvider(Provider):
    @provide(scope=Scope.APP)
    def settings(self) -> JwtVerifierSettings:
        return JwtVerifierSettings(
            issuer="https://keycloak.test/realms/ads",
            audience="ads",
            client_id="ads",
            jwks_uri="https://keycloak.test/realms/ads/protocol/openid-connect/certs",
            ssl_context=None,
        )

    @provide(scope=Scope.APP)
    def token_exchange_settings(self) -> TokenExchangeSettings:
        return TokenExchangeSettings(
            token_endpoint="https://keycloak.test/realms/ads/protocol/openid-connect/token",
            client_id="ads",
            client_secret="secret",
            ssl_context=None,
        )


def test_commons_beans_provider_yields_app_beans() -> None:
    container = make_container(CommonsBeansProvider(), _SettingsProvider())
    assert isinstance(container.get(JwtVerifier), JwtVerifier)
    token_exchange = container.get(TokenExchange)
    assert isinstance(token_exchange, TokenExchange)
    assert container.get(TokenExchange) is token_exchange
    container.close()
