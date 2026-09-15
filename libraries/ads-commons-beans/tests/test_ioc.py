from dishka import Provider, Scope, make_container, provide

from ads_commons_beans import CommonsBeansProvider, JwtVerifier, JwtVerifierSettings


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


def test_commons_beans_provider_yields_jwt_verifier() -> None:
    container = make_container(CommonsBeansProvider(), _SettingsProvider())
    assert isinstance(container.get(JwtVerifier), JwtVerifier)
    container.close()
