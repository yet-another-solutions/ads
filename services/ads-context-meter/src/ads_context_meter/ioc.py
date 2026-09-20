import ssl

from dishka import Provider, Scope, provide

from ads_commons.security import jwks_uri_from_well_known
from ads_commons_beans import JwtVerifierSettings
from ads_context_meter.config import Settings
from ads_context_meter.service import ContextMeterService
from ads_context_meter.worker import TokenCounter


class AppProvider(Provider):
    def __init__(self, settings: Settings, counter: TokenCounter) -> None:
        super().__init__()
        self._settings = settings
        self._counter = counter

    @provide(scope=Scope.APP)
    def counter(self) -> TokenCounter:
        return self._counter

    @provide(scope=Scope.APP)
    def jwt_verifier_settings(self) -> JwtVerifierSettings:
        ca = self._settings.tls_ca_bundle
        context = ssl.create_default_context(cafile=str(ca)) if ca is not None else None
        return JwtVerifierSettings(
            issuer=self._settings.keycloak_issuer,
            audience=self._settings.keycloak_audience,
            client_id=self._settings.keycloak_client_id,
            jwks_uri=jwks_uri_from_well_known(self._settings.keycloak_well_known_url, context),
            ssl_context=context,
        )

    service = provide(ContextMeterService, scope=Scope.REQUEST)
