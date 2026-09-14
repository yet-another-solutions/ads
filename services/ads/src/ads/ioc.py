from __future__ import annotations

from dishka import Provider, Scope, provide

from ads.config import Settings
from ads.hello.service import HelloService
from ads.oidc import OidcClient
from ads_policy.client import PolicyClient, build_policy_client
from ads_policy.config import GovernanceSettings


class AppProvider(Provider):
    def __init__(self, settings: Settings) -> None:
        super().__init__()
        self._settings = settings

    @provide(scope=Scope.APP)
    def settings(self) -> Settings:
        return self._settings

    @provide(scope=Scope.APP)
    def oidc_client(self, settings: Settings) -> OidcClient:
        return OidcClient(settings)

    @provide(scope=Scope.APP)
    def policy_client(self, settings: Settings) -> PolicyClient:
        return build_policy_client(
            settings.policy_url,
            settings.policy_api_token,
            denied_message=GovernanceSettings().denied_message,
            ca_bundle=settings.tls_ca_bundle,
        )

    @provide(scope=Scope.APP)
    def hello_service(self) -> HelloService:
        return HelloService()
