from __future__ import annotations

from dishka import Provider, Scope, provide

from ads.config import Settings
from ads.hello.service import HelloService
from ads.oidc import OidcClient


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
    def hello_service(self) -> HelloService:
        return HelloService()
