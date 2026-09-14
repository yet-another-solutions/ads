from __future__ import annotations

import ssl

from dishka import Provider, Scope, provide

from ads_commons.security import JwtVerifier, jwks_uri_from_well_known
from ads_engine.chat import ChatStreamer, LangChainChatStreamer
from ads_engine.config import Settings
from ads_engine.store import ActiveSessionStore


class AppProvider(Provider):
    def __init__(self, settings: Settings) -> None:
        super().__init__()
        self._settings = settings

    @provide(scope=Scope.APP)
    def settings(self) -> Settings:
        return self._settings

    @provide(scope=Scope.APP)
    def store(self, settings: Settings) -> ActiveSessionStore:
        return ActiveSessionStore(settings.database_url)

    @provide(scope=Scope.APP)
    def chat(self) -> ChatStreamer:
        return LangChainChatStreamer()

    @provide(scope=Scope.APP)
    def jwt_verifier(self, settings: Settings) -> JwtVerifier:
        ssl_context: ssl.SSLContext | None = None
        if settings.tls_ca_bundle is not None:
            ssl_context = ssl.create_default_context(cafile=str(settings.tls_ca_bundle))
        jwks_uri = jwks_uri_from_well_known(settings.keycloak_well_known_url, ssl_context)
        return JwtVerifier(
            issuer=settings.keycloak_issuer,
            audience=settings.keycloak_audience,
            client_id=settings.keycloak_client_id,
            ssl_context=ssl_context,
            jwks_uri=jwks_uri,
        )
