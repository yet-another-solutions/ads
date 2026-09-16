from __future__ import annotations

from collections.abc import Callable, Iterator

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from dishka import Provider, Scope, provide
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from ads.abort_subjects import AbortSubjects
from ads.catalog_service import CatalogService
from ads.config import Settings
from ads.engine_output_controller import EngineOutputController
from ads.engine_output_service import EngineOutputService, SessionFactory
from ads.kafka import (
    AiokafkaEngineRequests,
    EngineOutputConsumer,
    EngineRequests,
    SeekToEndListener,
)
from ads.live import LiveHub
from ads.oidc import OidcClient
from ads.preferences_client import PreferencesClient
from ads.project_service import ProjectService
from ads.repository import (
    ProjectRepository,
    SessionEntryRepository,
    SessionRepository,
    SessionRunBufferRepository,
    SessionRunRepository,
)
from ads.send_service import SendService
from ads.session_service import SessionService
from ads.tokens import TokenAuthenticator, TokenMinter, ssl_context_for
from ads.watchdog import Watchdog
from ads_commons.preferences import PreferencesApi
from ads_commons.security import (
    jwks_uri_from_well_known,
    token_endpoint_from_well_known,
)
from ads_commons_beans import (
    JwtVerifier,
    JwtVerifierSettings,
    TokenExchange,
    TokenExchangeSettings,
)
from ads_policy.client import PolicyClient, build_policy_client
from ads_policy.config import GovernanceSettings


class SecuritySettingsProvider(Provider):
    """Adapt ads settings for the shared security beans."""

    def __init__(self, settings: Settings) -> None:
        super().__init__()
        self._settings = settings

    @provide(scope=Scope.APP)
    def jwt_verifier_settings(self) -> JwtVerifierSettings:
        ssl_context = ssl_context_for(self._settings)
        return JwtVerifierSettings(
            issuer=self._settings.keycloak_issuer,
            audience=self._settings.keycloak_audience,
            client_id=self._settings.keycloak_client_id,
            jwks_uri=jwks_uri_from_well_known(
                self._settings.keycloak_well_known_url,
                ssl_context,
            ),
            ssl_context=ssl_context,
        )

    @provide(scope=Scope.APP)
    def token_exchange_settings(self) -> TokenExchangeSettings:
        ssl_context = ssl_context_for(self._settings)
        return TokenExchangeSettings(
            token_endpoint=token_endpoint_from_well_known(
                self._settings.keycloak_well_known_url,
                ssl_context,
            ),
            client_id=self._settings.keycloak_client_id,
            client_secret=self._settings.keycloak_client_secret,
            ssl_context=ssl_context,
        )


class AppProvider(Provider):
    """APP: engine, settings, gateways. REQUEST: Session, repositories, services."""

    def __init__(
        self,
        settings: Settings,
        engine: Engine,
        preferences: PreferencesApi | None = None,
        kafka: EngineRequests | None = None,
        hub: LiveHub | None = None,
    ) -> None:
        super().__init__()
        self._settings = settings
        self._engine = engine
        self._preferences = preferences
        self._kafka = kafka
        self._hub = hub

    @provide(scope=Scope.APP)
    def settings(self) -> Settings:
        return self._settings

    @provide(scope=Scope.APP)
    def db_engine(self) -> Engine:
        return self._engine

    oidc_client = provide(OidcClient, scope=Scope.APP)

    @provide(scope=Scope.APP)
    def policy_client(self, settings: Settings) -> PolicyClient:
        return build_policy_client(
            settings.policy_url,
            settings.policy_api_token,
            denied_message=GovernanceSettings().denied_message,
            ca_bundle=settings.tls_ca_bundle,
        )

    @provide(scope=Scope.APP)
    def preferences(self, settings: Settings, tokens: TokenMinter) -> PreferencesApi:
        if self._preferences is not None:
            return self._preferences
        return PreferencesClient(settings, tokens)

    @provide(scope=Scope.APP)
    def kafka(self, settings: Settings) -> EngineRequests:
        if self._kafka is not None:
            return self._kafka
        return AiokafkaEngineRequests(
            settings,
            AIOKafkaProducer(bootstrap_servers=settings.kafka_bootstrap_servers),
        )

    @provide(scope=Scope.APP)
    def hub(self) -> LiveHub:
        if self._hub is not None:
            return self._hub
        return LiveHub()

    @provide(scope=Scope.APP)
    def tokens(self, exchange: TokenExchange) -> TokenMinter:
        return exchange

    @provide(scope=Scope.APP)
    def authenticator(self, verifier: JwtVerifier) -> TokenAuthenticator:
        return verifier

    @provide(scope=Scope.APP)
    def session_factory(self, engine: Engine) -> SessionFactory:
        return session_factory_for(engine)

    engine_output = provide(EngineOutputService, scope=Scope.APP)
    engine_output_controller = provide(EngineOutputController, scope=Scope.APP)

    @provide(scope=Scope.APP)
    def engine_output_consumer(
        self,
        settings: Settings,
        controller: EngineOutputController,
    ) -> EngineOutputConsumer:
        consumer = AIOKafkaConsumer(
            bootstrap_servers=settings.kafka_bootstrap_servers,
            group_id=settings.engine_consumer_group,
            enable_auto_commit=False,
            auto_offset_reset="latest",
        )
        listener = SeekToEndListener(consumer)
        return EngineOutputConsumer(
            settings,
            controller.on_record,
            consumer,
            listener,
        )

    watchdog = provide(Watchdog, scope=Scope.APP)
    abort_subjects = provide(AbortSubjects, scope=Scope.APP)

    @provide(scope=Scope.REQUEST)
    def session(self, engine: Engine) -> Iterator[Session]:
        session = Session(engine)
        try:
            yield session
        finally:
            session.close()

    project_repository = provide(ProjectRepository, scope=Scope.REQUEST)
    session_repository = provide(SessionRepository, scope=Scope.REQUEST)
    entry_repository = provide(SessionEntryRepository, scope=Scope.REQUEST)
    run_repository = provide(SessionRunRepository, scope=Scope.REQUEST)
    buffer_repository = provide(SessionRunBufferRepository, scope=Scope.REQUEST)
    project_service = provide(ProjectService, scope=Scope.REQUEST)
    session_service = provide(SessionService, scope=Scope.REQUEST)
    send_service = provide(SendService, scope=Scope.REQUEST)
    catalog_service = provide(CatalogService, scope=Scope.REQUEST)


def session_factory_for(engine: Engine) -> Callable[[], Session]:
    def factory() -> Session:
        return Session(engine)

    return factory
