from __future__ import annotations

from collections.abc import Callable, Iterator

from dishka import Provider, Scope, provide
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from ads.abort_subjects import AbortSubjects
from ads.catalog_service import CatalogService
from ads.config import Settings
from ads.engine_output_service import EngineOutputService
from ads.kafka import EngineRequests
from ads.live import LiveHub
from ads.oidc import OidcClient
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
from ads_commons_beans import JwtVerifier, JwtVerifierSettings, TokenExchangeSettings


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
        preferences: PreferencesApi,
        kafka: EngineRequests,
        hub: LiveHub,
        tokens: TokenMinter,
        authenticator: TokenAuthenticator,
        subjects: AbortSubjects,
    ) -> None:
        super().__init__()
        self._settings = settings
        self._engine = engine
        self._preferences = preferences
        self._kafka = kafka
        self._hub = hub
        self._tokens = tokens
        self._authenticator = authenticator
        self._subjects = subjects

    @provide(scope=Scope.APP)
    def settings(self) -> Settings:
        return self._settings

    @provide(scope=Scope.APP)
    def db_engine(self) -> Engine:
        return self._engine

    @provide(scope=Scope.APP)
    def oidc_client(self, settings: Settings, verifier: JwtVerifier) -> OidcClient:
        return OidcClient(settings, verifier)

    @provide(scope=Scope.APP)
    def preferences(self) -> PreferencesApi:
        return self._preferences

    @provide(scope=Scope.APP)
    def kafka(self) -> EngineRequests:
        return self._kafka

    @provide(scope=Scope.APP)
    def hub(self) -> LiveHub:
        return self._hub

    @provide(scope=Scope.APP)
    def tokens(self) -> TokenMinter:
        return self._tokens

    @provide(scope=Scope.APP)
    def authenticator(self) -> TokenAuthenticator:
        return self._authenticator

    @provide(scope=Scope.APP)
    def engine_output(
        self,
        engine: Engine,
        kafka: EngineRequests,
        hub: LiveHub,
        tokens: TokenMinter,
        authenticator: TokenAuthenticator,
        settings: Settings,
        subjects: AbortSubjects,
    ) -> EngineOutputService:
        return EngineOutputService(
            session_factory=session_factory_for(engine),
            kafka=kafka,
            hub=hub,
            tokens=tokens,
            authenticator=authenticator,
            settings=settings,
            subjects=subjects,
        )

    @provide(scope=Scope.APP)
    def watchdog(
        self,
        engine: Engine,
        engine_output: EngineOutputService,
        settings: Settings,
    ) -> Watchdog:
        return Watchdog(session_factory_for(engine), engine_output, settings)

    @provide(scope=Scope.APP)
    def abort_subjects(self) -> AbortSubjects:
        return self._subjects

    @provide(scope=Scope.REQUEST)
    def session(self, engine: Engine) -> Iterator[Session]:
        session = Session(engine)
        try:
            yield session
        finally:
            session.close()

    @provide(scope=Scope.REQUEST)
    def projects_repository(self, session: Session) -> ProjectRepository:
        return ProjectRepository(session=session)

    @provide(scope=Scope.REQUEST)
    def sessions_repository(self, session: Session) -> SessionRepository:
        return SessionRepository(session=session)

    @provide(scope=Scope.REQUEST)
    def entries_repository(self, session: Session) -> SessionEntryRepository:
        return SessionEntryRepository(session=session)

    @provide(scope=Scope.REQUEST)
    def runs_repository(self, session: Session) -> SessionRunRepository:
        return SessionRunRepository(session=session)

    @provide(scope=Scope.REQUEST)
    def buffer_repository(self, session: Session) -> SessionRunBufferRepository:
        return SessionRunBufferRepository(session=session)

    @provide(scope=Scope.REQUEST)
    def project_service(
        self,
        session: Session,
        projects: ProjectRepository,
        sessions: SessionRepository,
        runs: SessionRunRepository,
    ) -> ProjectService:
        return ProjectService(session=session, projects=projects, sessions=sessions, runs=runs)

    @provide(scope=Scope.REQUEST)
    def session_service(
        self,
        session: Session,
        projects: ProjectRepository,
        sessions: SessionRepository,
        entries: SessionEntryRepository,
        runs: SessionRunRepository,
        buffer: SessionRunBufferRepository,
    ) -> SessionService:
        return SessionService(
            session=session,
            projects=projects,
            sessions=sessions,
            entries=entries,
            runs=runs,
            buffer=buffer,
        )

    @provide(scope=Scope.REQUEST)
    def send_service(
        self,
        session: Session,
        sessions: SessionRepository,
        entries: SessionEntryRepository,
        runs: SessionRunRepository,
        preferences: PreferencesApi,
        kafka: EngineRequests,
        tokens: TokenMinter,
        settings: Settings,
        subjects: AbortSubjects,
    ) -> SendService:
        return SendService(
            session=session,
            sessions=sessions,
            entries=entries,
            runs=runs,
            preferences=preferences,
            kafka=kafka,
            tokens=tokens,
            settings=settings,
            subjects=subjects,
        )

    @provide(scope=Scope.REQUEST)
    def catalog_service(self, preferences: PreferencesApi) -> CatalogService:
        return CatalogService(preferences=preferences)


def session_factory_for(engine: Engine) -> Callable[[], Session]:
    def factory() -> Session:
        return Session(engine)

    return factory
