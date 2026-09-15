from __future__ import annotations

import ssl
from collections.abc import Iterator

from dishka import Provider, Scope, provide
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from ads_commons.security import jwks_uri_from_well_known
from ads_commons_beans import JwtVerifierSettings
from ads_preferences.config import Settings
from ads_preferences.repository import UserModelRepository
from ads_preferences.service import PreferencesService


class SecuritySettingsProvider(Provider):
    """Adapt preferences settings for the shared security beans."""

    def __init__(self, settings: Settings) -> None:
        super().__init__()
        self._settings = settings

    @provide(scope=Scope.APP)
    def jwt_verifier_settings(self) -> JwtVerifierSettings:
        ssl_context = (
            ssl.create_default_context(cafile=str(self._settings.tls_ca_bundle))
            if self._settings.tls_ca_bundle is not None
            else None
        )
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


class AppProvider(Provider):
    def __init__(self, settings: Settings, engine: Engine) -> None:
        super().__init__()
        self._settings = settings
        self._engine = engine

    @provide(scope=Scope.APP)
    def settings(self) -> Settings:
        return self._settings

    @provide(scope=Scope.APP)
    def engine(self) -> Engine:
        return self._engine

    @provide(scope=Scope.REQUEST)
    def session(self, engine: Engine) -> Iterator[Session]:
        session = Session(engine)
        try:
            yield session
        finally:
            session.close()

    @provide(scope=Scope.REQUEST)
    def repository(self, session: Session) -> UserModelRepository:
        return UserModelRepository(session=session)

    @provide(scope=Scope.REQUEST)
    def service(self, session: Session, repository: UserModelRepository) -> PreferencesService:
        return PreferencesService(session=session, repository=repository)
