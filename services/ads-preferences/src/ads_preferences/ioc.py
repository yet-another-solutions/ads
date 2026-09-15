from __future__ import annotations

from collections.abc import Iterator

from dishka import Provider, Scope, provide
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from ads_preferences.config import Settings
from ads_preferences.repository import UserModelRepository
from ads_preferences.service import PreferencesService


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
