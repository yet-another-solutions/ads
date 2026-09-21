from __future__ import annotations

from dishka import Provider, Scope, make_async_container, provide
from dishka.integrations.litestar import LitestarProvider, setup_dishka
from litestar import Litestar
from sqlalchemy import Engine

from ads_commons_beans import CommonsBeansProvider, JwtVerifier
from ads_preferences.config import Settings
from ads_preferences.controller import ModelsController
from ads_preferences.db import Base, create_db_engine
from ads_preferences.egress_controller import ProjectEgressController
from ads_preferences.exceptions import EXCEPTION_HANDLERS
from ads_preferences.health import live, ready
from ads_preferences.ioc import AppProvider, SecuritySettingsProvider
from ads_preferences.logconfig import configure_logging
from ads_preferences.middleware import jwt_caller_middleware
from ads_preferences.models import UserModel

_ = UserModel


class _JwtVerifierOverrideProvider(Provider):
    def __init__(self, verifier: JwtVerifier) -> None:
        super().__init__()
        self._verifier = verifier

    @provide(scope=Scope.APP, override=True)
    def jwt_verifier(self) -> JwtVerifier:
        return self._verifier


def create_app(
    settings: Settings,
    *,
    jwt_verifier: JwtVerifier | None = None,
    engine: Engine | None = None,
) -> Litestar:
    configure_logging()
    db_engine = engine if engine is not None else create_db_engine(settings.database_url)
    overrides: list[Provider] = []
    if jwt_verifier is not None:
        overrides.append(_JwtVerifierOverrideProvider(jwt_verifier))
    container = make_async_container(
        AppProvider(settings, db_engine),
        CommonsBeansProvider(),
        SecuritySettingsProvider(settings),
        *overrides,
        LitestarProvider(),
        skip_validation=True,
    )
    verifier = container.get_sync(JwtVerifier)
    app = Litestar(
        route_handlers=[ModelsController, ProjectEgressController, live, ready],
        middleware=[jwt_caller_middleware(settings, verifier)],
        exception_handlers=EXCEPTION_HANDLERS,
        on_shutdown=[container.close],
    )
    setup_dishka(container, app)
    app.state.db_engine = db_engine
    return app


def create_schema(engine: Engine) -> None:
    Base.metadata.create_all(engine)
