from __future__ import annotations

from dishka import make_async_container
from dishka.integrations.litestar import LitestarProvider, setup_dishka
from litestar import Litestar
from sqlalchemy import Engine

from ads_commons_beans import JwtVerifier
from ads_preferences.config import Settings
from ads_preferences.controller import ModelsController
from ads_preferences.db import Base, create_db_engine
from ads_preferences.exceptions import EXCEPTION_HANDLERS
from ads_preferences.health import live, ready
from ads_preferences.ioc import AppProvider
from ads_preferences.logconfig import configure_logging
from ads_preferences.middleware import jwt_caller_middleware
from ads_preferences.models import UserModel

_ = UserModel


def create_app(
    settings: Settings,
    *,
    jwt_verifier: JwtVerifier | None = None,
    engine: Engine | None = None,
) -> Litestar:
    configure_logging()
    db_engine = engine if engine is not None else create_db_engine(settings.database_url)
    container = make_async_container(AppProvider(settings, db_engine), LitestarProvider())
    app = Litestar(
        route_handlers=[ModelsController, live, ready],
        middleware=[jwt_caller_middleware(settings, jwt_verifier)],
        exception_handlers=EXCEPTION_HANDLERS,
        on_shutdown=[container.close],
    )
    setup_dishka(container, app)
    app.state.db_engine = db_engine
    return app


def create_schema(engine: Engine) -> None:
    Base.metadata.create_all(engine)
