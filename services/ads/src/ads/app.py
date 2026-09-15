from __future__ import annotations

from pathlib import Path

import structlog
from dishka import Provider, Scope, make_async_container, make_container, provide
from dishka.integrations.litestar import LitestarProvider, setup_dishka
from litestar import Litestar
from litestar.middleware.session.client_side import CookieBackendConfig
from litestar.plugins.htmx import HTMXPlugin
from litestar.plugins.jinja import JinjaTemplateEngine
from litestar.static_files import create_static_files_router
from litestar.template.config import TemplateConfig
from sqlalchemy import Engine

from ads.auth import AuthController
from ads.config import Settings
from ads.db import Base, create_db_engine
from ads.engine_output_controller import EngineOutputController
from ads.engine_output_service import EngineOutputService
from ads.exceptions import EXCEPTION_HANDLERS
from ads.frontend import LoginRequired, handle_login_required
from ads.health import live, ready
from ads.ioc import AppProvider, SecuritySettingsProvider, session_factory_for
from ads.kafka import EngineOutputConsumer, EngineRequests
from ads.live import LiveHub
from ads.live_controller import live_socket
from ads.logconfig import configure_logging
from ads.models import Project
from ads.models_controller import ModelsController
from ads.project_controller import ProjectController
from ads.security_middleware import SecurityContextMiddleware
from ads.session_controller import SessionController
from ads.shell_controller import ShellController
from ads.tokens import TokenAuthenticator, TokenMinter
from ads.watchdog import Watchdog
from ads_commons.preferences import PreferencesApi
from ads_commons_beans import CommonsBeansProvider, JwtVerifier, TokenExchange

_ = Project

log = structlog.get_logger("ads")


class _JwtVerifierOverrideProvider(Provider):
    def __init__(self, verifier: JwtVerifier) -> None:
        super().__init__()
        self._verifier = verifier

    @provide(scope=Scope.APP, override=True)
    def jwt_verifier(self) -> JwtVerifier:
        return self._verifier


def build_session_config(settings: Settings) -> CookieBackendConfig:
    return CookieBackendConfig(
        secret=settings.session_secret_bytes(),
        httponly=True,
        secure=settings.cookie_secure(),
        samesite="lax",
        exclude=["/health/live", "/health/ready"],
    )


def create_schema(engine: Engine) -> None:
    Base.metadata.create_all(engine)


def create_app(
    settings: Settings,
    *,
    engine: Engine | None = None,
    preferences: PreferencesApi | None = None,
    kafka: EngineRequests | None = None,
    hub: LiveHub | None = None,
    tokens: TokenMinter | None = None,
    jwt_verifier: TokenAuthenticator | None = None,
    oidc_verifier: JwtVerifier | None = None,
) -> Litestar:
    configure_logging()
    root = Path(__file__).resolve().parent
    db_engine = engine if engine is not None else create_db_engine(settings.database_url)
    authenticator: TokenAuthenticator
    minter: TokenMinter
    if jwt_verifier is not None and tokens is not None:
        authenticator = jwt_verifier
        minter = tokens
    else:
        security_container = make_container(
            CommonsBeansProvider(),
            SecuritySettingsProvider(settings),
        )
        try:
            authenticator = (
                jwt_verifier if jwt_verifier is not None else security_container.get(JwtVerifier)
            )
            minter = tokens if tokens is not None else security_container.get(TokenExchange)
        finally:
            security_container.close()
    session_factory = session_factory_for(db_engine)
    app_provider = AppProvider(
        settings=settings,
        engine=db_engine,
        preferences=preferences,
        kafka=kafka,
        hub=hub,
        tokens=minter,
        authenticator=authenticator,
    )
    container = make_async_container(
        app_provider,
        CommonsBeansProvider(),
        SecuritySettingsProvider(settings),
        *((_JwtVerifierOverrideProvider(oidc_verifier),) if oidc_verifier is not None else ()),
        LitestarProvider(),
    )
    requests = container.get_sync(EngineRequests)
    live_hub = container.get_sync(LiveHub)
    engine_output = container.get_sync(EngineOutputService)
    watchdog = container.get_sync(Watchdog)
    output_controller = EngineOutputController(engine_output)
    consumer = (
        EngineOutputConsumer(settings, output_controller.on_record)
        if settings.kafka_bootstrap_servers.strip()
        else None
    )
    session_config = build_session_config(settings)

    async def _startup() -> None:
        await watchdog.start()
        if consumer is not None:
            await consumer.start()

    async def _shutdown() -> None:
        if consumer is not None:
            await consumer.stop()
        await watchdog.stop()
        await container.close()

    app = Litestar(
        route_handlers=[
            ShellController,
            ProjectController,
            SessionController,
            ModelsController,
            AuthController,
            live_socket,
            live,
            ready,
            create_static_files_router(
                path="/static", directories=[root / "static"], name="static"
            ),
        ],
        plugins=[HTMXPlugin()],
        template_config=TemplateConfig(
            engine=JinjaTemplateEngine(directory=root / "templates"),
        ),
        middleware=[session_config.middleware, SecurityContextMiddleware],
        exception_handlers={
            LoginRequired: handle_login_required,
            **EXCEPTION_HANDLERS,
        },
        on_startup=[_startup],
        on_shutdown=[_shutdown],
    )
    setup_dishka(container, app)
    app.state.db_engine = db_engine
    app.state.db_session_factory = session_factory
    app.state.live_hub = live_hub
    app.state.engine_output = engine_output
    app.state.engine_output_controller = output_controller
    app.state.watchdog = watchdog
    app.state.kafka = requests
    return app
