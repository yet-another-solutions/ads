from __future__ import annotations

from pathlib import Path

from dishka import make_async_container
from dishka.integrations.litestar import LitestarProvider, setup_dishka
from litestar import Litestar
from litestar.middleware.session.client_side import CookieBackendConfig
from litestar.plugins.jinja import JinjaTemplateEngine
from litestar.template.config import TemplateConfig

from ads.auth import AuthController
from ads.authenticated import LoginRequired, handle_login_required
from ads.config import Settings
from ads.health import live, ready
from ads.hello.controller import HelloController
from ads.ioc import AppProvider
from ads.logconfig import configure_logging


def build_session_config(settings: Settings) -> CookieBackendConfig:
    return CookieBackendConfig(
        secret=settings.session_secret_bytes(),
        httponly=True,
        secure=settings.cookie_secure(),
        samesite="lax",
        exclude=["/health/live", "/health/ready"],
    )


def create_app(settings: Settings) -> Litestar:
    configure_logging()
    templates = Path(__file__).resolve().parent / "templates"
    session_config = build_session_config(settings)
    container = make_async_container(AppProvider(settings), LitestarProvider())
    app = Litestar(
        route_handlers=[HelloController, AuthController, live, ready],
        template_config=TemplateConfig(
            engine=JinjaTemplateEngine(directory=templates),
        ),
        middleware=[session_config.middleware],
        exception_handlers={LoginRequired: handle_login_required},
        on_shutdown=[container.close],
    )
    setup_dishka(container, app)
    return app
