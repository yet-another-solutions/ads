from typing import Any

from dishka import Provider, Scope, make_async_container, provide
from dishka.integrations.litestar import LitestarProvider, setup_dishka
from litestar import Litestar, Request, Response

from ads_commons.security import AccessDenied, AuthenticationRequired
from ads_commons_beans import CommonsBeansProvider, JwtVerifier
from ads_context_meter.config import Settings
from ads_context_meter.controller import MeterController
from ads_context_meter.health import live, ready
from ads_context_meter.ioc import AppProvider
from ads_context_meter.logconfig import configure_logging
from ads_context_meter.middleware import jwt_caller_middleware
from ads_context_meter.worker import TokenCounter


class _VerifierOverride(Provider):
    def __init__(self, verifier: JwtVerifier) -> None:
        super().__init__()
        self._verifier = verifier

    @provide(scope=Scope.APP, override=True)
    def verifier(self) -> JwtVerifier:
        return self._verifier


def security_error(request: Request[Any, Any, Any], exc: Exception) -> Response[Any]:
    status = 401 if isinstance(exc, AuthenticationRequired) else 403
    return Response(
        {"status_code": status, "detail": "unauthorized" if status == 401 else "forbidden"},
        status_code=status,
    )


def create_app(
    settings: Settings,
    *,
    jwt_verifier: JwtVerifier | None = None,
    counter: TokenCounter | None = None,
) -> Litestar:
    configure_logging()
    counter = counter if counter is not None else TokenCounter(settings)
    overrides = [_VerifierOverride(jwt_verifier)] if jwt_verifier is not None else []
    container = make_async_container(
        AppProvider(settings, counter),
        CommonsBeansProvider(),
        *overrides,
        LitestarProvider(),
        skip_validation=True,
    )
    try:
        verifier = container.get_sync(JwtVerifier)
    except BaseException:
        counter.close()
        raise

    async def shutdown() -> None:
        await container.close()
        counter.close()

    app = Litestar(
        route_handlers=[MeterController, live, ready],
        middleware=[jwt_caller_middleware(settings, verifier)],
        exception_handlers={AuthenticationRequired: security_error, AccessDenied: security_error},
        on_shutdown=[shutdown],
        openapi_config=None,
        request_max_body_size=16 * 1024 * 1024,
    )
    setup_dishka(container, app)
    return app
