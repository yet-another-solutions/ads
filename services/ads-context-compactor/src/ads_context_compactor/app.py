from __future__ import annotations

import ssl
from typing import Any

from dishka import Provider, Scope, make_async_container, provide
from dishka.integrations.litestar import LitestarProvider, setup_dishka
from litestar import Litestar, Request, Response

from ads_commons.security import (
    AccessDenied,
    AuthenticationRequired,
    jwks_uri_from_well_known,
    token_endpoint_from_well_known,
)
from ads_commons_beans import (
    CommonsBeansProvider,
    JwtVerifier,
    JwtVerifierSettings,
    TokenExchange,
    TokenExchangeSettings,
)
from ads_context_compactor.config import Settings
from ads_context_compactor.controller import CompactorController
from ads_context_compactor.health import live, ready
from ads_context_compactor.middleware import jwt_caller_middleware
from ads_context_compactor.service import ContextCompactorService
from ads_context_runtime.frames import ContextFailure
from ads_context_runtime.http import ContextClients


class AppProvider(Provider):
    def __init__(self, settings: Settings) -> None:
        super().__init__()
        self.settings = settings

    @provide(scope=Scope.APP)
    def verifier_settings(self) -> JwtVerifierSettings:
        s = self.settings
        context = ssl.create_default_context(cafile=s.tls_ca_bundle)
        return JwtVerifierSettings(
            issuer=s.keycloak_issuer,
            audience=s.keycloak_audience,
            client_id=s.keycloak_client_id,
            jwks_uri=jwks_uri_from_well_known(s.keycloak_well_known_url, context),
            ssl_context=context,
        )

    @provide(scope=Scope.APP)
    def exchange_settings(self) -> TokenExchangeSettings:
        s = self.settings
        context = ssl.create_default_context(cafile=s.tls_ca_bundle)
        return TokenExchangeSettings(
            token_endpoint=token_endpoint_from_well_known(s.keycloak_well_known_url, context),
            client_id=s.keycloak_client_id,
            client_secret=s.keycloak_client_secret,
            ssl_context=context,
        )

    @provide(scope=Scope.REQUEST)
    def service(self, exchange: TokenExchange) -> ContextCompactorService:
        s = self.settings
        clients = ContextClients(
            exchange,
            s.meter_url,
            "",
            ssl.create_default_context(cafile=s.tls_ca_bundle),
        )
        return ContextCompactorService(clients, reserve=s.reserve, summary_cap=s.summary_cap)


def failure(request: Request[Any, Any, Any], exc: Exception) -> Response[Any]:
    status = (
        401
        if isinstance(exc, AuthenticationRequired)
        else (403 if isinstance(exc, AccessDenied) else 422)
    )
    return Response({"detail": "context request failed"}, status_code=status)


def create_app(settings: Settings, *, overrides: list[Provider] | None = None) -> Litestar:
    container = make_async_container(
        AppProvider(settings),
        CommonsBeansProvider(),
        *(overrides or []),
        LitestarProvider(),
        skip_validation=True,
    )
    verifier = container.get_sync(JwtVerifier)
    app = Litestar(
        route_handlers=[CompactorController, live, ready],
        middleware=[jwt_caller_middleware(settings, verifier)],
        exception_handlers={
            AuthenticationRequired: failure,
            AccessDenied: failure,
            ContextFailure: failure,
        },
        on_shutdown=[container.close],
        openapi_config=None,
        request_max_body_size=16 * 1024 * 1024,
    )
    setup_dishka(container, app)
    return app
