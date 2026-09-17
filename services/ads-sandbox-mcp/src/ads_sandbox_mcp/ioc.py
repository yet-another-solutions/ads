from __future__ import annotations

import ssl

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from dishka import Provider, Scope, provide
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from ads_commons.security import jwks_uri_from_well_known, token_endpoint_from_well_known
from ads_commons_beans import JwtVerifierSettings, TokenExchange, TokenExchangeSettings
from ads_sandbox_mcp.config import Settings
from ads_sandbox_mcp.controller import ToolController
from ads_sandbox_mcp.kafka import KafkaPublisher, KafkaRuntime, ReplyController, consumer_group
from ads_sandbox_mcp.scheduler import ClusterScheduler
from ads_sandbox_mcp.service import ExecService, Publisher, TokenMinter, Watchdog
from ads_sandbox_mcp.store import InFlightRepository


class AppProvider(Provider):
    def __init__(self, settings: Settings) -> None:
        super().__init__()
        self._settings = settings

    @provide(scope=Scope.APP)
    def settings(self) -> Settings:
        return self._settings

    @provide(scope=Scope.APP)
    def engine(self, settings: Settings) -> AsyncEngine:
        return create_async_engine(settings.database_url, pool_pre_ping=True)

    @provide(scope=Scope.APP)
    def sessions(self, engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
        return async_sessionmaker(engine, expire_on_commit=False)

    @provide(scope=Scope.APP)
    def producer(self, settings: Settings) -> AIOKafkaProducer:
        return AIOKafkaProducer(bootstrap_servers=settings.kafka_bootstrap_servers)

    @provide(scope=Scope.APP)
    def consumer(self, settings: Settings) -> AIOKafkaConsumer:
        return AIOKafkaConsumer(
            bootstrap_servers=settings.kafka_bootstrap_servers,
            group_id=consumer_group(),
            enable_auto_commit=False,
            auto_offset_reset="latest",
        )

    @provide(scope=Scope.APP)
    def tokens(self, exchange: TokenExchange) -> TokenMinter:
        return exchange

    repository = provide(InFlightRepository, scope=Scope.APP)
    watchdog = provide(Watchdog, scope=Scope.APP)
    publisher = provide(KafkaPublisher, scope=Scope.APP, provides=Publisher)
    exec_service = provide(ExecService, scope=Scope.APP)
    tools = provide(ToolController, scope=Scope.APP)
    replies = provide(ReplyController, scope=Scope.APP)
    kafka = provide(KafkaRuntime, scope=Scope.APP)
    scheduler = provide(ClusterScheduler, scope=Scope.APP)

    @provide(scope=Scope.APP)
    def jwt_settings(self, settings: Settings) -> JwtVerifierSettings:
        context = _ssl(settings)
        return JwtVerifierSettings(
            issuer=settings.keycloak_issuer,
            audience="ads-sandbox-mcp",
            client_id="ads-sandbox-mcp",
            jwks_uri=jwks_uri_from_well_known(settings.keycloak_well_known_url, context),
            ssl_context=context,
        )

    @provide(scope=Scope.APP)
    def exchange_settings(self, settings: Settings) -> TokenExchangeSettings:
        context = _ssl(settings)
        return TokenExchangeSettings(
            token_endpoint=token_endpoint_from_well_known(
                settings.keycloak_well_known_url, context
            ),
            client_id="ads-sandbox-mcp",
            client_secret=settings.keycloak_client_secret,
            ssl_context=context,
        )


def _ssl(settings: Settings) -> ssl.SSLContext | None:
    return (
        ssl.create_default_context(cafile=str(settings.tls_ca_bundle))
        if settings.tls_ca_bundle
        else None
    )
