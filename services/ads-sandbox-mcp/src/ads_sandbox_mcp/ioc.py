from __future__ import annotations

import ssl
from collections.abc import AsyncIterator
from typing import Any

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from dishka import Provider, Scope, provide
from mcp.server import Server
from mcp.server.transport_security import TransportSecuritySettings
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
from ads_sandbox_mcp.runtime import McpRuntime
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
    async def engine(self, settings: Settings) -> AsyncIterator[AsyncEngine]:
        engine = create_async_engine(settings.database_url, pool_pre_ping=True)
        try:
            yield engine
        finally:
            await engine.dispose()

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
    runtime = provide(McpRuntime, scope=Scope.APP)

    @provide(scope=Scope.APP)
    def sdk(self, tools: ToolController, settings: Settings) -> Server[Any]:
        sdk: Server[Any] = Server(
            "ads-sandbox-mcp",
            version="0.0.1",
            on_list_tools=tools.list_tools,
            on_call_tool=tools.call_tool,
        )
        sdk.streamable_http_app(
            json_response=True,
            stateless_http=True,
            max_request_body_size=max(4194304, settings.input_bytes * 6 + 65536),
            transport_security=TransportSecuritySettings(
                allowed_hosts=list(settings.allowed_hosts),
                allowed_origins=list(settings.allowed_origins),
            ),
        )
        return sdk

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
