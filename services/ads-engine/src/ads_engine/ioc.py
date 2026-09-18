from __future__ import annotations

import ssl
import uuid
from collections.abc import Sequence

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from dishka import Provider, Scope, provide

from ads_commons.engine import EngineOutput, encode_output
from ads_commons.security import (
    SecurityContext,
    jwks_uri_from_well_known,
    token_endpoint_from_well_known,
)
from ads_commons_beans import (
    JwtVerifier,
    JwtVerifierSettings,
    TokenExchange,
    TokenExchangeSettings,
)
from ads_engine.chat import ChatStreamer
from ads_engine.config import Settings
from ads_engine.executor import ExecutorChatStreamer
from ads_engine.kafka import SeekToEndListener
from ads_engine.listener import EngineListener, TokenAuthenticator
from ads_engine.mcp_client import SandboxClient
from ads_engine.mcp_credentials import McpCredentials
from ads_engine.service import EngineService, OutputPublisher, TokenMinter
from ads_engine.store import ActiveSessionStore


class KafkaPublisher:
    def __init__(self, producer: AIOKafkaProducer, settings: Settings) -> None:
        self._producer = producer
        self._topic = settings.output_topic

    async def publish(
        self,
        session_id: uuid.UUID,
        message: EngineOutput,
        headers: Sequence[tuple[str, bytes]] | None = None,
    ) -> None:
        await self._producer.send_and_wait(
            self._topic,
            key=str(session_id).encode("utf-8"),
            value=encode_output(message),
            headers=list(headers or ()),
        )


class AcknowledgeTokens:
    def __init__(self, exchange: TokenExchange) -> None:
        self._exchange = exchange

    def mint(self, audience: str) -> SecurityContext:
        return self._exchange.mint(audience, scope="ads-engine-ack")


class AppProvider(Provider):
    def __init__(self, settings: Settings) -> None:
        super().__init__()
        self._settings = settings

    @provide(scope=Scope.APP)
    def settings(self) -> Settings:
        return self._settings

    store = provide(ActiveSessionStore, scope=Scope.APP)

    credentials = provide(McpCredentials, scope=Scope.APP)
    sandbox = provide(SandboxClient, scope=Scope.APP)
    chat = provide(ExecutorChatStreamer, scope=Scope.APP, provides=ChatStreamer)

    @provide(scope=Scope.APP)
    def producer(self, settings: Settings) -> AIOKafkaProducer:
        return AIOKafkaProducer(bootstrap_servers=settings.kafka_bootstrap_servers)

    @provide(scope=Scope.APP)
    def consumer(self, settings: Settings) -> AIOKafkaConsumer:
        return AIOKafkaConsumer(
            bootstrap_servers=settings.kafka_bootstrap_servers,
            group_id=settings.consumer_group,
            enable_auto_commit=False,
            auto_offset_reset="latest",
        )

    @provide(scope=Scope.APP)
    def seek_to_end_listener(
        self,
        consumer: AIOKafkaConsumer,
    ) -> SeekToEndListener:
        return SeekToEndListener(consumer)

    publisher = provide(KafkaPublisher, scope=Scope.APP, provides=OutputPublisher)

    @provide(scope=Scope.APP)
    def tokens(self, exchange: TokenExchange) -> TokenMinter:
        return AcknowledgeTokens(exchange)

    engine_service = provide(EngineService, scope=Scope.APP)

    @provide(scope=Scope.APP)
    def authenticator(self, verifier: JwtVerifier) -> TokenAuthenticator:
        return verifier

    engine_listener = provide(EngineListener, scope=Scope.APP)

    @provide(scope=Scope.APP)
    def jwt_verifier_settings(self, settings: Settings) -> JwtVerifierSettings:
        ssl_context = _ssl_context(settings)
        jwks_uri = jwks_uri_from_well_known(settings.keycloak_well_known_url, ssl_context)
        return JwtVerifierSettings(
            issuer=settings.keycloak_issuer,
            audience=settings.keycloak_audience,
            client_id=settings.keycloak_client_id,
            ssl_context=ssl_context,
            jwks_uri=jwks_uri,
        )

    @provide(scope=Scope.APP)
    def token_exchange_settings(self, settings: Settings) -> TokenExchangeSettings:
        ssl_context = _ssl_context(settings)
        token_endpoint = token_endpoint_from_well_known(
            settings.keycloak_well_known_url,
            ssl_context,
        )
        return TokenExchangeSettings(
            token_endpoint=token_endpoint,
            client_id=settings.keycloak_audience,
            client_secret=settings.keycloak_client_secret,
            ssl_context=ssl_context,
        )


def _ssl_context(settings: Settings) -> ssl.SSLContext | None:
    if settings.tls_ca_bundle is None:
        return None
    return ssl.create_default_context(cafile=str(settings.tls_ca_bundle))
