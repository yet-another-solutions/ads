from __future__ import annotations

import ssl
import uuid
from collections.abc import Sequence

from aiokafka import AIOKafkaProducer
from dishka import Provider, Scope, provide

from ads_commons.engine import EngineOutput, encode_output
from ads_commons.security import (
    jwks_uri_from_well_known,
    token_endpoint_from_well_known,
)
from ads_commons_beans import (
    JwtVerifier,
    JwtVerifierSettings,
    TokenExchange,
    TokenExchangeSettings,
)
from ads_engine.chat import ChatStreamer, LangChainChatStreamer
from ads_engine.config import Settings
from ads_engine.listener import EngineListener
from ads_engine.service import EngineService, OutputPublisher
from ads_engine.store import ActiveSessionStore


class KafkaPublisher:
    def __init__(self, producer: AIOKafkaProducer, topic: str) -> None:
        self._producer = producer
        self._topic = topic

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


class AppProvider(Provider):
    def __init__(self, settings: Settings) -> None:
        super().__init__()
        self._settings = settings

    @provide(scope=Scope.APP)
    def settings(self) -> Settings:
        return self._settings

    @provide(scope=Scope.APP)
    def store(self, settings: Settings) -> ActiveSessionStore:
        return ActiveSessionStore(settings.database_url)

    @provide(scope=Scope.APP)
    def chat(self) -> ChatStreamer:
        return LangChainChatStreamer()

    @provide(scope=Scope.APP)
    def producer(self, settings: Settings) -> AIOKafkaProducer:
        return AIOKafkaProducer(bootstrap_servers=settings.kafka_bootstrap_servers)

    @provide(scope=Scope.APP, provides=OutputPublisher)
    def publisher(
        self,
        producer: AIOKafkaProducer,
        settings: Settings,
    ) -> KafkaPublisher:
        return KafkaPublisher(producer, settings.output_topic)

    @provide(scope=Scope.APP)
    def engine_service(
        self,
        store: ActiveSessionStore,
        publisher: OutputPublisher,
        chat: ChatStreamer,
        tokens: TokenExchange,
        settings: Settings,
    ) -> EngineService:
        return EngineService(
            store=store,
            publisher=publisher,
            chat=chat,
            ping_interval_seconds=settings.ping_interval_seconds,
            allowed_callers=settings.allowed_callers,
            tokens=tokens,
            ack_timeout_seconds=settings.ack_timeout_seconds,
            ack_audience=settings.ack_audience,
        )

    @provide(scope=Scope.APP)
    def engine_listener(
        self,
        service: EngineService,
        publisher: OutputPublisher,
        authenticator: JwtVerifier,
        settings: Settings,
    ) -> EngineListener:
        return EngineListener(
            service=service,
            publisher=publisher,
            authenticator=authenticator,
            allowed_callers=settings.allowed_callers,
        )

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
