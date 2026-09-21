from __future__ import annotations

import ssl
from collections.abc import AsyncIterator

from aiokafka import AIOKafkaProducer
from dishka import Provider, Scope, provide

from ads_commons.security import jwks_uri_from_well_known, token_endpoint_from_well_known
from ads_commons_beans import JwtVerifierSettings, TokenExchange, TokenExchangeSettings
from ads_sandbox_ipc.auth import ClientCredentials, TokenMinter
from ads_sandbox_ipc.config import Settings
from ads_sandbox_ipc.controller import KafkaController
from ads_sandbox_ipc.egress import EgressDelivery, RevisionFloor
from ads_sandbox_ipc.egress_transport import HttpsEgressTransport
from ads_sandbox_ipc.guest import GuestExecutor, Kubernetes
from ads_sandbox_ipc.kafka import KafkaPublisher, KafkaRuntime
from ads_sandbox_ipc.kube import KubeClient
from ads_sandbox_ipc.pid_store import PidStore
from ads_sandbox_ipc.service import IpcService, Publisher


class AppProvider(Provider):
    def __init__(self, settings: Settings) -> None:
        super().__init__()
        self._settings = settings

    @provide(scope=Scope.APP)
    def settings(self) -> Settings:
        return self._settings

    @provide(scope=Scope.APP)
    def producer(self, settings: Settings) -> AIOKafkaProducer:
        return AIOKafkaProducer(**settings.kafka_options())

    @provide(scope=Scope.APP)
    async def kube(self, settings: Settings) -> AsyncIterator[Kubernetes]:
        kube = KubeClient(settings)
        try:
            yield kube
        finally:
            await kube.close()

    @provide(scope=Scope.APP)
    def tokens(self, exchange: TokenExchange) -> TokenMinter:
        return exchange

    store = provide(PidStore, scope=Scope.APP)
    guest = provide(GuestExecutor, scope=Scope.APP)
    client_credentials = provide(ClientCredentials, scope=Scope.APP)
    publisher = provide(KafkaPublisher, scope=Scope.APP, provides=Publisher)
    service = provide(IpcService, scope=Scope.APP)
    controller = provide(KafkaController, scope=Scope.APP)

    @provide(scope=Scope.APP)
    def egress(self, settings: Settings, tokens: TokenExchange) -> EgressDelivery | None:
        pair = settings.egress
        if pair is None:
            return None  # legacy no-NIC deployments only; pair provisioning always injects binding
        return EgressDelivery(
            pair.project_id,
            RevisionFloor(settings.pid_directory, pair.project_id),
            HttpsEgressTransport(
                pair.base_url,
                pair.relay_urls,
                tokens,
                self._ssl(settings),
                settings.control_seconds,
            ),
            settings.control_seconds,
        )

    @provide(scope=Scope.APP)
    def runtime(
        self,
        settings: Settings,
        producer: AIOKafkaProducer,
        controller: KafkaController,
        service: IpcService,
        tokens: TokenExchange,
    ) -> KafkaRuntime:
        return KafkaRuntime(settings, producer, controller, service, tokens)

    @provide(scope=Scope.APP)
    def jwt_settings(self, settings: Settings) -> JwtVerifierSettings:
        context = self._ssl(settings)
        return JwtVerifierSettings(
            issuer=settings.keycloak_issuer,
            audience="ads-sandbox-ipc",
            client_id="ads-sandbox-ipc",
            jwks_uri=jwks_uri_from_well_known(settings.keycloak_well_known_url, context),
            ssl_context=context,
        )

    @provide(scope=Scope.APP)
    def exchange_settings(self, settings: Settings) -> TokenExchangeSettings:
        context = self._ssl(settings)
        return TokenExchangeSettings(
            token_endpoint=token_endpoint_from_well_known(
                settings.keycloak_well_known_url, context
            ),
            client_id="ads-sandbox-ipc",
            client_secret=settings.keycloak_client_secret,
            ssl_context=context,
        )

    @staticmethod
    def _ssl(settings: Settings) -> ssl.SSLContext | None:
        return (
            ssl.create_default_context(cafile=str(settings.tls_ca_bundle))
            if settings.tls_ca_bundle
            else None
        )
