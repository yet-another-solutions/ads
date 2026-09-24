from __future__ import annotations

import asyncio
import ssl
from collections.abc import AsyncIterator

from dishka import Provider, Scope, provide
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from ads_commons.egress import SessionProjectsApi
from ads_commons.security import jwks_uri_from_well_known, token_endpoint_from_well_known
from ads_commons_beans import JwtVerifierSettings, TokenExchange, TokenExchangeSettings
from ads_sandbox_manager.auth import MANAGER, ClientCredentials, TokenMinter
from ads_sandbox_manager.barrier import CoordinationPort, ManagerBarrier
from ads_sandbox_manager.binding import AdsSessionProjects, BindingService
from ads_sandbox_manager.ca import CaEnsure
from ads_sandbox_manager.cleanup import CleanupAdapter, CleanupKubernetes
from ads_sandbox_manager.config import Settings
from ads_sandbox_manager.controller import KafkaController
from ads_sandbox_manager.golden import GoldenEnsure
from ads_sandbox_manager.health import Dependencies, DependencyHealth
from ads_sandbox_manager.kafka import KafkaRuntime, KafkaTopics, KafkaTransport
from ads_sandbox_manager.kube import KubeClient, Kubernetes, SessionKubernetes
from ads_sandbox_manager.lifecycle import LifecycleService
from ads_sandbox_manager.lifecycle_store import LifecycleRepository
from ads_sandbox_manager.pair_cleanup import PairCleanupCapture, PairCleanupKubernetes
from ads_sandbox_manager.pair_creation import PairCreation
from ads_sandbox_manager.pair_kube import PairControlAdapter
from ads_sandbox_manager.pair_runtime_teardown import PairRuntimeTeardown
from ads_sandbox_manager.recovery import RecoveryService
from ads_sandbox_manager.runtime import ManagerRuntime
from ads_sandbox_manager.service import Maintenance, Publisher, TransitService
from ads_sandbox_manager.sessions import SessionProvisioner, TopicPreparation
from ads_sandbox_manager.store import SessionRepository


class AppProvider(Provider):
    def __init__(self, settings: Settings) -> None:
        super().__init__()
        self._settings = settings

    @provide(scope=Scope.APP)
    def settings(self) -> Settings:
        return self._settings

    @provide(scope=Scope.APP)
    async def kube(self, settings: Settings) -> AsyncIterator[KubeClient]:
        kube = KubeClient(settings)
        try:
            yield kube
        finally:
            await kube.close()

    @provide(scope=Scope.APP)
    def golden_kube(self, kube: KubeClient) -> Kubernetes:
        return kube

    @provide(scope=Scope.APP)
    def ca(self, settings: Settings, kube: Kubernetes) -> CaEnsure | None:
        return CaEnsure(settings, kube) if settings.ca is not None else None

    @provide(scope=Scope.APP)
    def session_kube(self, kube: KubeClient) -> SessionKubernetes:
        return kube

    @provide(scope=Scope.APP)
    def sessions(self, engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
        return async_sessionmaker(engine, expire_on_commit=False)

    @provide(scope=Scope.APP)
    async def engine(self, settings: Settings) -> AsyncIterator[AsyncEngine]:
        engine = create_async_engine(settings.database_url, pool_pre_ping=True, echo=False)
        try:
            yield engine
        finally:
            await engine.dispose()

    @provide(scope=Scope.APP)
    async def dependencies(
        self, settings: Settings, engine: AsyncEngine
    ) -> AsyncIterator[Dependencies]:
        health = DependencyHealth(settings, engine)
        try:
            yield health
        finally:
            await health.close()

    golden = provide(GoldenEnsure, scope=Scope.APP)
    runtime = provide(ManagerRuntime, scope=Scope.APP)
    repository = provide(SessionRepository, scope=Scope.APP)
    bindings = provide(BindingService, scope=Scope.APP)
    provisioner = provide(SessionProvisioner, scope=Scope.APP)
    client_credentials = provide(ClientCredentials, scope=Scope.APP)
    transport = provide(KafkaTransport, scope=Scope.APP)
    barrier = provide(ManagerBarrier, scope=Scope.APP)
    topics = provide(KafkaTopics, scope=Scope.APP, provides=TopicPreparation)
    service = provide(TransitService, scope=Scope.APP)
    controller = provide(KafkaController, scope=Scope.APP)
    kafka = provide(KafkaRuntime, scope=Scope.APP)
    cleanup = provide(CleanupAdapter, scope=Scope.APP, provides=CleanupKubernetes)
    lifecycle_repository = provide(LifecycleRepository, scope=Scope.APP)
    pair_cleanup_kube = provide(PairControlAdapter, scope=Scope.APP, provides=PairCleanupKubernetes)
    pair_capture = provide(PairCleanupCapture, scope=Scope.APP)
    lifecycle = provide(LifecycleService, scope=Scope.APP)
    recovery = provide(RecoveryService, scope=Scope.APP)

    @provide(scope=Scope.APP)
    def pair_runtime(
        self,
        settings: Settings,
        sessions: async_sessionmaker[AsyncSession],
        repository: LifecycleRepository,
        kube: KubeClient,
        storage: CleanupKubernetes,
    ) -> PairRuntimeTeardown | None:
        # Node-owner delivery is not installed by this component. The service
        # returns blocked without it, never a production success-returning fake.
        return PairRuntimeTeardown(
            settings, sessions, repository, PairControlAdapter(kube), storage
        )

    @provide(scope=Scope.APP)
    def pair_creation(
        self,
        settings: Settings,
        sessions: async_sessionmaker[AsyncSession],
        kube: KubeClient,
        golden: GoldenEnsure,
        ca: CaEnsure | None,
        topics: TopicPreparation,
    ) -> PairCreation | None:
        if settings.pair_inputs is None:
            return None  # Direct isolated component fixtures; environment startup requires inputs.
        if ca is None:
            raise RuntimeError("paired creation requires the CA service")
        return PairCreation(settings, sessions, kube, golden, ca, topics)

    @provide(scope=Scope.APP)
    def projects(self, settings: Settings, exchange: TokenExchange) -> SessionProjectsApi:
        return AdsSessionProjects(settings, exchange, self._ssl(settings))

    @provide(scope=Scope.APP)
    def maintenance(self, lifecycle: LifecycleService) -> Maintenance:
        return lifecycle

    @provide(scope=Scope.APP)
    def coordination(self, transport: KafkaTransport) -> CoordinationPort:
        return transport

    @provide(scope=Scope.APP)
    def publisher(self, transport: KafkaTransport) -> Publisher:
        return transport

    @provide(scope=Scope.APP)
    def tokens(self, exchange: TokenExchange) -> TokenMinter:
        return exchange

    @provide(scope=Scope.APP)
    async def jwt_settings(self, settings: Settings) -> JwtVerifierSettings:
        context = self._ssl(settings)
        uri = await asyncio.to_thread(
            jwks_uri_from_well_known, settings.keycloak_well_known_url, context
        )
        return JwtVerifierSettings(
            issuer=settings.keycloak_issuer,
            audience=MANAGER,
            client_id=MANAGER,
            jwks_uri=uri,
            ssl_context=context,
        )

    @provide(scope=Scope.APP)
    async def exchange_settings(self, settings: Settings) -> TokenExchangeSettings:
        context = self._ssl(settings)
        endpoint = await asyncio.to_thread(
            token_endpoint_from_well_known, settings.keycloak_well_known_url, context
        )
        return TokenExchangeSettings(
            token_endpoint=endpoint,
            client_id=MANAGER,
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
