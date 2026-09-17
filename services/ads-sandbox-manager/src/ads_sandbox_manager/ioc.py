from __future__ import annotations

from collections.abc import AsyncIterator

from dishka import Provider, Scope, provide
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from ads_sandbox_manager.config import Settings
from ads_sandbox_manager.golden import GoldenEnsure
from ads_sandbox_manager.health import Dependencies, DependencyHealth
from ads_sandbox_manager.kube import KubeClient, Kubernetes, SessionKubernetes
from ads_sandbox_manager.runtime import ManagerRuntime
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

    dependencies = provide(DependencyHealth, scope=Scope.APP, provides=Dependencies)
    golden = provide(GoldenEnsure, scope=Scope.APP)
    runtime = provide(ManagerRuntime, scope=Scope.APP)
    repository = provide(SessionRepository, scope=Scope.APP)
    # SessionProvisioner is composed by slice 9, once a real TopicPreparation
    # provider exists. Never silently install a no-op Kafka port in production.
