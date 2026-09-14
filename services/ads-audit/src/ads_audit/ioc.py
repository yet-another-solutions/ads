from __future__ import annotations

from collections.abc import AsyncIterator

import aio_pika
from aio_pika.abc import AbstractRobustConnection
from dishka import Provider, Scope, provide
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from ads_audit.config import Settings
from ads_audit.repository import AuditRepository, SqlAuditRepository
from ads_audit.service import AuditService


class AppProvider(Provider):
    def __init__(
        self,
        settings: Settings,
        repository: AuditRepository | None = None,
        connection: AbstractRobustConnection | None = None,
    ) -> None:
        super().__init__()
        self._settings = settings
        self._repository = repository
        self._connection = connection

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
    async def broker(self, settings: Settings) -> AsyncIterator[AbstractRobustConnection]:
        if self._connection is not None:
            yield self._connection
            return
        connection = await aio_pika.connect_robust(settings.amqp_url)
        try:
            yield connection
        finally:
            await connection.close()

    @provide(scope=Scope.REQUEST)
    async def repository(
        self, sessions: async_sessionmaker[AsyncSession]
    ) -> AsyncIterator[AuditRepository]:
        """Transaction on the service boundary: one request, one unit of work."""
        if self._repository is not None:
            yield self._repository
            return
        async with sessions() as session, session.begin():
            yield SqlAuditRepository(session)

    @provide(scope=Scope.REQUEST)
    def audit_service(self, settings: Settings, repository: AuditRepository) -> AuditService:
        return AuditService(repository, settings.deny_repeat_multiplier)
