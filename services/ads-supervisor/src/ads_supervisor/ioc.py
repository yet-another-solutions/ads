from __future__ import annotations

from collections.abc import AsyncIterator

import aio_pika
from aio_pika.abc import AbstractRobustConnection
from dishka import Provider, Scope, provide

from ads_policy.audit import AuditSink, BufferedAuditSink, RabbitAuditSink
from ads_policy.build import identity
from ads_policy.client import PolicyClient, build_policy_client
from ads_policy.config import GovernanceSettings
from ads_supervisor.config import Settings
from ads_supervisor.proxy import Proxy
from ads_supervisor.supervisor import Supervisor


class AppProvider(Provider):
    def __init__(
        self,
        settings: Settings,
        client: PolicyClient | None = None,
        sink: AuditSink | None = None,
    ) -> None:
        super().__init__()
        self._settings = settings
        self._client = client
        self._sink = sink

    @provide(scope=Scope.APP)
    def settings(self) -> Settings:
        return self._settings

    @provide(scope=Scope.APP)
    def governance(self) -> GovernanceSettings:
        return GovernanceSettings()

    @provide(scope=Scope.APP)
    def policy_client(self, settings: Settings, governance: GovernanceSettings) -> PolicyClient:
        if self._client is not None:
            return self._client
        return build_policy_client(
            settings.policy_url,
            settings.policy_api_token,
            denied_message=governance.denied_message,
            ca_bundle=settings.tls_ca_bundle,
        )

    @provide(scope=Scope.APP)
    async def broker(self, settings: Settings) -> AsyncIterator[AbstractRobustConnection | None]:
        if self._sink is not None:
            yield None
            return
        connection = await aio_pika.connect_robust(settings.amqp_url)
        try:
            yield connection
        finally:
            await connection.close()

    @provide(scope=Scope.APP)
    def audit(
        self, governance: GovernanceSettings, broker: AbstractRobustConnection | None
    ) -> BufferedAuditSink:
        sink = self._sink if broker is None else RabbitAuditSink(broker)
        assert sink is not None
        return BufferedAuditSink(sink, governance, decided_by=identity("ads-supervisor"))

    @provide(scope=Scope.APP)
    def supervisor(
        self,
        settings: Settings,
        client: PolicyClient,
        audit: BufferedAuditSink,
        governance: GovernanceSettings,
    ) -> Supervisor:
        return Supervisor(settings=settings, client=client, audit=audit, governance=governance)

    @provide(scope=Scope.APP)
    async def proxy(self, settings: Settings, supervisor: Supervisor) -> AsyncIterator[Proxy]:
        standing_in = Proxy(settings, supervisor)
        try:
            yield standing_in
        finally:
            await standing_in.close()
