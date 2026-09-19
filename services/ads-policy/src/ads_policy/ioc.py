from __future__ import annotations

from collections.abc import AsyncIterator

import aio_pika
from aio_pika.abc import AbstractRobustConnection
from dishka import Provider, Scope, provide
from redis.asyncio import Redis

from ads_policy.audit import AuditSink, BufferedAuditSink, RabbitAuditSink
from ads_policy.blocks import ConversationBlocks, RedisConversationBlocks
from ads_policy.build import identity
from ads_policy.config import Settings, policy_document_path
from ads_policy.contract import Policy
from ads_policy.pdp import PolicyDecisionPoint
from ads_policy.policy import load_policy, org_policy, read_policy_document
from ads_policy.run import RedisRunStore, RunStore
from ads_policy.service import PolicyService


class AppProvider(Provider):
    def __init__(
        self,
        settings: Settings,
        redis: Redis | None = None,
        sink: AuditSink | None = None,
    ) -> None:
        super().__init__()
        self._settings = settings
        self._redis = redis
        self._sink = sink

    @provide(scope=Scope.APP)
    def settings(self) -> Settings:
        return self._settings

    @provide(scope=Scope.APP)
    def policy(self, settings: Settings) -> Policy:
        document = read_policy_document(policy_document_path(settings))
        if document is None:
            return org_policy(settings.policy_defaults)
        return load_policy(document, settings.policy_defaults)

    @provide(scope=Scope.APP)
    def pdp(self, settings: Settings, policy: Policy) -> PolicyDecisionPoint:
        return PolicyDecisionPoint(
            policy,
            settings.naming,
            settings.policy_versions_kept,
            settings.denied_message,
        )

    @provide(scope=Scope.APP)
    async def redis(self, settings: Settings) -> AsyncIterator[Redis]:
        if self._redis is not None:
            yield self._redis
            return
        client: Redis = Redis.from_url(settings.redis_url)
        try:
            yield client
        finally:
            await client.aclose()

    @provide(scope=Scope.APP)
    def runs(self, settings: Settings, redis: Redis) -> RunStore:
        return RedisRunStore(redis, settings.run_ttl_seconds)

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
        self, settings: Settings, broker: AbstractRobustConnection | None
    ) -> BufferedAuditSink:
        sink = self._sink if broker is None else RabbitAuditSink(broker)
        assert sink is not None
        return BufferedAuditSink(sink, settings.audit_backlog, decided_by=identity("ads-policy"))

    @provide(scope=Scope.APP)
    def blocks(self, redis: Redis) -> ConversationBlocks:
        return RedisConversationBlocks(redis)

    @provide(scope=Scope.APP)
    def policy_service(
        self,
        settings: Settings,
        pdp: PolicyDecisionPoint,
        runs: RunStore,
        audit: BufferedAuditSink,
        blocks: ConversationBlocks,
    ) -> PolicyService:
        return PolicyService(
            pdp,
            runs,
            audit,
            settings.placement,
            blocks,
            settings.denied_message,
            settings.policy_defaults.default_weight,
        )
