from __future__ import annotations

import asyncio
from collections.abc import Collection, Sequence
from typing import Any
from uuid import UUID, uuid4

import structlog
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from aiokafka.abc import ConsumerRebalanceListener

from ads_commons.engine import authorization_token
from ads_commons.sandbox.handshake import (
    SandboxExecInbound,
    decode_outbound,
    encode_inbound,
    peek_execution_id,
)
from ads_commons.security import AccessDenied, InvalidAccessToken, ensure_caller
from ads_commons_beans import JwtVerifier
from ads_sandbox_mcp.config import Settings
from ads_sandbox_mcp.service import ExecService, VerifiedReply

log = structlog.get_logger("ads_sandbox_mcp")


class KafkaPublisher:
    def __init__(self, producer: AIOKafkaProducer, settings: Settings) -> None:
        self._producer = producer
        self._settings = settings

    async def publish(
        self,
        message: SandboxExecInbound,
        headers: Sequence[tuple[str, bytes]],
        *,
        session_id: UUID,
    ) -> None:
        if session_id != message.session_id:
            raise ValueError("Kafka key must match message session_id")
        await self._producer.send_and_wait(
            self._settings.request_topic,
            key=str(session_id).encode(),
            value=encode_inbound(message),
            headers=list(headers),
        )


class ReplyController:
    """Authenticate Kafka replies without changing the HTTP security holder."""

    def __init__(self, verifier: JwtVerifier, service: ExecService) -> None:
        self._verifier = verifier
        self._service = service

    async def on_message(
        self, raw: bytes, headers: Sequence[tuple[str | bytes, bytes | None]] | None = None
    ) -> None:
        if peek_execution_id(raw) is None:
            log.warning("reply_missing_execution_id")
            return
        token = authorization_token(headers)
        if token is None:
            log.warning("reply_missing_authorization")
            return
        try:
            context = await asyncio.to_thread(self._verifier.authenticate, token)
            ensure_caller(context, "ads-sandbox-manager")
        except (InvalidAccessToken, AccessDenied):
            log.warning("reply_unauthorized")
            return
        try:
            message = decode_outbound(raw)
        except (ValueError, TypeError):
            log.warning("reply_invalid")
            return
        try:
            await self._service.accept_reply(VerifiedReply(message, token))
        except Exception:
            # No token, payload, exception text, or stdout in logs. Waiter watchdog owns failure.
            log.warning("reply_processing_failed", execution_id=str(message.execution_id))


class SeekToEnd(ConsumerRebalanceListener):  # type: ignore[misc]
    def __init__(self, consumer: AIOKafkaConsumer) -> None:
        self._consumer = consumer

    async def on_partitions_revoked(self, revoked: Collection[Any]) -> None:
        pass

    async def on_partitions_assigned(self, assigned: Collection[Any]) -> None:
        if assigned:
            offsets = await self._consumer.end_offsets(list(assigned))
            for partition, offset in offsets.items():
                self._consumer.seek(partition, offset)


class KafkaRuntime:
    def __init__(
        self,
        settings: Settings,
        producer: AIOKafkaProducer,
        consumer: AIOKafkaConsumer,
        controller: ReplyController,
    ) -> None:
        self._settings = settings
        self._producer = producer
        self._consumer = consumer
        self._controller = controller
        self._task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        self._consumer.subscribe([self._settings.reply_topic], listener=SeekToEnd(self._consumer))
        await self._producer.start()
        try:
            await self._consumer.start()
        except BaseException:
            await self._producer.stop()
            raise
        self._task = asyncio.create_task(self._consume())

    async def _consume(self) -> None:
        async for record in self._consumer:
            await self._controller.on_message(record.value, record.headers)

    def ready(self) -> bool:
        return self._task is not None and not self._task.done()

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
        await self._consumer.stop()
        await self._producer.stop()


def consumer_group() -> str:
    """Broadcast replies to every MCP process, including the process owning the HTTP waiter."""
    return f"ads-sandbox-mcp-{uuid4()}"
