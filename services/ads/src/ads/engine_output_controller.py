"""Kafka listener is the request layer: decode, map, call one service. No transactions here."""

from __future__ import annotations

import uuid
from collections.abc import Sequence

import msgspec
import structlog

from ads.engine_output_service import EngineOutputService
from ads.models import (
    KIND_MESSAGE,
    KIND_NOTICE,
    KIND_REASONING,
    KIND_TOMBSTONE,
    KIND_TOOL_CALL,
    KIND_TOOL_RESULT,
)
from ads_commons.engine import (
    Acknowledge,
    EngineOutput,
    ErrorOutput,
    Finish,
    PartialResponse,
    Ping,
    authorization_token,
)

log = structlog.get_logger("ads.engine_output")


class _FinishPeek(msgspec.Struct):
    """A finish without ``last_order`` is invalid, not undecodable."""

    type: str | None = None
    session_id: str | None = None
    last_order: int | None = None
    message_id: uuid.UUID | None = None


class EngineOutputController:
    """One Kafka record maps to exactly one EngineOutputService call."""

    def __init__(self, service: EngineOutputService) -> None:
        self._service = service

    async def on_record(
        self,
        raw: bytes,
        headers: Sequence[tuple[str | bytes, bytes | None]] | None = None,
    ) -> None:
        try:
            output: EngineOutput = msgspec.json.decode(raw, type=EngineOutput)
        except (msgspec.DecodeError, msgspec.ValidationError):
            await self._maybe_invalid_finish(raw)
            return
        if isinstance(output, (PartialResponse, Finish)) and output.message_id is None:
            return
        await self.dispatch(output, headers)

    async def dispatch(
        self,
        output: EngineOutput,
        headers: Sequence[tuple[str | bytes, bytes | None]] | None = None,
    ) -> None:
        if isinstance(output, Acknowledge):
            await self._service.acknowledge(
                output.session_id,
                output.message_id,
                authorization_token(headers),
            )
            return
        if isinstance(output, PartialResponse):
            kind, text = _delta(output)
            if kind is None:
                log.info("partial_without_primitive", session_id=str(output.session_id))
                return
            await self._service.partial_response(
                output.session_id,
                output.order,
                kind,
                text,
                output.pressure,
                output.message_id,
            )
            return
        if isinstance(output, Ping):
            await self._service.ping(output.session_id)
            return
        if isinstance(output, Finish):
            await self._service.finish(output.session_id, output.last_order, output.message_id)
            return
        if isinstance(output, ErrorOutput):
            await self._service.error(output.session_id, output.message_id, output.text)

    async def _maybe_invalid_finish(self, raw: bytes) -> None:
        """``finish`` with no ``last_order`` still has to break the run."""
        try:
            peek = msgspec.json.decode(raw, type=_FinishPeek)
        except (msgspec.DecodeError, msgspec.ValidationError):
            return
        if peek.type != "finish" or peek.session_id is None or peek.message_id is None:
            return
        try:
            session_id = uuid.UUID(peek.session_id)
        except ValueError:
            return
        await self._service.finish(session_id, peek.last_order, peek.message_id)


def _delta(output: PartialResponse) -> tuple[str | None, str]:
    primitives = [
        output.reasoning,
        output.message,
        output.notice,
        output.tool_call,
        output.tool_result,
        output.compaction,
        output.tombstone,
    ]
    if sum(item is not None for item in primitives) != 1:
        return None, ""
    if output.compaction is not None:
        kind = output.compaction.type
        return kind, "Compacting context" if kind == "compacting_context" else "Context compacted"
    if output.tombstone is not None:
        return KIND_TOMBSTONE, msgspec.json.encode(output.tombstone).decode()
    if output.reasoning is not None:
        return KIND_REASONING, output.reasoning.text
    if output.message is not None:
        return KIND_MESSAGE, output.message.text
    if output.notice is not None:
        return KIND_NOTICE, output.notice.text
    if output.tool_call is not None:
        return KIND_TOOL_CALL, msgspec.json.encode(output.tool_call).decode()
    if output.tool_result is not None:
        return KIND_TOOL_RESULT, msgspec.json.encode(output.tool_result).decode()
    return None, ""
