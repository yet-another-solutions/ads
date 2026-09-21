"""Engine-owned context service clients and per-run pressure boundaries."""

from __future__ import annotations

import ssl
import uuid
from collections.abc import AsyncGenerator

from ads_commons.context_compactor import CompactionBoundary, CompactRequest, active_context
from ads_commons.engine import CompactionStatus, ContextPressure, EngineRequest, HistoryTurn
from ads_commons_beans import TokenExchange
from ads_context_runtime.failures import failure_reason
from ads_context_runtime.frames import ContextFailure, LangChainFrameModel, RecallRuntime
from ads_context_runtime.http import ContextClients
from ads_engine.chat import StreamDelta
from ads_engine.config import Settings


class CompactionFailed(ContextFailure):
    """Only a failed compaction operation, not general model/tool/meter failures."""


class EngineContextFactory:
    def __init__(self, settings: Settings, exchange: TokenExchange) -> None:
        self._settings = settings
        self._exchange = exchange

    def open(self, request: EngineRequest) -> EngineContext:
        s = self._settings
        clients = ContextClients(
            self._exchange,
            s.context_meter_url,
            s.context_compactor_url,
            ssl.create_default_context(cafile=s.tls_ca_bundle),
            subject_token=request.authorization.token,
        )
        runtime = RecallRuntime(
            clients,
            LangChainFrameModel(request.model),
            request.model,
            reserve=s.recall_reserve,
            answer_cap=s.recall_answer_cap,
            answer_completion_cap=s.recall_completion_cap,
            starvation_percentage=s.recall_starvation_percentage,
            top_level_reserve=s.top_level_recall_reserve,
            top_level_answer_cap=s.top_level_recall_answer_cap,
            top_level_completion_cap=s.top_level_recall_completion_cap,
            top_level_starvation_percentage=s.top_level_recall_starvation_percentage,
        )
        return EngineContext(request, clients, runtime, s.context_trigger, s.context_target)


class EngineContext:
    def __init__(
        self,
        request: EngineRequest,
        clients: ContextClients,
        recall: RecallRuntime,
        trigger: int = 80,
        target: int = 50,
    ) -> None:
        self.request = request
        self.clients = clients
        self.recall = recall
        self.trigger = trigger
        self.target = target
        self.pressure: ContextPressure | None = None

    async def measure(self, active: list[HistoryTurn]) -> ContextPressure:
        self.pressure = ContextPressure(
            self.request.model.options.max_context_tokens,
            await self.recall.count(active),
        )
        return self.pressure

    async def boundary(
        self, active: list[HistoryTurn], phase: CompactionBoundary = "admission"
    ) -> AsyncGenerator[StreamDelta, None]:
        pressure = await self.measure(active)
        if pressure.used_context * 100 < pressure.total_context * self.trigger:
            return
        yield StreamDelta(
            "compaction",
            compaction=CompactionStatus("compacting_context"),
            pressure=pressure,
        )
        try:
            memory = await self.clients.compact(
                CompactRequest(
                    list(active),
                    self.request.model,
                    self.target,
                    session_id=self.request.session_id,
                    message_id=self.request.message_id,
                    compaction_id=uuid.uuid4(),
                    boundary=phase,
                )
            )
            replacement = active_context(memory)
            pressure = await self.measure(replacement)
        except Exception as exc:
            raise CompactionFailed(failure_reason(exc)) from None
        # Do not mutate the caller's context unless replacement and metering succeeded.
        active[:] = replacement
        yield StreamDelta(
            "compaction",
            compaction=CompactionStatus("compacted_context"),
            pressure=pressure,
        )
        yield StreamDelta("tombstone", tombstone=memory, pressure=pressure)
