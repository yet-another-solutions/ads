"""Engine-owned context service clients and per-run pressure boundaries."""

from __future__ import annotations

import ssl
from collections.abc import AsyncGenerator

from ads_commons.context_compactor import CompactRequest, active_context
from ads_commons.engine import CompactionStatus, ContextPressure, EngineRequest, HistoryTurn
from ads_commons_beans import TokenExchange
from ads_context_runtime.frames import LangChainFrameModel, RecallRuntime
from ads_context_runtime.http import ContextClients
from ads_engine.chat import StreamDelta
from ads_engine.config import Settings


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
            reserve=s.context_output_reserve,
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

    async def boundary(self, active: list[HistoryTurn]) -> AsyncGenerator[StreamDelta, None]:
        pressure = await self.measure(active)
        if pressure.used_context * 100 < pressure.total_context * self.trigger:
            return
        yield StreamDelta(
            "compaction",
            compaction=CompactionStatus("compacting_context"),
            pressure=pressure,
        )
        memory = await self.clients.compact(
            CompactRequest(
                list(active),
                self.request.model,
                self.target,
            )
        )
        active[:] = active_context(memory)
        pressure = await self.measure(active)
        yield StreamDelta(
            "compaction",
            compaction=CompactionStatus("compacted_context"),
            pressure=pressure,
        )
        yield StreamDelta("tombstone", tombstone=memory, pressure=pressure)
