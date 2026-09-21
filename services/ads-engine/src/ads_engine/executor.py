"""Engine-owned LangGraph execution with context checks at every safe boundary."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator
from contextlib import aclosing
from dataclasses import replace
from typing import Any, TypedDict, cast

import structlog
from langchain_core.messages import AIMessageChunk
from langgraph.config import get_stream_writer
from langgraph.graph import END, START, StateGraph
from langsmith import tracing_context

from ads_commons.context_compactor import CompactionBoundary
from ads_commons.engine import (
    AssistantHistoryTurn,
    ContextPressure,
    EngineRequest,
    HistoryTurn,
    Tombstone,
    ToolCall,
    ToolResult,
    UserHistoryTurn,
)
from ads_context_runtime.failures import failure_reason
from ads_context_runtime.frames import LOCAL_TOOLS, ContextFailure
from ads_engine.chat import (
    AdsChatOpenAI,
    StreamDelta,
    context_messages,
    deltas_from_chunk,
    tool_call_from_native,
    tool_result_from_message,
)
from ads_engine.context import CompactionFailed, EngineContextFactory
from ads_engine.mcp_client import SandboxClient
from ads_engine.mcp_credentials import ExecutionFailed, McpCredentials

log = structlog.get_logger("ads_engine")
COMPLETE_ONLY_PROMPT = (
    "\nContext compaction or recall failed. Complete the answer now using available evidence. "
    "No further tools are available or permitted, including memory_recall. "
    "State any limitations; do not claim unperformed work or invent tool results."
)
EMPTY_COMPLETION = (
    "I cannot continue tool-based work in this turn because context compaction or recall "
    "could not complete. No further tools were executed after that failure."
)


class ExecutionState(TypedDict):
    active: list[HistoryTurn]
    done: bool
    started: bool
    complete_only: bool


class ExecutorChatStreamer:
    def __init__(
        self,
        credentials: McpCredentials,
        sandbox: SandboxClient,
        context: EngineContextFactory,
    ) -> None:
        self._credentials = credentials
        self._sandbox = sandbox
        self._context = context

    async def stream(self, request: EngineRequest) -> AsyncGenerator[StreamDelta, None]:
        admission_failure: CompactionFailed | None = None
        with tracing_context(enabled=False):
            try:
                context = self._context.open(request)
                async with self._credentials.open(request.authorization.token) as credentials:
                    async with self._sandbox.open(request, credentials) as tools:
                        schemas = await tools.schemas()
                        model_token = request.model.authentication.openai_bearer.token
                        base_model = AdsChatOpenAI(
                            model=request.model.options.model_name,
                            base_url=request.model.url,
                            api_key=lambda: model_token,
                            streaming=True,
                            max_retries=0,
                        )
                        emitted = False
                        dispatched = False
                        publications: dict[int, asyncio.Event] = {}
                        meter_unavailable = False

                        async def measure(
                            active: list[HistoryTurn], complete_only: bool = False
                        ) -> ContextPressure | None:
                            nonlocal meter_unavailable
                            if meter_unavailable:
                                return None
                            try:
                                return await context.measure(active)
                            except Exception:
                                if not complete_only:
                                    raise
                                # Recovery must not depend on the failed recall's meter.
                                # No guessed counts or alternate tokenizer: omit pressure.
                                meter_unavailable = True
                                log.warning(
                                    "complete_only_meter_unavailable",
                                    session_id=str(request.session_id),
                                    message_id=str(request.message_id),
                                )
                                return None

                        async def publish_call(delta: StreamDelta) -> None:
                            nonlocal emitted
                            accepted = asyncio.Event()
                            publications[id(delta)] = accepted
                            try:
                                emitted = True
                                get_stream_writer()(delta)
                                # Resuming our outer generator means its consumer accepted
                                # this part. Closing after a Kafka failure never releases it.
                                await accepted.wait()
                            finally:
                                publications.pop(id(delta), None)

                        async def boundary(state: ExecutionState) -> ExecutionState:
                            nonlocal emitted, admission_failure
                            if state["complete_only"]:
                                return state
                            writer = get_stream_writer()
                            phase: CompactionBoundary = (
                                "admission"
                                if not state["started"]
                                else ("finish" if state["done"] else "continuation")
                            )
                            try:
                                async for delta in context.boundary(state["active"], phase):
                                    emitted = True
                                    writer(delta)
                            except CompactionFailed as exc:
                                if not state["started"]:
                                    admission_failure = exc
                                    log.warning(
                                        "context_compaction_admission_failed",
                                        session_id=str(request.session_id),
                                        message_id=str(request.message_id),
                                        reason=str(exc),
                                    )
                                    raise
                                state = {**state, "complete_only": True}
                                log.warning(
                                    "context_compaction_complete_only",
                                    session_id=str(request.session_id),
                                    message_id=str(request.message_id),
                                    boundary=phase,
                                    reason=str(exc),
                                    total_context=context.pressure.total_context
                                    if context.pressure
                                    else None,
                                    used_context=context.pressure.used_context
                                    if context.pressure
                                    else None,
                                )
                            return state

                        async def model_step(state: ExecutionState) -> ExecutionState:
                            nonlocal emitted, dispatched
                            writer = get_stream_writer()
                            active = state["active"]
                            memory_visible = any(isinstance(item, Tombstone) for item in active)
                            complete_only = state["complete_only"]
                            bound = (
                                base_model
                                if complete_only
                                else base_model.bind_tools(
                                    [*schemas, *([LOCAL_TOOLS[1]] if memory_visible else [])],
                                    parallel_tool_calls=False,
                                )
                            )
                            instructions = request.instructions
                            if memory_visible and not complete_only:
                                instructions += (
                                    "\nVisible memory can be queried with memory_recall."
                                )
                            pressure = await measure(active, complete_only)
                            if pressure is not None:
                                instructions += (
                                    "\nADS context budget (estimated model-visible messages; "
                                    "excludes system instructions, tool schemas and provider "
                                    f"overhead): total_context_tokens={pressure.total_context}; "
                                    "remaining_context_tokens="
                                    f"{max(0, pressure.total_context - pressure.used_context)}."
                                )
                            else:
                                instructions += (
                                    "\nADS context budget: "
                                    "total_context_tokens="
                                    f"{request.model.options.max_context_tokens}; "
                                    "remaining_context_tokens=unknown (meter unavailable)."
                                )
                            if complete_only:
                                instructions += COMPLETE_ONLY_PROMPT
                            messages = context_messages(active, instructions)
                            response: AIMessageChunk | None = None
                            text = ""
                            for attempt in range(3):
                                try:
                                    async with aclosing(
                                        cast(
                                            AsyncGenerator[AIMessageChunk, None],
                                            bound.astream(messages),
                                        )
                                    ) as stream:
                                        async for chunk in stream:
                                            if not isinstance(chunk, AIMessageChunk):
                                                continue
                                            response = (
                                                chunk if response is None else response + chunk
                                            )
                                            for delta in deltas_from_chunk(chunk):
                                                if delta.kind == "message":
                                                    text += delta.text
                                                candidate = [*active]
                                                if text:
                                                    candidate.append(AssistantHistoryTurn(text))
                                                pressure = await measure(candidate, complete_only)
                                                emitted = True
                                                writer(replace(delta, pressure=pressure))
                                    break
                                except Exception:
                                    if emitted or dispatched or attempt == 2:
                                        raise
                                    response = None
                            if response is None:
                                raise ExecutionFailed("invalid model response")
                            if complete_only:
                                # This gate precedes every MCP admission and local recall path.
                                # Even a provider ignoring the absent tools cannot dispatch.
                                if response.tool_calls or response.invalid_tool_calls:
                                    log.warning(
                                        "complete_only_tool_calls_ignored",
                                        session_id=str(request.session_id),
                                        message_id=str(request.message_id),
                                    )
                                if not text:
                                    text = EMPTY_COMPLETION
                                    writer(
                                        StreamDelta(
                                            "message",
                                            text=text,
                                            pressure=await measure(
                                                [*active, AssistantHistoryTurn(text)], True
                                            ),
                                        )
                                    )
                                    emitted = True
                                active.append(AssistantHistoryTurn(text))
                                return {**state, "active": active, "started": True, "done": True}
                            if response.invalid_tool_calls:
                                raise ExecutionFailed("invalid model response")
                            if text:
                                active.append(AssistantHistoryTurn(text))
                            local = [
                                call
                                for call in response.tool_calls
                                if call["name"] == "memory_recall"
                            ]
                            if local:
                                if not memory_visible or len(local) != len(response.tool_calls):
                                    raise ExecutionFailed("invalid local recall batch")
                                calls = [tool_call_from_native(native) for native in local]
                                seen = {item.id for item in active if isinstance(item, ToolCall)}
                                for call in calls:
                                    if not call.id or call.id in seen:
                                        raise ExecutionFailed("invalid local recall call id")
                                    seen.add(call.id)
                                for call in calls:
                                    active.append(call)
                                    await publish_call(
                                        StreamDelta(
                                            "tool_call",
                                            tool_call=call,
                                            pressure=await context.measure(active),
                                        )
                                    )
                                    emitted = True
                                for call in calls:
                                    if state["complete_only"]:
                                        result = ToolResult(
                                            call.id, call.name, "error", "recall_failed"
                                        )
                                    else:
                                        try:
                                            result = await context.recall.recall_top_level(
                                                active, call
                                            )
                                        except Exception as exc:
                                            result = ToolResult(
                                                call.id, call.name, "error", failure_reason(exc)
                                            )
                                        if result.status == "error":
                                            state = {**state, "complete_only": True}
                                            log.warning(
                                                "recall_complete_only",
                                                session_id=str(request.session_id),
                                                message_id=str(request.message_id),
                                                tool_call_id=call.id,
                                                reason=failure_reason(
                                                    ContextFailure(str(result.content))
                                                ),
                                            )
                                    active.append(result)
                                    writer(
                                        StreamDelta(
                                            "tool_result",
                                            tool_result=result,
                                            pressure=await measure(active, state["complete_only"]),
                                        )
                                    )
                            else:
                                # Original provider-native object and IDs reach the MCP gate.
                                tools.admit(tools.executor_run_id, response)
                            for native in [] if local else response.tool_calls:
                                call = tool_call_from_native(native)
                                await publish_call(
                                    StreamDelta(
                                        "tool_call",
                                        tool_call=call,
                                        pressure=await context.measure([*active, call]),
                                    )
                                )
                                emitted = True
                                dispatched = True
                                result = tool_result_from_message(
                                    await tools.call(tools.executor_run_id, native),
                                )
                                active.extend([call, result])
                                writer(
                                    StreamDelta(
                                        "tool_result",
                                        tool_result=result,
                                        pressure=await context.measure(active),
                                    )
                                )
                            return {
                                **state,
                                "active": active,
                                "started": True,
                                "done": not response.tool_calls,
                            }

                        graph = StateGraph(ExecutionState)
                        graph.add_node("admission", boundary)
                        graph.add_node("model_and_tools", model_step)
                        graph.add_node("continuation_or_finish", boundary)
                        graph.add_edge(START, "admission")
                        graph.add_edge("admission", "model_and_tools")
                        graph.add_edge("model_and_tools", "continuation_or_finish")
                        graph.add_edge("continuation_or_finish", END)
                        compiled = graph.compile()
                        state: ExecutionState = {
                            "active": [*request.history, UserHistoryTurn(request.user_input)],
                            "done": False,
                            "started": False,
                            "complete_only": False,
                        }
                        while not state["done"]:
                            async with aclosing(
                                cast(
                                    AsyncGenerator[tuple[str, Any], None],
                                    compiled.astream(
                                        state,
                                        stream_mode=["custom", "values"],
                                    ),
                                )
                            ) as stream:
                                async for mode, value in stream:
                                    if mode == "values":
                                        state = value
                                    else:
                                        try:
                                            yield value
                                        except GeneratorExit:
                                            return
                                        accepted = publications.get(id(value))
                                        if accepted is not None:
                                            accepted.set()
            except Exception:
                # MCP teardown may wrap the original failure in an ExceptionGroup.
                if admission_failure is not None:
                    raise ExecutionFailed(
                        f"context compaction failed: {admission_failure}"
                    ) from None
                raise ExecutionFailed("sandbox executor failed") from None
