"""Engine-owned LangGraph execution with context checks at every safe boundary."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import aclosing
from dataclasses import replace
from typing import Any, TypedDict, cast

import structlog
from langchain_core.messages import AIMessageChunk, ToolMessage
from langgraph.config import get_stream_writer
from langgraph.graph import END, START, StateGraph
from langsmith import tracing_context

from ads_commons.engine import (
    AssistantHistoryTurn,
    EngineRequest,
    HistoryTurn,
    Notice,
    Tombstone,
    ToolCall,
    UserHistoryTurn,
)
from ads_context_runtime.frames import LOCAL_TOOLS
from ads_engine.chat import (
    AdsChatOpenAI,
    StreamDelta,
    context_messages,
    deltas_from_chunk,
    tool_call_from_native,
    tool_result_from_message,
)
from ads_engine.config import Settings
from ads_engine.context import EngineContextFactory
from ads_engine.guardrail import ConversationRuns, ToolsUnavailable
from ads_engine.mcp_client import SandboxClient, ToolCallRefused
from ads_engine.mcp_credentials import ExecutionFailed, McpCredentials, RunCredentials

log = structlog.get_logger("ads_engine")


class ExecutionState(TypedDict):
    active: list[HistoryTurn]
    done: bool


class ExecutorChatStreamer:
    def __init__(
        self,
        credentials: McpCredentials,
        sandbox: SandboxClient,
        context: EngineContextFactory,
        settings: Settings,
        runs: ConversationRuns | None = None,
    ) -> None:
        self._credentials = credentials
        self._sandbox = sandbox
        self._context = context
        self._settings = settings
        self._runs = runs

    async def stream(self, request: EngineRequest) -> AsyncGenerator[StreamDelta, None]:
        with tracing_context(enabled=False):
            try:
                context = self._context.open(request)
                async with self._credentials.open(request.authorization.token) as credentials:
                    run_id = await self._run_of(request, credentials)
                    async with self._sandbox.open(request, credentials, run_id) as tools:
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

                        async def boundary(state: ExecutionState) -> ExecutionState:
                            nonlocal emitted
                            writer = get_stream_writer()
                            async for delta in context.boundary(state["active"]):
                                emitted = True
                                writer(delta)
                            return state

                        async def model_step(state: ExecutionState) -> ExecutionState:
                            nonlocal emitted, dispatched
                            writer = get_stream_writer()
                            active = state["active"]
                            memory_visible = any(isinstance(item, Tombstone) for item in active)
                            bound = base_model.bind_tools(
                                [*schemas, *([LOCAL_TOOLS[1]] if memory_visible else [])],
                                parallel_tool_calls=False,
                            )
                            instructions = request.instructions
                            if memory_visible:
                                instructions += (
                                    "\nVisible memory can be queried with memory_recall."
                                )
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
                                                pressure = await context.measure(candidate)
                                                emitted = True
                                                writer(replace(delta, pressure=pressure))
                                    break
                                except Exception:
                                    if emitted or dispatched or attempt == 2:
                                        raise
                                    response = None
                            if response is None or response.invalid_tool_calls:
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
                                    context.recall.visible_memory(active, call)
                                for call in calls:
                                    active.append(call)
                                    writer(
                                        StreamDelta(
                                            "tool_call",
                                            tool_call=call,
                                            pressure=await context.measure(active),
                                        )
                                    )
                                    emitted = True
                                for call in calls:
                                    result = await context.recall.recall_top_level(active, call)
                                    active.append(result)
                                    writer(
                                        StreamDelta(
                                            "tool_result",
                                            tool_result=result,
                                            pressure=await context.measure(active),
                                        )
                                    )
                            else:
                                # Original provider-native object and IDs reach the MCP gate.
                                tools.admit(tools.executor_run_id, response)
                            for native in [] if local else response.tool_calls:
                                call = tool_call_from_native(native)
                                writer(
                                    StreamDelta(
                                        "tool_call",
                                        tool_call=call,
                                        pressure=await context.measure([*active, call]),
                                    )
                                )
                                emitted = True
                                # Mark before send: an ambiguous failure must never
                                # replay a possibly executed shell/Python side effect.
                                dispatched = True
                                refused_notice: Notice | None = None
                                try:
                                    message = await tools.call(tools.executor_run_id, native)
                                except ToolCallRefused as refused:
                                    message = _refusal_message(refused)
                                    refused_notice = refused.refusal.notice(refused.tool, "")
                                result = tool_result_from_message(message)
                                if refused_notice is not None:
                                    writer(
                                        StreamDelta(
                                            "notice",
                                            text=refused_notice.text,
                                            notice=refused_notice,
                                        )
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
                                "active": active,
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
            except Exception as exc:
                stage, kinds = _stage_and_kinds_of(exc)
                log.warning(
                    "sandbox_executor_failed",
                    session_id=str(request.session_id),
                    stage=stage,
                    kinds=kinds,
                )
                raise ExecutionFailed("sandbox executor failed") from None

    async def _run_of(self, request: EngineRequest, credentials: RunCredentials) -> str:
        """The guardrail in front needs a run; without one configured there is no proxy.

        Opened with the credential, not the person's inbound token: that one is not
        addressed to the guardrail, which verifies every person's token by its audience.
        """
        if self._runs is None or self._settings.guardrail is None:
            return ""
        try:
            return await self._runs.id_for(
                credentials.current().context.access_token or "",
                self._settings.guardrail.workspace,
                request.session_id,
            )
        except ToolsUnavailable as exc:
            raise ExecutionFailed("no run was opened for the tools") from exc


def _stage_and_kinds_of(failure: BaseException) -> tuple[str | None, list[str]]:
    # Our own ExecutionFailed wording and exception type names only, never an exception's
    # text: SDK, provider and identity errors can carry request bodies and credentials.
    stage: str | None = None
    kinds: list[str] = []
    pending: list[BaseException] = [failure]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        if stage is None and isinstance(current, ExecutionFailed):
            stage = str(current)
        if isinstance(current, BaseExceptionGroup):
            pending.extend(current.exceptions)
            continue
        underlying = current.__cause__ or current.__context__
        if underlying is None:
            kinds.append(type(current).__name__)
        else:
            pending.append(underlying)
    return stage, kinds


def _refusal_message(refused: ToolCallRefused) -> ToolMessage:
    return ToolMessage(
        content=refused.refusal.for_model(),
        tool_call_id=refused.tool_call_id,
        name=refused.tool,
        status="error",
    )
