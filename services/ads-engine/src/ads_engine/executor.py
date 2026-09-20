"""Engine-owned LangGraph execution with context checks at every safe boundary."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import aclosing
from dataclasses import replace
from typing import Any, TypedDict, cast

from langchain_core.messages import AIMessageChunk
from langgraph.config import get_stream_writer
from langgraph.graph import END, START, StateGraph
from langsmith import tracing_context

from ads_commons.engine import (
    AssistantHistoryTurn,
    EngineRequest,
    HistoryTurn,
    Tombstone,
    UserHistoryTurn,
)
from ads_context_runtime.frames import LOCAL_TOOLS, RECALL_PROMPT, Frame
from ads_engine.chat import (
    AdsChatOpenAI,
    StreamDelta,
    context_messages,
    deltas_from_chunk,
    tool_call_from_native,
    tool_result_from_message,
)
from ads_engine.context import EngineContextFactory
from ads_engine.mcp_client import SandboxClient
from ads_engine.mcp_credentials import ExecutionFailed, McpCredentials


class ExecutionState(TypedDict):
    active: list[HistoryTurn]
    done: bool
    finalization_only: bool


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
                            finalization = state["finalization_only"]
                            bound = (
                                base_model.bind(max_completion_tokens=context.recall.answer_cap)
                                if finalization
                                else base_model.bind_tools(
                                    [*schemas, *([LOCAL_TOOLS[1]] if memory_visible else [])],
                                    parallel_tool_calls=False,
                                )
                            )
                            instructions = request.instructions
                            if memory_visible:
                                instructions += (
                                    "\nVisible memory can be queried with memory_recall."
                                )
                            if finalization:
                                instructions += "\nContext starvation: finalize without tools."
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
                            if finalization and response.tool_calls:
                                raise ExecutionFailed("tools prohibited during finalization")
                            if text:
                                active.append(AssistantHistoryTurn(text))
                            local = [
                                call
                                for call in response.tool_calls
                                if call["name"] == "memory_recall"
                            ]
                            if local:
                                if not memory_visible or len(response.tool_calls) != 1:
                                    raise ExecutionFailed("invalid local recall batch")
                            else:
                                # Original provider-native object and IDs reach the MCP gate.
                                tools.admit(tools.executor_run_id, response)
                            for native in response.tool_calls:
                                call = tool_call_from_native(native)
                                writer(
                                    StreamDelta(
                                        "tool_call",
                                        tool_call=call,
                                        pressure=await context.measure([*active, call]),
                                    )
                                )
                                emitted = True
                                if local:
                                    frame = Frame(
                                        list(active), "", RECALL_PROMPT, context.recall.answer_cap
                                    )
                                    result = await context.recall.dispatch(frame, call)
                                    finalization = frame.finalization_only
                                else:
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
                                "active": active,
                                "done": not response.tool_calls,
                                "finalization_only": finalization,
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
                            "finalization_only": False,
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
            except Exception:
                raise ExecutionFailed("sandbox executor failed") from None
