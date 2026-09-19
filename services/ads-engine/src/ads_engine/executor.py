"""Bounded LangChain executor loop. Thinkers use the separate tool-free streamer."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import aclosing
from typing import cast

from langchain_core.messages import AIMessageChunk, ToolMessage
from langsmith import tracing_context

from ads_commons.engine import EngineRequest, Notice
from ads_engine.chat import (
    AdsChatOpenAI,
    StreamDelta,
    _history_messages,
    deltas_from_chunk,
    tool_call_from_native,
    tool_result_from_message,
)
from ads_engine.config import Settings
from ads_engine.guardrail import ConversationRuns, ToolsUnavailable
from ads_engine.mcp_client import SandboxClient, ToolCallRefused
from ads_engine.mcp_credentials import ExecutionFailed, McpCredentials


class ExecutorChatStreamer:
    def __init__(
        self,
        credentials: McpCredentials,
        sandbox: SandboxClient,
        settings: Settings,
        runs: ConversationRuns | None = None,
    ) -> None:
        self._credentials = credentials
        self._sandbox = sandbox
        self._settings = settings
        self._runs = runs

    async def stream(self, request: EngineRequest) -> AsyncGenerator[StreamDelta, None]:
        # No credential, dispatcher or MCP session enters messages, callbacks,
        # checkpoints or provider invoke fields. Explicitly disable auto-tracing
        # around this credential-bearing run; trace IDs belong in runtime logs.
        with tracing_context(enabled=False):
            try:
                run_id = await self._run_of(request)
                async with self._credentials.open(request.authorization.token) as credentials:
                    async with self._sandbox.open(request, credentials, run_id) as tools:
                        schemas = await tools.schemas()
                        model_token = request.model.authentication.openai_bearer.token
                        model = AdsChatOpenAI(
                            model=request.model.options.model_name,
                            base_url=request.model.url,
                            api_key=lambda: model_token,
                            streaming=True,
                            max_retries=0,
                        ).bind_tools(schemas, parallel_tool_calls=False)
                        messages = _history_messages(request)
                        emitted = False
                        dispatched = False
                        while True:
                            response: AIMessageChunk | None = None
                            for attempt in range(3):
                                try:
                                    async with aclosing(
                                        cast(
                                            AsyncGenerator[AIMessageChunk, None],
                                            model.astream(messages),
                                        )
                                    ) as stream:
                                        async for chunk in stream:
                                            if not isinstance(chunk, AIMessageChunk):
                                                continue
                                            response = (
                                                chunk if response is None else response + chunk
                                            )
                                            for delta in deltas_from_chunk(chunk):
                                                emitted = True
                                                try:
                                                    yield delta
                                                except GeneratorExit:
                                                    # aclose after an output failure must
                                                    # exit SDK task groups normally, not
                                                    # wrap GeneratorExit in a BaseExceptionGroup.
                                                    return
                                    break
                                except Exception:
                                    if emitted or dispatched or attempt == 2:
                                        raise
                                    response = None
                            if response is None:
                                raise ExecutionFailed("model returned no response")
                            tools.admit(tools.executor_run_id, response)
                            if not response.tool_calls:
                                return
                            messages.append(response)
                            for call in response.tool_calls:
                                try:
                                    yield StreamDelta(
                                        kind="tool_call",
                                        tool_call=tool_call_from_native(call),
                                    )
                                except GeneratorExit:
                                    return
                                # Mark before send: an ambiguous failure must never
                                # replay a possibly executed shell/Python side effect.
                                dispatched = True
                                refused_notice: Notice | None = None
                                try:
                                    result = await tools.call(tools.executor_run_id, call)
                                except ToolCallRefused as refused:
                                    result = _refusal_message(refused)
                                    refused_notice = refused.refusal.notice(refused.tool, "")
                                messages.append(result)
                                if refused_notice is not None:
                                    try:
                                        yield StreamDelta(
                                            kind="notice",
                                            text=refused_notice.text,
                                            notice=refused_notice,
                                        )
                                    except GeneratorExit:
                                        return
                                try:
                                    yield StreamDelta(
                                        kind="tool_result",
                                        tool_result=tool_result_from_message(result),
                                    )
                                except GeneratorExit:
                                    return
            except Exception:
                # SDK/provider exceptions and exception groups can carry request
                # bodies. Never log/emit them and never retry the entire run.
                raise ExecutionFailed("sandbox executor failed") from None

    async def _run_of(self, request: EngineRequest) -> str:
        """The guardrail in front needs a run; without one configured there is no proxy."""
        if self._runs is None or self._settings.guardrail is None:
            return ""
        try:
            return await self._runs.id_for(
                request.authorization.token,
                self._settings.guardrail.workspace,
                request.session_id,
            )
        except ToolsUnavailable as exc:
            raise ExecutionFailed("no run was opened for the tools") from exc


def _refusal_message(refused: ToolCallRefused) -> ToolMessage:
    return ToolMessage(
        content=refused.refusal.for_model(),
        tool_call_id=refused.tool_call_id,
        name=refused.tool,
        status="error",
    )
