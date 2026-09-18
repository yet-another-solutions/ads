"""Bounded LangChain executor loop. Thinkers use the separate tool-free streamer."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import aclosing
from typing import cast

from langchain_core.messages import AIMessageChunk
from langsmith import tracing_context

from ads_commons.engine import EngineRequest
from ads_engine.chat import AdsChatOpenAI, StreamDelta, _history_messages, deltas_from_chunk
from ads_engine.mcp_client import SandboxClient
from ads_engine.mcp_credentials import ExecutionFailed, McpCredentials


class ExecutorChatStreamer:
    def __init__(self, credentials: McpCredentials, sandbox: SandboxClient) -> None:
        self._credentials = credentials
        self._sandbox = sandbox

    async def stream(self, request: EngineRequest) -> AsyncGenerator[StreamDelta, None]:
        # No credential, dispatcher or MCP session enters messages, callbacks,
        # checkpoints or provider invoke fields. Explicitly disable auto-tracing
        # around this credential-bearing run; trace IDs belong in runtime logs.
        with tracing_context(enabled=False):
            try:
                async with self._credentials.open(request.authorization.token) as credentials:
                    async with self._sandbox.open(request, credentials) as tools:
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
                                # Mark before send: an ambiguous failure must never
                                # replay a possibly executed shell/Python side effect.
                                dispatched = True
                                messages.append(await tools.call(tools.executor_run_id, call))
            except Exception:
                # SDK/provider exceptions and exception groups can carry request
                # bodies. Never log/emit them and never retry the entire run.
                raise ExecutionFailed("sandbox executor failed") from None
