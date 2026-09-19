"""SDK-owned modern MCP transport and executor-only sequential dispatch."""

from __future__ import annotations

import ssl
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx2
from langchain_core.messages import AIMessage, ToolCall, ToolMessage
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.types import DiscoverResult

from ads_commons.engine import EngineRequest
from ads_engine.config import Settings
from ads_engine.mcp_credentials import ExecutionFailed, RunCredentials


class SandboxTools:
    def __init__(self, client: Client, credentials: RunCredentials, settings: Settings) -> None:
        self._client = client
        self._credentials = credentials
        self._timeout = settings.mcp_timeout_seconds
        self._remaining = settings.max_tool_calls
        self._pending: list[ToolCall] = []
        self._seen: set[str] = set()
        self._busy = False
        self.executor_run_id = uuid.uuid4()

    async def schemas(self) -> list[dict[str, Any]]:
        # Explicit mode installs synthetic discovery state. Probe the server
        # through the SDK rather than accepting that cached local assumption.
        discovery = DiscoverResult.model_validate(
            await self._client.session.send_discover("2026-07-28")
        )
        if "2026-07-28" not in discovery.supported_versions:
            raise ExecutionFailed("required MCP protocol unavailable")
        self._client.session.adopt(discovery)
        listing = await self._client.list_tools()
        expected = {"exec_shell": "command", "exec_python": "code"}
        if listing.next_cursor or {tool.name for tool in listing.tools} != set(expected):
            raise ExecutionFailed("required sandbox tools unavailable")
        if len(listing.tools) != len(expected):
            raise ExecutionFailed("duplicate sandbox tools")
        schemas = []
        for tool in listing.tools:
            schema = tool.input_schema
            argument = expected[tool.name]
            if (
                schema.get("type") != "object"
                or schema.get("additionalProperties") is not False
                or schema.get("required") != [argument]
                or set(schema.get("properties", {})) != {argument}
                or schema["properties"][argument].get("type") != "string"
                or schema["properties"][argument].get("minLength") != 1
            ):
                raise ExecutionFailed("invalid sandbox tool contract")
            schemas.append(
                {
                    "type": "function",
                    "function": {
                        "name": tool.name,
                        "description": tool.description or tool.name,
                        "parameters": schema,
                    },
                }
            )
        return schemas

    def admit(self, executor_run_id: uuid.UUID, native: AIMessage) -> None:
        """Called only for the completed provider-native executor response.

        Never parses message text or planner JSON as a call. Validate the whole
        batch before any side effect, then execute each call serially.
        """
        if executor_run_id != self.executor_run_id or self._pending or self._busy:
            raise ExecutionFailed("invalid executor invocation")
        if native.invalid_tool_calls or len(native.tool_calls) > self._remaining:
            raise ExecutionFailed("invalid tool calls or tool budget exceeded")
        ids: set[str] = set()
        for call in native.tool_calls:
            name, args, call_id = call.get("name"), call.get("args"), call.get("id")
            arg = {"exec_shell": "command", "exec_python": "code"}.get(name)
            if (
                arg is None
                or not call_id
                or call_id in self._seen
                or call_id in ids
                or not isinstance(args, dict)
                or set(args) != {arg}
                or not isinstance(args[arg], str)
                or not args[arg]
            ):
                raise ExecutionFailed("invalid native sandbox call")
            ids.add(call_id)
        self._pending = list(native.tool_calls)
        self._seen.update(ids)

    async def call(self, executor_run_id: uuid.UUID, native: ToolCall) -> ToolMessage:
        if (
            executor_run_id != self.executor_run_id
            or self._busy
            or not self._pending
            or native is not self._pending[0]
        ):
            raise ExecutionFailed("sandbox dispatch requires an admitted native executor call")
        # Current verified role authorization is checked again at every call.
        self._credentials.current()
        self._pending.pop(0)
        self._remaining -= 1
        self._busy = True
        try:
            result = await self._client.session.call_tool(
                native["name"], native["args"], read_timeout_seconds=self._timeout
            )
            return ToolMessage(
                content=result.model_dump_json(by_alias=True, exclude_none=True),
                tool_call_id=native["id"] or "",
                name=native["name"],
                status="error" if result.is_error else "success",
            )
        finally:
            self._busy = False


class SandboxClient:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    @asynccontextmanager
    async def open(
        self, request: EngineRequest, credentials: RunCredentials
    ) -> AsyncIterator[SandboxTools]:
        async def authorize(outgoing: httpx2.Request) -> None:
            # Runs for discovery, listing and every tools/call, not just at open.
            # This path never mints, refreshes, signals a watcher, or waits on a lock.
            pair = credentials.current()
            outgoing.headers["Authorization"] = f"Bearer {pair.context.access_token}"
            outgoing.headers["x-ads-session-id"] = str(request.session_id)
            outgoing.headers["x-ads-message-id"] = str(request.message_id)

        verify = ssl.create_default_context(
            cafile=str(self._settings.tls_ca_bundle) if self._settings.tls_ca_bundle else None
        )
        async with httpx2.AsyncClient(
            verify=verify,
            timeout=self._settings.mcp_timeout_seconds,
            follow_redirects=False,
            event_hooks={"request": [authorize]},
        ) as http:
            async with Client(
                streamable_http_client(
                    self._settings.mcp_url, http_client=http, terminate_on_close=False
                ),
                mode="2026-07-28",
                read_timeout_seconds=self._settings.mcp_timeout_seconds,
                cache=None,
            ) as client:
                yield SandboxTools(client, credentials, self._settings)
