"""MCP servers behind the guardrail. The SDK owns the protocol and negotiates its era."""

from __future__ import annotations

import ssl
from collections.abc import AsyncIterator, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx2
import msgspec
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.exceptions import MCPError
from mcp.types import ContentBlock

from ads_engine.guardrail import RUN_HEADER, Refusal, ToolsUnavailable, refusal_in


class McpUnavailable(ToolsUnavailable):
    pass


class McpTool(msgspec.Struct, frozen=True):
    name: str
    description: str = ""
    input_schema: dict[str, Any] = msgspec.field(default_factory=dict, name="inputSchema")


@dataclass(frozen=True, slots=True)
class ToolOutcome:
    text: str
    is_error: bool = False
    refusal: Refusal | None = None


class McpSession:
    """One server, reached through the guardrail as the person.

    A connection lives inside one call and no longer. The SDK's transport owns anyio
    cancel scopes, and a turn yields between tool calls: held open across those yields
    the scopes would be exited in another frame than the one that entered them.
    """

    def __init__(
        self,
        url: str,
        bearer: str,
        timeout_seconds: float = 60.0,
        ca_bundle: Path | None = None,
    ) -> None:
        self.url = url
        self.bearer = bearer
        # Set once the run is open, which is after the tools are offered; the request
        # hook reads it per request rather than at connect.
        self.run_id = ""
        self._timeout = timeout_seconds
        self._ca_bundle = ca_bundle

    async def list_tools(self) -> list[McpTool]:
        async with self._connected() as client:
            try:
                listing = await client.list_tools()
            except Exception as exc:
                raise McpUnavailable(f"{self.url} listed no tools: {exc}") from exc
        return [
            McpTool(
                name=tool.name,
                description=tool.description or "",
                input_schema=dict(tool.input_schema),
            )
            for tool in listing.tools
        ]

    async def call_tool(self, name: str, arguments: Mapping[str, Any]) -> ToolOutcome:
        async with self._connected() as client:
            try:
                result = await client.call_tool(
                    name, dict(arguments), read_timeout_seconds=self._timeout
                )
            except MCPError as exc:
                refusal = refusal_in(exc.error.data)
                if refusal is None:
                    raise McpUnavailable(f"{self.url} answered {name} with an error") from None
                return ToolOutcome(text=exc.error.message, is_error=True, refusal=refusal)
            except Exception as exc:
                raise McpUnavailable(f"{self.url}: {exc}") from exc
        return ToolOutcome(text=_text_of(result.content), is_error=bool(result.is_error))

    @asynccontextmanager
    async def _connected(self) -> AsyncIterator[Client]:
        verify: ssl.SSLContext | bool = True
        if self._ca_bundle is not None:
            verify = ssl.create_default_context(cafile=str(self._ca_bundle))
        try:
            async with httpx2.AsyncClient(
                verify=verify,
                timeout=self._timeout,
                follow_redirects=False,
                event_hooks={"request": [self._authorize]},
            ) as http:
                async with Client(
                    streamable_http_client(self.url, http_client=http),
                    read_timeout_seconds=self._timeout,
                ) as client:
                    yield client
        except McpUnavailable:
            raise
        except Exception as exc:
            raise McpUnavailable(f"{self.url}: {exc}") from exc

    async def _authorize(self, outgoing: httpx2.Request) -> None:
        outgoing.headers["authorization"] = f"Bearer {self.bearer}"
        if self.run_id:
            outgoing.headers[RUN_HEADER] = self.run_id


def _text_of(content: Sequence[ContentBlock]) -> str:
    texts: list[str] = []
    for block in content:
        text = getattr(block, "text", None)
        if isinstance(text, str):
            texts.append(text)
        else:
            texts.append(block.model_dump_json(by_alias=True, exclude_none=True))
    return "\n".join(texts)
