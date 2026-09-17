from __future__ import annotations

import itertools
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

import aiohttp
import msgspec

from ads_engine.config import Workspace

PROTOCOL_VERSION = "2025-06-18"
REFUSED_BY_GUARDRAIL = "ads-guardrail"
REFUSED_FOR_PROMPT_INJECTION = "prompt-injection"
SESSION_HEADER = "mcp-session-id"
RUN_HEADER = "x-ads-run"
ACCEPT = "application/json, text/event-stream"
SSE_MEDIA_TYPE = "text/event-stream"


class McpUnavailable(ConnectionError):
    pass


class McpTool(msgspec.Struct, frozen=True):
    name: str
    description: str = ""
    input_schema: dict[str, Any] = msgspec.field(default_factory=dict, name="inputSchema")


@dataclass(frozen=True, slots=True)
class Refusal:
    prompt_injection: bool
    alternative: str


@dataclass(frozen=True, slots=True)
class ToolOutcome:
    text: str
    is_error: bool = False
    refusal: Refusal | None = None


class RunView(msgspec.Struct, frozen=True):
    id: str
    state: str


class _Workspace(msgspec.Struct, frozen=True):
    project: str
    repo: str
    env: str
    workdir: str


class _Opening(msgspec.Struct, frozen=True):
    bearer: str
    workspace: _Workspace
    conversation: str


@dataclass(slots=True, eq=False)
class GuardrailRuns:
    http: aiohttp.ClientSession
    base_url: str
    api_token: str

    async def find(self, run_id: str) -> RunView | None:
        url = f"{self.base_url}/guardrail/runs/{quote(run_id, safe='')}"
        try:
            async with self.http.get(url, headers=self._authorization()) as response:
                if response.status == 404:
                    return None
                if response.status != 200:
                    raise McpUnavailable(f"guardrail answered {response.status}")
                return msgspec.json.decode(await response.read(), type=RunView)
        except (aiohttp.ClientError, TimeoutError, msgspec.DecodeError) as exc:
            raise McpUnavailable(f"guardrail runs: {exc}") from exc

    async def open(self, bearer: str, workspace: Workspace, conversation: str) -> RunView:
        opening = _Opening(
            bearer=bearer,
            workspace=_Workspace(
                project=workspace.project,
                repo=workspace.repo,
                env=workspace.env,
                workdir=workspace.workdir,
            ),
            conversation=conversation,
        )
        try:
            async with self.http.post(
                f"{self.base_url}/guardrail/runs",
                data=msgspec.json.encode(opening),
                headers={**self._authorization(), "content-type": "application/json"},
            ) as response:
                if response.status not in (200, 201):
                    raise McpUnavailable(f"guardrail refused to open a run: {response.status}")
                return msgspec.json.decode(await response.read(), type=RunView)
        except (aiohttp.ClientError, TimeoutError, msgspec.DecodeError) as exc:
            raise McpUnavailable(f"guardrail runs: {exc}") from exc

    def _authorization(self) -> dict[str, str]:
        return {"authorization": f"Bearer {self.api_token}"}


@dataclass(slots=True, eq=False)
class McpSession:
    http: aiohttp.ClientSession
    url: str
    bearer: str
    run_id: str = ""
    session_id: str = ""
    _request_ids: itertools.count[int] = field(default_factory=lambda: itertools.count(1))

    async def open(self) -> None:
        await self._request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "ads-engine", "version": "0.0.1"},
            },
        )
        await self._notify("notifications/initialized")

    async def list_tools(self) -> list[McpTool]:
        answer = await self._request("tools/list", {})
        result = answer.get("result")
        if not isinstance(result, Mapping):
            raise McpUnavailable(f"{self.url} listed no tools")
        return msgspec.convert(result.get("tools", []), type=list[McpTool])

    async def call_tool(self, name: str, arguments: Mapping[str, Any]) -> ToolOutcome:
        answer = await self._request("tools/call", {"name": name, "arguments": dict(arguments)})
        error = answer.get("error")
        if isinstance(error, Mapping):
            return _outcome_of_error(error)
        result = answer.get("result")
        if not isinstance(result, Mapping):
            raise McpUnavailable(f"{self.url} answered a tool call with nothing")
        return ToolOutcome(
            text=_text_of(result.get("content")), is_error=bool(result.get("isError"))
        )

    async def close(self) -> None:
        if not self.session_id:
            return
        try:
            async with self.http.delete(self.url, headers=self._headers()):
                pass
        except (aiohttp.ClientError, TimeoutError):
            return

    async def _notify(self, method: str) -> None:
        message = {"jsonrpc": "2.0", "method": method}
        try:
            async with self.http.post(
                self.url, data=msgspec.json.encode(message), headers=self._headers()
            ) as response:
                if response.status >= 400:
                    raise McpUnavailable(f"{self.url} answered {response.status} to {method}")
        except (aiohttp.ClientError, TimeoutError) as exc:
            raise McpUnavailable(f"{self.url}: {exc}") from exc

    async def _request(self, method: str, params: Mapping[str, Any]) -> dict[str, Any]:
        request_id = next(self._request_ids)
        message = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
        try:
            async with self.http.post(
                self.url, data=msgspec.json.encode(message), headers=self._headers()
            ) as response:
                if response.status != 200:
                    raise McpUnavailable(f"{self.url} answered {response.status} to {method}")
                self.session_id = response.headers.get(SESSION_HEADER, self.session_id)
                body = await response.read()
                if response.content_type == SSE_MEDIA_TYPE:
                    return _answer_in_events(body, request_id)
                return _answer_in_json(body, request_id)
        except (aiohttp.ClientError, TimeoutError) as exc:
            raise McpUnavailable(f"{self.url}: {exc}") from exc

    def _headers(self) -> dict[str, str]:
        headers = {
            "authorization": f"Bearer {self.bearer}",
            "accept": ACCEPT,
            "content-type": "application/json",
            "mcp-protocol-version": PROTOCOL_VERSION,
        }
        if self.session_id:
            headers[SESSION_HEADER] = self.session_id
        if self.run_id:
            headers[RUN_HEADER] = self.run_id
        return headers


def _answer_in_json(body: bytes, request_id: int) -> dict[str, Any]:
    try:
        message = msgspec.json.decode(body)
    except msgspec.DecodeError as exc:
        raise McpUnavailable(f"unreadable MCP answer: {exc}") from exc
    for candidate in message if isinstance(message, list) else [message]:
        if isinstance(candidate, dict) and candidate.get("id") == request_id:
            return candidate
    raise McpUnavailable("the MCP answer does not answer the request")


def _answer_in_events(body: bytes, request_id: int) -> dict[str, Any]:
    for event in body.replace(b"\r\n", b"\n").split(b"\n\n"):
        data = b"\n".join(
            line.split(b":", 1)[1].lstrip(b" ")
            for line in event.split(b"\n")
            if line.startswith(b"data:")
        )
        if not data:
            continue
        try:
            message = msgspec.json.decode(data)
        except msgspec.DecodeError:
            continue
        if isinstance(message, dict) and message.get("id") == request_id:
            return message
    raise McpUnavailable("the MCP event stream ended without an answer")


def _outcome_of_error(error: Mapping[str, Any]) -> ToolOutcome:
    message = str(error.get("message", ""))
    data = error.get("data")
    if isinstance(data, Mapping) and data.get("refused_by") == REFUSED_BY_GUARDRAIL:
        return ToolOutcome(
            text=message,
            is_error=True,
            refusal=Refusal(
                prompt_injection=data.get("reason") == REFUSED_FOR_PROMPT_INJECTION,
                alternative=str(data.get("alternative", "")),
            ),
        )
    return ToolOutcome(text=message, is_error=True)


def _text_of(content: object) -> str:
    if not isinstance(content, list):
        return ""
    texts: list[str] = []
    for block in content:
        if not isinstance(block, Mapping):
            continue
        text = block.get("text")
        if isinstance(text, str):
            texts.append(text)
        elif text is not None:
            texts.append(msgspec.json.encode(text).decode())
    return "\n".join(texts)
