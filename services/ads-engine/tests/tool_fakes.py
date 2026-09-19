from __future__ import annotations

import json
import uuid
from collections.abc import AsyncIterator, Sequence
from dataclasses import dataclass, field
from typing import Any

from aiohttp import web
from langchain_core.messages import AIMessageChunk, BaseMessage

GUARDRAIL_API_TOKEN = "guardrail-api-token-32-bytes"
MCP_TOKEN = "mcp-audience-token"
SESSION_ID = "probe-session-1"

PROBE_TOOLS = [
    {
        "name": "echo",
        "description": "Returns the text it is given.",
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        },
    },
    {
        "name": "leak",
        "description": "Returns a key.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


@dataclass
class ToolAnswer:
    text: str = ""
    refusal_reason: str = ""
    alternative: str = ""
    failures_first: int = 0
    as_event_stream: bool = False


@dataclass
class FakeGuardrail:
    runs: dict[str, dict[str, Any]] = field(default_factory=dict)
    openings: list[dict[str, Any]] = field(default_factory=list)
    answers: dict[str, ToolAnswer] = field(default_factory=dict)
    calls: list[dict[str, Any]] = field(default_factory=list)
    call_headers: list[dict[str, str]] = field(default_factory=list)
    unavailable_servers: set[str] = field(default_factory=set)
    ended_sessions: list[str] = field(default_factory=list)
    failures_so_far: dict[str, int] = field(default_factory=dict)
    prompts: list[dict[str, Any]] = field(default_factory=list)
    prompt_reading: dict[str, Any] | None = None

    def application(self) -> web.Application:
        app = web.Application()
        app.router.add_get("/guardrail/runs/{run_id}", self.find_run)
        app.router.add_post("/guardrail/runs", self.open_run)
        app.router.add_post("/guardrail/prompts", self.inspect_prompt)
        app.router.add_post("/mcp/{server}", self.mcp)
        app.router.add_delete("/mcp/{server}", self.end_session)
        return app

    def run_in_state(self, state: str) -> str:
        run_id = uuid.uuid4().hex
        self.runs[run_id] = {"id": run_id, "state": state}
        return run_id

    async def find_run(self, request: web.Request) -> web.Response:
        if request.headers.get("authorization") != f"Bearer {GUARDRAIL_API_TOKEN}":
            return web.json_response({}, status=401)
        run = self.runs.get(request.match_info["run_id"])
        if run is None:
            return web.json_response({"detail": "no such run"}, status=404)
        return web.json_response(run)

    async def open_run(self, request: web.Request) -> web.Response:
        if request.headers.get("authorization") != f"Bearer {GUARDRAIL_API_TOKEN}":
            return web.json_response({}, status=401)
        opening = await request.json()
        self.openings.append(opening)
        run_id = self.run_in_state("running")
        return web.json_response(self.runs[run_id], status=201)

    async def inspect_prompt(self, request: web.Request) -> web.Response:
        if request.headers.get("authorization") != f"Bearer {GUARDRAIL_API_TOKEN}":
            return web.json_response({}, status=401)
        asked = await request.json()
        self.prompts.append(asked)
        reading = self.prompt_reading or {
            "decision": {"rule_id": "prompt.inspected"},
            "texts": asked["texts"],
            "withheld": False,
        }
        return web.json_response(reading, status=201)

    async def end_session(self, request: web.Request) -> web.Response:
        self.ended_sessions.append(request.headers.get("mcp-session-id", ""))
        return web.Response(status=200)

    async def mcp(self, request: web.Request) -> web.StreamResponse:
        server = request.match_info["server"]
        if server in self.unavailable_servers:
            return web.json_response({"error": "down"}, status=502)
        message = await request.json()
        method = message.get("method")
        if "id" not in message:
            return web.Response(status=202)
        if method == "initialize":
            return web.json_response(
                _result(
                    message,
                    {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "ads-mcp-probe", "version": "0.0.1"},
                    },
                ),
                headers={"mcp-session-id": SESSION_ID},
            )
        if method == "tools/list":
            return web.json_response(_result(message, {"tools": PROBE_TOOLS}))
        if method == "tools/call":
            return await self._tool_call(request, server, message)
        return web.json_response(_error(message, "no such method"))

    async def _tool_call(
        self, request: web.Request, server: str, message: dict[str, Any]
    ) -> web.StreamResponse:
        name = message["params"]["name"]
        self.calls.append({"server": server, **message["params"]})
        self.call_headers.append({k.lower(): v for k, v in request.headers.items()})
        answer = self.answers.get(name, ToolAnswer(text=f"{name} done"))
        failed = self.failures_so_far.get(name, 0)
        if failed < answer.failures_first:
            self.failures_so_far[name] = failed + 1
            return web.json_response({"error": "try again"}, status=503)
        if answer.refusal_reason:
            data: dict[str, Any] = {"refused_by": "ads-guardrail", "reason": answer.refusal_reason}
            if answer.alternative:
                data["alternative"] = answer.alternative
            payload = _error(message, "this action is not available", data)
        else:
            payload = _result(
                message, {"content": [{"type": "text", "text": answer.text}], "isError": False}
            )
        if not answer.as_event_stream:
            return web.json_response(payload)
        response = web.StreamResponse(headers={"content-type": "text/event-stream"})
        await response.prepare(request)
        progress = {"jsonrpc": "2.0", "method": "notifications/progress", "params": {}}
        await response.write(f"data: {json.dumps(progress)}\n\n".encode())
        await response.write(f"id: 1\ndata: {json.dumps(payload)}\n\n".encode())
        await response.write_eof()
        return response


def _result(message: dict[str, Any], value: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": message["id"], "result": value}


def _error(
    message: dict[str, Any], text: str, data: dict[str, Any] | None = None
) -> dict[str, Any]:
    error: dict[str, Any] = {"code": -32600, "message": text}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": message["id"], "error": error}


def tool_call_chunk(name: str, args: dict[str, Any], call_id: str) -> AIMessageChunk:
    return AIMessageChunk(
        content="",
        tool_call_chunks=[
            {
                "name": name,
                "args": json.dumps(args),
                "id": call_id,
                "index": 0,
                "type": "tool_call_chunk",
            }
        ],
    )


class ScriptedToolModel:
    def __init__(self, rounds: Sequence[Sequence[AIMessageChunk]]) -> None:
        self.rounds = [list(chunks) for chunks in rounds]
        self.bound_tools: list[dict[str, Any]] | None = None
        self.received: list[list[BaseMessage]] = []

    def bind_tools(self, tools: Sequence[dict[str, Any]]) -> ScriptedToolModel:
        self.bound_tools = list(tools)
        return self

    def astream(self, input: Any) -> AsyncIterator[Any]:
        return self._answer(list(input))

    async def _answer(self, messages: list[BaseMessage]) -> AsyncIterator[Any]:
        self.received.append(messages)
        round_number = len(self.received) - 1
        chunks = self.rounds[round_number] if round_number < len(self.rounds) else []
        for chunk in chunks:
            yield chunk


class FakeMcpTokenExchange:
    def __init__(self, error: Exception | None = None) -> None:
        self.exchanges: list[tuple[str, str | None]] = []
        self.error = error

    def exchange(self, audience: str, subject_token: str | None = None) -> str:
        self.exchanges.append((audience, subject_token))
        if self.error is not None:
            raise self.error
        return MCP_TOKEN
