from __future__ import annotations

import functools
import re
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol, TypeVar

import aiohttp
import anyio
import anyio.to_thread
import structlog
from langchain_core.messages import AIMessageChunk, ToolMessage
from langchain_core.messages.tool import ToolCall

from ads_commons.engine import EngineRequest, Notice, NoticeKind
from ads_engine.chat import (
    SideEffectsHappened,
    StreamDelta,
    build_chat_model,
    deltas_from_chunk,
    history_messages,
)
from ads_engine.config import ToolSettings
from ads_engine.mcp import GuardrailRuns, McpSession, McpTool, McpUnavailable, ToolOutcome

log = structlog.get_logger("ads_engine")

RUN_FINISHED = "finished"
TOOL_NAME_SEPARATOR = "__"
TOOL_NAME_UNSAFE = re.compile(r"[^A-Za-z0-9_-]")
MAX_TOOL_NAME_LENGTH = 64

REFUSED_NOTICE = "Запрос к инструменту {tool} отклонён политикой безопасности."
ALTERNATIVE_NOTICE = " Можно так: {alternative}."
INJECTION_NOTICE = "Результат инструмента {tool} скрыт: в нём обнаружена попытка промпт-инъекции."
UNAVAILABLE_NOTICE = "Сервис инструментов {server} недоступен, попробуйте позже."
ROUNDS_EXHAUSTED_MESSAGE = "\n\n(Остановлено: слишком много вызовов инструментов подряд.)"

REFUSED_FOR_MODEL = "The security policy refused this tool call."
ALTERNATIVE_FOR_MODEL = " A permitted alternative: {alternative}."
INJECTION_FOR_MODEL = (
    "The security policy withheld this result: it contained a prompt injection. "
    "Do not retry; tell the user."
)
UNAVAILABLE_FOR_MODEL = "The tool service is unavailable. Tell the user to try again later."
UNKNOWN_TOOL_FOR_MODEL = "There is no such tool."

T = TypeVar("T")


class StreamingModel(Protocol):
    def astream(self, input: Any) -> AsyncIterator[Any]: ...


class ToolCallingModel(StreamingModel, Protocol):
    def bind_tools(self, tools: Sequence[dict[str, Any]]) -> StreamingModel: ...


class TokenExchanger(Protocol):
    def exchange(self, audience: str, subject_token: str | None = None) -> str: ...


class ConversationRunStore(Protocol):
    async def run_of_conversation(self, session_id: uuid.UUID) -> str | None: ...

    async def remember_run_of_conversation(self, session_id: uuid.UUID, run_id: str) -> None: ...


ChatModelFactory = Callable[[EngineRequest], ToolCallingModel]


@dataclass(slots=True, eq=False)
class ToolingChatStreamer:
    settings: ToolSettings
    http: aiohttp.ClientSession
    tokens: TokenExchanger
    conversation_runs: ConversationRunStore
    model_factory: ChatModelFactory = build_chat_model

    def stream(self, request: EngineRequest) -> AsyncIterator[StreamDelta]:
        return _ToolTurn(self, request).stream()


@dataclass(frozen=True, slots=True)
class _OfferedTool:
    server: str
    session: McpSession
    tool: McpTool

    @property
    def label(self) -> str:
        return f"{self.server}/{self.tool.name}"

    def spec(self, offered_name: str) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": offered_name,
                "description": self.tool.description,
                "parameters": self.tool.input_schema or {"type": "object", "properties": {}},
            },
        }


@dataclass(slots=True, eq=False)
class _ToolTurn:
    streamer: ToolingChatStreamer
    request: EngineRequest
    sessions: dict[str, McpSession] = field(default_factory=dict)
    offered: dict[str, _OfferedTool] = field(default_factory=dict)
    unavailable_servers: set[str] = field(default_factory=set)
    run_id: str = ""
    bearer: str = ""

    @property
    def settings(self) -> ToolSettings:
        return self.streamer.settings

    async def stream(self) -> AsyncIterator[StreamDelta]:
        try:
            async for delta in self._stream():
                yield delta
        except Exception as exc:
            if self.run_id:
                raise SideEffectsHappened(f"failed after tools were called: {exc}") from exc
            raise
        finally:
            for session in self.sessions.values():
                await session.close()

    async def _stream(self) -> AsyncIterator[StreamDelta]:
        async for unavailable_notice in self._offer_tools():
            yield unavailable_notice
        model = self.streamer.model_factory(self.request)
        specs = [offered.spec(name) for name, offered in self.offered.items()]
        answering: StreamingModel = model.bind_tools(specs) if specs else model
        messages = history_messages(self.request)
        for _ in range(self.settings.max_model_rounds):
            gathered: AIMessageChunk | None = None
            async for chunk in answering.astream(messages):
                if not isinstance(chunk, AIMessageChunk):
                    continue
                for delta in deltas_from_chunk(chunk):
                    yield delta
                gathered = chunk if gathered is None else gathered + chunk
            calls = gathered.tool_calls if gathered is not None else []
            if gathered is None or not calls:
                return
            messages.append(gathered)
            for call in calls:
                outcome_for_model, notice = await self._call(call)
                if notice is not None:
                    yield notice
                messages.append(
                    ToolMessage(content=outcome_for_model, tool_call_id=call.get("id") or "")
                )
        yield StreamDelta(kind="message", text=ROUNDS_EXHAUSTED_MESSAGE)

    async def _offer_tools(self) -> AsyncIterator[StreamDelta]:
        try:
            self.bearer = await anyio.to_thread.run_sync(
                self.streamer.tokens.exchange,
                self.settings.mcp_audience,
                self.request.authorization.token,
            )
        except Exception as exc:
            log.warning("mcp token exchange failed", error=str(exc))
            for server in self.settings.mcp_servers:
                if notice := self._unavailable(server):
                    yield notice
            return
        for server in self.settings.mcp_servers:
            session = McpSession(
                self.streamer.http, f"{self.settings.guardrail_url}/mcp/{server}", self.bearer
            )
            try:
                tools = await self._with_retries(functools.partial(_opened_tools, session))
            except McpUnavailable as exc:
                log.warning("mcp server unavailable", server=server, error=str(exc))
                if notice := self._unavailable(server):
                    yield notice
                continue
            self.sessions[server] = session
            for tool in tools:
                self.offered[_offered_name(server, tool.name)] = _OfferedTool(server, session, tool)

    async def _call(self, call: ToolCall) -> tuple[str, StreamDelta | None]:
        offered = self.offered.get(call["name"])
        if offered is None:
            return UNKNOWN_TOOL_FOR_MODEL, None
        try:
            await self._ensure_run()
            outcome = await self._with_retries(
                lambda: offered.session.call_tool(offered.tool.name, call.get("args") or {})
            )
        except McpUnavailable as exc:
            log.warning("tool call not delivered", tool=offered.label, error=str(exc))
            return UNAVAILABLE_FOR_MODEL, self._unavailable(offered.server)
        return _answer_for(offered.label, outcome)

    async def _ensure_run(self) -> None:
        if self.run_id:
            return
        runs = GuardrailRuns(
            self.streamer.http, self.settings.guardrail_url, self.settings.guardrail_api_token
        )
        conversation = self.request.session_id
        remembered = await self.streamer.conversation_runs.run_of_conversation(conversation)
        if remembered:
            found = await self._with_retries(lambda: runs.find(remembered))
            if found is not None and found.state != RUN_FINISHED:
                self._use_run(found.id)
                return
        opened = await self._with_retries(
            lambda: runs.open(self.bearer, self.settings.workspace, str(conversation))
        )
        await self.streamer.conversation_runs.remember_run_of_conversation(conversation, opened.id)
        log.info("conversation run opened", session_id=str(conversation), run_id=opened.id)
        self._use_run(opened.id)

    def _use_run(self, run_id: str) -> None:
        self.run_id = run_id
        for session in self.sessions.values():
            session.run_id = run_id

    async def _with_retries(self, attempt: Callable[[], Awaitable[T]]) -> T:
        attempts = max(1, self.settings.call_attempts)
        for number in range(1, attempts + 1):
            try:
                with anyio.fail_after(self.settings.timeout_seconds):
                    return await attempt()
            except (McpUnavailable, TimeoutError) as exc:
                if number == attempts:
                    raise McpUnavailable(str(exc)) from exc
                await anyio.sleep(self.settings.retry_pause_seconds)
        raise AssertionError("unreachable")

    def _unavailable(self, server: str) -> StreamDelta | None:
        if server in self.unavailable_servers:
            return None
        self.unavailable_servers.add(server)
        return _notice("tools-unavailable", server, UNAVAILABLE_NOTICE.format(server=server))


async def _opened_tools(session: McpSession) -> list[McpTool]:
    if not session.session_id:
        await session.open()
    return await session.list_tools()


def _answer_for(label: str, outcome: ToolOutcome) -> tuple[str, StreamDelta | None]:
    refusal = outcome.refusal
    if refusal is None:
        text = f"Tool error: {outcome.text}" if outcome.is_error else outcome.text
        return text, None
    if refusal.prompt_injection:
        return INJECTION_FOR_MODEL, _notice(
            "prompt-injection", label, INJECTION_NOTICE.format(tool=label)
        )
    for_model = REFUSED_FOR_MODEL
    notice = REFUSED_NOTICE.format(tool=label)
    if refusal.alternative:
        for_model += ALTERNATIVE_FOR_MODEL.format(alternative=refusal.alternative)
        notice += ALTERNATIVE_NOTICE.format(alternative=refusal.alternative)
    return for_model, _notice("tool-refused", label, notice)


def _notice(kind: NoticeKind, tool: str, text: str) -> StreamDelta:
    return StreamDelta(kind="notice", text=text, notice=Notice(kind=kind, tool=tool, text=text))


def _offered_name(server: str, tool: str) -> str:
    name = TOOL_NAME_UNSAFE.sub("_", f"{server}{TOOL_NAME_SEPARATOR}{tool}")
    return name[:MAX_TOOL_NAME_LENGTH]
