from __future__ import annotations

import asyncio
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import replace
from typing import Any

import aiohttp
import pytest
from aiohttp.test_utils import TestServer
from langchain_core.messages import AIMessageChunk, ToolMessage

from ads_engine.chat import SideEffectsHappened, StreamDelta
from ads_engine.config import Settings, ToolSettings, Workspace
from ads_engine.store import ActiveSessionStore
from ads_engine.tooling import ToolingChatStreamer
from engine_fakes import make_request
from tool_fakes import (
    GUARDRAIL_API_TOKEN,
    MCP_TOKEN,
    SESSION_ID,
    FakeGuardrail,
    FakeMcpTokenExchange,
    ScriptedToolModel,
    ToolAnswer,
    tool_call_chunk,
)

USER_TOKEN = "user-jwt-for-ads-engine"
CHAT = uuid.UUID("33333333-3333-3333-3333-333333333333")
WORKSPACE = Workspace(project="ads", repo="yet-another-solutions/ads", env="test", workdir="/w")

Scenario = Callable[["ToolHarness"], Awaitable[None]]


class ToolHarness:
    def __init__(self, guardrail: FakeGuardrail, url: str, store: ActiveSessionStore) -> None:
        self.guardrail = guardrail
        self.url = url
        self.store = store
        self.exchange = FakeMcpTokenExchange()
        self.http: aiohttp.ClientSession | None = None
        self.settings = ToolSettings(
            mcp_servers=("probe",),
            guardrail_url=url,
            guardrail_api_token=GUARDRAIL_API_TOKEN,
            mcp_audience="ads-mcp",
            workspace=WORKSPACE,
            call_attempts=3,
            retry_pause_seconds=0.0,
            timeout_seconds=5.0,
        )

    async def answer(self, model: ScriptedToolModel, **setting_changes: Any) -> list[StreamDelta]:
        assert self.http is not None
        streamer = ToolingChatStreamer(
            replace(self.settings, **setting_changes),
            self.http,
            self.exchange,
            self.store,
            model_factory=lambda request: model,
        )
        request = make_request(session_id=CHAT, authorization_token=USER_TOKEN)
        return [delta async for delta in streamer.stream(request)]


def _run(
    store: ActiveSessionStore, scenario: Scenario, guardrail: FakeGuardrail | None = None
) -> None:
    async def main() -> None:
        fake = guardrail or FakeGuardrail()
        server = TestServer(fake.application())
        await server.start_server()
        harness = ToolHarness(fake, str(server.make_url("")).rstrip("/"), store)
        async with aiohttp.ClientSession() as http:
            harness.http = http
            try:
                await scenario(harness)
            finally:
                await server.close()

    asyncio.run(main())


def _text(content: str) -> AIMessageChunk:
    return AIMessageChunk(content=content)


def _notices(deltas: list[StreamDelta]) -> list[tuple[str, str]]:
    return [(d.notice.kind, d.text) for d in deltas if d.notice is not None]


def _messages(deltas: list[StreamDelta]) -> str:
    return "".join(d.text for d in deltas if d.kind == "message")


def test_tools_are_offered_under_their_server_names(store: ActiveSessionStore) -> None:
    async def scenario(harness: ToolHarness) -> None:
        model = ScriptedToolModel([[_text("hello")]])
        deltas = await harness.answer(model)
        assert _messages(deltas) == "hello"
        assert model.bound_tools is not None
        names = [tool["function"]["name"] for tool in model.bound_tools]
        assert names == ["probe__echo", "probe__leak"]
        echo = model.bound_tools[0]["function"]
        assert echo["parameters"]["required"] == ["text"]
        leak = model.bound_tools[1]["function"]
        assert leak["parameters"] == {"type": "object", "properties": {}}
        assert harness.exchange.exchanges == [("ads-mcp", USER_TOKEN)]

    _run(store, scenario)


def test_every_message_is_read_before_the_model_sees_it(store: ActiveSessionStore) -> None:
    async def scenario(harness: ToolHarness) -> None:
        deltas = await harness.answer(ScriptedToolModel([[_text("just text")]]))
        assert len(harness.guardrail.openings) == 1
        assert harness.guardrail.prompts[0]["texts"] == [make_request().user_input]
        assert [delta.text for delta in deltas if delta.kind == "message"] == ["just text"]

    _run(store, scenario)


def test_a_refused_prompt_never_reaches_the_model(store: ActiveSessionStore) -> None:
    guardrail = FakeGuardrail()
    guardrail.prompt_reading = {
        "decision": {"rule_id": "payload.injection"},
        "texts": [],
        "withheld": True,
    }

    async def scenario(harness: ToolHarness) -> None:
        model = ScriptedToolModel([[_text("the model should never answer")]])
        deltas = await harness.answer(model)
        assert [delta.kind for delta in deltas] == ["notice"]
        assert deltas[0].notice is not None
        assert deltas[0].notice.kind == "prompt-refused"
        assert model.received == []

    _run(store, scenario, guardrail)


def test_a_secret_in_a_message_is_cut_out_before_the_model(store: ActiveSessionStore) -> None:
    guardrail = FakeGuardrail()
    guardrail.prompt_reading = {
        "decision": {"rule_id": "payload.leak"},
        "texts": ["deploy with [redacted:aws-access-token]"],
        "withheld": False,
    }

    async def scenario(harness: ToolHarness) -> None:
        model = ScriptedToolModel([[_text("done")]])
        await harness.answer(model)
        assert model.received[-1][-1].content == "deploy with [redacted:aws-access-token]"

    _run(store, scenario, guardrail)


def test_a_tool_call_opens_the_chat_run_and_feeds_the_result_back(
    store: ActiveSessionStore,
) -> None:
    async def scenario(harness: ToolHarness) -> None:
        model = ScriptedToolModel(
            [[tool_call_chunk("probe__echo", {"text": "hi"}, "call-1")], [_text("it said hi")]]
        )
        deltas = await harness.answer(model)
        assert _messages(deltas) == "it said hi"
        (opening,) = harness.guardrail.openings
        assert opening["bearer"] == MCP_TOKEN
        assert opening["conversation"] == str(CHAT)
        assert opening["workspace"]["project"] == "ads"
        (call,) = harness.guardrail.calls
        assert call == {"server": "probe", "name": "echo", "arguments": {"text": "hi"}}
        headers = harness.guardrail.call_headers[0]
        assert headers["authorization"] == f"Bearer {MCP_TOKEN}"
        assert headers["x-ads-run"] == await store.run_of_conversation(CHAT)
        assert headers["mcp-session-id"] == SESSION_ID
        tool_message = model.received[1][-1]
        assert isinstance(tool_message, ToolMessage)
        assert tool_message.content == "echo done"
        assert tool_message.tool_call_id == "call-1"

    _run(store, scenario)


def test_the_next_message_of_the_chat_keeps_its_running_run(store: ActiveSessionStore) -> None:
    async def scenario(harness: ToolHarness) -> None:
        for _ in range(2):
            await harness.answer(
                ScriptedToolModel(
                    [[tool_call_chunk("probe__echo", {"text": "x"}, "c")], [_text("ok")]]
                )
            )
        assert len(harness.guardrail.openings) == 1
        first, second = harness.guardrail.call_headers
        assert first["x-ads-run"] == second["x-ads-run"]

    _run(store, scenario)


@pytest.mark.parametrize(("state", "reopened"), [("finished", True), ("revoked", False)])
def test_a_finished_run_is_replaced_but_a_revoked_one_is_kept(
    store: ActiveSessionStore, state: str, reopened: bool
) -> None:
    async def scenario(harness: ToolHarness) -> None:
        old = harness.guardrail.run_in_state(state)
        await store.remember_run_of_conversation(CHAT, old)
        await harness.answer(
            ScriptedToolModel([[tool_call_chunk("probe__echo", {"text": "x"}, "c")], []])
        )
        assert (len(harness.guardrail.openings) == 1) is reopened
        used = harness.guardrail.call_headers[0]["x-ads-run"]
        assert (used != old) is reopened
        assert await store.run_of_conversation(CHAT) == used

    _run(store, scenario)


def test_a_run_the_guardrail_no_longer_knows_is_replaced(store: ActiveSessionStore) -> None:
    async def scenario(harness: ToolHarness) -> None:
        await store.remember_run_of_conversation(CHAT, "expired-run")
        await harness.answer(
            ScriptedToolModel([[tool_call_chunk("probe__echo", {"text": "x"}, "c")], []])
        )
        assert len(harness.guardrail.openings) == 1

    _run(store, scenario)


def test_a_policy_refusal_is_a_notice_with_the_alternative(store: ActiveSessionStore) -> None:
    guardrail = FakeGuardrail(
        answers={"echo": ToolAnswer(refusal_reason="policy", alternative="use db.query")}
    )

    async def scenario(harness: ToolHarness) -> None:
        model = ScriptedToolModel(
            [[tool_call_chunk("probe__echo", {"text": "x"}, "c")], [_text("sorry")]]
        )
        deltas = await harness.answer(model)
        assert _notices(deltas) == [
            (
                "tool-refused",
                "Запрос к инструменту probe/echo отклонён политикой безопасности."
                " Можно так: use db.query.",
            )
        ]
        tool_message = model.received[1][-1]
        assert "refused" in str(tool_message.content)
        assert "use db.query" in str(tool_message.content)

    _run(store, scenario, guardrail)


def test_a_withheld_injection_is_a_notice_that_names_the_reason(
    store: ActiveSessionStore,
) -> None:
    guardrail = FakeGuardrail(answers={"leak": ToolAnswer(refusal_reason="prompt-injection")})

    async def scenario(harness: ToolHarness) -> None:
        model = ScriptedToolModel([[tool_call_chunk("probe__leak", {}, "c")], [_text("ok")]])
        deltas = await harness.answer(model)
        (notice,) = [d.notice for d in deltas if d.notice is not None]
        assert notice.kind == "prompt-injection"
        assert notice.tool == "probe/leak"
        assert "промпт-инъекции" in notice.text
        assert "prompt injection" in str(model.received[1][-1].content)

    _run(store, scenario, guardrail)


def test_a_flaky_tool_call_is_retried(store: ActiveSessionStore) -> None:
    guardrail = FakeGuardrail(answers={"echo": ToolAnswer(text="finally", failures_first=2)})

    async def scenario(harness: ToolHarness) -> None:
        model = ScriptedToolModel(
            [[tool_call_chunk("probe__echo", {"text": "x"}, "c")], [_text("ok")]]
        )
        deltas = await harness.answer(model)
        assert _notices(deltas) == []
        assert model.received[1][-1].content == "finally"
        assert len(harness.guardrail.calls) == 3

    _run(store, scenario, guardrail)


def test_a_tool_that_stays_down_is_a_notice_to_try_later(store: ActiveSessionStore) -> None:
    guardrail = FakeGuardrail(answers={"echo": ToolAnswer(failures_first=10)})

    async def scenario(harness: ToolHarness) -> None:
        model = ScriptedToolModel(
            [
                [tool_call_chunk("probe__echo", {"text": "x"}, "c1")],
                [tool_call_chunk("probe__echo", {"text": "y"}, "c2")],
                [_text("gave up")],
            ]
        )
        deltas = await harness.answer(model)
        assert _notices(deltas) == [
            ("tools-unavailable", "Сервис инструментов probe недоступен, попробуйте позже.")
        ]
        assert "unavailable" in str(model.received[1][-1].content)
        assert _messages(deltas) == "gave up"

    _run(store, scenario, guardrail)


def test_an_unreachable_server_is_left_out_with_a_notice(store: ActiveSessionStore) -> None:
    guardrail = FakeGuardrail(unavailable_servers={"probe"})

    async def scenario(harness: ToolHarness) -> None:
        model = ScriptedToolModel([[_text("no tools today")]])
        deltas = await harness.answer(model)
        assert [kind for kind, _ in _notices(deltas)] == ["tools-unavailable"]
        assert model.bound_tools is None
        assert _messages(deltas) == "no tools today"

    _run(store, scenario, guardrail)


def test_a_failed_token_exchange_leaves_the_tools_out(store: ActiveSessionStore) -> None:
    async def scenario(harness: ToolHarness) -> None:
        harness.exchange = FakeMcpTokenExchange(error=RuntimeError("keycloak down"))
        model = ScriptedToolModel([[_text("plain")]])
        deltas = await harness.answer(model)
        assert [kind for kind, _ in _notices(deltas)] == ["tools-unavailable"]
        assert model.bound_tools is None

    _run(store, scenario)


def test_an_answer_streamed_as_events_is_read(store: ActiveSessionStore) -> None:
    guardrail = FakeGuardrail(
        answers={"echo": ToolAnswer(text="from a stream", as_event_stream=True)}
    )

    async def scenario(harness: ToolHarness) -> None:
        model = ScriptedToolModel(
            [[tool_call_chunk("probe__echo", {"text": "x"}, "c")], [_text("ok")]]
        )
        await harness.answer(model)
        assert model.received[1][-1].content == "from a stream"

    _run(store, scenario, guardrail)


def test_endless_tool_calls_stop_after_the_round_limit(store: ActiveSessionStore) -> None:
    async def scenario(harness: ToolHarness) -> None:
        call = tool_call_chunk("probe__echo", {"text": "again"}, "c")
        model = ScriptedToolModel([[call]] * 5)
        deltas = await harness.answer(model, max_model_rounds=3)
        assert len(harness.guardrail.calls) == 3
        assert "слишком много вызовов" in _messages(deltas)

    _run(store, scenario)


def test_the_mcp_session_is_ended(store: ActiveSessionStore) -> None:
    async def scenario(harness: ToolHarness) -> None:
        await harness.answer(ScriptedToolModel([[_text("bye")]]))
        assert harness.guardrail.ended_sessions == [SESSION_ID]

    _run(store, scenario)


def test_an_unknown_tool_name_is_answered_without_a_call(store: ActiveSessionStore) -> None:
    async def scenario(harness: ToolHarness) -> None:
        model = ScriptedToolModel(
            [[tool_call_chunk("elsewhere__format_disk", {}, "c")], [_text("ok")]]
        )
        await harness.answer(model)
        assert harness.guardrail.calls == []
        assert model.received[1][-1].content == "There is no such tool."

    _run(store, scenario)


class _ModelThatFailsAfterTheFirstRound(ScriptedToolModel):
    async def _answer(self, messages: list[Any]) -> Any:
        self.received.append(messages)
        if len(self.received) > 1:
            raise RuntimeError("model went away")
        yield tool_call_chunk("probe__echo", {"text": "x"}, "c")


def test_a_failure_after_a_tool_call_says_it_must_not_be_retried(
    store: ActiveSessionStore,
) -> None:
    async def scenario(harness: ToolHarness) -> None:
        with pytest.raises(SideEffectsHappened):
            await harness.answer(_ModelThatFailsAfterTheFirstRound([]))
        assert len(harness.guardrail.calls) == 1

    _run(store, scenario)


def test_a_failure_before_any_tool_call_stays_retryable(store: ActiveSessionStore) -> None:
    class _ModelThatFailsAtOnce(ScriptedToolModel):
        async def _answer(self, messages: list[Any]) -> Any:
            raise RuntimeError("model unavailable")
            yield  # pragma: no cover

    async def scenario(harness: ToolHarness) -> None:
        with pytest.raises(RuntimeError) as raised:
            await harness.answer(_ModelThatFailsAtOnce([]))
        assert not isinstance(raised.value, SideEffectsHappened)

    _run(store, scenario)


def test_settings_without_servers_mean_no_tools(settings: Settings) -> None:
    assert settings.tools is None
