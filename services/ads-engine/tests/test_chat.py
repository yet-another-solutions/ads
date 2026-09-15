from __future__ import annotations

from langchain_core.messages import (
    AIMessage,
    AIMessageChunk,
    HumanMessage,
    SystemMessage,
)

from ads_commons.engine import AssistantHistoryTurn, EngineRequest, UserHistoryTurn
from ads_engine.chat import _history_messages, deltas_from_chunk
from engine_fakes import make_request


def test_history_then_user_input_are_sent_once() -> None:
    base = make_request()
    request = EngineRequest(
        session_id=base.session_id,
        message_id=base.message_id,
        history=[
            UserHistoryTurn(text="hi"),
            AssistantHistoryTurn(text="hello"),
        ],
        user_input="next",
        instructions="be brief",
        model=base.model,
        authorization=base.authorization,
    )
    messages = _history_messages(request)
    assert isinstance(messages[0], SystemMessage)
    assert messages[0].content == "be brief"
    assert isinstance(messages[1], HumanMessage)
    assert messages[1].content == "hi"
    assert isinstance(messages[2], AIMessage)
    assert messages[2].content == "hello"
    assert isinstance(messages[3], HumanMessage)
    assert messages[3].content == "next"
    assert len(messages) == 4


def test_deltas_map_reasoning_then_assistant_text() -> None:
    chunk = AIMessageChunk(
        content="Hello",
        additional_kwargs={"reasoning_content": "think"},
    )
    deltas = deltas_from_chunk(chunk)
    assert [(delta.kind, delta.text) for delta in deltas] == [
        ("reasoning", "think"),
        ("message", "Hello"),
    ]
