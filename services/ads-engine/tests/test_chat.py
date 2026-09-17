from __future__ import annotations

from langchain_core.messages import (
    AIMessage,
    AIMessageChunk,
    HumanMessage,
    SystemMessage,
)

from ads_commons.engine import AssistantHistoryTurn, EngineRequest, UserHistoryTurn
from ads_engine.chat import AdsChatOpenAI, deltas_from_chunk, history_messages
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
    messages = history_messages(request)
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


def test_deltas_map_reasoning_summary_content_block() -> None:
    chunk = AIMessageChunk(
        content=[
            {
                "type": "reasoning",
                "summary": [{"type": "summary_text", "text": "plan"}],
            },
            {"type": "text", "text": "done"},
        ]
    )
    deltas = deltas_from_chunk(chunk)
    assert [(delta.kind, delta.text) for delta in deltas] == [
        ("reasoning", "plan"),
        ("message", "done"),
    ]


def test_deltas_map_reasoning_dict_in_additional_kwargs() -> None:
    chunk = AIMessageChunk(
        content="",
        additional_kwargs={
            "reasoning": {
                "type": "reasoning",
                "summary": [{"type": "summary_text", "text": "why"}],
            }
        },
    )
    deltas = deltas_from_chunk(chunk)
    assert [(delta.kind, delta.text) for delta in deltas] == [("reasoning", "why")]


def test_chat_openai_chunk_keeps_reasoning_content() -> None:
    model = AdsChatOpenAI(model="test", api_key="x", streaming=True, max_retries=0)
    generation = model._convert_chunk_to_generation_chunk(
        {
            "id": "chunk-1",
            "choices": [
                {
                    "index": 0,
                    "delta": {"content": "Hi", "reasoning_content": "think"},
                }
            ],
        },
        AIMessageChunk,
        None,
    )
    assert generation is not None
    assert isinstance(generation.message, AIMessageChunk)
    deltas = deltas_from_chunk(generation.message)
    assert [(delta.kind, delta.text) for delta in deltas] == [
        ("reasoning", "think"),
        ("message", "Hi"),
    ]


def test_chat_openai_reasoning_only_chunk_is_reasoning() -> None:
    model = AdsChatOpenAI(model="test", api_key="x", streaming=True, max_retries=0)
    generation = model._convert_chunk_to_generation_chunk(
        {
            "id": "chunk-2",
            "choices": [
                {
                    "index": 0,
                    "delta": {"content": None, "reasoning_content": "step"},
                }
            ],
        },
        AIMessageChunk,
        None,
    )
    assert generation is not None
    assert isinstance(generation.message, AIMessageChunk)
    deltas = deltas_from_chunk(generation.message)
    assert [(delta.kind, delta.text) for delta in deltas] == [("reasoning", "step")]
