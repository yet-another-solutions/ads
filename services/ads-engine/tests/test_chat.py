from __future__ import annotations

import json

from langchain_core.messages import (
    AIMessage,
    AIMessageChunk,
    HumanMessage,
    SystemMessage,
    ToolMessage,
)

from ads_commons.engine import (
    AssistantHistoryTurn,
    EngineRequest,
    ToolCall,
    ToolResult,
    UserHistoryTurn,
)
from ads_engine.chat import AdsChatOpenAI, _history_messages, deltas_from_chunk
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


def test_history_coalesces_tool_calls_then_results() -> None:
    base = make_request()
    request = EngineRequest(
        session_id=base.session_id,
        message_id=base.message_id,
        history=[
            UserHistoryTurn(text="run"),
            AssistantHistoryTurn(text=""),
            ToolCall(
                id="call-1",
                name="exec_shell",
                arguments={"command": "printf hi"},
                metadata={"index": 0},
            ),
            ToolResult(
                tool_call_id="call-1",
                name="exec_shell",
                status="success",
                content={"structuredContent": {"stdout": "hi"}},
            ),
            AssistantHistoryTurn(text="done"),
        ],
        user_input="next",
        instructions="",
        model=base.model,
        authorization=base.authorization,
    )
    messages = _history_messages(request)
    assert isinstance(messages[0], HumanMessage)
    assert messages[0].content == "run"
    assert isinstance(messages[1], AIMessage)
    assert messages[1].content == ""
    assert messages[1].tool_calls[0]["name"] == "exec_shell"
    assert messages[1].tool_calls[0]["args"] == {"command": "printf hi"}
    assert messages[1].tool_calls[0]["id"] == "call-1"
    assert isinstance(messages[2], ToolMessage)
    assert messages[2].tool_call_id == "call-1"
    assert messages[2].status == "success"
    assert json.loads(messages[2].content)["structuredContent"]["stdout"] == "hi"
    assert isinstance(messages[3], AIMessage)
    assert messages[3].content == "done"
    assert not messages[3].tool_calls
    assert isinstance(messages[4], HumanMessage)
    assert messages[4].content == "next"


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
