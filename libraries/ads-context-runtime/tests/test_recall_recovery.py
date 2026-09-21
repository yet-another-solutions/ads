import asyncio

import pytest
from langchain_core.messages import AIMessage, ToolMessage

from ads_commons.engine import ToolCall, ToolResult
from ads_commons.engine import UserHistoryTurn as U
from ads_context_runtime.frames import RECALL_PROMPT, ContextFailure, Frame, RecallRuntime
from context_fakes import Meter, Model, memory, model_settings, native


def test_each_turn_gets_own_fresh_budget_and_visible_answer_limit():
    model = Model(native("remaining_context"), "done")
    runtime = RecallRuntime(Meter(), model, model_settings(10000), reserve=100)
    frame = Frame([U("source")], "question", RECALL_PROMPT, 55)
    assert asyncio.run(runtime.run(frame)) == "done"
    prompts = [call[0][0].content for call in model.calls]
    assert all("total_context_tokens=10000" in p for p in prompts)
    assert "remaining_context_tokens=9886" in prompts[0]
    assert prompts[0] != prompts[1]
    assert all("Final visible answer must not exceed 55 tokens" in p for p in prompts)
    assert all(call[2] is None for call in model.calls)
    assert frame.source == [U("source")]


@pytest.mark.parametrize("content", ["", "#", "partial answer"])
def test_truncated_completion_never_becomes_success(content):
    model = Model(AIMessage(content, response_metadata={"finish_reason": "length"}))
    runtime = RecallRuntime(Meter(), model, model_settings(), reserve=100)
    with pytest.raises(ContextFailure, match="frame_completion_truncated"):
        asyncio.run(runtime.run(Frame([U("evidence")], "question", RECALL_PROMPT, 100)))


@pytest.mark.parametrize(
    "failure,reason",
    [
        (ContextFailure("empty_frame_answer"), "empty_frame_answer"),
        (RuntimeError("secret-provider-payload"), "internal_error"),
    ],
)
def test_nested_failure_closes_batch_and_finalizes_without_more_children(failure, reason):
    m = memory([U("evidence")])
    calls = [
        {
            "id": name,
            "name": "memory_recall",
            "args": {"memory_id": str(m.memory_id), "question": "q"},
        }
        for name in ("first", "second")
    ]
    model = Model(AIMessage("", tool_calls=calls), failure, "Evidence unavailable")
    runtime = RecallRuntime(Meter(), model, model_settings(), reserve=100)
    frame = Frame([m], "question", RECALL_PROMPT, 100)
    assert asyncio.run(runtime.run(frame)) == "Evidence unavailable"
    results = [m for m in frame.exchanges if isinstance(m, ToolResult)]
    assert [(r.tool_call_id, r.status, r.content) for r in results] == [
        ("first", "error", reason),
        ("second", "error", "recall_failed"),
    ]
    assert len(model.calls) == 3 and model.calls[-1][1] == []
    assert frame.finalization_only and frame.pending_results == []
    assert len([m for m in model.calls[-1][0] if isinstance(m, ToolMessage)]) == 2
    assert "secret-provider-payload" not in str(model.calls)


def test_child_context_is_independent_of_parent_usage_and_reasoning_not_answer_size():
    m = memory([U("archive")])
    model = Model(
        AIMessage(
            "ok",
            usage_metadata={
                "input_tokens": 20,
                "output_tokens": 5002,
                "total_tokens": 5022,
                "output_token_details": {"reasoning": 5000},
            },
        )
    )
    runtime = RecallRuntime(Meter(), model, model_settings(10000), top_level_answer_cap=2)
    call = ToolCall("top", "memory_recall", {"memory_id": str(m.memory_id), "question": "q"})
    result = asyncio.run(runtime.recall_top_level([m, U("x" * 20000)], call))
    assert result.status == "success" and result.content == {"answer": "ok"}
    prompt = model.calls[0][0][0].content
    assert "total_context_tokens=10000" in prompt
    assert "remaining_context_tokens=8968" in prompt
    assert "Final visible answer must not exceed 2 tokens" in prompt


@pytest.mark.parametrize("has_inner", [False, True])
def test_recall_worker_exposes_memory_recall_only_with_inner_tombstone(has_inner):
    inner = memory([U("older evidence")]) if has_inner else None
    outer = memory([U("direct archive")], [U("not recall source")], inner)
    model = Model("answer")
    runtime = RecallRuntime(Meter(), model, model_settings())
    call = ToolCall("top", "memory_recall", {"memory_id": str(outer.memory_id), "question": "q"})
    assert asyncio.run(runtime.recall_top_level([outer], call)).status == "success"
    names = {tool["function"]["name"] for tool in model.calls[0][1]}
    assert ("memory_recall" in names) is has_inner
    assert names == ({"remaining_context", "memory_recall"} if has_inner else {"remaining_context"})
    assert "not recall source" not in str(model.calls)


def test_nested_child_without_inner_tombstone_loses_recall_tool():
    inner = memory([U("original evidence")])
    outer = memory([U("recent archive")], inner=inner)
    model = Model(
        native("memory_recall", {"memory_id": str(inner.memory_id), "question": "older?"}),
        "original answer",
        "combined answer",
    )
    runtime = RecallRuntime(Meter(), model, model_settings())
    call = ToolCall("top", "memory_recall", {"memory_id": str(outer.memory_id), "question": "q"})
    assert asyncio.run(runtime.recall_top_level([outer], call)).content == {
        "answer": "combined answer"
    }
    names = [{tool["function"]["name"] for tool in call[1]} for call in model.calls]
    assert names == [
        {"remaining_context", "memory_recall"},
        {"remaining_context"},
        {"remaining_context", "memory_recall"},
    ]


def test_absent_inner_memory_cannot_be_dispatched_even_if_provider_invents_call():
    outer = memory([U("direct archive")])
    model = Model(
        native("memory_recall", {"memory_id": str(outer.memory_id), "question": "q"}),
        "No deeper archive is available",
    )
    runtime = RecallRuntime(Meter(), model, model_settings())
    call = ToolCall("top", "memory_recall", {"memory_id": str(outer.memory_id), "question": "q"})
    result = asyncio.run(runtime.recall_top_level([outer], call))
    assert result.status == "success"
    assert len(model.calls) == 2
    assert {t["function"]["name"] for t in model.calls[0][1]} == {"remaining_context"}
    assert model.calls[-1][1] == []
    results = [m for m in model.calls[-1][0] if isinstance(m, ToolMessage)]
    assert len(results) == 1 and "unauthorized_memory" in results[0].content
