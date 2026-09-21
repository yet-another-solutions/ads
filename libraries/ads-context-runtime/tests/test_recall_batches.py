import asyncio

import pytest
from langchain_core.messages import AIMessage, ToolMessage

from ads_commons.context_meter import MeterResponse
from ads_commons.engine import AssistantHistoryTurn as A
from ads_commons.engine import Tombstone, ToolCall, ToolResult
from ads_commons.engine import UserHistoryTurn as U
from ads_context_runtime.frames import (
    RECALL_PROMPT,
    STARVATION,
    ContextFailure,
    ContextOverflow,
    Frame,
    RecallRuntime,
)
from context_fakes import Meter, Model, memory, model_settings


class BudgetMeter:
    """Fixed envelope weights make threshold crossings exact and deterministic."""

    async def meter(self, body):
        size = 0
        for item in body.messages:
            if isinstance(item, Tombstone):
                size += 100
            elif isinstance(item, ToolCall):
                size += 10
            elif isinstance(item, ToolResult):
                size += 10
                if item.status == "success":
                    size += len(item.content["answer"])
            else:
                size += len(item.text)
        return MeterResponse(size)


def batch(m, ids=("a", "b", "c")):
    return AIMessage(
        "",
        tool_calls=[
            {
                "id": id_,
                "name": "memory_recall",
                "args": {
                    "memory_id": str(m.memory_id),
                    "question": "q",
                },
            }
            for id_ in ids
        ],
    )


@pytest.mark.parametrize("padding,executed", [(500, 2), (480, 3)])
def test_batch_runs_in_order_until_below_ten_percent_then_resolves_remaining(padding, executed):
    m = memory([U("archive")])
    answers = [batch(m), "a" * 80, "b" * 80]
    if executed == 3:
        answers.append("third")
    model = Model(*answers, "final")
    runtime = RecallRuntime(BudgetMeter(), model, model_settings(1000), reserve=100)
    frame = Frame([U("x" * padding), m], "", RECALL_PROMPT, 100)
    assert asyncio.run(runtime.run(frame)) == "final"
    assert len(model.calls) == executed + 2
    assert not frame.pending_results
    calls = [i for i in frame.exchanges if isinstance(i, ToolCall)]
    results = [i for i in frame.exchanges if isinstance(i, ToolResult)]
    assert [i.id for i in calls] == ["a", "b", "c"]
    assert [i.tool_call_id for i in results] == ["a", "b", "c"]
    assert [i.status for i in results] == ["success"] * executed + ["error"] * (3 - executed)
    if executed == 2:
        assert results[-1].content == STARVATION
        assert frame.finalization_only and model.calls[-1][1] == []
    else:
        # Exactly ten percent after the second answer still admits the third.
        assert results[1].content["remaining_tokens"] == 100
    wire = model.calls[-1][0]
    batches = [message for message in wire if isinstance(message, AIMessage) and message.tool_calls]
    assert len(batches) == 1
    assert [c["id"] for c in batches[0].tool_calls] == ["a", "b", "c"]
    assert [m.tool_call_id for m in wire if isinstance(m, ToolMessage)] == ["a", "b", "c"]
    assert asyncio.run(runtime.remaining(frame.charged))["remaining_tokens"] >= 0


def test_batch_envelopes_and_closure_are_charged_before_any_dispatch():
    m = memory([U("must not be read")])
    model = Model(batch(m), "final")
    runtime = RecallRuntime(BudgetMeter(), model, model_settings(1000), reserve=100)
    # Source has 12% remaining; the full batch lowers it below 10%.
    frame = Frame([U("x" * 680), m], "", RECALL_PROMPT, 100)
    assert asyncio.run(runtime.run(frame)) == "final"
    assert len(model.calls) == 2
    assert all(i.status == "error" for i in frame.exchanges if isinstance(i, ToolResult))
    assert len([i for i in frame.exchanges if isinstance(i, ToolCall)]) == 3
    assert model.calls[-1][1] == []


def test_no_room_for_required_error_results_fails_before_execution():
    runtime = RecallRuntime(BudgetMeter(), Model(), model_settings(1000), reserve=100)
    frame = Frame([U("x" * 881)], "", RECALL_PROMPT, 100)
    with pytest.raises(ContextOverflow, match="recall_batch_closure_does_not_fit"):
        asyncio.run(runtime.dispatch_batch(frame, [ToolCall("a", "remaining_context", {})]))
    assert frame.exchanges == [] and frame.pending_results == []
    assert runtime.model.calls == []


@pytest.mark.parametrize("ids", [("a", "a"), ("", "b")])
def test_invalid_batch_ids_fail_before_dispatch(ids):
    m = memory()
    runtime = RecallRuntime(Meter(), Model(batch(m, ids)), model_settings(), reserve=100)
    frame = Frame([m], "", RECALL_PROMPT, 100)
    with pytest.raises(ContextFailure, match="invalid_recall_call_id"):
        asyncio.run(runtime.run(frame))
    assert frame.exchanges == []


def test_batch_cannot_reuse_an_id_from_an_earlier_step():
    runtime = RecallRuntime(Meter(), Model(), model_settings(), reserve=100)
    frame = Frame(
        [],
        "",
        RECALL_PROMPT,
        100,
        exchanges=[
            ToolCall("a", "remaining_context", {}),
            ToolResult("a", "remaining_context", "error", STARVATION),
        ],
    )
    with pytest.raises(ContextFailure, match="invalid_recall_call_id"):
        asyncio.run(runtime.dispatch_batch(frame, [ToolCall("a", "remaining_context", {})]))
    assert len(frame.exchanges) == 2


def test_oversized_child_retries_once_then_prohibits_the_rest_of_the_batch():
    m = memory([U("evidence")])
    model = Model(batch(m), "x" * 4000, "x" * 4000, "final")
    runtime = RecallRuntime(Meter(), model, model_settings(2000), reserve=100)
    frame = Frame([m], "", RECALL_PROMPT, 100)
    assert asyncio.run(runtime.run(frame)) == "final"
    assert len(model.calls) == 4
    assert "Compact-result retry" in str(model.calls[2][0])
    assert "x" * 4000 not in str(frame.exchanges)
    assert len([i for i in frame.exchanges if isinstance(i, ToolResult)]) == 3
    assert all(i.content == STARVATION for i in frame.exchanges if isinstance(i, ToolResult))
    assert model.calls[-1][1] == []


def test_starved_batch_prohibits_remaining_context_too():
    runtime = RecallRuntime(BudgetMeter(), Model(), model_settings(1000), reserve=100)
    frame = Frame([U("x" * 790)], "", RECALL_PROMPT, 100)
    asyncio.run(
        runtime.dispatch_batch(
            frame,
            [
                ToolCall("a", "remaining_context", {}),
                ToolCall("b", "remaining_context", {}),
            ],
        )
    )
    assert [i.content for i in frame.exchanges if isinstance(i, ToolResult)] == [STARVATION] * 2
    assert frame.finalization_only


@pytest.mark.parametrize("used,permitted", [(750, True), (751, False)])
def test_configurable_fifteen_percent_boundary(used, permitted):
    runtime = RecallRuntime(
        Meter(),
        Model("final"),
        model_settings(1000),
        reserve=100,
        starvation_percentage=15,
    )
    frame = Frame([U("x" * used)], "", RECALL_PROMPT, 100)
    assert asyncio.run(runtime.run(frame)) == "final"
    assert bool(runtime.model.calls[0][1]) is permitted


def test_completion_allowance_is_separate_and_clipped_to_metered_headroom():
    model = Model("final")
    runtime = RecallRuntime(Meter(), model, model_settings(1000), reserve=100)
    frame = Frame([U("x" * 700)], "", RECALL_PROMPT, 50, completion_cap=8192)
    assert asyncio.run(runtime.run(frame)) == "final"
    assert model.calls[0][2] == 300
    assert frame.cap == 50


def test_finalization_guard_still_rejects_model_calls_without_tools():
    m = memory()
    runtime = RecallRuntime(Meter(), Model(batch(m)), model_settings(), reserve=100)
    frame = Frame([m], "", RECALL_PROMPT, 100, finalization_only=True)
    with pytest.raises(ContextFailure, match="recall_tools_prohibited"):
        asyncio.run(runtime.run(frame))
    assert runtime.model.calls[0][1] == []
    assert frame.exchanges == []


def test_invalid_native_calls_are_not_silently_ignored():
    model = Model(
        AIMessage(
            "",
            invalid_tool_calls=[
                {"id": "bad", "name": "memory_recall", "args": "{", "error": "invalid JSON"},
            ],
        )
    )
    runtime = RecallRuntime(Meter(), model, model_settings(), reserve=100)
    with pytest.raises(ContextFailure, match="invalid_recall_tool_calls"):
        asyncio.run(runtime.run(Frame([], "", RECALL_PROMPT, 100)))


def test_pending_results_and_retained_text_are_counted_once():
    call = ToolCall("a", "remaining_context", {})
    placeholder = ToolResult("a", call.name, "error", STARVATION)
    frame = Frame(
        [U("source")],
        "question",
        RECALL_PROMPT,
        100,
        exchanges=[A("retained"), call],
        pending_results=[placeholder],
    )
    accepted = ToolResult("a", call.name, "success", {"answer": "ok"})
    candidate = frame.with_result(call, accepted)
    assert candidate.count(call) == 1
    assert candidate.count(accepted) == 1
    assert placeholder not in candidate
    assert candidate.count(A("retained")) == 1


@pytest.mark.parametrize(
    "setting",
    [
        {"reserve": 0},
        {"answer_cap": 0},
        {"answer_completion_cap": 0},
        {"starvation_percentage": 0},
        {"starvation_percentage": 100},
        {"top_level_reserve": 0},
        {"top_level_answer_cap": 0},
        {"top_level_completion_cap": 0},
        {"top_level_starvation_percentage": 100},
    ],
)
def test_invalid_runtime_budgets_fail_closed(setting):
    with pytest.raises(ValueError, match="invalid recall budgets"):
        RecallRuntime(Meter(), Model(), model_settings(), **setting)


def test_nested_batches_are_local_and_child_completion_cap_is_independent():
    inner = memory([U("original")])
    outer = memory([U("recent")], inner=inner)
    model = Model(
        batch(outer, ("outer",)),
        batch(inner, ("inner-a", "inner-b")),
        "first",
        "second",
        "combined",
        "final",
    )
    runtime = RecallRuntime(
        Meter(),
        model,
        model_settings(),
        reserve=100,
        answer_cap=500,
        answer_completion_cap=4096,
    )
    frame = Frame([outer], "", RECALL_PROMPT, 100, completion_cap=2048)
    assert asyncio.run(runtime.run(frame)) == "final"
    assert [m.id for m in frame.exchanges if isinstance(m, ToolCall)] == ["outer"]
    assert [m.tool_call_id for m in frame.exchanges if isinstance(m, ToolResult)] == ["outer"]
    assert [call[2] for call in model.calls] == [2048, 4096, 4096, 4096, 4096, 2048]


def test_top_level_worker_caps_are_separate_from_recursive_children_and_parent_capacity():
    inner = memory([U("original")])
    outer = memory([U("recent")], inner=inner)
    model = Model(batch(inner, ("inner",)), "child", "top answer")
    runtime = RecallRuntime(
        Meter(),
        model,
        model_settings(),
        reserve=100,
        answer_cap=5,
        answer_completion_cap=2048,
        top_level_reserve=500,
        top_level_answer_cap=100,
        top_level_completion_cap=4096,
        top_level_starvation_percentage=20,
    )
    call = ToolCall("top", "memory_recall", {"memory_id": str(outer.memory_id), "question": "q"})
    result = asyncio.run(runtime.recall_top_level([outer, U("x" * 20000)], call))
    assert result.status == "success" and result.content == {"answer": "top answer"}
    assert [c[2] for c in model.calls] == [4096, 2048, 4096]


@pytest.mark.parametrize("size,allowed", [(699, True), (700, False)])
def test_top_level_worker_uses_own_reserve_and_internal_threshold(size, allowed):
    m = memory([U("x" * size)])
    model = Model("answer")
    runtime = RecallRuntime(
        Meter(),
        model,
        model_settings(1000),
        reserve=100,
        starvation_percentage=10,
        top_level_reserve=150,
        top_level_starvation_percentage=15,
    )
    call = ToolCall("top", "memory_recall", {"memory_id": str(m.memory_id), "question": "q"})
    assert asyncio.run(runtime.recall_top_level([m], call)).status == "success"
    assert bool(model.calls[0][1]) is allowed


def test_top_level_visible_output_limit_is_not_a_parent_starvation_result():
    m = memory([U("evidence")])
    model = Model("too long", "still too long")
    runtime = RecallRuntime(
        Meter(),
        model,
        model_settings(),
        top_level_answer_cap=3,
        top_level_completion_cap=4096,
    )
    call = ToolCall("top", "memory_recall", {"memory_id": str(m.memory_id), "question": "q"})
    result = asyncio.run(runtime.recall_top_level([m], call))
    assert result.status == "error" and result.content == "recall_answer_limit_exceeded"
    assert [c[2] for c in model.calls] == [4096, 4096]
    assert "Final visible answer must not exceed 1 tokens" in str(model.calls[1][0])


def test_retained_response_text_and_calls_remain_in_one_provider_message():
    m = memory()
    response = batch(m, ("a", "b"))
    response.content = "consulting evidence"
    model = Model(response, "first", "second", "final")
    runtime = RecallRuntime(Meter(), model, model_settings(), reserve=100)
    frame = Frame([m], "", RECALL_PROMPT, 100)
    assert asyncio.run(runtime.run(frame)) == "final"
    provider_batches = [
        message
        for message in model.calls[-1][0]
        if isinstance(message, AIMessage) and message.tool_calls
    ]
    assert len(provider_batches) == 1
    assert provider_batches[0].content == response.content
    assert len(provider_batches[0].tool_calls) == 2
