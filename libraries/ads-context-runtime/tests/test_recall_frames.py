import asyncio

import pytest

from ads_commons.context_compactor import active_context, recall_source
from ads_commons.engine import AssistantHistoryTurn as A
from ads_commons.engine import ToolCall
from ads_commons.engine import UserHistoryTurn as U
from ads_context_runtime.frames import (
    RECALL_PROMPT,
    STARVATION,
    ContextFailure,
    Frame,
    RecallRuntime,
)
from context_fakes import Meter, Model, memory, model_settings, native


def test_active_and_recursive_sources_never_duplicate_remainders():
    inner = memory([U("old")], [U("old remainder")])
    outer = memory([U("new archive")], [U("current")], inner)
    assert active_context(outer) == [outer, U("current")]
    assert recall_source(outer) == [inner, U("new archive")]
    assert recall_source(inner) == [U("old")]
    frame = Frame([outer], "question", RECALL_PROMPT, 100)
    text = str(frame.provider_messages())
    assert "old remainder" not in text and "new archive" not in text
    assert "current" not in text and str(outer.memory_id) in text


@pytest.mark.parametrize("used,permitted", [(800, True), (801, False)])
def test_exact_ten_percent_threshold_disables_both_tools(used, permitted):
    m = memory(summary="x" * (used - 100))
    model = Model("answer")
    runtime = RecallRuntime(Meter(), model, model_settings(1000), reserve=100)
    frame = Frame([m], "", RECALL_PROMPT, 100)
    assert asyncio.run(runtime.run(frame)) == "answer"
    assert bool(model.calls[0][1]) is permitted
    assert frame.finalization_only is not permitted
    if permitted:
        assert {t["function"]["name"] for t in model.calls[0][1]} == {
            "remaining_context",
            "memory_recall",
        }


def test_retained_text_calls_results_and_metadata_are_charged():
    model = Model(native("remaining_context", text="retained"), "done")
    meter = Meter()
    runtime = RecallRuntime(meter, model, model_settings(), reserve=100)
    frame = Frame([U("source")], "question", RECALL_PROMPT, 100)
    assert asyncio.run(runtime.run(frame)) == "done"
    assert frame.exchanges[0] == A("retained")
    result = frame.exchanges[-1]
    report = asyncio.run(runtime.remaining(frame.charged))
    assert 0 <= report["remaining_tokens"] - result.content["remaining_tokens"] < 30
    assert result.content["remaining_percentage"] <= report["remaining_percentage"]
    assert "retained" in str(model.calls[1][0])
    assert all(t["function"]["name"] != "exec_shell" for _, ts, _ in model.calls for t in ts)


def test_nested_recall_only_unwraps_visible_memory():
    inner = memory([U("original")], [U("forbidden stale suffix")])
    outer = memory([U("recent archive")], [U("forbidden current suffix")], inner)
    model = Model(
        native("memory_recall", {"memory_id": str(inner.memory_id), "question": "old?"}),
        "original answer",
        "combined answer",
    )
    runtime = RecallRuntime(Meter(), model, model_settings(), reserve=100)
    result = asyncio.run(runtime.recall([outer], outer.memory_id, "question"))
    assert result.content["answer"] == "combined answer"
    assert len(model.calls) == 3
    assert "original" in str(model.calls[1][0])
    assert "forbidden" not in str(model.calls)
    assert "model-secret" not in str(model.calls)


def test_child_overflow_closes_call_and_finalizes_parent_without_retry():
    m = memory([U("x" * 5000)])
    model = Model("not called")
    runtime = RecallRuntime(Meter(), model, model_settings(2000), reserve=100)
    frame = Frame([m], "", RECALL_PROMPT, 100)
    call = ToolCall("call", "memory_recall", {"memory_id": str(m.memory_id), "question": "q"})
    result = asyncio.run(runtime.dispatch(frame, call))
    assert result.status == "error" and result.content == "frame_source_overflow"
    assert frame.finalization_only and frame.exchanges == [call, result]
    assert not model.calls


@pytest.mark.parametrize("second,accepted", [("small", True), ("x" * 4000, False)])
def test_oversized_answer_one_retry_never_enters_parent(second, accepted):
    m = memory([U("evidence")])
    model = Model("x" * 4000, second)
    runtime = RecallRuntime(Meter(), model, model_settings(2000), reserve=100)
    frame = Frame([m], "", RECALL_PROMPT, 100)
    call = ToolCall("call", "memory_recall", {"memory_id": str(m.memory_id), "question": "q"})
    result = asyncio.run(runtime.dispatch(frame, call))
    assert len(model.calls) == 2
    assert "Compact-result retry" in str(model.calls[1][0])
    assert model.calls[1][2] is model.calls[0][2] is None
    first_report = asyncio.run(runtime.remaining([m, U("")]))
    retry_cap = min(runtime.answer_cap, int(first_report["remaining_tokens"]) // 2) // 2
    assert f"Final visible answer must not exceed {retry_cap} tokens" in str(model.calls[1][0])
    assert "x" * 4000 not in str(frame.exchanges)
    assert result.status == ("success" if accepted else "error")
    assert frame.finalization_only is not accepted
    if not accepted:
        assert result.content == STARVATION
        with pytest.raises(ContextFailure, match="recall prohibited"):
            asyncio.run(runtime.dispatch(frame, ToolCall("again", "remaining_context", {})))


def test_parent_starvation_prevents_child_and_meter_errors_have_no_fallback():
    model = Model("not called")
    runtime = RecallRuntime(Meter(), model, model_settings(1000), reserve=100)
    frame = Frame([U("x" * 801)], "", RECALL_PROMPT, 100)
    with pytest.raises(ContextFailure, match="recall prohibited"):
        asyncio.run(runtime.dispatch(frame, ToolCall("c", "remaining_context", {})))
    assert not model.calls

    class Broken:
        async def meter(self, body):
            raise RuntimeError("private detail")

    runtime.meter = Broken()
    with pytest.raises(ContextFailure, match="meter_failed") as exc:
        asyncio.run(runtime.count([]))
    assert "private" not in str(exc.value)
