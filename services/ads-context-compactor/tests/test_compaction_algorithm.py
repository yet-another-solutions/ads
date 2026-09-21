import asyncio
import json
import logging
from uuid import uuid4

import pytest

from ads_commons.context_compactor import CompactRequest, active_context, recall_source
from ads_commons.engine import AssistantHistoryTurn as A
from ads_commons.engine import TaskTransition, ToolCall, ToolResult
from ads_commons.engine import UserHistoryTurn as U
from ads_commons.security import (
    AccessDenied,
    AuthenticationRequired,
    SecurityContext,
    SecurityContextHolder,
)
from ads_context_compactor.service import ContextCompactorService, parse_summary, safe_boundaries
from ads_context_runtime.frames import ContextFailure, ContextOverflow
from context_fakes import Meter, Model, memory, model_settings

SUMMARY = '<ads-compaction-result>{"summary":"concise"}</ads-compaction-result>'
IDENTITY = SecurityContext("test", "engine", frozenset(), authorized_party="ads-engine")


def compact(source, model, total=10000, target=50):
    with SecurityContextHolder.bound(IDENTITY):
        return asyncio.run(
            ContextCompactorService(Meter(), model=model, reserve=100, summary_cap=1000).compact(
                CompactRequest(source, model_settings(total), target)
            )
        )


@pytest.mark.parametrize(
    "text",
    [
        "summary",
        "<ads-compaction-result>{}</ads-compaction-result>",
        '<ads-compaction-result>{"summary":""}</ads-compaction-result>',
        '<ads-compaction-result>{"summary":"x","memory_id":"invented"}</ads-compaction-result>',
        '<ads-compaction-result>{"summary":"x","summary":"y"}</ads-compaction-result>',
        '<ads-compaction-result>{"summary":null}</ads-compaction-result>',
        SUMMARY + "trailing",
    ],
)
def test_strict_summary(text):
    with pytest.raises(ContextFailure):
        parse_summary(text)


@pytest.mark.parametrize("length,accepted", [(700, True), (701, False)])
def test_configured_reduction_floor_and_independent_completion_allowance(length, accepted):
    model = Model(
        '<ads-compaction-result>{"summary":"' + "x" * length + '"}</ads-compaction-result>'
    )
    service = ContextCompactorService(
        Meter(),
        model=model,
        reserve=100,
        summary_cap=1000,
        completion_cap=8192,
        minimum_reduction_percentage=20,
    )
    body = CompactRequest([U("a" * 1000), U("b" * 900)], model_settings(), 50)
    with SecurityContextHolder.bound(IDENTITY):
        if accepted:
            assert len(asyncio.run(service.compact(body)).summarization) == length
        else:
            with pytest.raises(ContextFailure, match="insufficient_compaction_progress"):
                asyncio.run(service.compact(body))
    assert model.calls[0][2] == 8192


def test_large_completion_allowance_does_not_relax_summary_size_limit():
    service = ContextCompactorService(
        Meter(),
        model=Model(SUMMARY),
        reserve=100,
        summary_cap=6,
        completion_cap=8192,
    )
    with (
        SecurityContextHolder.bound(IDENTITY),
        pytest.raises(ContextFailure, match="summary_output_limit"),
    ):
        asyncio.run(
            service.compact(CompactRequest([U("a" * 1000), U("b" * 900)], model_settings(), 50))
        )


def test_summary_and_compactor_recall_frames_have_independent_budgets(monkeypatch):
    from ads_context_runtime.frames import RecallRuntime
    from context_fakes import native

    archived = memory([U("evidence")])
    model = Model(
        native("memory_recall", {"memory_id": str(archived.memory_id), "question": "q"}),
        "answer",
        SUMMARY,
    )
    frames = []
    original = RecallRuntime.run

    async def record(self, frame):
        frames.append(
            (
                frame.reserve if frame.reserve is not None else self.reserve,
                frame.starvation_percentage
                if frame.starvation_percentage is not None
                else self.starvation_percentage,
                frame.cap,
                frame.completion_cap,
            )
        )
        return await original(self, frame)

    monkeypatch.setattr(RecallRuntime, "run", record)
    service = ContextCompactorService(
        Meter(),
        model=model,
        reserve=111,
        summary_cap=1234,
        completion_cap=2048,
        starvation_percentage=5,
        recall_reserve=777,
        recall_answer_cap=500,
        recall_completion_cap=4096,
        recall_starvation_percentage=30,
    )
    body = CompactRequest(
        [archived, U("a" * 3000), A("b" * 3000), U("current")],
        model_settings(),
        50,
    )
    with SecurityContextHolder.bound(IDENTITY):
        assert asyncio.run(service.compact(body)).summarization == "concise"
    assert frames == [(111, 5, 1234, 2048), (777, 30, 500, 4096)]


def test_first_and_repeated_compaction_preserve_originals_and_current_user_once():
    source = [U("a" * 2008), A("b" * 2000), U("c" * 2000), A("d" * 2000), U("current")]
    model = Model(SUMMARY, SUMMARY, SUMMARY)
    result = compact(source, model)
    assert result.messages == source[:2]
    assert result.remaining_messages == source[2:]
    assert active_context(result).count(U("current")) == 1
    second_source = [*active_context(result), A("e" * 2000), U("next")]
    second = compact(second_source, model)
    assert second.inner_tombstone == result
    assert recall_source(second) == [result, *source[2:4]]
    assert U("next") in second.remaining_messages
    assert result.remaining_messages == source[2:]


def test_summary_and_format_repair_receive_fresh_frame_budget_in_system_prompt():
    model = Model("invalid envelope", SUMMARY)
    source = [U("a" * 3000), A("b" * 3000), U("current")]
    result = compact(source, model)
    assert result.summarization == "concise" and len(model.calls) == 2
    prompts = [call[0][0].content for call in model.calls]
    assert all("total_context_tokens=10000" in prompt for prompt in prompts)
    assert all("remaining_context_tokens=" in prompt for prompt in prompts)
    assert all("Final visible answer must not exceed" in prompt for prompt in prompts)
    assert prompts[0] != prompts[1]
    assert "FORMAT REPAIR" in prompts[1] and model.calls[1][1] == []


def test_fixed_target_resets_after_each_success_no_whole_remainder_pass():
    source = []
    for char in "abcd":
        source.extend([U(char * (1008 if char == "a" else 1000)), A(char * 1000)])
    source.append(U("current"))
    model = Model(SUMMARY, SUMMARY, SUMMARY)
    result = compact(source, model, target=25)
    assert len(model.calls) == 2
    assert result.inner_tombstone is not None
    assert result.remaining_messages == source[6:]
    assert (
        asyncio.run(
            Meter().meter(type("Body", (), {"messages": active_context(result)})())
        ).estimated_tokens
        <= 2500
    )


def test_overflow_skips_duplicate_boundary_and_backs_off_to_smaller_prefix():
    source = [U("a" * 3000), A("b" * 3000), U("middle"), A("c" * 1000), U("current")]
    model = Model(ContextOverflow("provider_context_overflow"))
    with pytest.raises(ContextFailure, match="no_safe_fitting_prefix"):
        compact(source, model)
    assert len(model.calls) == 1  # 50/40/30/20/10 all resolve to the same next user.


def test_reduction_uses_selected_prefix_not_whole_input():
    source = [U("a" * 1000), U("b" * 1000), U("current")]
    model = Model('<ads-compaction-result>{"summary":"' + "x" * 1800 + '"}</ads-compaction-result>')
    with pytest.raises(ContextFailure, match="summary_output_limit"):
        compact(source, model)
    model = Model('<ads-compaction-result>{"summary":"' + "x" * 850 + '"}</ads-compaction-result>')
    with pytest.raises(ContextFailure, match="insufficient_compaction_progress"):
        compact([U("a" * 1000), U("b" * 900)], model)


def test_unreachable_remainder_fails_explicitly():
    with pytest.raises(ContextFailure, match="no_safe_fitting_prefix"):
        compact([U("old" * 1000), U("protected" * 1000)], Model(SUMMARY))


def test_one_format_repair_is_tool_free_and_second_invalid_fails():
    model = Model("bad", SUMMARY)
    result = compact([U("a" * 3000), A("b" * 3000), U("current")], model)
    assert result.summarization == "concise"
    assert len(model.calls) == 2 and model.calls[1][1] == []
    assert "bad" in str(model.calls[1][0])
    with pytest.raises(ContextFailure, match="invalid_summary_envelope"):
        compact([U("a" * 3000), U("current")], Model("bad", "bad again"))


def test_safe_boundaries_preserve_calls_and_async_lifetimes():
    source = [
        U("start"),
        ToolCall("a", "start_task", {}),
        ToolResult(
            "a", "start_task", "success", {}, task_transitions=[TaskTransition("task", "created")]
        ),
        U("unsafe"),
        ToolCall("b", "wait_task", {"task_id": "task"}),
        ToolResult(
            "b", "wait_task", "success", {}, task_transitions=[TaskTransition("task", "succeeded")]
        ),
        U("safe"),
    ]
    assert safe_boundaries(source) == [6]
    with pytest.raises(ContextFailure, match="incomplete_tool_lifecycle"):
        safe_boundaries([U("x"), ToolCall("unfinished", "exec_shell", {})])
    with pytest.raises(ContextFailure, match="orphan_tool_result"):
        safe_boundaries([ToolResult("orphan", "exec_shell", "success", "")])
    with pytest.raises(ContextFailure, match="memory_must_be_first"):
        safe_boundaries([U("x"), memory()])


@pytest.mark.parametrize(
    "failure", [None, "no_safe_fitting_prefix", "private-provider-message", "unexpected"]
)
def test_rendered_logs_correlate_requests_and_never_include_content(caplog, failure):
    caplog.set_level(logging.INFO, logger="ads_context_compactor.service")
    sid, mid, cid = uuid4(), uuid4(), uuid4()
    source = [U("private-source" * 200), U("private-current")]
    model = Model(SUMMARY)
    if failure == "no_safe_fitting_prefix":
        source = [memory(summary="private-memory"), U("private-current" * 600)]
    elif failure == "unexpected":
        model = Model(RuntimeError("private-provider-message"))
    elif failure:
        model = Model(ContextFailure(failure))
    body = CompactRequest(
        source,
        model_settings(),
        50,
        session_id=sid,
        message_id=mid,
        compaction_id=cid,
        boundary="continuation",
    )
    with SecurityContextHolder.bound(IDENTITY):
        if failure:
            with pytest.raises(ContextFailure):
                asyncio.run(
                    ContextCompactorService(Meter(), model=model, reserve=100).compact(body)
                )
        else:
            asyncio.run(ContextCompactorService(Meter(), model=model, reserve=100).compact(body))
    records = [r.getMessage() for r in caplog.records if r.name == "ads_context_compactor.service"]
    rendered = "\n".join(records)
    for secret in (
        "private-source",
        "private-current",
        "private-memory",
        "model-secret",
        "private-provider-message",
    ):
        assert secret not in rendered
    assert records[0].startswith("context_compaction_started ")
    event, raw = records[-1].split(" ", 1)
    fields = json.loads(raw)
    assert fields["session_id"] == str(sid) and fields["message_id"] == str(mid)
    assert fields["compaction_id"] == str(cid) and fields["boundary"] == "continuation"
    assert fields["target_tokens"] == 5000 and fields["total_context_tokens"] == 10000
    assert fields["duration_ms"] >= 0 and fields["source_tokens"] > 0
    if failure:
        assert event == "context_compaction_failed"
        assert fields["reason"] == (
            "no_safe_fitting_prefix" if failure == "no_safe_fitting_prefix" else "internal_error"
        )
    else:
        assert event == "context_compaction_succeeded"


def test_service_caller_guard():
    service = ContextCompactorService(Meter(), model=Model(SUMMARY))
    body = CompactRequest([], model_settings(), 50)
    with pytest.raises(AuthenticationRequired):
        asyncio.run(service.compact(body))
    with (
        SecurityContextHolder.bound(
            SecurityContext("test", "wrong", frozenset({"admin"}), authorized_party="ads")
        ),
        pytest.raises(AccessDenied),
    ):
        asyncio.run(service.compact(body))


@pytest.mark.parametrize("length,accepted", [(800, True), (801, False)])
def test_exact_ten_percent_reduction_floor(length, accepted):
    model = Model(
        '<ads-compaction-result>{"summary":"' + "x" * length + '"}</ads-compaction-result>'
    )
    if accepted:
        result = compact([U("a" * 1000), U("b" * 900)], model)
        assert len(result.summarization) == length
    else:
        with pytest.raises(ContextFailure, match="insufficient_compaction_progress"):
            compact([U("a" * 1000), U("b" * 900)], model)


def test_overflow_uses_smaller_distinct_boundary_then_resets():
    source = [U(str(i) * 1000) for i in range(9)] + [U("current")]
    model = Model(ContextOverflow("provider_context_overflow"), SUMMARY, SUMMARY)
    result = compact(source, model, target=30)
    assert len(model.calls) == 3
    first = str(model.calls[0][0])
    second = str(model.calls[1][0])
    assert "4" * 1000 in first and "4" * 1000 not in second
    assert result.inner_tombstone is not None
    assert result.remaining_messages[-1] == U("current")
