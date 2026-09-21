import uuid

import msgspec
import pytest

from ads_commons.engine import (
    AssistantHistoryTurn,
    AssistantMessage,
    CompactionStatus,
    ContextPressure,
    ErrorOutput,
    Finish,
    PartialResponse,
    ToolCall,
    ToolResult,
    UserHistoryTurn,
)
from context_fakes import memory
from tests.threadline_db import chat_of, emit, emit_raw, entries_of, parts_of, run_of
from tests.threadline_fakes import login
from tests.threadline_flows import create_project, create_session, send


@pytest.fixture
def context_session(client, preferences):
    model = preferences.seed()
    login(client)
    project = create_project(client)
    return project, create_session(client, project), model.id


def test_uncorrelated_kafka_parts_and_stale_malformed_finish_are_ignored(
    client, app, db_engine, kafka, context_session
):
    project, sid, mid = context_session
    send(client, project, sid, "current", mid)
    req = kafka.requests[-1]
    payloads = [
        PartialResponse(sid, 0, message=AssistantMessage("uncorrelated")),
        Finish(sid, 0),
        {"type": "finish", "session_id": sid},
        {"type": "finish", "session_id": sid, "message_id": uuid.uuid4()},
    ]
    for payload in payloads:
        emit_raw(app, msgspec.json.encode(payload))
        assert run_of(db_engine, sid).message_id == req.message_id
        assert len(entries_of(db_engine, sid)) == 1
    emit_raw(
        app,
        msgspec.json.encode(
            PartialResponse(sid, 0, message=AssistantMessage("valid"), message_id=req.message_id)
        ),
    )
    emit_raw(app, msgspec.json.encode(Finish(sid, 0, req.message_id)))
    assert run_of(db_engine, sid) is None
    assert entries_of(db_engine, sid)[-1].text == "valid"


def test_latest_candidate_commits_only_after_complete_finish_and_reconstructs_once(
    client, app, db_engine, kafka, context_session
):
    project, sid, mid = context_session
    send(client, project, sid, "current", mid)
    req = kafka.requests[-1]
    first = memory([UserHistoryTurn("old")], [UserHistoryTurn("current")])
    latest = memory([UserHistoryTurn("current")], [AssistantHistoryTurn("retained")], first)

    def part(order, **primitive):
        emit(
            app,
            PartialResponse(
                session_id=sid,
                message_id=req.message_id,
                order=order,
                pressure=ContextPressure(10000, 2000 if order > 0 else 8500),
                **primitive,
            ),
        )

    part(0, compaction=CompactionStatus("compacting_context"))
    part(1, compaction=CompactionStatus("compacted_context"))
    part(2, tombstone=first)
    assert chat_of(db_engine, sid).committed_tombstone_id is None
    assert run_of(db_engine, sid).candidate_tombstone_id == entries_of(db_engine, sid)[-1].id
    part(4, message=AssistantMessage("after"))
    emit(app, Finish(sid, 4, req.message_id))
    assert run_of(db_engine, sid) is not None
    assert chat_of(db_engine, sid).committed_tombstone_id is None
    page = client.get(f"/projects/{project}/sessions/{sid}").text
    assert "Context 20.0%" in page and 'id="context-pressure"' in page
    assert "Compacting context" in page and "Context compacted" in page
    assert str(first.memory_id) not in page  # hidden even across a stream gap
    part(3, tombstone=latest)
    rows = entries_of(db_engine, sid)
    assert [r.kind for r in rows] == [
        "message",
        "compacting_context",
        "compacted_context",
        "tombstone",
        "tombstone",
        "message",
    ]
    assert chat_of(db_engine, sid).committed_tombstone_id == rows[-2].id
    assert run_of(db_engine, sid) is None
    page = client.get(f"/projects/{project}/sessions/{sid}").text
    assert 'id="context-pressure"' not in page and str(latest.memory_id) not in page
    send(client, project, sid, "next", mid)
    assert kafka.requests[-1].history == [
        latest,
        AssistantHistoryTurn("retained"),
        AssistantHistoryTurn("after"),
    ]
    assert kafka.requests[-1].user_input == "next"


@pytest.mark.parametrize("failure_after", [0, 1, 2])
def test_failure_rewinds_candidates_and_late_parts_cannot_revive_new_run(
    client, app, db_engine, kafka, context_session, failure_after
):
    project, sid, mid = context_session
    send(client, project, sid, "base", mid)
    req = kafka.requests[-1]
    base = memory([UserHistoryTurn("older")], [UserHistoryTurn("base")])
    emit(app, PartialResponse(sid, 0, tombstone=base, message_id=req.message_id))
    emit(app, Finish(sid, 0, req.message_id))
    committed = chat_of(db_engine, sid).committed_tombstone_id
    before = parts_of(db_engine, sid)
    send(client, project, sid, "failed-turn", mid)
    failed = kafka.requests[-1]
    candidate = memory([UserHistoryTurn("base")], [UserHistoryTurn("failed-turn")], base)
    payloads = [
        {"compaction": CompactionStatus("compacting_context")},
        {"compaction": CompactionStatus("compacted_context")},
        {"tombstone": candidate},
    ]
    for order in range(failure_after + 1):
        emit(
            app,
            PartialResponse(
                sid,
                order,
                message_id=failed.message_id,
                pressure=ContextPressure(10000, 3000),
                **payloads[order],
            ),
        )
    emit(app, ErrorOutput(sid, failed.message_id, "compaction failed"))
    assert parts_of(db_engine, sid) == before
    assert chat_of(db_engine, sid).committed_tombstone_id == committed
    page = client.get(f"/projects/{project}/sessions/{sid}").text
    assert "failed-turn" not in page and 'id="context-pressure"' not in page
    send(client, project, sid, "retry", mid)
    current = run_of(db_engine, sid)
    emit(app, PartialResponse(sid, 0, tombstone=candidate, message_id=failed.message_id))
    emit(app, Finish(sid, 0, failed.message_id))
    emit(app, ErrorOutput(sid, failed.message_id, "late"))
    assert run_of(db_engine, sid).id == current.id
    assert run_of(db_engine, sid).watermark == -1
    assert chat_of(db_engine, sid).committed_tombstone_id == committed
    assert all(str(candidate.memory_id) not in row.text for row in entries_of(db_engine, sid))
    assert kafka.requests[-1].history == [base, UserHistoryTurn("base")]


def test_failed_recall_tool_result_and_normal_finish_preserve_work_and_history(
    client, app, db_engine, kafka, context_session
):
    project, sid, model_id = context_session
    send(client, project, sid, "remember", model_id)
    req = kafka.requests[-1]
    call = ToolCall("recall-1", "memory_recall", {"memory_id": str(uuid.uuid4()), "question": "q"})
    result = ToolResult(call.id, call.name, "error", "frame_completion_truncated")
    for order, payload in enumerate(
        [
            {"message": AssistantMessage("Completed earlier work.")},
            {"tool_call": call},
            {"tool_result": result},
            {"message": AssistantMessage("Recall failed. Final answer uses existing evidence.")},
        ]
    ):
        emit(app, PartialResponse(sid, order, message_id=req.message_id, **payload))
    emit(app, Finish(sid, 3, req.message_id))
    assert run_of(db_engine, sid) is None
    rows = entries_of(db_engine, sid)
    assert rows[0].text == "remember"
    assert any(row.text == "Completed earlier work." for row in rows)
    assert rows[-1].text == "Recall failed. Final answer uses existing evidence."
    send(client, project, sid, "continue", model_id)
    history = kafka.requests[-1].history
    assert call in history and result in history
    assert AssistantHistoryTurn("Completed earlier work.") in history


def test_pressure_follows_contiguous_part_order_not_arrival(
    client, app, db_engine, kafka, context_session
):
    project, sid, mid = context_session
    send(client, project, sid, "current", mid)
    message = kafka.requests[-1].message_id
    emit(
        app,
        PartialResponse(
            sid,
            1,
            message=AssistantMessage("b"),
            pressure=ContextPressure(1000, 600),
            message_id=message,
        ),
    )
    assert run_of(db_engine, sid).used_context is None
    emit(
        app,
        PartialResponse(
            sid,
            0,
            message=AssistantMessage("a"),
            pressure=ContextPressure(1000, 500),
            message_id=message,
        ),
    )
    assert run_of(db_engine, sid).used_context == 600
    emit(
        app,
        PartialResponse(
            sid,
            2,
            message=AssistantMessage("stale"),
            pressure=ContextPressure(1000, 900),
            message_id=uuid.uuid4(),
        ),
    )
    assert run_of(db_engine, sid).used_context == 600


def test_complete_only_finish_preserves_turn_and_last_successful_candidate(
    client, app, db_engine, kafka, context_session
):
    project, sid, mid = context_session
    send(client, project, sid, "current", mid)
    req = kafka.requests[-1]
    candidate = memory([UserHistoryTurn("old")], [UserHistoryTurn("current")])
    payloads = [
        {"compaction": CompactionStatus("compacting_context")},
        {"compaction": CompactionStatus("compacted_context")},
        {"tombstone": candidate},
        {"message": AssistantMessage("work before fallback")},
        {"compaction": CompactionStatus("compacting_context")},
        {"message": AssistantMessage("complete-only final answer")},
    ]
    for order, payload in enumerate(payloads):
        emit(app, PartialResponse(sid, order, message_id=req.message_id, **payload))
    emit(app, Finish(sid, len(payloads) - 1, req.message_id))
    rows = entries_of(db_engine, sid)
    assert run_of(db_engine, sid) is None
    assert rows[0].text == "current" and rows[-1].text == "complete-only final answer"
    assert chat_of(db_engine, sid).committed_tombstone_id == next(
        row.id for row in rows if row.kind == "tombstone"
    )
    send(client, project, sid, "next", mid)
    assert kafka.requests[-1].history == [
        candidate,
        UserHistoryTurn("current"),
        AssistantHistoryTurn("work before fallback"),
        AssistantHistoryTurn("complete-only final answer"),
    ]
