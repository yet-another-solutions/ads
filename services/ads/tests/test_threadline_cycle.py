from __future__ import annotations

import uuid

import msgspec
import pytest
from litestar import Litestar
from litestar.testing import TestClient
from sqlalchemy import Engine

from ads.config import Settings
from ads.models import STATUS_FINISHED, STATUS_FINISHING, STATUS_PENDING, STATUS_RUNNING
from ads_commons.engine import (
    Acknowledge,
    AssistantHistoryTurn,
    AssistantMessage,
    ErrorOutput,
    Finish,
    PartialResponse,
    Ping,
    Reasoning,
    ToolCall,
    ToolResult,
    UserHistoryTurn,
)
from tests.threadline_db import (
    buffer_of,
    chat_of,
    emit,
    emit_raw,
    entries_of,
    later,
    parts_of,
    run_of,
    runs_of,
    tick,
)
from tests.threadline_fakes import (
    ENGINE_TOKEN,
    STORED_BEARER,
    FakeOidcVerifier,
    FakePreferences,
    FakeTokens,
    RecordingKafka,
    headers,
    login,
)
from tests.threadline_flows import create_project, create_session, send


@pytest.fixture
def opened(
    client: TestClient, preferences: FakePreferences
) -> tuple[uuid.UUID, uuid.UUID, uuid.UUID]:
    model = preferences.seed()
    login(client)
    project = create_project(client)
    session_id = create_session(client, project)
    return project, session_id, model.id


def test_golden_cycle_then_next_send(
    client: TestClient,
    app: Litestar,
    db_engine: Engine,
    kafka: RecordingKafka,
    opened: tuple[uuid.UUID, uuid.UUID, uuid.UUID],
) -> None:
    project, session_id, model_id = opened
    first = send(client, project, session_id, "wrap this session", model_id)
    assert first.status_code in (200, 201)
    assert "wrap this session" in first.text
    assert 'data-inflight="true"' in first.text
    request = kafka.requests[0]
    assert request.session_id == session_id
    assert request.user_input == "wrap this session"
    assert request.history == []
    assert request.instructions == ""
    assert request.authorization.token == "ste-ads-engine"
    assert request.model.authentication.openai_bearer.token == STORED_BEARER
    assert request.model.options.model_name == "glm-5.3"
    assert request.model.url == "https://llm.example/v1"

    run = run_of(db_engine, session_id)
    assert run is not None and run.status == STATUS_PENDING and run.watermark == -1

    emit(app, Acknowledge(session_id=session_id, message_id=request.message_id), headers())
    assert run_of(db_engine, session_id).status == STATUS_RUNNING  # type: ignore[union-attr]

    emit(app, PartialResponse(session_id=session_id, order=0, reasoning=Reasoning(text="plan. ")))
    emit(
        app,
        PartialResponse(
            session_id=session_id, order=1, message=AssistantMessage(text="Threadline")
        ),
    )
    emit(app, Finish(session_id=session_id, last_order=1))

    assert run_of(db_engine, session_id) is None
    assert parts_of(db_engine, session_id) == [
        ("message", "user", "wrap this session"),
        ("reasoning", None, "plan. "),
        ("message", "assistant", "Threadline"),
    ]
    page = client.get(f"/projects/{project}/sessions/{session_id}")
    assert "Threadline" in page.text
    assert 'data-inflight="false"' in page.text

    second = send(client, project, session_id, "and now the engine", model_id)
    assert second.status_code in (200, 201)
    assert kafka.requests[1].history == [
        UserHistoryTurn(text="wrap this session"),
        AssistantHistoryTurn(text="Threadline"),
    ]
    assert kafka.requests[1].user_input == "and now the engine"


def test_consecutive_same_kind_appends_into_one_shell(
    client: TestClient,
    app: Litestar,
    db_engine: Engine,
    kafka: RecordingKafka,
    opened: tuple[uuid.UUID, uuid.UUID, uuid.UUID],
) -> None:
    project, session_id, model_id = opened
    send(client, project, session_id, "hi", model_id)
    for order, text in ((0, "one "), (1, "two "), (2, "three")):
        emit(
            app,
            PartialResponse(
                session_id=session_id,
                order=order,
                message=AssistantMessage(text=text),
            ),
        )
    emit(app, Finish(session_id=session_id, last_order=2))
    assert parts_of(db_engine, session_id) == [
        ("message", "user", "hi"),
        ("message", "assistant", "one two three"),
    ]


def test_tool_primitives_persist_render_and_return_in_history(
    client: TestClient,
    app: Litestar,
    db_engine: Engine,
    kafka: RecordingKafka,
    opened: tuple[uuid.UUID, uuid.UUID, uuid.UUID],
) -> None:
    project, session_id, model_id = opened
    send(client, project, session_id, "run tools", model_id)
    shell = ToolCall(
        id="call-1",
        name="exec_shell",
        arguments={"command": "printf hi"},
        metadata={"index": 0},
    )
    shell_out = ToolResult(
        tool_call_id="call-1",
        name="exec_shell",
        status="success",
        content={
            "content": [{"type": "text", "text": "hi"}],
            "structuredContent": {"stdout": "hi", "exit_code": 0},
        },
    )
    py = ToolCall(id="call-2", name="exec_python", arguments={"code": "print(1)"})
    py_out = ToolResult(
        tool_call_id="call-2",
        name="exec_python",
        status="success",
        content={"structuredContent": {"stdout": "1\n"}},
    )
    generic = ToolCall(
        id="call-3",
        name="search",
        arguments={"query": "ads"},
        metadata={"provider": "mcp"},
    )
    generic_out = ToolResult(
        tool_call_id="call-3",
        name="search",
        status="success",
        content={"hits": 2},
    )
    emit(app, PartialResponse(session_id=session_id, order=0, tool_call=shell))
    emit(app, PartialResponse(session_id=session_id, order=1, tool_result=shell_out))
    emit(app, PartialResponse(session_id=session_id, order=2, tool_call=py))
    emit(app, PartialResponse(session_id=session_id, order=3, tool_result=py_out))
    emit(app, PartialResponse(session_id=session_id, order=4, tool_call=generic))
    emit(app, PartialResponse(session_id=session_id, order=5, tool_result=generic_out))
    emit(
        app,
        PartialResponse(session_id=session_id, order=6, message=AssistantMessage(text="done")),
    )
    emit(app, Finish(session_id=session_id, last_order=6))

    stored = parts_of(db_engine, session_id)
    assert stored[0] == ("message", "user", "run tools")
    assert stored[1][0] == "tool_call"
    assert msgspec.json.decode(stored[1][2].encode(), type=ToolCall) == shell
    assert stored[2][0] == "tool_result"
    assert msgspec.json.decode(stored[2][2].encode(), type=ToolResult) == shell_out
    assert stored[-1] == ("message", "assistant", "done")

    page = client.get(f"/projects/{project}/sessions/{session_id}")
    assert 'class="tool-block tool-call terminal"' in page.text
    assert "printf hi" in page.text
    assert 'data-tool="exec_shell"' in page.text
    assert ">output</div>" in page.text
    assert 'class="tool-block tool-call python"' in page.text
    assert "print(1)" in page.text
    assert 'class="tool-block tool-call generic"' in page.text
    assert 'data-tool="search"' in page.text
    assert "tool search" in page.text
    assert "result search" in page.text

    second = send(client, project, session_id, "again", model_id)
    assert second.status_code in (200, 201)
    assert kafka.requests[1].history == [
        UserHistoryTurn(text="run tools"),
        shell,
        shell_out,
        py,
        py_out,
        generic,
        generic_out,
        AssistantHistoryTurn(text="done"),
    ]


def test_consecutive_tool_calls_are_not_concatenated(
    client: TestClient,
    app: Litestar,
    db_engine: Engine,
    opened: tuple[uuid.UUID, uuid.UUID, uuid.UUID],
) -> None:
    project, session_id, model_id = opened
    send(client, project, session_id, "hi", model_id)
    first = ToolCall(id="a", name="exec_shell", arguments={"command": "one"})
    second = ToolCall(id="b", name="exec_shell", arguments={"command": "two"})
    emit(app, PartialResponse(session_id=session_id, order=0, tool_call=first))
    emit(app, PartialResponse(session_id=session_id, order=1, tool_call=second))
    emit(app, Finish(session_id=session_id, last_order=1))
    rows = [part for part in parts_of(db_engine, session_id) if part[0] == "tool_call"]
    assert len(rows) == 2
    assert msgspec.json.decode(rows[0][2].encode(), type=ToolCall) == first
    assert msgspec.json.decode(rows[1][2].encode(), type=ToolCall) == second


def test_silver_out_of_order_then_continuous_flush(
    client: TestClient,
    app: Litestar,
    db_engine: Engine,
    opened: tuple[uuid.UUID, uuid.UUID, uuid.UUID],
) -> None:
    project, session_id, model_id = opened
    send(client, project, session_id, "hi", model_id)
    emit(app, PartialResponse(session_id=session_id, order=2, message=AssistantMessage(text="c")))
    run = run_of(db_engine, session_id)
    assert run is not None and run.watermark == -1
    assert parts_of(db_engine, session_id) == [("message", "user", "hi")]
    emit(app, PartialResponse(session_id=session_id, order=0, message=AssistantMessage(text="a")))
    assert run_of(db_engine, session_id).watermark == 0  # type: ignore[union-attr]
    emit(app, PartialResponse(session_id=session_id, order=1, message=AssistantMessage(text="b")))
    assert run_of(db_engine, session_id).watermark == 2  # type: ignore[union-attr]
    assert parts_of(db_engine, session_id) == [
        ("message", "user", "hi"),
        ("message", "assistant", "abc"),
    ]


def test_duplicate_partial_is_first_write_wins(
    client: TestClient,
    app: Litestar,
    db_engine: Engine,
    opened: tuple[uuid.UUID, uuid.UUID, uuid.UUID],
) -> None:
    project, session_id, model_id = opened
    send(client, project, session_id, "hi", model_id)
    emit(app, PartialResponse(session_id=session_id, order=0, message=AssistantMessage(text="a")))
    emit(app, PartialResponse(session_id=session_id, order=0, message=AssistantMessage(text="z")))
    assert parts_of(db_engine, session_id) == [
        ("message", "user", "hi"),
        ("message", "assistant", "a"),
    ]


def test_lost_part_waits_then_finishes_when_the_hole_fills(
    client: TestClient,
    app: Litestar,
    db_engine: Engine,
    settings: Settings,
    opened: tuple[uuid.UUID, uuid.UUID, uuid.UUID],
) -> None:
    project, session_id, model_id = opened
    send(client, project, session_id, "hi", model_id)
    emit(app, PartialResponse(session_id=session_id, order=0, message=AssistantMessage(text="a")))
    emit(app, PartialResponse(session_id=session_id, order=2, message=AssistantMessage(text="c")))
    emit(app, Finish(session_id=session_id, last_order=2))
    run = run_of(db_engine, session_id)
    assert run is not None and run.status == STATUS_FINISHING and run.finish_at is not None
    first_finish_at = run.finish_at
    emit(app, Finish(session_id=session_id, last_order=2))
    assert run_of(db_engine, session_id).finish_at == first_finish_at  # type: ignore[union-attr]
    emit(app, Ping(session_id=session_id))
    tick(app, db_engine, settings, later(5))
    assert run_of(db_engine, session_id).status == STATUS_FINISHING  # type: ignore[union-attr]
    emit(app, PartialResponse(session_id=session_id, order=1, message=AssistantMessage(text="b")))
    finished = run_of(db_engine, session_id)
    assert finished is None or finished.status == STATUS_FINISHED
    assert parts_of(db_engine, session_id) == [
        ("message", "user", "hi"),
        ("message", "assistant", "abc"),
    ]


def test_gapped_finish_that_never_fills_is_broken_after_ten_seconds(
    client: TestClient,
    app: Litestar,
    db_engine: Engine,
    settings: Settings,
    kafka: RecordingKafka,
    opened: tuple[uuid.UUID, uuid.UUID, uuid.UUID],
) -> None:
    project, session_id, model_id = opened
    send(client, project, session_id, "hi", model_id)
    emit(app, PartialResponse(session_id=session_id, order=0, message=AssistantMessage(text="a")))
    emit(app, PartialResponse(session_id=session_id, order=2, message=AssistantMessage(text="c")))
    emit(app, Finish(session_id=session_id, last_order=2))
    tick(app, db_engine, settings, later(10))
    assert runs_of(db_engine, session_id) == []
    assert parts_of(db_engine, session_id) == []
    assert chat_of(db_engine, session_id).latest_entry_id is None
    assert kafka.aborts == []
    page = client.get(f"/projects/{project}/sessions/{session_id}")
    assert 'data-inflight="false"' in page.text


def test_finish_below_the_watermark_breaks_immediately(
    client: TestClient,
    app: Litestar,
    db_engine: Engine,
    kafka: RecordingKafka,
    opened: tuple[uuid.UUID, uuid.UUID, uuid.UUID],
) -> None:
    project, session_id, model_id = opened
    send(client, project, session_id, "hi", model_id)
    emit(app, PartialResponse(session_id=session_id, order=0, message=AssistantMessage(text="a")))
    emit(app, PartialResponse(session_id=session_id, order=1, message=AssistantMessage(text="b")))
    emit(app, Finish(session_id=session_id, last_order=0))
    assert runs_of(db_engine, session_id) == []
    assert parts_of(db_engine, session_id) == []
    assert kafka.aborts == []


def test_finish_without_last_order_breaks_immediately(
    client: TestClient,
    app: Litestar,
    db_engine: Engine,
    kafka: RecordingKafka,
    opened: tuple[uuid.UUID, uuid.UUID, uuid.UUID],
) -> None:
    project, session_id, model_id = opened
    send(client, project, session_id, "hi", model_id)
    emit(app, PartialResponse(session_id=session_id, order=0, message=AssistantMessage(text="a")))
    emit_raw(app, b'{"type": "finish", "session_id": "' + str(session_id).encode() + b'"}')
    assert runs_of(db_engine, session_id) == []
    assert kafka.aborts == []


def test_handshake_exchanges_the_acknowledge_header(
    client: TestClient,
    app: Litestar,
    db_engine: Engine,
    kafka: RecordingKafka,
    tokens: FakeTokens,
    opened: tuple[uuid.UUID, uuid.UUID, uuid.UUID],
) -> None:
    project, session_id, model_id = opened
    send(client, project, session_id, "hi", model_id)
    message_id = kafka.requests[0].message_id
    emit(app, Acknowledge(session_id=session_id, message_id=message_id), headers())
    assert len(kafka.ack_responses) == 1
    ack, token = kafka.ack_responses[0]
    assert ack.session_id == session_id
    assert ack.message_id == message_id
    assert token == "ste-ads-engine"
    assert ("ads-engine", ENGINE_TOKEN) in tokens.calls
    assert run_of(db_engine, session_id).status == STATUS_RUNNING  # type: ignore[union-attr]
    emit(app, PartialResponse(session_id=session_id, order=0, message=AssistantMessage(text="a")))
    assert parts_of(db_engine, session_id)[-1] == ("message", "assistant", "a")


def test_acknowledge_without_a_valid_header_stays_pending(
    client: TestClient,
    app: Litestar,
    db_engine: Engine,
    kafka: RecordingKafka,
    opened: tuple[uuid.UUID, uuid.UUID, uuid.UUID],
) -> None:
    project, session_id, model_id = opened
    send(client, project, session_id, "hi", model_id)
    message_id = kafka.requests[0].message_id
    emit(app, Acknowledge(session_id=session_id, message_id=message_id), None)
    emit(app, Acknowledge(session_id=session_id, message_id=message_id), headers("garbage"))
    assert kafka.ack_responses == []
    assert run_of(db_engine, session_id).status == STATUS_PENDING  # type: ignore[union-attr]


def test_acknowledge_with_a_mismatched_message_id_is_ignored(
    client: TestClient,
    app: Litestar,
    db_engine: Engine,
    kafka: RecordingKafka,
    opened: tuple[uuid.UUID, uuid.UUID, uuid.UUID],
) -> None:
    project, session_id, model_id = opened
    send(client, project, session_id, "hi", model_id)
    emit(app, Acknowledge(session_id=session_id, message_id=uuid.uuid4()), headers())
    assert kafka.ack_responses == []
    assert run_of(db_engine, session_id).status == STATUS_PENDING  # type: ignore[union-attr]


def test_engine_error_deletes_the_message_and_unlocks_without_abort(
    client: TestClient,
    app: Litestar,
    db_engine: Engine,
    kafka: RecordingKafka,
    opened: tuple[uuid.UUID, uuid.UUID, uuid.UUID],
) -> None:
    project, session_id, model_id = opened
    send(client, project, session_id, "first", model_id)
    emit(app, PartialResponse(session_id=session_id, order=0, message=AssistantMessage(text="a")))
    emit(app, Finish(session_id=session_id, last_order=0))
    send(client, project, session_id, "second", model_id)
    failing = kafka.requests[1].message_id
    emit(app, PartialResponse(session_id=session_id, order=0, message=AssistantMessage(text="x")))
    emit(app, ErrorOutput(session_id=session_id, message_id=failing, text="model exploded"))
    assert run_of(db_engine, session_id) is None
    assert parts_of(db_engine, session_id) == [
        ("message", "user", "first"),
        ("message", "assistant", "a"),
    ]
    chat = chat_of(db_engine, session_id)
    entries = entries_of(db_engine, session_id)
    assert chat.latest_entry_id == entries[-1].id
    assert entries[-1].next_id is None
    assert kafka.aborts == []


def test_engine_error_for_another_message_id_leaves_the_run_alone(
    client: TestClient,
    app: Litestar,
    db_engine: Engine,
    kafka: RecordingKafka,
    opened: tuple[uuid.UUID, uuid.UUID, uuid.UUID],
) -> None:
    project, session_id, model_id = opened
    send(client, project, session_id, "hi", model_id)
    emit(app, ErrorOutput(session_id=session_id, message_id=uuid.uuid4(), text="duplicate"))
    run = run_of(db_engine, session_id)
    assert run is not None and run.status == STATUS_PENDING
    emit(app, PartialResponse(session_id=session_id, order=0, message=AssistantMessage(text="a")))
    emit(app, Finish(session_id=session_id, last_order=0))
    assert parts_of(db_engine, session_id)[-1] == ("message", "assistant", "a")


def test_ping_silence_aborts_then_breaks(
    client: TestClient,
    app: Litestar,
    db_engine: Engine,
    settings: Settings,
    kafka: RecordingKafka,
    tokens: FakeTokens,
    opened: tuple[uuid.UUID, uuid.UUID, uuid.UUID],
) -> None:
    project, session_id, model_id = opened
    send(client, project, session_id, "hi", model_id)
    message_id = kafka.requests[0].message_id
    tick(app, db_engine, settings, later(29))
    assert run_of(db_engine, session_id) is not None
    tick(app, db_engine, settings, later(30))
    assert len(kafka.aborts) == 1
    abort, token = kafka.aborts[0]
    assert abort.session_id == session_id
    assert abort.message_id == message_id
    assert token == "ste-ads-engine"
    assert ("ads-engine", "user-access-token") in tokens.calls
    assert runs_of(db_engine, session_id) == []
    assert parts_of(db_engine, session_id) == []


def test_ping_keeps_the_run_alive(
    client: TestClient,
    app: Litestar,
    db_engine: Engine,
    settings: Settings,
    opened: tuple[uuid.UUID, uuid.UUID, uuid.UUID],
) -> None:
    project, session_id, model_id = opened
    send(client, project, session_id, "hi", model_id)
    emit(app, Ping(session_id=session_id))
    tick(app, db_engine, settings, later(25))
    assert run_of(db_engine, session_id) is not None


def test_produce_failure_leaves_the_run_pending_until_the_timeout(
    settings: Settings,
    db_engine: Engine,
    preferences: FakePreferences,
    tokens: FakeTokens,
    authenticator: object,
) -> None:
    from ads.app import build_session_config, create_app

    broken = RecordingKafka(fail_request=True)
    app = create_app(
        settings,
        engine=db_engine,
        preferences=preferences,
        kafka=broken,
        tokens=tokens,
        jwt_verifier=authenticator,  # type: ignore[arg-type]
        oidc_verifier=FakeOidcVerifier(),
    )
    model = preferences.seed()
    with TestClient(app=app, session_config=build_session_config(settings)) as client:
        login(client)
        project = create_project(client)
        session_id = create_session(client, project)
        failed = send(client, project, session_id, "hi", model.id)
        assert failed.status_code == 502
        run = run_of(db_engine, session_id)
        assert run is not None and run.status == STATUS_PENDING
        assert broken.requests == []
        tick(app, db_engine, settings, later(30))
        assert runs_of(db_engine, session_id) == []
        assert parts_of(db_engine, session_id) == []


def test_second_send_while_in_flight_is_409(
    client: TestClient,
    db_engine: Engine,
    kafka: RecordingKafka,
    opened: tuple[uuid.UUID, uuid.UUID, uuid.UUID],
) -> None:
    project, session_id, model_id = opened
    send(client, project, session_id, "first", model_id)
    conflict = send(client, project, session_id, "second", model_id)
    assert conflict.status_code == 409
    assert len(kafka.requests) == 1
    run = run_of(db_engine, session_id)
    assert run is not None and run.message_id == kafka.requests[0].message_id
    assert parts_of(db_engine, session_id) == [("message", "user", "first")]


def test_missing_model_id_is_a_composer_warning(
    client: TestClient,
    db_engine: Engine,
    kafka: RecordingKafka,
    opened: tuple[uuid.UUID, uuid.UUID, uuid.UUID],
) -> None:
    project, session_id, _ = opened
    response = send(client, project, session_id, "hi", None)
    assert response.status_code == 400
    assert 'id="composer-warn"' in response.text
    assert kafka.requests == []
    assert parts_of(db_engine, session_id) == []


def test_unknown_model_id_is_a_composer_warning(
    client: TestClient,
    db_engine: Engine,
    kafka: RecordingKafka,
    opened: tuple[uuid.UUID, uuid.UUID, uuid.UUID],
) -> None:
    project, session_id, _ = opened
    response = send(client, project, session_id, "hi", uuid.uuid4())
    assert response.status_code == 400
    assert "No such model" in response.text
    assert kafka.requests == []
    assert parts_of(db_engine, session_id) == []


def test_empty_user_input_is_a_composer_warning(
    client: TestClient,
    db_engine: Engine,
    kafka: RecordingKafka,
    opened: tuple[uuid.UUID, uuid.UUID, uuid.UUID],
) -> None:
    project, session_id, model_id = opened
    response = send(client, project, session_id, "   ", model_id)
    assert response.status_code == 400
    assert 'class="composer-warn"' in response.text
    assert kafka.requests == []
    assert parts_of(db_engine, session_id) == []


def test_other_users_send_is_403(
    client: TestClient,
    db_engine: Engine,
    kafka: RecordingKafka,
    opened: tuple[uuid.UUID, uuid.UUID, uuid.UUID],
) -> None:
    project, session_id, model_id = opened
    login(client, sub=uuid.UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd"))
    response = send(client, project, session_id, "hi", model_id)
    assert response.status_code == 403
    assert kafka.requests == []
    assert parts_of(db_engine, session_id) == []


def test_reconnect_shows_entries_plus_buffer_above_the_watermark(
    client: TestClient,
    app: Litestar,
    db_engine: Engine,
    opened: tuple[uuid.UUID, uuid.UUID, uuid.UUID],
) -> None:
    project, session_id, model_id = opened
    send(client, project, session_id, "hi", model_id)
    emit(
        app,
        PartialResponse(
            session_id=session_id, order=0, message=AssistantMessage(text="committed ")
        ),
    )
    emit(
        app,
        PartialResponse(session_id=session_id, order=2, message=AssistantMessage(text="buffered")),
    )
    run = run_of(db_engine, session_id)
    assert run is not None and run.watermark == 0
    assert [row.order_no for row in buffer_of(db_engine, run.id)] == [0, 2]
    page = client.get(f"/projects/{project}/sessions/{session_id}")
    assert "committed " in page.text
    assert "buffered" in page.text
    assert page.text.count("buffered") == 1


def test_orders_above_last_order_are_ignored(
    client: TestClient,
    app: Litestar,
    db_engine: Engine,
    opened: tuple[uuid.UUID, uuid.UUID, uuid.UUID],
) -> None:
    project, session_id, model_id = opened
    send(client, project, session_id, "hi", model_id)
    emit(app, PartialResponse(session_id=session_id, order=0, message=AssistantMessage(text="a")))
    emit(app, PartialResponse(session_id=session_id, order=2, message=AssistantMessage(text="c")))
    emit(app, Finish(session_id=session_id, last_order=2))
    emit(app, PartialResponse(session_id=session_id, order=3, message=AssistantMessage(text="d")))
    run = run_of(db_engine, session_id)
    assert run is not None and run.status == STATUS_FINISHING
    assert [row.order_no for row in buffer_of(db_engine, run.id)] == [0, 2]
    emit(app, PartialResponse(session_id=session_id, order=1, message=AssistantMessage(text="b")))
    assert parts_of(db_engine, session_id) == [
        ("message", "user", "hi"),
        ("message", "assistant", "abc"),
    ]


def test_abort_produce_failure_still_unwinds_locally(
    settings: Settings,
    db_engine: Engine,
    preferences: FakePreferences,
    authenticator: object,
) -> None:
    from ads.app import build_session_config, create_app

    class _BrokenAbort(RecordingKafka):
        async def produce_abort(self, message: object, token: str) -> None:  # type: ignore[override]
            raise RuntimeError("kafka is down")

    kafka = _BrokenAbort()
    app = create_app(
        settings,
        engine=db_engine,
        preferences=preferences,
        kafka=kafka,
        tokens=FakeTokens(),
        jwt_verifier=authenticator,  # type: ignore[arg-type]
        oidc_verifier=FakeOidcVerifier(),
    )
    model = preferences.seed()
    with TestClient(app=app, session_config=build_session_config(settings)) as client:
        login(client)
        project = create_project(client)
        session_id = create_session(client, project)
        send(client, project, session_id, "hi", model.id)
        tick(app, db_engine, settings, later(30))
        assert kafka.aborts == []
        assert runs_of(db_engine, session_id) == []
        assert parts_of(db_engine, session_id) == []


def test_token_exchange_failure_on_abort_still_unwinds(
    settings: Settings,
    db_engine: Engine,
    preferences: FakePreferences,
    kafka: RecordingKafka,
    authenticator: object,
) -> None:
    from ads.app import build_session_config, create_app
    from ads_commons.security import TokenExchangeError

    class _OnlySendWorks(FakeTokens):
        def exchange(self, audience: str, subject_token: str | None = None) -> str:
            self.calls.append((audience, subject_token))
            if len(self.calls) > 1:
                raise TokenExchangeError("keycloak is down")
            return f"ste-{audience}"

    app = create_app(
        settings,
        engine=db_engine,
        preferences=preferences,
        kafka=kafka,
        tokens=_OnlySendWorks(),
        jwt_verifier=authenticator,  # type: ignore[arg-type]
        oidc_verifier=FakeOidcVerifier(),
    )
    model = preferences.seed()
    with TestClient(app=app, session_config=build_session_config(settings)) as client:
        login(client)
        project = create_project(client)
        session_id = create_session(client, project)
        send(client, project, session_id, "hi", model.id)
        tick(app, db_engine, settings, later(30))
        assert kafka.aborts == []
        assert runs_of(db_engine, session_id) == []
        assert parts_of(db_engine, session_id) == []
