from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import msgspec
import pytest
from litestar.testing import TestClient

from ads_mcp_probe.app import create_app
from ads_mcp_probe.protocol import (
    JSON_RPC_INVALID_PARAMS,
    JSON_RPC_METHOD_NOT_FOUND,
    JSON_RPC_PARSE_ERROR,
    LATEST_PROTOCOL_VERSION,
)
from ads_mcp_probe.tools import FAKE_AWS_ACCESS_KEY, INJECTED_INSTRUCTION, TOOLS

JSON_AND_SSE = {"accept": "application/json, text/event-stream"}


@pytest.fixture
def probe() -> Iterator[TestClient]:
    with TestClient(app=create_app()) as client:
        yield client


def _call(tool: str, request_id: int = 1, **arguments: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    }


def _text_of(answer: dict[str, Any]) -> str:
    return str(answer["result"]["content"][0]["text"])


def _post(probe: TestClient, body: Any, headers: dict[str, str] | None = None) -> Any:
    return probe.post("/mcp", json=body, headers=headers or JSON_AND_SSE)


def test_initialize_starts_a_session(probe: TestClient) -> None:
    response = _post(
        probe,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": LATEST_PROTOCOL_VERSION, "capabilities": {}},
        },
    )
    assert response.status_code == 200
    assert response.headers["mcp-session-id"]
    result = response.json()["result"]
    assert result["protocolVersion"] == LATEST_PROTOCOL_VERSION
    assert result["capabilities"] == {"tools": {"listChanged": False}}


def test_an_unknown_protocol_version_is_answered_with_the_latest(probe: TestClient) -> None:
    body = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "1"}}
    assert _post(probe, body).json()["result"]["protocolVersion"] == LATEST_PROTOCOL_VERSION


def test_a_notification_is_accepted_without_an_answer(probe: TestClient) -> None:
    response = _post(probe, {"jsonrpc": "2.0", "method": "notifications/initialized"})
    assert response.status_code == 202
    assert response.content == b""


def test_every_tool_is_listed(probe: TestClient) -> None:
    listed = _post(probe, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).json()
    names = [tool["name"] for tool in listed["result"]["tools"]]
    assert names == [tool.name for tool in TOOLS]
    assert all("inputSchema" in tool for tool in listed["result"]["tools"])


def test_echo_returns_its_text(probe: TestClient) -> None:
    assert _text_of(_post(probe, _call("echo", text="hello")).json()) == "hello"


def test_leak_returns_a_fake_cloud_key(probe: TestClient) -> None:
    assert FAKE_AWS_ACCESS_KEY in _text_of(_post(probe, _call("leak")).json())


def test_inject_returns_an_injected_instruction(probe: TestClient) -> None:
    assert INJECTED_INSTRUCTION in _text_of(_post(probe, _call("inject")).json())


def test_read_file_and_run_touch_nothing(probe: TestClient) -> None:
    read = _text_of(_post(probe, _call("read_file", path="/etc/shadow")).json())
    ran = _text_of(_post(probe, _call("run", command="rm -rf /")).json())
    assert read == "probe: contents of /etc/shadow"
    assert ran == "probe: would run rm -rf /"


def test_a_missing_argument_is_a_tool_error(probe: TestClient) -> None:
    result = _post(probe, _call("echo")).json()["result"]
    assert result["isError"] is True


def test_an_unknown_tool_is_an_invalid_call(probe: TestClient) -> None:
    answer = _post(probe, _call("format_disk")).json()
    assert answer["error"]["code"] == JSON_RPC_INVALID_PARAMS


def test_an_unknown_method_is_not_found(probe: TestClient) -> None:
    answer = _post(probe, {"jsonrpc": "2.0", "id": 1, "method": "resources/list"}).json()
    assert answer["error"]["code"] == JSON_RPC_METHOD_NOT_FOUND


def test_a_body_that_is_not_json_is_a_parse_error(probe: TestClient) -> None:
    response = probe.post("/mcp", content=b"{not json", headers=JSON_AND_SSE)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == JSON_RPC_PARSE_ERROR


def test_a_batch_is_answered_request_by_request(probe: TestClient) -> None:
    batch = [
        _call("echo", request_id=1, text="one"),
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        _call("echo", request_id=2, text="two"),
    ]
    answers = _post(probe, batch).json()
    assert [answer["id"] for answer in answers] == [1, 2]


def test_stream_answers_with_events_when_the_client_accepts_them(probe: TestClient) -> None:
    response = _post(probe, _call("stream", text="streamed"))
    assert response.headers["content-type"].startswith("text/event-stream")
    data_lines = [line for line in response.text.splitlines() if line.startswith("data: ")]
    messages = [msgspec.json.decode(line.removeprefix("data: ")) for line in data_lines]
    assert messages[0]["method"] == "notifications/progress"
    assert _text_of(messages[-1]) == "streamed"
    assert "id: 1" in response.text.splitlines()


def test_stream_answers_with_json_when_the_client_accepts_only_json(probe: TestClient) -> None:
    response = _post(probe, _call("stream", text="plain"), headers={"accept": "application/json"})
    assert response.headers["content-type"].startswith("application/json")
    assert _text_of(response.json()) == "plain"


def test_the_listening_stream_is_not_offered(probe: TestClient) -> None:
    assert probe.get("/mcp").status_code == 405


def test_a_session_can_be_ended(probe: TestClient) -> None:
    assert probe.delete("/mcp").status_code == 200


def test_health_is_served(probe: TestClient) -> None:
    assert probe.get("/health/live").json() == {"status": "ok"}
    assert probe.get("/health/ready").json() == {"status": "ok"}
