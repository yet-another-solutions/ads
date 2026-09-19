from __future__ import annotations

import time
from dataclasses import replace

import pytest
from litestar.testing import TestClient

from ads_commons.security import SecurityContextHolder
from sandbox_support import Harness, rpc


@pytest.mark.parametrize(
    "changes",
    [
        {"aud": "ads-engine"},
        {"iss": "https://wrong.test"},
        {"exp": int(time.time()) - 30},
        {"sub": "not-a-uuid"},
    ],
)
def test_jwt_failures_are_401_before_tools(harness: Harness, changes: dict) -> None:
    with TestClient(harness.app()) as client:
        headers = harness.headers()
        headers["Authorization"] = f"Bearer {harness.keys.token(**changes)}"
        response = client.post("/mcp", headers=headers, json=rpc())
        assert response.status_code == 401
    assert harness.publisher.messages == []
    assert harness.tokens.calls == []
    assert SecurityContextHolder.get() is None


@pytest.mark.parametrize("authorization", ["", "Bearer ", "Basic abc", "Bearer garbage"])
def test_missing_or_invalid_bearer(harness: Harness, authorization: str) -> None:
    with TestClient(harness.app()) as client:
        headers = harness.headers()
        headers["Authorization"] = authorization
        assert client.post("/mcp", headers=headers, json=rpc()).status_code == 401
    assert harness.publisher.messages == []


@pytest.mark.parametrize("azp", ["ads", "ads-sandbox-manager", "", None])
def test_wrong_caller_403_before_header_validation(harness: Harness, azp: str | None) -> None:
    with TestClient(harness.app()) as client:
        headers = {"Authorization": f"Bearer {harness.keys.token(azp=azp)}"}
        assert client.post("/mcp", headers=headers, json=rpc()).status_code == 403
    assert harness.publisher.messages == []


def test_only_the_configured_callers_are_served(harness: Harness) -> None:
    harness.settings = replace(harness.settings, allowed_callers=("ads-guardrail",))
    harness.rebuild()
    with TestClient(harness.app()) as client:
        headers = harness.headers()
        headers["Authorization"] = f"Bearer {harness.keys.token(azp='ads-engine')}"
        assert client.post("/mcp", headers=headers, json=rpc()).status_code == 403
        headers["Authorization"] = f"Bearer {harness.keys.token(azp='ads-guardrail')}"
        assert client.post("/mcp", headers=headers, json=rpc()).status_code != 403


@pytest.mark.parametrize(
    "header,value",
    [
        ("x-ads-session-id", ""),
        ("x-ads-message-id", ""),
        ("x-ads-session-id", "invalid"),
        ("x-ads-message-id", "invalid"),
    ],
)
def test_required_ads_uuid_headers(harness: Harness, header: str, value: str) -> None:
    with TestClient(harness.app()) as client:
        headers = harness.headers()
        headers[header] = value
        assert client.post("/mcp", headers=headers, json=rpc()).status_code == 400
    assert harness.publisher.messages == []


def test_health_discovery_list_and_sdk_ping_rejection(harness: Harness) -> None:
    with TestClient(harness.app()) as client:
        assert client.get("/health/live").status_code == 200
        assert client.get("/health/ready").status_code == 200
        response = client.post("/mcp", headers=harness.headers(), json=rpc())
        assert response.status_code == 200, response.text
        tools = response.json()["result"]["tools"]
        assert [t["name"] for t in tools] == ["exec_shell", "exec_python"]
        assert tools[0]["inputSchema"]["additionalProperties"] is False
        assert list(tools[0]["inputSchema"]["properties"]) == ["command"]
        assert list(tools[1]["inputSchema"]["properties"]) == ["code"]
        assert "mcp-session-id" not in response.headers
        for method in ("server/discover", "ping", "resources/list", "prompts/list", "initialize"):
            reply = client.post("/mcp", headers=harness.headers(method), json=rpc(method))
            if method == "server/discover":
                assert "result" in reply.json(), reply.text
            else:
                assert reply.json()["error"]["code"] == -32601, reply.text
        headers = harness.headers()
        headers["Mcp-Session-Id"] = "ignored"
        assert "mcp-session-id" not in client.post("/mcp", headers=headers, json=rpc()).headers
        for method in ("GET", "DELETE"):
            assert client.request(method, "/mcp", headers=headers).status_code == 405
        notification = rpc("notifications/initialized")
        del notification["id"]
        reply = client.post(
            "/mcp",
            headers=harness.headers("notifications/initialized"),
            json=notification,
        )
        assert reply.status_code == 202
        assert not reply.content
    assert harness.publisher.messages == []
    assert harness.tokens.calls == []


@pytest.mark.parametrize("mismatch", ["version", "method", "name"])
def test_sdk_validates_mcp_routing_headers(harness: Harness, mismatch: str) -> None:
    headers = harness.headers("tools/call", "exec_shell")
    body = rpc("tools/call", name="exec_shell", arguments={"command": "echo hi"})
    if mismatch == "version":
        body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] = "2025-11-25"
    elif mismatch == "method":
        headers["Mcp-Method"] = "tools/list"
    else:
        headers["Mcp-Name"] = "exec_python"
    with TestClient(harness.app()) as client:
        response = client.post("/mcp", headers=headers, json=body)
        assert response.status_code == 400, response.text
        assert response.json()["error"]["code"] == -32020
    assert harness.publisher.messages == []


@pytest.mark.parametrize("version", ["", "2025-11-25", "not-a-version"])
def test_deployment_rejects_nonmodern_version(harness: Harness, version: str) -> None:
    headers = harness.headers()
    headers["MCP-Protocol-Version"] = version
    with TestClient(harness.app()) as client:
        assert client.post("/mcp", headers=headers, json=rpc()).status_code == 400


@pytest.mark.parametrize(
    "name,args",
    [
        ("exec_shell", {}),
        ("exec_python", {}),
        ("exec_shell", {"command": ""}),
        ("exec_python", {"code": ""}),
        ("exec_shell", {"command": ["echo", "x"]}),
        ("exec_shell", {"command": "hi", "max_output": 10}),
        ("exec_python", {"code": "print(1)", "session_id": "x"}),
        ("unknown", {"command": "hi"}),
    ],
)
def test_bad_tool_arguments_are_sdk_errors(harness: Harness, name: str, args: dict) -> None:
    with TestClient(harness.app()) as client:
        reply = client.post(
            "/mcp",
            headers=harness.headers("tools/call", name),
            json=rpc("tools/call", name=name, arguments=args),
        )
        assert reply.json()["error"]["code"] == -32602, reply.text
    assert harness.publisher.messages == []


@pytest.mark.parametrize(
    "name,arg,payload",
    [
        ("exec_shell", "command", "printf hi | tee /workspace/log; false"),
        ("exec_python", "code", "print('hello')\nraise SystemExit(7)\n"),
    ],
)
def test_full_tool_roundtrip_preserves_payload_and_nonzero_exit(
    long_harness: Harness,
    name: str,
    arg: str,
    payload: str,
) -> None:
    h = long_harness
    h.publisher.exit_code = 7
    with TestClient(h.app()) as client:
        headers = h.headers("tools/call", name)
        response = client.post(
            "/mcp",
            headers=headers,
            json=rpc("tools/call", name=name, arguments={arg: payload}),
        )
        assert response.status_code == 200, response.text
        result = response.json()["result"]
        assert result["isError"] is False
        assert result["structuredContent"] == {
            "exit_code": 7,
            "stdout": "hello",
            "stderr": "",
            "truncated": False,
            "duration_ms": 17,
        }
        request = h.publisher.messages[0]
        assert request.payload == payload
        assert str(request.session_id) == headers["x-ads-session-id"]
        assert str(request.message_id) == headers["x-ads-message-id"]
        assert [type(m).__name__ for m in h.publisher.messages] == [
            "SandboxRequest",
            "SandboxAckReply",
        ]
        assert len(h.tokens.calls) == 2
        assert h.publisher.headers[0] != h.publisher.headers[1]


def test_byte_caps_do_not_leak_full_output(harness: Harness) -> None:
    harness.settings = replace(harness.settings, stdout_bytes=5, stderr_bytes=3, input_bytes=5)
    harness.rebuild()
    harness.publisher.stdout = "ééé-tail"
    harness.publisher.stderr = "abcdef"
    with TestClient(harness.app()) as client:
        response = client.post(
            "/mcp",
            headers=harness.headers("tools/call", "exec_shell"),
            json=rpc("tools/call", name="exec_shell", arguments={"command": "ééé"}),
        )
        assert response.json()["error"]["code"] == -32602
        response = client.post(
            "/mcp",
            headers=harness.headers("tools/call", "exec_shell"),
            json=rpc("tools/call", name="exec_shell", arguments={"command": "éé"}),
        )
        data = response.json()["result"]
        assert data["structuredContent"]["stdout"] == "éé"
        assert data["structuredContent"]["stderr"] == "abc"
        assert data["structuredContent"]["truncated"] is True
        assert "tail" not in response.text


def test_origin_and_host_protection(harness: Harness) -> None:
    with TestClient(harness.app()) as client:
        headers = harness.headers()
        headers["Origin"] = "https://evil.test"
        assert client.post("/mcp", headers=headers, json=rpc()).status_code == 403
        headers.pop("Origin")
        headers["Host"] = "evil.test"
        assert client.post("/mcp", headers=headers, json=rpc()).status_code == 421
    assert harness.publisher.messages == []
