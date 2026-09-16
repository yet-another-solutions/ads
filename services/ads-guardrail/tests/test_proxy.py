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
from ads_guardrail.contract import Application, Sandbox
from ads_guardrail.guardrail import fingerprint
from ads_policy.audit import BufferedAuditSink, CollectingAuditSink
from ads_policy.client import PolicyClient
from ads_policy.config import GovernanceSettings
from ads_policy.contract import (
    DEFAULT_RESPONSE,
    Binding,
    Capability,
    Interception,
    InterceptionPoint,
    Placement,
    Side,
    Switch,
)
from ads_policy.pdp import PolicyDecisionPoint
from ads_policy.policy import org_policy
from ads_policy.run import InMemoryRunStore
from ads_policy.service import PolicyService
from guardrail_helpers import (
    ALICE,
    APP_KEY,
    BOB,
    FORGING_KEY,
    TOKEN,
    USER_TOKEN,
    VERIFIER,
    DirectPolicyClient,
    opening_body,
    token,
)

GOVERNANCE = GovernanceSettings()
WORKDIR_FILE = f"{GOVERNANCE.workdir}/src/app.py"
AWS_KEY = "AKIAQYLPMN5HHHFPZAM2"
SESSION = "3f6c1d2e-session"
ACCEPT = {"accept": "application/json, text/event-stream"}

#: A deployment standing in front of one MCP server binds that server's tools. The
#: built-in bindings are for `opencode`; `mcp:retriever` is a different source, and the
#: same tool name from two servers means two different things.
RETRIEVER = (
    Binding("mcp:retriever", "read", Capability.FS_READ, argument="filePath"),
    Binding("mcp:retriever", "webfetch", Capability.NET_EGRESS, argument="url"),
    Binding("mcp:retriever", "bash", Capability.PROCESS_EXEC, argument="command"),
)


def _as(bearer: str) -> dict[str, str]:
    return {**ACCEPT, "authorization": f"Bearer {bearer}"}


def _event(message: dict[str, Any], event_id: str = "") -> bytes:
    head = f"id: {event_id}\n" if event_id else ""
    return f"{head}data: {json.dumps(message)}\n\n".encode()


class Upstream:
    """A Streamable HTTP MCP server, and a record of what actually reached it.

    ``stream`` makes it answer tool calls with an event stream — a progress
    notification, then the result — written a few bytes at a time, the way a real
    network hands them over.
    """

    def __init__(self) -> None:
        self.seen: list[dict[str, Any]] = []
        self.headers: list[dict[str, str]] = []
        self.result: Any = "contents of the file"
        self.progress = "reading the file"
        self.stream = False
        self.escape = False
        self.deleted: list[str] = []
        self.url = ""

    async def post(self, request: web.Request) -> web.StreamResponse:
        self.headers.append({k.lower(): v for k, v in request.headers.items()})
        try:
            body = json.loads(await request.read())
        except json.JSONDecodeError:
            # A real server answers for nonsense itself; the proxy just carried it.
            return web.json_response({"error": "not json"}, status=400)
        self.seen.append(body)
        if isinstance(body, list):
            return web.json_response([self._answer(item) for item in body])
        if "id" not in body:
            return web.Response(status=202)
        if body.get("method") == "initialize":
            return web.json_response(self._answer(body), headers={"Mcp-Session-Id": SESSION})
        if body.get("method") == "tools/call" and self.stream:
            return await self._streamed(request, body)
        if self.escape:
            # Legal JSON for the same text, and invisible to a search of the raw body.
            text = json.dumps(self._answer(body)).replace("AKIA", "\\u0041KIA")
            return web.Response(text=text, content_type="application/json")
        return web.json_response(self._answer(body))

    async def _streamed(self, request: web.Request, body: dict[str, Any]) -> web.StreamResponse:
        response = web.StreamResponse(headers={"Content-Type": "text/event-stream"})
        await response.prepare(request)
        progress = {
            "jsonrpc": "2.0",
            "method": "notifications/progress",
            "params": {"progressToken": 1, "progress": 1, "message": self.progress},
        }
        wire = _event(progress, "1") + _event(self._answer(body), "2")
        for start in range(0, len(wire), 7):
            await response.write(wire[start : start + 7])
        await response.write_eof()
        return response

    async def get(self, request: web.Request) -> web.StreamResponse:
        """The stream an agent opens to hear what the server sends unasked."""
        response = web.StreamResponse(headers={"Content-Type": "text/event-stream"})
        await response.prepare(request)
        changed = {"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}
        await response.write(_event(changed))
        await response.write_eof()
        return response

    async def delete(self, request: web.Request) -> web.Response:
        self.deleted.append(request.headers.get("Mcp-Session-Id", ""))
        return web.Response(status=200)

    def _answer(self, body: dict[str, Any]) -> dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": body.get("id"),
            "result": {"content": [{"type": "text", "text": self.result}]},
        }


@pytest.fixture
def upstream() -> Iterator[Upstream]:
    """A server on a real socket: the proxy is an HTTP hop, so the test is one too."""
    mcp = Upstream()
    app = web.Application()
    app.router.add_post("/mcp", mcp.post)
    app.router.add_get("/mcp", mcp.get)
    app.router.add_delete("/mcp", mcp.delete)
    server = TestServer(app)
    # Its own loop, in its own thread — the app under test owns the calling one.
    with start_blocking_portal("asyncio") as portal:
        portal.call(server.start_server)
        mcp.url = str(server.make_url("/mcp"))
        try:
            yield mcp
        finally:
            portal.call(server.close)


def _service(interception: Interception | None = None) -> PolicyService:
    policy = replace(org_policy(), bindings=RETRIEVER, interception=interception or Interception())
    journal = BufferedAuditSink(CollectingAuditSink())
    return PolicyService(PolicyDecisionPoint(policy), InMemoryRunStore(), journal)


@pytest.fixture
def policy_service() -> PolicyService:
    return _service()


def _table(settings: Settings, upstream: Upstream) -> Settings:
    """Two names, one real server: what differs is only what the bindings call them."""
    return replace(settings, mcp_servers={"retriever": upstream.url, "jira": upstream.url})


@pytest.fixture
def api(
    settings: Settings, policy_client: PolicyClient, upstream: Upstream
) -> Iterator[TestClient]:
    app = create_app(_table(settings, upstream), policy_client, CollectingAuditSink(), VERIFIER)
    with TestClient(app=app) as client:
        yield client


def _call(tool: str, arguments: dict[str, Any], request_id: int = 1) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    }


def _post(
    api: TestClient,
    body: Any,
    bearer: str | None = USER_TOKEN,
    server: str = "retriever",
    run: str = "",
) -> Any:
    headers = _as(bearer) if bearer else dict(ACCEPT)
    if run:
        headers["x-ads-run"] = run
    response = api.post(f"/mcp/{server}", json=body, headers=headers)
    assert response.status_code == 200
    return response.json()


def _events(raw: str) -> list[dict[str, Any]]:
    """The messages in an event stream, in order."""
    return [
        json.loads(line.removeprefix("data:").strip())
        for line in raw.splitlines()
        if line.startswith("data:")
    ]


def _open_run(api: TestClient, bearer: str = USER_TOKEN) -> str:
    response = api.post(
        "/guardrail/runs",
        json=opening_body(bearer=bearer),
        headers={"authorization": f"Bearer {TOKEN}"},
    )
    assert response.status_code == 201
    return str(response.json()["id"])


# --- which run a call belongs to ----------------------------------------------------


def test_hermes_is_recognised_by_its_configured_key(
    settings: Settings, policy_client: PolicyClient, upstream: Upstream
) -> None:
    """hermes as deployed: its key is in the configuration, and that is all."""
    hermes = Application(
        name="hermes",
        key_sha256=fingerprint(APP_KEY),
        sandbox=Sandbox(
            project="ads",
            repo="yet-another-solutions/ads",
            env="test",
            workdir=GOVERNANCE.workdir,
            placement=Placement.CLUSTER,
            node_labels={GOVERNANCE.application_node_label: GOVERNANCE.node_label_value},
        ),
    )
    configured = replace(_table(settings, upstream), applications=(hermes,))
    app = create_app(configured, policy_client, CollectingAuditSink(), VERIFIER)
    with TestClient(app=app) as api:
        answer = _post(api, _call("read", {"filePath": WORKDIR_FILE}), bearer=APP_KEY)
    assert "result" in answer


def test_a_person_is_recognised_by_their_token(api: TestClient, upstream: Upstream) -> None:
    _open_run(api)
    answer = _post(api, _call("read", {"filePath": WORKDIR_FILE}), bearer=USER_TOKEN)
    assert "result" in answer


def test_a_refreshed_token_carries_on_in_the_same_run(api: TestClient, upstream: Upstream) -> None:
    """The sandbox service refreshes the token mid-task; the run does not notice."""
    _open_run(api)
    refreshed = token(ALICE, issued=-60, jti="refreshed")
    answer = _post(api, _call("read", {"filePath": WORKDIR_FILE}), bearer=refreshed)
    assert "result" in answer


def test_an_expired_token_is_refused(api: TestClient, upstream: Upstream) -> None:
    _open_run(api)
    answer = _post(api, _call("read", {"filePath": WORKDIR_FILE}), bearer=token(issued=-3600))
    assert upstream.seen == []
    assert answer["error"]["message"] == GOVERNANCE.denied_message


def test_a_forged_token_is_refused(api: TestClient, upstream: Upstream) -> None:
    _open_run(api)
    answer = _post(api, _call("read", {"filePath": WORKDIR_FILE}), bearer=token(key=FORGING_KEY))
    assert upstream.seen == []
    assert "error" in answer


def test_a_call_without_credentials_belongs_to_no_run(api: TestClient, upstream: Upstream) -> None:
    """One process serves many runs, so an unlabelled call belongs to none of them."""
    _open_run(api)
    answer = _post(api, _call("read", {"filePath": WORKDIR_FILE}), bearer=None)
    assert upstream.seen == []
    assert answer["error"]["message"] == GOVERNANCE.denied_message


def test_credentials_nobody_opened_a_run_for_are_refused(
    api: TestClient, upstream: Upstream
) -> None:
    _open_run(api)
    answer = _post(api, _call("read", {"filePath": WORKDIR_FILE}), bearer="a-stranger")
    assert upstream.seen == []
    assert answer["error"]["message"] == GOVERNANCE.denied_message


def test_the_refusal_does_not_say_why_the_run_was_not_found(api: TestClient) -> None:
    """The agent is told nothing about the wall, this one included."""
    answer = _post(api, _call("read", {"filePath": WORKDIR_FILE}), bearer="a-stranger")
    assert "credentials" not in answer["error"]["message"]


def test_two_sandboxes_on_one_token_need_the_call_to_name_one(
    api: TestClient, upstream: Upstream
) -> None:
    _open_run(api)
    second = _open_run(api)
    refused = _post(api, _call("read", {"filePath": WORKDIR_FILE}))
    assert "error" in refused
    assert upstream.seen == []
    named = _post(api, _call("read", {"filePath": WORKDIR_FILE}), run=second)
    assert "result" in named


def test_a_named_run_that_is_not_theirs_is_refused(api: TestClient, upstream: Upstream) -> None:
    """A run id alone is not a credential."""
    theirs = _open_run(api, bearer=token(BOB))
    _open_run(api)
    answer = _post(api, _call("read", {"filePath": WORKDIR_FILE}), run=theirs)
    assert upstream.seen == []
    assert "error" in answer


# --- deciding ----------------------------------------------------------------------


def test_a_permitted_call_reaches_the_server(api: TestClient, upstream: Upstream) -> None:
    _open_run(api)
    answer = _post(api, _call("read", {"filePath": WORKDIR_FILE}))
    assert upstream.seen[-1]["params"]["name"] == "read"
    assert answer["result"]["content"][0]["text"] == "contents of the file"


def test_a_refused_call_never_reaches_the_server(api: TestClient, upstream: Upstream) -> None:
    """The point of standing in front of it: the server never hears the question."""
    _open_run(api)
    answer = _post(api, _call("read", {"filePath": "/etc/shadow"}))
    assert upstream.seen == []
    assert answer["error"]["message"] == GOVERNANCE.denied_message


def test_a_refusal_speaks_the_agent_s_own_protocol(api: TestClient) -> None:
    """A transport error would read as a broken server, and the agent would retry."""
    _open_run(api)
    answer = _post(api, _call("read", {"filePath": "/etc/shadow"}, request_id=7))
    assert answer["jsonrpc"] == "2.0"
    assert answer["id"] == 7
    assert "error" in answer
    assert "result" not in answer


def test_a_tool_nothing_binds_is_refused(api: TestClient, upstream: Upstream) -> None:
    _open_run(api)
    answer = _post(api, _call("telepathy", {"thought": "rm -rf /"}))
    assert upstream.seen == []
    assert "error" in answer


def test_a_credential_in_the_arguments_is_refused(api: TestClient, upstream: Upstream) -> None:
    _open_run(api)
    answer = _post(api, _call("webfetch", {"url": "mirror.interlab", "body": f"K={AWS_KEY}"}))
    assert upstream.seen == []
    assert "error" in answer


@pytest.mark.parametrize("nested", [{"deep": {"k": "v"}}, [1, 2, 3], 42])
def test_a_nested_argument_is_read_as_the_json_it_is(
    api: TestClient, upstream: Upstream, nested: Any
) -> None:
    _open_run(api)
    _post(api, _call("bash", {"command": "uv sync", "extra": nested}))
    assert upstream.seen != []


def test_a_tool_call_inside_a_batch_is_refused_whole(api: TestClient, upstream: Upstream) -> None:
    """Otherwise a batch would carry a call past the check inside something else."""
    _open_run(api)
    batch = [
        {"jsonrpc": "2.0", "id": 1, "method": "ping"},
        _call("bash", {"command": "rm -rf /"}, request_id=2),
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
    ]
    answers = _post(api, batch)
    assert upstream.seen == []
    assert [answer["id"] for answer in answers] == [1, 2]
    assert all("error" in answer for answer in answers)


def test_a_batch_without_a_tool_call_goes_through(api: TestClient, upstream: Upstream) -> None:
    batch = [{"jsonrpc": "2.0", "id": 1, "method": "ping"}]
    _post(api, batch)
    assert upstream.seen == [batch]


# --- reading what comes back -------------------------------------------------------


def test_a_credential_in_the_result_is_redacted(api: TestClient, upstream: Upstream) -> None:
    """The call already happened, so the answer is cleaned rather than withheld."""
    upstream.result = f"export KEY={AWS_KEY}"
    _open_run(api)
    answer = _post(api, _call("read", {"filePath": WORKDIR_FILE}))
    assert answer["result"]["content"][0]["text"] == "export KEY=[redacted:aws-access-token]"


def test_a_credential_behind_json_escaping_is_still_found(
    api: TestClient, upstream: Upstream
) -> None:
    """The strings are read, not the JSON text: ``\\u0041`` is an A to the agent."""
    upstream.result = f"export KEY={AWS_KEY}"
    upstream.escape = True
    _open_run(api)
    answer = _post(api, _call("read", {"filePath": WORKDIR_FILE}))
    assert answer["result"]["content"][0]["text"] == "export KEY=[redacted:aws-access-token]"


def test_a_structured_result_keeps_its_shape(api: TestClient, upstream: Upstream) -> None:
    """Every string is read; numbers, keys and nesting come back as they went."""
    upstream.result = {"files": [{"path": "a.env", "size": 3, "body": f"KEY={AWS_KEY}"}]}
    _open_run(api)
    answer = _post(api, _call("read", {"filePath": WORKDIR_FILE}))
    returned = answer["result"]["content"][0]["text"]
    assert returned["files"][0]["size"] == 3
    assert returned["files"][0]["path"] == "a.env"
    assert returned["files"][0]["body"] == "KEY=[redacted:aws-access-token]"


def test_a_clean_result_comes_back_byte_for_byte(api: TestClient, upstream: Upstream) -> None:
    """Nothing is re-encoded unless something was cut."""
    _open_run(api)
    raw = api.post(
        "/mcp/retriever",
        json=_call("read", {"filePath": WORKDIR_FILE}),
        headers=_as(USER_TOKEN),
    )
    assert raw.content == json.dumps(upstream._answer({"id": 1})).encode()


def test_the_inbound_side_under_review_hands_the_result_back_whole(
    settings: Settings, upstream: Upstream
) -> None:
    """The finding is recorded; the agent still gets what the server actually said."""
    upstream.result = f"export KEY={AWS_KEY}"
    reviewing_side = Side(checks=DEFAULT_RESPONSE.checks, on=Switch.REVIEW)
    client = DirectPolicyClient(_service(Interception(response=reviewing_side)))
    app = create_app(_table(settings, upstream), client, CollectingAuditSink(), VERIFIER)
    with TestClient(app=app) as reviewing:
        _open_run(reviewing)
        answer = _post(reviewing, _call("read", {"filePath": WORKDIR_FILE}))
    assert AWS_KEY in json.dumps(answer)


# --- streams -----------------------------------------------------------------------


def _streamed(api: TestClient) -> Any:
    _open_run(api)
    return api.post(
        "/mcp/retriever",
        json=_call("read", {"filePath": WORKDIR_FILE}),
        headers=_as(USER_TOKEN),
    )


def test_a_streamed_answer_stays_a_stream(api: TestClient, upstream: Upstream) -> None:
    upstream.stream = True
    response = _streamed(api)
    assert response.headers["content-type"].startswith("text/event-stream")
    messages = _events(response.text)
    assert messages[0]["method"] == "notifications/progress"
    assert messages[1]["result"]["content"][0]["text"] == "contents of the file"


def test_every_event_in_a_stream_is_read(api: TestClient, upstream: Upstream) -> None:
    """Progress is content too, and it reaches the agent before the result does."""
    upstream.stream = True
    upstream.progress = f"found KEY={AWS_KEY} while reading"
    upstream.result = f"export KEY={AWS_KEY}"
    response = _streamed(api)
    assert AWS_KEY not in response.text
    messages = _events(response.text)
    assert "[redacted:aws-access-token]" in messages[0]["params"]["message"]
    assert "[redacted:aws-access-token]" in messages[1]["result"]["content"][0]["text"]


def test_an_event_keeps_its_id_when_it_is_rewritten(api: TestClient, upstream: Upstream) -> None:
    """A client resumes a broken stream from the last id it saw."""
    upstream.stream = True
    upstream.result = f"export KEY={AWS_KEY}"
    response = _streamed(api)
    assert "id: 2" in response.text.splitlines()


def test_an_event_that_never_ends_is_cut_rather_than_passed_unread(
    api: TestClient, upstream: Upstream, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("ads_guardrail.proxy.MAX_EVENT_BYTES", 64)
    upstream.stream = True
    upstream.result = f"export KEY={AWS_KEY} " + "x" * 200
    response = _streamed(api)
    assert AWS_KEY not in response.text


def test_the_listening_stream_reaches_the_agent(api: TestClient) -> None:
    """What the server sends unasked is not a tool result, and goes through as it is."""
    response = api.get("/mcp/retriever", headers={"accept": "text/event-stream"})
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert _events(response.text)[0]["method"] == "notifications/tools/list_changed"


# --- the rest of the protocol ------------------------------------------------------


def test_everything_that_is_not_a_tool_call_passes_through(
    api: TestClient, upstream: Upstream
) -> None:
    """The less of the protocol this understands, the less of it breaks underneath us."""
    for method in ("initialize", "ping", "tools/list", "resources/list"):
        _post(api, {"jsonrpc": "2.0", "id": 1, "method": method})
    assert [seen["method"] for seen in upstream.seen] == [
        "initialize",
        "ping",
        "tools/list",
        "resources/list",
    ]


def test_the_session_id_reaches_the_agent(api: TestClient) -> None:
    """Without it every call after initialize would be refused by the server."""
    response = api.post(
        "/mcp/retriever",
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
        headers=ACCEPT,
    )
    assert response.headers["mcp-session-id"] == SESSION


def test_the_agent_s_headers_reach_the_server(api: TestClient, upstream: Upstream) -> None:
    """The credentials among them: the server may check them itself."""
    _open_run(api)
    api.post(
        "/mcp/retriever",
        json=_call("read", {"filePath": WORKDIR_FILE}),
        headers={
            **_as(USER_TOKEN),
            "mcp-session-id": SESSION,
            "mcp-protocol-version": "2025-06-18",
        },
    )
    seen = upstream.headers[-1]
    assert seen["authorization"] == f"Bearer {USER_TOKEN}"
    assert seen["mcp-session-id"] == SESSION
    assert seen["mcp-protocol-version"] == "2025-06-18"
    assert seen["accept"] == ACCEPT["accept"]


def test_the_run_header_is_ours_and_stops_here(api: TestClient, upstream: Upstream) -> None:
    run = _open_run(api)
    _post(api, _call("read", {"filePath": WORKDIR_FILE}), run=run)
    assert "x-ads-run" not in upstream.headers[-1]


def test_a_notification_is_accepted_with_nothing_to_say(api: TestClient) -> None:
    response = api.post(
        "/mcp/retriever",
        json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        headers=ACCEPT,
    )
    assert response.status_code == 202
    assert response.content == b""


def test_ending_a_session_reaches_the_server(api: TestClient, upstream: Upstream) -> None:
    response = api.delete("/mcp/retriever", headers={"mcp-session-id": SESSION})
    assert response.status_code == 200
    assert upstream.deleted == [SESSION]


def test_a_body_that_is_not_json_goes_upstream_untouched(api: TestClient) -> None:
    """Unparseable is the real server's problem to answer for, not ours to guess at."""
    response = api.post("/mcp/retriever", content=b"not json at all")
    assert response.status_code == 400


# --- the table ---------------------------------------------------------------------


def test_a_server_nobody_put_in_the_table_does_not_exist(
    api: TestClient, upstream: Upstream
) -> None:
    response = api.post("/mcp/elsewhere", json=_call("read", {"filePath": WORKDIR_FILE}))
    assert response.status_code == 404
    assert upstream.seen == []


def test_one_agent_reaches_several_servers_within_one_run(
    api: TestClient, upstream: Upstream
) -> None:
    """`read` is bound for the retriever only; the jira server's `read` binds to nothing."""
    _open_run(api)
    allowed = _post(api, _call("read", {"filePath": WORKDIR_FILE}), server="retriever")
    refused = _post(api, _call("read", {"filePath": WORKDIR_FILE}), server="jira")
    assert "result" in allowed
    assert "error" in refused
    assert len(upstream.seen) == 1


def test_calls_that_are_not_tool_calls_reach_any_listed_server(
    api: TestClient, upstream: Upstream
) -> None:
    _post(api, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, server="jira")
    assert upstream.seen[-1]["method"] == "tools/list"


def test_a_server_that_does_not_answer_is_a_bad_gateway(
    settings: Settings, policy_client: PolicyClient
) -> None:
    unreachable = replace(settings, mcp_servers={"gone": "http://127.0.0.1:9/mcp"})
    app = create_app(unreachable, policy_client, CollectingAuditSink(), VERIFIER)
    with TestClient(app=app) as api:
        response = api.post("/mcp/gone", json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert response.status_code == 502


# --- the decision API, beside the proxy --------------------------------------------


def test_the_capability_comes_back_on_the_decision(api: TestClient) -> None:
    run = _open_run(api)
    response = api.post(
        "/guardrail/permissions",
        headers={"authorization": f"Bearer {TOKEN}"},
        json={
            "run_id": run,
            "source": "mcp:retriever",
            "tool": "read",
            "arguments": {"filePath": WORKDIR_FILE},
        },
    )
    assert response.status_code == 201
    decision = response.json()
    assert decision["capability"] == Capability.FS_READ.value
    assert decision["point"] == InterceptionPoint.CALL.value
