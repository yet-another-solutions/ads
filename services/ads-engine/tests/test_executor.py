from __future__ import annotations

import asyncio
import json
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import replace
from types import SimpleNamespace

import httpx2
import pytest
from langchain_core.messages import AIMessage, AIMessageChunk, ToolMessage
from mcp.server import Server
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import CallToolResult, ListToolsResult, Tool

from ads_commons.security import SecurityContextHolder, ensure_role
from ads_engine.chat import LangChainChatStreamer
from ads_engine.config import GuardrailSettings, Workspace
from ads_engine.executor import ExecutorChatStreamer
from ads_engine.mcp_client import SandboxClient, SandboxTools
from ads_engine.mcp_credentials import ExecutionFailed, RunCredentials, TokenPair
from ads_sandbox_mcp.http import AdsAuthentication
from engine_fakes import FakeContextFactory, make_request
from sandbox_support import Keys


def native(name="exec_shell", arg="command", value="printf hi", call_id="call-1"):
    return AIMessageChunk(
        content="",
        tool_call_chunks=[
            {"name": name, "args": json.dumps({arg: value}), "id": call_id, "index": 0}
        ],
    )


class FakeModel:
    scripts = []
    calls = []
    bindings = []
    options = []

    def __init__(self, **options):
        self.options.append(options)

    def bind_tools(self, schemas, **kwargs):
        self.bindings.append((schemas, kwargs))
        return self

    async def astream(self, messages):
        self.calls.append(list(messages))
        script = self.scripts.pop(0)
        for item in script:
            if isinstance(item, Exception):
                raise item
            yield item


@pytest.mark.parametrize("boundary", ["admission", "tool_result", "terminal"])
def test_compaction_precedes_continuation_and_terminal_finish(sdk_harness, boundary):
    import msgspec

    from ads_commons.context_meter import MeterResponse
    from ads_commons.engine import AssistantHistoryTurn, Tombstone, ToolResult, UserHistoryTurn
    from ads_context_runtime.frames import RecallRuntime
    from ads_engine.context import EngineContext
    from context_fakes import Model, memory, model_settings

    h = sdk_harness
    compacted = []

    class Clients:
        async def meter(self, body):
            has_memory = any(isinstance(m, Tombstone) for m in body.messages)
            high = boundary == "admission"
            high |= boundary == "tool_result" and any(
                isinstance(m, ToolResult) for m in body.messages
            )
            high |= boundary == "terminal" and any(
                isinstance(m, AssistantHistoryTurn) and m.text == "done" for m in body.messages
            )
            return MeterResponse(100 if has_memory or not high else 900)

        async def compact(self, body):
            compacted.append(list(body.messages))
            return memory(body.messages[:2], body.messages[2:])

    clients = Clients()

    class Factory:
        def open(self, request):
            return EngineContext(
                request, clients, RecallRuntime(clients, Model(), request.model, reserve=100)
            )

    streamer = ExecutorChatStreamer(h.credentials, h.streamer._sandbox, Factory(), h.settings)
    request = msgspec.structs.replace(
        make_request(),
        model=model_settings(1000),
        history=[UserHistoryTurn("old question"), AssistantHistoryTurn("old answer")],
    )
    FakeModel.scripts = (
        [[native()], [AIMessageChunk(content="done")]]
        if boundary == "tool_result"
        else [[AIMessageChunk(content="done")]]
    )

    async def scenario():
        async with h.sdk.session_manager.run():
            return await _collect(streamer.stream(request))

    deltas = asyncio.run(scenario())
    assert len(compacted) == 1
    positions = [i for i, d in enumerate(deltas) if d.kind in {"compaction", "tombstone"}]
    assert len(positions) == 3 and positions == list(range(positions[0], positions[0] + 3))
    start, end, tombstone = [deltas[i] for i in positions]
    assert start.compaction.type == "compacting_context" and start.tombstone is None
    assert end.compaction.type == "compacted_context" and end.tombstone is None
    assert tombstone.tombstone is not None and tombstone.compaction is None
    assert start.pressure.used_context == 900 and tombstone.pressure.used_context == 100
    assert all(d.pressure is not None for d in deltas)
    assert compacted[0].count(UserHistoryTurn(request.user_input)) == 1
    if boundary == "terminal":
        assert len(FakeModel.calls) == 1 and positions[-1] == len(deltas) - 1
    elif boundary == "tool_result":
        assert any(isinstance(m, ToolResult) for m in compacted[0])
        assert positions[0] > next(i for i, d in enumerate(deltas) if d.kind == "tool_result")
        assert str(tombstone.tombstone.memory_id) in str(FakeModel.calls[1])
    else:
        assert positions[0] == 0
        assert str(tombstone.tombstone.memory_id) in str(FakeModel.calls[0])


@pytest.mark.parametrize("waiting", ["compaction", "nested_recall"])
@pytest.mark.parametrize("ending", ["finish", "abort", "error"])
def test_pings_continue_during_context_waits_and_late_results_cannot_revive(
    sdk_harness, store, jwt_verifier, access_token, waiting, ending
):
    import msgspec

    from ads_commons.context_meter import MeterResponse
    from ads_commons.engine import (
        Abort,
        AckResponse,
        AssistantHistoryTurn,
        ErrorOutput,
        Finish,
        Ping,
        Tombstone,
        UserHistoryTurn,
        authorization_headers,
        encode_abort,
        encode_ack_response,
        encode_request,
    )
    from ads_context_runtime.frames import ContextFailure, RecallRuntime
    from ads_engine.context import EngineContext
    from ads_engine.listener import EngineListener
    from ads_engine.service import EngineService
    from context_fakes import Meter, memory, model_settings
    from engine_fakes import FakeTokenExchange, RecordingPublisher

    h = sdk_harness
    entered, released, pinged, closed = (asyncio.Event() for _ in range(4))
    inner = memory([UserHistoryTurn("original evidence")])
    outer = memory([UserHistoryTurn("recent evidence")], inner=inner)

    async def wait_for_release():
        entered.set()
        try:
            await released.wait()
            if ending == "error":
                raise ContextFailure("context_fixture_failure")
        finally:
            closed.set()

    class Clients(Meter):
        async def meter(self, body):
            if waiting == "compaction":
                return MeterResponse(
                    100 if any(isinstance(m, Tombstone) for m in body.messages) else 9000
                )
            return await super().meter(body)

        async def compact(self, body):
            await wait_for_release()
            return memory(body.messages[:2], body.messages[2:])

    class RecallModel:
        calls = 0

        async def invoke(self, messages, tools, cap):
            self.calls += 1
            if self.calls == 1:
                return AIMessage(
                    "",
                    tool_calls=[
                        {
                            "id": "inner",
                            "name": "memory_recall",
                            "args": {"memory_id": str(inner.memory_id), "question": "original?"},
                        }
                    ],
                )
            if self.calls == 2:
                await wait_for_release()
            return AIMessage("original evidence")

    clients, model = Clients(), RecallModel()

    class Factory:
        def open(self, request):
            return EngineContext(
                request, clients, RecallRuntime(clients, model, request.model, reserve=100)
            )

    class Publisher(RecordingPublisher):
        async def publish(self, session_id, message, headers=None):
            await super().publish(session_id, message, headers)
            if isinstance(message, Ping) and entered.is_set():
                pinged.set()

    streamer = ExecutorChatStreamer(h.credentials, h.streamer._sandbox, Factory(), h.settings)
    settings = replace(h.settings, ping_interval_seconds=0.01)
    publisher = Publisher()
    service = EngineService(store, publisher, streamer, FakeTokenExchange(), settings)
    listener = EngineListener(service, publisher, jwt_verifier, settings)
    request = msgspec.structs.replace(
        make_request(authorization_token=access_token),
        model=model_settings(),
        history=[outer]
        if waiting == "nested_recall"
        else [UserHistoryTurn("old"), AssistantHistoryTurn("old answer")],
    )
    FakeModel.scripts = (
        [
            [
                AIMessageChunk(
                    "",
                    tool_call_chunks=[
                        {
                            "id": "outer",
                            "name": "memory_recall",
                            "index": 0,
                            "args": json.dumps(
                                {"memory_id": str(outer.memory_id), "question": "old?"}
                            ),
                        }
                    ],
                )
            ],
            [AIMessageChunk(content="done")],
        ]
        if waiting == "nested_recall"
        else [[AIMessageChunk(content="done")]]
    )

    async def scenario():
        async with h.sdk.session_manager.run():
            task = asyncio.create_task(listener.on_message(encode_request(request)))
            await asyncio.wait_for(publisher.acknowledged.wait(), 2)
            await listener.on_message(
                encode_ack_response(AckResponse(request.session_id, request.message_id)),
                headers=authorization_headers(access_token),
            )
            await asyncio.wait_for(entered.wait(), 2)
            await asyncio.wait_for(pinged.wait(), 2)
            assert not any(isinstance(x, Finish) for x in publisher.messages)
            if ending == "abort":
                await listener.on_message(
                    encode_abort(Abort(request.session_id, request.message_id)),
                    headers=authorization_headers(access_token),
                )
            else:
                released.set()
            await asyncio.wait_for(task, 3)
            assert closed.is_set()
            snapshot = list(publisher.messages)
            released.set()
            await asyncio.sleep(0.03)
            assert publisher.messages == snapshot

    asyncio.run(scenario())
    assert sum(isinstance(x, Finish) for x in publisher.messages) == (ending == "finish")
    assert sum(isinstance(x, ErrorOutput) for x in publisher.messages) == (ending == "error")
    assert not h.executions and h.run._pair is None


class FakeCredentials:
    def __init__(self, run):
        self.run = run
        self.opens = []

    @asynccontextmanager
    async def open(self, inbound):
        self.opens.append(inbound)
        try:
            yield self.run
        finally:
            self.run.close()


@pytest.fixture
def sdk_harness(settings, monkeypatch):
    """Real SDK client, protocol server, and unchanged ADS JWT/header middleware."""
    keys = Keys()
    first = keys.token()
    pair = TokenPair(keys.verifier().authenticate(first), "refresh-secret", time.time() + 600, 1800)
    run = RunCredentials(pair, settings.mcp_timeout_seconds)
    credentials = FakeCredentials(run)
    http_requests, executions = [], []
    started, released, cancelled = asyncio.Event(), asyncio.Event(), asyncio.Event()
    behavior = SimpleNamespace(block=False, fail=False, is_error=False, refuse=False)
    schemas = [
        Tool(
            name=name,
            inputSchema={
                "type": "object",
                "properties": {arg: {"type": "string", "minLength": 1}},
                "required": [arg],
                "additionalProperties": False,
            },
        )
        for name, arg in [("exec_shell", "command"), ("exec_python", "code")]
    ]

    async def list_tools(ctx, params):
        return ListToolsResult(tools=schemas)

    async def call_tool(ctx, params):
        context = SecurityContextHolder.require()
        ensure_role(context, "user")
        executions.append((params.name, params.arguments, context))
        started.set()
        try:
            if behavior.block:
                await released.wait()
            if behavior.fail:
                raise RuntimeError("remote secret must not leak")
            return CallToolResult(
                content=[],
                structuredContent={
                    "exit_code": 7,
                    "stdout": "hello",
                    "stderr": "",
                    "truncated": False,
                    "duration_ms": 5,
                },
                isError=behavior.is_error,
            )
        finally:
            cancelled.set()

    sdk = Server("ads-sandbox-mcp", on_list_tools=list_tools, on_call_tool=call_tool)
    app = sdk.streamable_http_app(
        json_response=True,
        stateless_http=True,
        transport_security=TransportSecuritySettings(
            allowed_hosts=["mcp.test"], allowed_origins=[]
        ),
    )
    asgi = httpx2.ASGITransport(app=AdsAuthentication(app, keys.verifier()))
    real_client = httpx2.AsyncClient

    async def route(request):
        body = json.loads(request.content)
        http_requests.append((dict(request.headers), body))
        if behavior.refuse and body.get("method") == "tools/call":
            # What the guardrail in front answers; the sandbox never sees the call.
            return httpx2.Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "id": body.get("id"),
                    "error": {
                        "code": -32600,
                        "message": "the security policy refused this",
                        "data": {"refused_by": "ads-guardrail", "reason": "policy"},
                    },
                },
            )
        return await asgi.handle_async_request(request)

    monkeypatch.setattr(
        httpx2,
        "AsyncClient",
        lambda **kw: real_client(transport=httpx2.MockTransport(route), **kw),
    )
    FakeModel.scripts, FakeModel.calls, FakeModel.bindings, FakeModel.options = [], [], [], []
    monkeypatch.setattr("ads_engine.executor.AdsChatOpenAI", FakeModel)
    settings = replace(settings, mcp_url="https://mcp.test/mcp")
    yield SimpleNamespace(
        sdk=sdk,
        credentials=credentials,
        run=run,
        keys=keys,
        requests=http_requests,
        executions=executions,
        settings=settings,
        started=started,
        released=released,
        cancelled=cancelled,
        behavior=behavior,
        schemas=schemas,
        streamer=ExecutorChatStreamer(
            credentials, SandboxClient(settings), FakeContextFactory(), settings
        ),
    )


@pytest.mark.parametrize("model_name", ["glm-5.3", "glm-5.2"])
def test_real_sdk_sequential_shell_python_streams_tool_primitives(sdk_harness, model_name):
    h = sdk_harness
    FakeModel.scripts = [
        [native()],
        [native("exec_python", "code", "print(1)", "call-2")],
        [AIMessageChunk(content="done", additional_kwargs={"reasoning_content": "checked"})],
    ]

    async def scenario():
        async with h.sdk.session_manager.run():
            output = [
                delta async for delta in h.streamer.stream(make_request(model_name=model_name))
            ]
        assert [d.kind for d in output] == [
            "tool_call",
            "tool_result",
            "tool_call",
            "tool_result",
            "reasoning",
            "message",
        ]
        assert output[0].tool_call is not None
        assert output[0].tool_call.name == "exec_shell"
        assert output[0].tool_call.arguments == {"command": "printf hi"}
        assert output[1].tool_result is not None
        assert output[1].tool_result.status == "success"
        assert output[1].tool_result.content["structuredContent"]["exit_code"] == 7
        assert output[2].tool_call is not None
        assert output[2].tool_call.name == "exec_python"
        assert output[2].tool_call.arguments == {"code": "print(1)"}
        assert output[4].text == "checked"
        assert output[5].text == "done"

    asyncio.run(scenario())
    assert FakeModel.options[0]["model"] == model_name
    assert [e[0] for e in h.executions] == ["exec_shell", "exec_python"]
    assert h.executions[0][1] == {"command": "printf hi"}
    assert h.executions[1][1] == {"code": "print(1)"}
    tool_result = FakeModel.calls[1][-1]
    assert isinstance(tool_result, ToolMessage)
    assert tool_result.status == "success"  # nonzero exit is not a tool-layer error
    assert json.loads(tool_result.content)["structuredContent"]["exit_code"] == 7
    assert [body["method"] for _, body in h.requests] == [
        "server/discover",
        "tools/list",
        "tools/call",
        "tools/call",
    ]
    for headers, body in h.requests:
        assert headers["x-ads-session-id"] == str(make_request().session_id)
        assert headers["x-ads-message-id"] == str(make_request().message_id)
        assert headers["authorization"].startswith("Bearer ")
        assert headers["mcp-protocol-version"] == "2026-07-28"
        assert headers["mcp-method"] == body["method"]
        assert "mcp-session-id" not in headers
        assert "refresh-secret" not in str(headers)
        if body["method"] == "tools/call":
            assert headers["mcp-name"] == body["params"]["name"]
    assert FakeModel.bindings[0][1] == {"parallel_tool_calls": False}
    assert h.run._pair is None
    assert "jwt-not-verified" not in str(FakeModel.calls)
    assert "refresh-secret" not in str(FakeModel.calls)


def test_sdk_every_request_reads_current_pair_without_renewal(sdk_harness):
    h = sdk_harness

    async def scenario():
        async with h.sdk.session_manager.run():
            async with SandboxClient(h.settings).open(make_request(), h.run) as tools:
                await tools.schemas()
                initial = h.run.current()
                changed = replace(initial, context=h.keys.verifier().authenticate(h.keys.token()))
                h.run.replace(changed)
                message = native()
                tools.admit(tools.executor_run_id, message)
                await tools.call(tools.executor_run_id, message.tool_calls[0])
                assert (
                    h.requests[-1][0]["authorization"] == f"Bearer {changed.context.access_token}"
                )
                assert h.requests[0][0]["authorization"] == f"Bearer {initial.context.access_token}"
                assert h.credentials.opens == []
        h.run.close()

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "response",
    [
        AIMessageChunk(content='{"name":"exec_shell","args":{"command":"bad"}}'),
        AIMessageChunk(content='{"recommended_tool":"exec_shell","command":"bad"}'),
    ],
)
def test_text_and_thinker_suggestions_are_never_dispatched(sdk_harness, response):
    h = sdk_harness
    FakeModel.scripts = [[response]]

    async def scenario():
        async with h.sdk.session_manager.run():
            assert [d async for d in h.streamer.stream(make_request())]

    asyncio.run(scenario())
    assert h.executions == []


@pytest.mark.parametrize("model_name", ["glm-5.3", "glm-5.2"])
def test_tool_free_thinker_has_no_callable_tools_or_mcp(sdk_harness, monkeypatch, model_name):
    h = sdk_harness
    monkeypatch.setattr("ads_engine.chat.AdsChatOpenAI", FakeModel)
    FakeModel.scripts = [[native(), AIMessageChunk(content="proposal")]]
    output = asyncio.run(
        _collect(LangChainChatStreamer().stream(make_request(model_name=model_name)))
    )
    assert [d.text for d in output] == ["proposal"]
    assert FakeModel.bindings == [] and h.requests == [] and h.credentials.opens == []
    assert "tools" not in FakeModel.options[0] and "authorization" not in str(FakeModel.calls)
    assert FakeModel.options[0]["model"] == model_name


@pytest.mark.parametrize("invalid", ["missing", "extra_argument", "duplicates"])
def test_bad_tool_catalog_is_fatal_before_model(sdk_harness, invalid):
    h = sdk_harness
    if invalid == "missing":
        h.schemas.pop()
    elif invalid == "extra_argument":
        h.schemas[0].input_schema["additionalProperties"] = True
    else:
        h.schemas.append(h.schemas[0])

    async def scenario():
        async with h.sdk.session_manager.run():
            with pytest.raises(ExecutionFailed):
                await _collect(h.streamer.stream(make_request()))
        assert h.run._pair is None

    asyncio.run(scenario())
    assert FakeModel.calls == [] and h.executions == []


def test_tool_error_returned_to_model_without_retry(sdk_harness):
    h = sdk_harness
    h.behavior.is_error = True
    FakeModel.scripts = [[native()], [AIMessageChunk(content="failed safely")]]

    async def scenario():
        async with h.sdk.session_manager.run():
            await _collect(h.streamer.stream(make_request()))

    asyncio.run(scenario())
    assert len(h.executions) == 1
    assert FakeModel.calls[1][-1].status == "error"


def test_sdk_timeout_does_not_replay_tool(sdk_harness):
    h = sdk_harness
    h.behavior.block = True
    FakeModel.scripts = [[native()]]
    impatient = replace(h.settings, mcp_timeout_seconds=0.5)
    streamer = ExecutorChatStreamer(
        h.credentials,
        SandboxClient(impatient),
        FakeContextFactory(),
        impatient,
    )

    async def scenario():
        async with h.sdk.session_manager.run():
            with pytest.raises(ExecutionFailed):
                await asyncio.wait_for(_collect(streamer.stream(make_request())), 2)
        assert h.run._pair is None and h.cancelled.is_set()

    asyncio.run(scenario())
    assert len(h.executions) == 1 and len(h.credentials.opens) == 1


def test_output_failure_does_not_replay_tool(sdk_harness, store):
    from ads_engine.service import EngineService
    from engine_fakes import FakeTokenExchange

    h = sdk_harness
    FakeModel.scripts = [[native()], [AIMessageChunk(content="done")]]

    class FailedPublisher:
        async def publish(self, *args, **kwargs):
            raise RuntimeError("kafka unavailable")

    service = EngineService(store, FailedPublisher(), h.streamer, FakeTokenExchange(), h.settings)

    async def scenario():
        async with h.sdk.session_manager.run():
            with pytest.raises(RuntimeError, match="kafka unavailable"):
                await service._run_model(make_request())
        assert h.run._pair is None

    asyncio.run(scenario())
    assert len(h.executions) == 0 and len(h.credentials.opens) == 1


@pytest.mark.parametrize("ending", ["abort", "finish", "error"])
def test_engine_ping_during_sdk_execution_and_cleanup(
    sdk_harness, store, jwt_verifier, access_token, ending
):
    from ads_commons.engine import (
        Abort,
        AckResponse,
        ErrorOutput,
        Finish,
        Ping,
        authorization_headers,
        encode_abort,
        encode_ack_response,
        encode_request,
    )
    from ads_engine.listener import EngineListener
    from ads_engine.service import EngineService
    from engine_fakes import FakeTokenExchange, RecordingPublisher

    h = sdk_harness
    h.behavior.block = True
    FakeModel.scripts = [
        [native()],
        [
            RuntimeError("private-provider-error")
            if ending == "error"
            else AIMessageChunk(content="done")
        ],
    ]
    pinged = asyncio.Event()

    class Publisher(RecordingPublisher):
        async def publish(self, session_id, message, headers=None):
            await super().publish(session_id, message, headers)
            if isinstance(message, Ping):
                pinged.set()

    publisher = Publisher()
    settings = replace(h.settings, ping_interval_seconds=0.01)
    service = EngineService(store, publisher, h.streamer, FakeTokenExchange(), settings)
    listener = EngineListener(service, publisher, jwt_verifier, settings)
    request = make_request(authorization_token=access_token)

    async def scenario():
        async with h.sdk.session_manager.run():
            task = asyncio.create_task(listener.on_message(encode_request(request)))
            await asyncio.wait_for(publisher.acknowledged.wait(), 2)
            await asyncio.sleep(0.03)
            assert not any(isinstance(item, Ping) for item in publisher.messages)
            assert h.credentials.opens == []
            await listener.on_message(
                encode_ack_response(
                    AckResponse(session_id=request.session_id, message_id=request.message_id)
                ),
                headers=authorization_headers(access_token),
            )
            await asyncio.wait_for(h.started.wait(), 2)
            await asyncio.wait_for(pinged.wait(), 2)
            if ending == "abort":
                await listener.on_message(
                    encode_abort(
                        Abort(session_id=request.session_id, message_id=request.message_id)
                    ),
                    headers=authorization_headers(access_token),
                )
            else:
                h.released.set()
            await asyncio.wait_for(task, 2)
            assert h.cancelled.is_set() and h.run._pair is None
            assert await store.claim(request.session_id, request.message_id)
            snapshot = list(publisher.messages)
            await asyncio.sleep(0.03)
            assert publisher.messages == snapshot

    asyncio.run(scenario())
    assert len(h.executions) == 1 and len(h.credentials.opens) == 1
    assert sum(isinstance(m, Finish) for m in publisher.messages) == (ending == "finish")
    errors = [m for m in publisher.messages if isinstance(m, ErrorOutput)]
    assert len(errors) == (ending == "error")
    if errors:
        assert errors[0].text == "sandbox executor failed"
        assert errors[0].message_id == request.message_id


async def _collect(stream):
    return [item async for item in stream]


def test_dispatch_requires_native_identity_run_and_current_authorization(sdk_harness):
    h = sdk_harness
    tools = SandboxTools(None, h.run, h.settings)
    message = native()

    async def scenario():
        with pytest.raises(ExecutionFailed):
            await tools.call(tools.executor_run_id, message.tool_calls[0])
        with pytest.raises(ExecutionFailed):
            tools.admit(uuid.uuid4(), message)
        tools.admit(tools.executor_run_id, message)
        with pytest.raises(ExecutionFailed):
            await tools.call(uuid.uuid4(), message.tool_calls[0])
        with pytest.raises(ExecutionFailed):
            await tools.call(tools.executor_run_id, dict(message.tool_calls[0]))
        pair = h.run.current()
        h.run.replace(replace(pair, context=replace(pair.context, roles=frozenset())))
        with pytest.raises(ExecutionFailed, match="permission"):
            await tools.call(tools.executor_run_id, message.tool_calls[0])

    asyncio.run(scenario())


@pytest.mark.parametrize("kind", ["bad_name", "bad_args", "duplicate", "budget", "invalid"])
def test_entire_native_batch_validated_before_execution(sdk_harness, kind):
    h = sdk_harness
    tools = SandboxTools(None, h.run, replace(h.settings, max_tool_calls=1))
    message = AIMessage(content="", tool_calls=native().tool_calls)
    if kind == "bad_name":
        message.tool_calls[0]["name"] = "delete_everything"
    elif kind == "bad_args":
        message.tool_calls[0]["args"]["session_id"] = "injected"
    elif kind == "duplicate":
        tools._seen.add("call-1")
    elif kind == "budget":
        message.tool_calls.append(native(call_id="call-2").tool_calls[0])
    else:
        message.invalid_tool_calls = [{"name": "exec_shell", "args": "{", "id": "bad", "error": ""}]
    with pytest.raises(ExecutionFailed):
        tools.admit(tools.executor_run_id, message)
    assert tools._pending == [] and h.executions == []


@pytest.mark.parametrize("after_tool,after_partial", [(False, False), (False, True), (True, False)])
def test_model_retry_never_replays_partial_or_tool(sdk_harness, after_tool, after_partial):
    h = sdk_harness
    failure = RuntimeError("provider secret")
    FakeModel.scripts = (
        [[native()], [failure]]
        if after_tool
        else [[AIMessageChunk(content="partial"), failure]]
        if after_partial
        else [[failure], [failure], [AIMessageChunk(content="ok")]]
    )

    async def scenario():
        async with h.sdk.session_manager.run():
            if after_tool or after_partial:
                with pytest.raises(ExecutionFailed, match="sandbox executor failed"):
                    await _collect(h.streamer.stream(make_request()))
            else:
                assert [d.text for d in await _collect(h.streamer.stream(make_request()))] == ["ok"]

    asyncio.run(scenario())
    assert len(h.executions) == int(after_tool)
    assert len(FakeModel.calls) == (2 if after_tool else 1 if after_partial else 3)
    assert h.run._pair is None and len(h.credentials.opens) == 1


def test_cancellation_closes_blocking_sdk_http_call_and_credentials(sdk_harness):
    h = sdk_harness
    h.behavior.block = True
    FakeModel.scripts = [[native()]]

    async def scenario():
        async with h.sdk.session_manager.run():
            task = asyncio.create_task(_collect(h.streamer.stream(make_request())))
            await asyncio.wait_for(h.started.wait(), 3)
            task.cancel()
            await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), 3)
            assert h.cancelled.is_set()
            assert h.run._pair is None

    asyncio.run(scenario())


class FakeRuns:
    """Stands in for the guardrail's run bookkeeping; the proxy only needs the id."""

    def __init__(self, run_id="run-7"):
        self.run_id = run_id
        self.asked = []

    async def id_for(self, bearer, workspace, conversation):
        self.asked.append((bearer, workspace, conversation))
        return self.run_id


def _guarded(settings):
    return replace(
        settings,
        guardrail=GuardrailSettings(
            url="https://guardrail.test",
            api_token="guardrail-api-token-32-bytes",
            workspace=Workspace(project="ads", repo="r", env="test", workdir="/workspace"),
        ),
    )


def _streamer_through_guardrail(h, runs):
    guarded = _guarded(h.settings)
    return ExecutorChatStreamer(
        h.credentials, SandboxClient(guarded), FakeContextFactory(), guarded, runs
    )


def test_every_sandbox_request_names_the_conversation_run(sdk_harness):
    h = sdk_harness
    FakeModel.scripts = [[native()], [AIMessageChunk(content="done")]]
    runs = FakeRuns()
    streamer = _streamer_through_guardrail(h, runs)

    async def scenario():
        async with h.sdk.session_manager.run():
            return await _collect(streamer.stream(make_request()))

    asyncio.run(scenario())
    assert [headers.get("x-ads-run") for headers, _ in h.requests] == ["run-7"] * len(h.requests)
    assert runs.asked[0][2] == make_request().session_id
    assert runs.asked[0][1].project == "ads"


def test_a_refused_call_is_told_to_the_model_and_the_person_without_ending_the_run(sdk_harness):
    h = sdk_harness
    h.behavior.refuse = True
    FakeModel.scripts = [[native()], [AIMessageChunk(content="I cannot run that.")]]
    streamer = _streamer_through_guardrail(h, FakeRuns())

    async def scenario():
        async with h.sdk.session_manager.run():
            return await _collect(streamer.stream(make_request()))

    output = asyncio.run(scenario())
    assert [delta.kind for delta in output] == ["tool_call", "notice", "tool_result", "message"]
    assert output[1].notice is not None
    assert output[1].notice.kind == "tool-refused"
    assert output[1].notice.tool == "exec_shell"
    assert output[2].tool_result is not None
    assert output[2].tool_result.status == "error"
    assert output[3].text == "I cannot run that."
    assert h.executions == []
    told = FakeModel.calls[1][-1]
    assert isinstance(told, ToolMessage)
    assert told.status == "error"
    assert "refused" in told.content
