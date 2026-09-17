from __future__ import annotations

import json
import uuid

import msgspec
import pytest

from ads_commons.sandbox import (
    SandboxAbort,
    SandboxAcknowledge,
    SandboxAckReply,
    SandboxAckReset,
    SandboxIpcError,
    SandboxPing,
    SandboxReady,
    SandboxRequest,
    SandboxResult,
    SandboxShutdown,
    SandboxShutdownAck,
    decode_inbound,
    decode_outbound,
    decode_ping,
    decode_ready,
    encode_inbound,
    encode_outbound,
    encode_ping,
    encode_ready,
    peek_execution_id,
    peek_sandbox_id,
)

EXECUTION = uuid.UUID("11111111-1111-4111-8111-111111111111")
SESSION = uuid.UUID("22222222-2222-4222-8222-222222222222")
MESSAGE = uuid.UUID("33333333-3333-4333-8333-333333333333")
SANDBOX = uuid.UUID("44444444-4444-4444-8444-444444444444")
PING = uuid.UUID("55555555-5555-4555-8555-555555555555")


def test_request_round_trip() -> None:
    request = SandboxRequest(
        execution_id=EXECUTION,
        session_id=SESSION,
        message_id=MESSAGE,
        kind="shell",
        payload="true",
    )
    raw = encode_inbound(request)
    payload = json.loads(raw)
    assert payload == {
        "type": "request",
        "execution_id": str(EXECUTION),
        "session_id": str(SESSION),
        "message_id": str(MESSAGE),
        "kind": "shell",
        "payload": "true",
    }
    assert "authorization" not in payload
    decoded = decode_inbound(raw)
    assert decoded == request
    assert peek_execution_id(raw) == EXECUTION


def test_python_request_kind() -> None:
    request = SandboxRequest(
        execution_id=EXECUTION,
        session_id=SESSION,
        message_id=MESSAGE,
        kind="python",
        payload="print(1)",
    )
    decoded = decode_inbound(encode_inbound(request))
    assert decoded == request
    assert decoded.kind == "python"


@pytest.mark.parametrize(
    ("control", "tag"),
    [(SandboxAckReply, "ack-reply"), (SandboxAckReset, "ack-reset"), (SandboxAbort, "abort")],
)
def test_handshake_follow_ups_round_trip(control, tag) -> None:
    message = control(execution_id=EXECUTION, session_id=SESSION, message_id=MESSAGE)
    assert json.loads(encode_inbound(message)) == {
        "type": tag,
        "execution_id": str(EXECUTION),
        "session_id": str(SESSION),
        "message_id": str(MESSAGE),
    }
    assert decode_inbound(encode_inbound(message)) == message


@pytest.mark.parametrize("tag", ["acknowledge", "ack-reply", "ack-reset", "abort"])
@pytest.mark.parametrize("field", ["execution_id", "session_id", "message_id"])
@pytest.mark.parametrize("invalid", ["missing", None, "not-a-uuid", 123])
def test_controls_require_all_correlation_ids(tag, field, invalid) -> None:
    payload = {
        "type": tag,
        "execution_id": str(EXECUTION),
        "session_id": str(SESSION),
        "message_id": str(MESSAGE),
    }
    if invalid == "missing":
        del payload[field]
    else:
        payload[field] = invalid
    with pytest.raises(msgspec.ValidationError):
        decoder = decode_outbound if tag == "acknowledge" else decode_inbound
        decoder(json.dumps(payload).encode())


def test_acknowledge_and_result_round_trip() -> None:
    acknowledge = SandboxAcknowledge(EXECUTION, SESSION, MESSAGE)
    result = SandboxResult(
        execution_id=EXECUTION,
        exit_code=1,
        stdout="out",
        stderr="err",
        truncated=True,
        duration_ms=12,
        is_error=False,
    )
    assert json.loads(encode_outbound(acknowledge)) == {
        "type": "acknowledge",
        "execution_id": str(EXECUTION),
        "session_id": str(SESSION),
        "message_id": str(MESSAGE),
    }
    payload = json.loads(encode_outbound(result))
    assert payload == {
        "type": "result",
        "execution_id": str(EXECUTION),
        "exit_code": 1,
        "stdout": "out",
        "stderr": "err",
        "truncated": True,
        "duration_ms": 12,
        "is_error": False,
        "text": "",
    }
    assert "authorization" not in payload
    assert decode_outbound(encode_outbound(acknowledge)) == acknowledge
    assert decode_outbound(encode_outbound(result)) == result


def test_tool_layer_error_result() -> None:
    result = SandboxResult(
        execution_id=EXECUTION,
        exit_code=0,
        stdout="",
        stderr="",
        truncated=False,
        duration_ms=0,
        is_error=True,
        text="sandbox not ready",
    )
    payload = json.loads(encode_outbound(result))
    assert payload["type"] == "result"
    assert payload["is_error"] is True
    assert payload["text"] == "sandbox not ready"
    assert decode_outbound(encode_outbound(result)) == result


def test_inbound_rejects_outbound_types() -> None:
    acknowledge = encode_outbound(SandboxAcknowledge(EXECUTION, SESSION, MESSAGE))
    with pytest.raises(msgspec.ValidationError):
        decode_inbound(acknowledge)


def test_unknown_kind_is_rejected() -> None:
    raw = json.dumps(
        {
            "type": "request",
            "execution_id": str(EXECUTION),
            "session_id": str(SESSION),
            "message_id": str(MESSAGE),
            "kind": "pwsh",
            "payload": "true",
        }
    ).encode()
    with pytest.raises(msgspec.ValidationError):
        decode_inbound(raw)


def test_peek_execution_id_ignores_incomplete_payloads() -> None:
    assert peek_execution_id(b"not-json") is None
    assert peek_execution_id(b'{"session_id": "22222222-2222-4222-8222-222222222222"}') is None
    assert peek_execution_id(json.dumps({"execution_id": str(EXECUTION)}).encode()) == EXECUTION


def test_ready_lifecycle_round_trip() -> None:
    ready = SandboxReady(sandbox_id=SANDBOX)
    shutdown = SandboxShutdown(sandbox_id=SANDBOX)
    ack = SandboxShutdownAck(sandbox_id=SANDBOX)
    error = SandboxIpcError(sandbox_id=SANDBOX, text="ping failed")
    assert json.loads(encode_ready(ready)) == {"type": "ready", "sandbox_id": str(SANDBOX)}
    assert json.loads(encode_ready(shutdown))["type"] == "shutdown"
    assert json.loads(encode_ready(ack))["type"] == "shutdown-ack"
    error_payload = json.loads(encode_ready(error))
    assert error_payload == {
        "type": "error",
        "sandbox_id": str(SANDBOX),
        "text": "ping failed",
    }
    assert decode_ready(encode_ready(ready)) == ready
    assert decode_ready(encode_ready(shutdown)) == shutdown
    assert decode_ready(encode_ready(ack)) == ack
    assert decode_ready(encode_ready(error)) == error
    assert peek_sandbox_id(encode_ready(error)) == SANDBOX


def test_ping_round_trip() -> None:
    ping = SandboxPing(ping_id=PING, sandbox_id=SANDBOX)
    raw = encode_ping(ping)
    payload = json.loads(raw)
    assert payload == {"ping_id": str(PING), "sandbox_id": str(SANDBOX)}
    assert "type" not in payload
    assert "authorization" not in payload
    assert decode_ping(raw) == ping


def test_ping_rejects_unknown_fields() -> None:
    raw = json.dumps(
        {
            "ping_id": str(PING),
            "sandbox_id": str(SANDBOX),
            "type": "ping",
        }
    ).encode()
    with pytest.raises(msgspec.ValidationError):
        decode_ping(raw)
