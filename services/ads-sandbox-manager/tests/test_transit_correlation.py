from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import pytest
from msgspec.structs import replace

from ads_commons.sandbox import (
    SandboxAbort,
    SandboxAcknowledge,
    SandboxAckReply,
    SandboxAckReset,
    SandboxRequest,
    encode_inbound,
    encode_outbound,
)
from ads_sandbox_manager.auth import IPC, MCP
from ads_sandbox_manager.service import REPLY_TOPIC, TransitService, VerifiedExec


@pytest.fixture
def transit(manager_settings):
    service = TransitService(manager_settings, Mock(), Mock(), Mock(), Mock(), Mock(), AsyncMock())
    service._row = AsyncMock()
    service._send = AsyncMock()
    return service


@pytest.mark.anyio
@pytest.mark.parametrize("control", [SandboxAckReply, SandboxAckReset, SandboxAbort])
async def test_control_rejects_key_body_mismatch(transit, control):
    message = control(uuid4(), uuid4(), uuid4())
    await transit.accept(VerifiedExec(uuid4(), message, "subject", "token"))
    transit._row.assert_not_awaited()
    transit._send.assert_not_awaited()
    assert not transit._pending and not transit._workers


@pytest.mark.anyio
@pytest.mark.parametrize("control", [SandboxAckReset, SandboxAbort])
@pytest.mark.parametrize("mismatch", ["session_id", "message_id", "subject", None])
async def test_buffer_removal_requires_tuple_and_subject(transit, control, mismatch):
    request = SandboxRequest(uuid4(), uuid4(), uuid4(), "shell", "true")
    held = VerifiedExec(request.session_id, request, "subject", "token")
    transit._pending[request.execution_id] = held
    message = control(request.execution_id, request.session_id, request.message_id)
    subject = "subject"
    if mismatch == "subject":
        subject = "different"
    elif mismatch is not None:
        message = replace(message, **{mismatch: uuid4()})
    transit._row.return_value = None
    await transit.accept(VerifiedExec(message.session_id, message, subject, "fresh-token"))
    assert (request.execution_id in transit._pending) is (mismatch is not None)
    assert not transit._workers
    transit.provisioner.provision.assert_not_called()


@pytest.mark.anyio
@pytest.mark.parametrize("control", [SandboxAckReply, SandboxAckReset, SandboxAbort])
@pytest.mark.parametrize("status", ["creating", "ready", "stopped", "failed"])
async def test_control_forwarded_unchanged_without_provisioning(transit, control, status):
    message = control(uuid4(), uuid4(), uuid4())
    sandbox_id = uuid4()
    transit._row.return_value = SimpleNamespace(sandbox_id=sandbox_id, status=status)
    await transit.accept(VerifiedExec(message.session_id, message, "subject", "token"))
    transit._row.assert_awaited_once_with(message.session_id)
    transit._send.assert_awaited_once_with(
        f"sandbox.req.{sandbox_id}", message.session_id, encode_inbound(message), IPC, "token"
    )
    transit.provisioner.provision.assert_not_called()


@pytest.mark.anyio
@pytest.mark.parametrize("matching", [False, True])
async def test_acknowledge_must_match_sandbox_session(transit, matching):
    session_id, sandbox_id = uuid4(), uuid4()
    message = SandboxAcknowledge(uuid4(), session_id if matching else uuid4(), uuid4())
    db = Mock()

    @asynccontextmanager
    async def begin():
        yield db

    transit.sessions.begin = begin
    transit.repository.by_sandbox = AsyncMock(
        return_value=SimpleNamespace(session_id=session_id, status="failed")
    )
    await transit.reply(sandbox_id, message, "token")
    if matching:
        transit._send.assert_awaited_once_with(
            REPLY_TOPIC, session_id, encode_outbound(message), MCP, "token"
        )
    else:
        transit._send.assert_not_awaited()
