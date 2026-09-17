from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from ads_commons.sandbox import SandboxAbort, SandboxAckReply, SandboxAckReset, decode_inbound
from ads_sandbox_mcp.kafka import KafkaPublisher


@pytest.mark.anyio
@pytest.mark.parametrize("control", [SandboxAckReply, SandboxAckReset, SandboxAbort])
async def test_control_key_must_match_wire_session(control):
    producer = SimpleNamespace(send_and_wait=AsyncMock())
    publisher = KafkaPublisher(producer, SimpleNamespace(request_topic="ads.sandbox.exec.request"))
    message = control(uuid4(), uuid4(), uuid4())
    with pytest.raises(ValueError, match="session_id"):
        await publisher.publish(message, [], session_id=uuid4())
    producer.send_and_wait.assert_not_awaited()
    await publisher.publish(message, [], session_id=message.session_id)
    kwargs = producer.send_and_wait.call_args.kwargs
    assert kwargs["key"] == str(message.session_id).encode()
    assert decode_inbound(kwargs["value"]) == message
