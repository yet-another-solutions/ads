from __future__ import annotations

import json
import uuid

from ads_commons.engine import (
    AUTHORIZATION_HEADER,
    Abort,
    Acknowledge,
    AckResponse,
    AssistantHistoryTurn,
    AssistantMessage,
    Authorization,
    EngineRequest,
    ErrorOutput,
    Finish,
    OpenAiBearerToken,
    OpenAiStreamAuthentication,
    OpenAiStreamModel,
    PartialResponse,
    Ping,
    Reasoning,
    UserHistoryTurn,
    authorization_headers,
    authorization_token,
    decode_inbound,
    decode_request,
    encode_abort,
    encode_ack_response,
    encode_output,
    encode_request,
    peek_request_ids,
)

SESSION = uuid.UUID("11111111-1111-1111-1111-111111111111")
MESSAGE = uuid.UUID("22222222-2222-2222-2222-222222222222")


def test_request_round_trip() -> None:
    request = EngineRequest(
        session_id=SESSION,
        message_id=MESSAGE,
        history=[
            UserHistoryTurn(text="hi"),
            AssistantHistoryTurn(text="hello"),
        ],
        user_input="next",
        instructions="stay short",
        model=OpenAiStreamModel(
            name="gpt-test",
            url="https://llm.example/v1",
            authentication=OpenAiStreamAuthentication(
                openai_bearer=OpenAiBearerToken(token="sk-test"),
            ),
        ),
        authorization=Authorization(token="jwt-token"),
    )
    raw = encode_request(request)
    payload = json.loads(raw)
    assert payload["type"] == "request"
    assert payload["model"]["type"] == "openai-stream"
    assert payload["model"]["authentication"]["openai-bearer"] == {"token": "sk-test"}
    assert payload["history"][0] == {"type": "user", "text": "hi"}
    decoded = decode_request(raw)
    assert decoded == request
    assert decode_inbound(raw) == request


def test_ack_response_round_trip() -> None:
    ack = AckResponse(session_id=SESSION, message_id=MESSAGE)
    raw = encode_ack_response(ack)
    assert json.loads(raw) == {
        "type": "ack-response",
        "session_id": str(SESSION),
        "message_id": str(MESSAGE),
    }
    decoded = decode_inbound(raw)
    assert decoded == ack
    assert peek_request_ids(raw) == (SESSION, MESSAGE)


def test_abort_round_trip() -> None:
    abort = Abort(session_id=SESSION, message_id=MESSAGE)
    raw = encode_abort(abort)
    assert json.loads(raw) == {
        "type": "abort",
        "session_id": str(SESSION),
        "message_id": str(MESSAGE),
    }
    decoded = decode_inbound(raw)
    assert decoded == abort
    assert isinstance(decoded, Abort)
    assert peek_request_ids(raw) == (SESSION, MESSAGE)


def test_output_tags() -> None:
    acknowledge = json.loads(encode_output(Acknowledge(session_id=SESSION, message_id=MESSAGE)))
    assert acknowledge["type"] == "acknowledge"
    assert json.loads(encode_output(Ping(session_id=SESSION)))["type"] == "ping"
    assert json.loads(encode_output(Finish(session_id=SESSION, last_order=1))) == {
        "type": "finish",
        "session_id": str(SESSION),
        "last_order": 1,
    }
    partial = json.loads(
        encode_output(
            PartialResponse(
                session_id=SESSION,
                order=0,
                reasoning=Reasoning(text="thinking"),
            )
        )
    )
    assert partial["type"] == "partial-response"
    assert "message" not in partial
    message_partial = json.loads(
        encode_output(
            PartialResponse(
                session_id=SESSION,
                order=1,
                message=AssistantMessage(text="hi"),
            )
        )
    )
    assert message_partial["message"] == {"type": "assistant", "text": "hi"}
    error = json.loads(
        encode_output(ErrorOutput(session_id=SESSION, message_id=MESSAGE, text="boom"))
    )
    assert error["type"] == "error"


def test_peek_request_ids_ignores_incomplete_payloads() -> None:
    assert peek_request_ids(b"not-json") is None
    assert peek_request_ids(b'{"session_id": "11111111-1111-1111-1111-111111111111"}') is None
    assert peek_request_ids(
        b'{"session_id": "11111111-1111-1111-1111-111111111111",'
        b' "message_id": "22222222-2222-2222-2222-222222222222"}'
    ) == (SESSION, MESSAGE)


def test_authorization_headers_encode_raw_jwt() -> None:
    headers = authorization_headers("jwt-token")
    assert headers == [(AUTHORIZATION_HEADER, b"jwt-token")]
    assert authorization_token(headers) == "jwt-token"
    assert authorization_token([(b"Authorization", b"jwt-token")]) == "jwt-token"
    assert authorization_token([("x-other", b"jwt-token")]) is None
    assert authorization_token([("authorization", None)]) is None
    assert authorization_token(None) is None
