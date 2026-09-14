from __future__ import annotations

import json
import uuid

from ads_commons.engine import (
    AssistantHistoryTurn,
    AssistantMessage,
    Authorization,
    EngineRequest,
    ErrorOutput,
    OpenAiBearerToken,
    OpenAiStreamAuthentication,
    OpenAiStreamModel,
    PartialResponse,
    Reasoning,
    UserHistoryTurn,
    decode_request,
    encode_output,
    encode_request,
    peek_request_ids,
)


def _request() -> EngineRequest:
    return EngineRequest(
        session_id=uuid.UUID("11111111-1111-1111-1111-111111111111"),
        message_id=uuid.UUID("22222222-2222-2222-2222-222222222222"),
        history=[
            UserHistoryTurn(text="hi"),
            AssistantHistoryTurn(text="hello"),
        ],
        user_input="next",
        instructions="be brief",
        model=OpenAiStreamModel(
            name="test-model",
            url="https://llm.example/v1",
            authentication=OpenAiStreamAuthentication(
                openai_bearer=OpenAiBearerToken(token="sk-test"),
            ),
        ),
        authorization=Authorization(token="jwt-test"),
    )


def test_request_round_trip_uses_openai_stream_and_authorization_fields() -> None:
    raw = encode_request(_request())
    payload = json.loads(raw)
    assert payload["model"]["type"] == "openai-stream"
    assert payload["model"]["authentication"]["openai-bearer"]["token"] == "sk-test"
    assert payload["authorization"]["token"] == "jwt-test"
    assert payload["history"][0] == {"type": "user", "text": "hi"}
    decoded = decode_request(raw)
    assert decoded.user_input == "next"
    assert decoded.model.name == "test-model"


def test_peek_ids_drops_when_session_or_message_id_missing() -> None:
    assert peek_request_ids(b"{}") is None
    assert peek_request_ids(b'{"session_id": "11111111-1111-1111-1111-111111111111"}') is None
    assert peek_request_ids(b"not-json") is None
    ids = peek_request_ids(
        b'{"session_id": "11111111-1111-1111-1111-111111111111",'
        b' "message_id": "22222222-2222-2222-2222-222222222222"}'
    )
    assert ids is not None
    assert ids[0] == uuid.UUID("11111111-1111-1111-1111-111111111111")


def test_partial_response_omits_unused_primitive() -> None:
    reasoning = encode_output(
        PartialResponse(
            session_id=uuid.UUID("11111111-1111-1111-1111-111111111111"),
            order=0,
            reasoning=Reasoning(text="think"),
        )
    )
    payload = json.loads(reasoning)
    assert payload["type"] == "partial-response"
    assert payload["reasoning"] == {"text": "think"}
    assert "message" not in payload

    message = encode_output(
        PartialResponse(
            session_id=uuid.UUID("11111111-1111-1111-1111-111111111111"),
            order=1,
            message=AssistantMessage(text="Hello"),
        )
    )
    payload = json.loads(message)
    assert payload["message"] == {"type": "assistant", "text": "Hello"}
    assert "reasoning" not in payload


def test_error_output_carries_message_id_and_text() -> None:
    raw = encode_output(
        ErrorOutput(
            session_id=uuid.UUID("11111111-1111-1111-1111-111111111111"),
            message_id=uuid.UUID("22222222-2222-2222-2222-222222222222"),
            text="duplicate session",
        )
    )
    payload = json.loads(raw)
    assert payload == {
        "type": "error",
        "session_id": "11111111-1111-1111-1111-111111111111",
        "message_id": "22222222-2222-2222-2222-222222222222",
        "text": "duplicate session",
    }
