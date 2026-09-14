from __future__ import annotations

import uuid
from collections.abc import AsyncIterator

from ads_commons.engine import (
    Authorization,
    EngineRequest,
    OpenAiBearerToken,
    OpenAiStreamAuthentication,
    OpenAiStreamModel,
)
from ads_engine.chat import StreamDelta


def make_request(
    *,
    session_id: uuid.UUID | None = None,
    message_id: uuid.UUID | None = None,
    user_input: str = "hello",
    authorization_token: str = "jwt-not-verified",
) -> EngineRequest:
    return EngineRequest(
        session_id=session_id or uuid.UUID("11111111-1111-1111-1111-111111111111"),
        message_id=message_id or uuid.UUID("22222222-2222-2222-2222-222222222222"),
        history=[],
        user_input=user_input,
        instructions="be brief",
        model=OpenAiStreamModel(
            name="test-model",
            url="https://llm.example/v1",
            authentication=OpenAiStreamAuthentication(
                openai_bearer=OpenAiBearerToken(token="sk-test"),
            ),
        ),
        authorization=Authorization(token=authorization_token),
    )


class RecordingPublisher:
    def __init__(self) -> None:
        self.messages: list[object] = []

    async def publish(self, session_id: uuid.UUID, message: object) -> None:
        self.messages.append(message)


class ScriptedChat:
    def __init__(
        self,
        deltas: list[StreamDelta] | None = None,
        fail_times: int = 0,
        fail_after_partial: bool = False,
    ) -> None:
        self.deltas = list(deltas or [])
        self.fail_times = fail_times
        self.fail_after_partial = fail_after_partial
        self.calls = 0
        self.requests: list[EngineRequest] = []

    def stream(self, request: EngineRequest) -> AsyncIterator[StreamDelta]:
        return self._stream(request)

    async def _stream(self, request: EngineRequest) -> AsyncIterator[StreamDelta]:
        self.calls += 1
        self.requests.append(request)
        if self.calls <= self.fail_times:
            raise RuntimeError("openai unavailable")
        for delta in self.deltas:
            yield delta
            if self.fail_after_partial:
                raise RuntimeError("stream dropped")
