from __future__ import annotations

import asyncio
import json
import socket
import threading
import time
import uuid
from collections.abc import AsyncIterator, Callable, Coroutine, Iterator, Sequence
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from types import SimpleNamespace
from typing import Any

import jwt
import uvicorn
from cryptography.hazmat.primitives.asymmetric import rsa
from langchain_core.messages import AIMessageChunk, BaseMessage

from ads_commons.engine import (
    Authorization,
    EngineRequest,
    OpenAiBearerToken,
    OpenAiStreamAuthentication,
    OpenAiStreamModel,
    OpenAiStreamOptions,
)
from ads_commons_beans import JwtVerifier, JwtVerifierSettings
from ads_policy.contract import (
    DecisionRequest,
    PolicyDecision,
    Run,
    RunRequest,
    ToolCallRequest,
)
from ads_policy.service import PolicyService

ISSUER = "https://keycloak.test/realms/ads"
MCP_AUDIENCE = "ads-mcp"
ALICE = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
INJECTION_MARKER = "ignore previous instructions"

_SIGNING_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def person_token(sub: str = ALICE) -> str:
    now = int(time.time())
    return jwt.encode(
        {
            "sub": sub,
            "name": "Alice",
            "iss": ISSUER,
            "aud": MCP_AUDIENCE,
            "azp": "ads-engine",
            "iat": now,
            "exp": now + 300,
        },
        _SIGNING_KEY,
        algorithm="RS256",
    )


class _SigningKeys:
    def get_signing_key_from_jwt(self, token: str) -> SimpleNamespace:
        return SimpleNamespace(key=_SIGNING_KEY.public_key())


PERSON_TOKEN_VERIFIER = JwtVerifier(
    JwtVerifierSettings(
        issuer=ISSUER,
        audience=MCP_AUDIENCE,
        client_id=MCP_AUDIENCE,
        jwks_uri="https://keycloak.test/certs",
        ssl_context=None,
    ),
    _SigningKeys(),
)


class KeycloakExchange:
    def __init__(self) -> None:
        self.audiences: list[str] = []

    def exchange(self, audience: str, subject_token: str | None = None) -> str:
        self.audiences.append(audience)
        return person_token()


def engine_request(chat: uuid.UUID, user_token: str = "user-token-for-engine") -> EngineRequest:
    return EngineRequest(
        session_id=chat,
        message_id=uuid.uuid4(),
        history=[],
        user_input="use the tools",
        instructions="",
        model=OpenAiStreamModel(
            url="https://llm.example/v1",
            authentication=OpenAiStreamAuthentication(
                openai_bearer=OpenAiBearerToken(token="sk-test")
            ),
            options=OpenAiStreamOptions(model_name="scripted"),
        ),
        authorization=Authorization(token=user_token),
    )


class MarkerClassifier:
    def malicious_probability(self, text: str) -> float:
        return 0.99 if INJECTION_MARKER in text.lower() else 0.01


def run_blocking[T](coroutine: Coroutine[Any, Any, T]) -> T:
    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coroutine).result()


class InProcessPolicyClient:
    def __init__(self, service: PolicyService) -> None:
        self.service = service

    def start_run(self, request: RunRequest) -> Run:
        return run_blocking(self.service.start(request))

    def run(self, run_id: str) -> Run | None:
        return run_blocking(self.service.run(run_id))

    def runs_held(self, holder: str) -> list[Run]:
        return run_blocking(self.service.held_by(holder))

    def finish_run(self, run_id: str) -> Run | None:
        return run_blocking(self.service.finish(run_id))

    def revoke_run(self, run_id: str) -> Run:
        run = run_blocking(self.service.revoke(run_id))
        if run is None:
            raise KeyError(run_id)
        return run

    def decide(self, request: DecisionRequest) -> PolicyDecision:
        return run_blocking(self.service.decide(request))

    def decide_call(self, call: ToolCallRequest) -> PolicyDecision:
        return run_blocking(self.service.decide_call(call))


class PolicyServiceBlocker:
    def __init__(self, service: PolicyService) -> None:
        self.service = service

    async def block(self, conversation: str, budget: int) -> None:
        await self.service.block_conversation(conversation, budget, "ads-audit")


@contextmanager
def served(app: Any) -> Iterator[str]:
    listening = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listening.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listening.bind(("127.0.0.1", 0))
    port = listening.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, log_level="warning", lifespan="on"))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [listening]}, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started:
        if not thread.is_alive() or time.monotonic() > deadline:
            raise RuntimeError("test server did not start")
        time.sleep(0.01)
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        listening.close()


async def eventually(check: Callable[[], bool], seconds: float = 5.0) -> None:
    deadline = time.monotonic() + seconds
    while not check():
        if time.monotonic() > deadline:
            raise AssertionError("condition not reached in time")
        await asyncio.sleep(0.02)


def tool_call(name: str, arguments: dict[str, Any], call_id: str = "call-1") -> AIMessageChunk:
    return AIMessageChunk(
        content="",
        tool_call_chunks=[
            {
                "name": name,
                "args": json.dumps(arguments),
                "id": call_id,
                "index": 0,
                "type": "tool_call_chunk",
            }
        ],
    )


def said(text: str) -> AIMessageChunk:
    return AIMessageChunk(content=text)


class ScriptedModel:
    def __init__(self, rounds: Sequence[Sequence[AIMessageChunk]]) -> None:
        self.rounds = [list(chunks) for chunks in rounds]
        self.offered: list[str] = []
        self.received: list[list[BaseMessage]] = []

    def bind_tools(self, tools: Sequence[dict[str, Any]]) -> ScriptedModel:
        self.offered = [tool["function"]["name"] for tool in tools]
        return self

    def astream(self, input: Any) -> AsyncIterator[Any]:
        return self._answer(list(input))

    async def _answer(self, messages: list[BaseMessage]) -> AsyncIterator[Any]:
        self.received.append(messages)
        number = len(self.received) - 1
        for chunk in self.rounds[number] if number < len(self.rounds) else []:
            yield chunk

    def tool_result(self, round_number: int = 1) -> str:
        return str(self.received[round_number][-1].content)
