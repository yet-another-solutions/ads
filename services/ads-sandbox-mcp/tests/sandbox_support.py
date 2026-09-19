from __future__ import annotations

import asyncio
import contextvars
import time
from collections.abc import Sequence
from types import SimpleNamespace
from typing import Any
from uuid import UUID, uuid4

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from dishka import Provider, Scope, provide
from litestar import Litestar
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker

from ads_commons.sandbox.handshake import (
    SandboxAcknowledge,
    SandboxAckReply,
    SandboxExecInbound,
    SandboxRequest,
    SandboxResult,
    encode_outbound,
)
from ads_commons.security import SecurityContext, SecurityContextHolder
from ads_commons_beans import JwtVerifier, JwtVerifierSettings
from ads_sandbox_mcp.app import create_app
from ads_sandbox_mcp.config import Settings
from ads_sandbox_mcp.kafka import KafkaRuntime, ReplyController
from ads_sandbox_mcp.scheduler import ClusterScheduler
from ads_sandbox_mcp.service import ExecService, Watchdog
from ads_sandbox_mcp.store import InFlight, InFlightRepository

SUBJECT = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
META = {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientInfo": {"name": "ads-engine", "version": "test"},
    "io.modelcontextprotocol/clientCapabilities": {},
}


class Keys:
    def __init__(self) -> None:
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def get_signing_key_from_jwt(self, token: str) -> SimpleNamespace:
        return SimpleNamespace(key=self.key.public_key())

    def token(self, **changes: Any) -> str:
        claims = {
            "sub": SUBJECT,
            "iss": "https://identity.test",
            "aud": "ads-sandbox-mcp",
            "azp": "ads-engine",
            "iat": int(time.time()),
            "exp": int(time.time()) + 600,
            "realm_access": {"roles": ["user"]},
            "jti": str(uuid4()),
        }
        claims.update(changes)
        return jwt.encode(claims, self.key, algorithm="RS256")

    def verifier(self) -> JwtVerifier:
        return JwtVerifier(
            JwtVerifierSettings(
                issuer="https://identity.test",
                audience="ads-sandbox-mcp",
                client_id="ads-sandbox-mcp",
                jwks_uri="https://unused.test/jwks",
                ssl_context=None,
            ),
            self,
        )


class FakeTokens:
    def __init__(self, keys: Keys) -> None:
        self.keys = keys
        self.calls: list[tuple[str, str | None]] = []
        self.fail = False

    def mint(self, audience: str, subject_token: str | None = None) -> SecurityContext:
        if self.fail:
            raise RuntimeError("fake STE outage")
        if subject_token is None:
            subject_token = SecurityContextHolder.require().access_token
        assert subject_token
        self.calls.append((audience, subject_token))
        return self.keys.verifier().authenticate(
            self.keys.token(aud=audience, azp="ads-sandbox-mcp"), audience=audience
        )


class FakePublisher:
    def __init__(self, keys: Keys) -> None:
        self.keys = keys
        self.messages: list[SandboxExecInbound] = []
        self.headers: list[Sequence[tuple[str, bytes]]] = []
        self.tasks: list[asyncio.Task[None]] = []
        self.mode = "complete"
        self.fail = False
        self.exit_code = 0
        self.stdout = "hello"
        self.stderr = ""
        self.truncated = False
        self.controller: ReplyController

    async def publish(
        self,
        message: SandboxExecInbound,
        headers: Sequence[tuple[str, bytes]],
        *,
        session_id,
    ) -> None:
        if self.fail:
            raise RuntimeError("fake Kafka outage")
        self.messages.append(message)
        assert session_id == message.session_id
        if not isinstance(message, SandboxRequest):
            request = next(
                item
                for item in self.messages
                if isinstance(item, SandboxRequest) and item.execution_id == message.execution_id
            )
            assert (message.session_id, message.message_id) == (
                request.session_id,
                request.message_id,
            )
        self.headers.append(headers)
        if isinstance(message, SandboxRequest) and self.mode != "none":
            self.tasks.append(
                asyncio.create_task(
                    self._ack(message),
                    context=contextvars.Context(),
                )
            )
        elif isinstance(message, SandboxAckReply) and self.mode == "complete":
            self.tasks.append(
                asyncio.create_task(
                    self._result(message),
                    context=contextvars.Context(),
                )
            )

    async def _ack(self, request: SandboxRequest) -> None:
        await asyncio.sleep(0.005)
        if self.mode == "error":
            await self.reply(
                SandboxResult(request.execution_id, -1, "", "", False, 0, True, "not ready")
            )
        else:
            await self.reply(
                SandboxAcknowledge(request.execution_id, request.session_id, request.message_id)
            )

    async def _result(self, ack: SandboxAckReply) -> None:
        await asyncio.sleep(0.005)
        await self.reply(
            SandboxResult(
                ack.execution_id,
                self.exit_code,
                self.stdout,
                self.stderr,
                self.truncated,
                17,
                False,
            )
        )

    async def reply(self, message: SandboxAcknowledge | SandboxResult) -> None:
        await self.controller.on_message(
            encode_outbound(message),
            [("authorization", self.keys.token(azp="ads-sandbox-manager").encode())],
        )


class FakeRuntime(KafkaRuntime):
    def __init__(self, publisher: FakePublisher) -> None:
        self.publisher = publisher
        self.running = False

    async def start(self) -> None:
        self.running = True

    def ready(self) -> bool:
        return self.running

    async def stop(self) -> None:
        self.running = False
        for task in self.publisher.tasks:
            task.cancel()
        await asyncio.gather(*self.publisher.tasks, return_exceptions=True)


class FakeScheduler(ClusterScheduler):
    async def start(self) -> None:
        pass

    async def stop(self) -> None:
        pass


class Harness:
    def __init__(self, settings: Settings, engine: AsyncEngine) -> None:
        self.settings = settings
        self.engine = engine
        self.keys = Keys()
        self.verifier = self.keys.verifier()
        self.tokens = FakeTokens(self.keys)
        self.publisher = FakePublisher(self.keys)
        self.sessions = async_sessionmaker(engine, expire_on_commit=False)
        self.repository = InFlightRepository()
        self.rebuild()

    def rebuild(self) -> None:
        self.service = ExecService(
            self.settings,
            self.sessions,
            self.repository,
            self.publisher,
            self.tokens,
            Watchdog(self.settings),
        )
        self.controller = ReplyController(self.verifier, self.service)
        self.publisher.controller = self.controller

    def identity(self) -> SecurityContext:
        return self.verifier.authenticate(self.keys.token()).with_attributes(
            session_id=uuid4(),
            message_id=uuid4(),
        )

    def headers(self, method: str = "tools/list", name: str | None = None) -> dict[str, str]:
        headers = {
            "Authorization": f"Bearer {self.keys.token()}",
            "x-ads-session-id": str(uuid4()),
            "x-ads-message-id": str(uuid4()),
            "MCP-Protocol-Version": "2026-07-28",
            "Mcp-Method": method,
            "Accept": "application/json",
        }
        if name:
            headers["Mcp-Name"] = name
        return headers

    def app(self) -> Litestar:
        return create_app(self.settings, overrides=(HarnessOverrides(self),))


class HarnessOverrides(Provider):
    """Use the harness service for controlled races; keep SDK and runtime assembly real."""

    def __init__(self, harness: Harness) -> None:
        super().__init__()
        self.harness = harness

    @provide(scope=Scope.APP, override=True)
    def verifier(self) -> JwtVerifier:
        return self.harness.verifier

    @provide(scope=Scope.APP, override=True)
    def service(self) -> ExecService:
        return self.harness.service

    @provide(scope=Scope.APP, override=True)
    def runtime(self) -> KafkaRuntime:
        return FakeRuntime(self.harness.publisher)

    @provide(scope=Scope.APP, override=True)
    def scheduler(self) -> ClusterScheduler:
        h = self.harness
        return FakeScheduler(h.engine, h.repository, h.settings)


async def row(h: Harness, execution_id: UUID) -> InFlight | None:
    async with h.sessions() as session:
        return await session.get(InFlight, execution_id)


async def wait_for_message(h: Harness, kind: type) -> object:
    async with asyncio.timeout(5):
        while True:
            for message in h.publisher.messages:
                if isinstance(message, kind):
                    return message
            await asyncio.sleep(0.005)


def rpc(method: str = "tools/list", **params: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": 1, "method": method, "params": {"_meta": dict(META), **params}}
