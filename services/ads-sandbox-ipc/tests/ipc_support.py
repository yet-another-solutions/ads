from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from ads_commons.sandbox import SandboxRequest, encode_inbound, encode_ping, encode_ready
from ads_commons.security import SecurityContextHolder
from ads_commons_beans import JwtVerifier, JwtVerifierSettings
from ads_sandbox_ipc.config import Settings
from ads_sandbox_ipc.controller import PING_REQUEST_TOPIC, READY_TOPIC, KafkaController
from ads_sandbox_ipc.guest import Frame, GuestExecutor, Pod
from ads_sandbox_ipc.pid_store import PidStore
from ads_sandbox_ipc.service import IpcService

SUBJECT = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"


async def eventually(predicate: Callable[[], bool], seconds: float = 2) -> None:
    async with asyncio.timeout(seconds):
        while not predicate():
            await asyncio.sleep(0.002)


class Keys:
    def __init__(self) -> None:
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.verifier = JwtVerifier(
            JwtVerifierSettings(
                "https://identity.test",
                "ads-sandbox-ipc",
                "ads-sandbox-ipc",
                "https://identity.test/jwks",
                None,
            ),
            self,
        )

    def get_signing_key_from_jwt(self, token: str) -> SimpleNamespace:
        return SimpleNamespace(key=self.key.public_key())

    def token(self, **changes: Any) -> str:
        claims = {
            "sub": SUBJECT,
            "iss": "https://identity.test",
            "aud": "ads-sandbox-ipc",
            "azp": "ads-sandbox-manager",
            "iat": int(time.time()),
            "exp": int(time.time()) + 600,
            "jti": str(uuid4()),
        }
        claims.update(changes)
        return jwt.encode(claims, self.key, algorithm="RS256")


class FakeProcess:
    def __init__(self) -> None:
        self.frames: asyncio.Queue[Frame] = asyncio.Queue()
        self.closed = False
        self.reads = 0

    async def read(self) -> Frame:
        frame = await self.frames.get()
        self.reads += 1
        return frame

    async def close(self) -> None:
        self.closed = True


class FakeKube:
    def __init__(self) -> None:
        self.pod = Pod("ads-sandbox-replica", "pod-uid")
        self.ready = True
        self.pid: int | None = None
        self.next_pid = 420
        self.calls: list[tuple[Pod, list[str], bytes]] = []
        self.killed: list[tuple[Pod, int]] = []
        self.processes: list[FakeProcess] = []
        self.fail_prepare = False
        self.fail_kill = False
        self.fail_clear = False
        self.fail_start = False
        self.ping_exit = 0
        self.polls = 0
        self.pause_ready = asyncio.Event()
        self.pause_ready.set()

    async def ready_pod(self) -> Pod | None:
        self.polls += 1
        await self.pause_ready.wait()
        if self.fail_prepare:
            raise RuntimeError("fake kube failure")
        return self.pod if self.ready else None

    async def start(self, pod: Pod, argv: list[str], stdin: bytes) -> FakeProcess:
        if self.fail_start:
            raise RuntimeError("fake start failure")
        self.calls.append((pod, list(argv), stdin))
        process = FakeProcess()
        self.processes.append(process)
        if argv == ["ads-session-exec", "shell", "true"]:
            process.frames.put_nowait(Frame(exit_code=self.ping_exit))
        else:
            self.pid = self.next_pid
            self.next_pid += 1
        return process

    async def read_pid(self, pod: Pod) -> int | None:
        return self.pid

    async def kill_tree(self, pod: Pod, pid: int) -> None:
        if self.fail_kill:
            raise RuntimeError("fake reap failure")
        self.killed.append((pod, pid))
        self.pid = None

    async def clear_pid(self, pod: Pod) -> None:
        if self.fail_clear:
            raise RuntimeError("fake clear failure")
        self.pid = None


class FakePublisher:
    def __init__(self) -> None:
        self.messages: list[Any] = []
        self.subject_tokens: list[str | None] = []
        self.fail_type: type | None = None
        self.block_type: type | None = None
        self.blocked = asyncio.Event()
        self.release = asyncio.Event()

    async def publish(self, message: Any, subject_token: str | None = None) -> None:
        assert SecurityContextHolder.get() is None
        if isinstance(message, self.block_type or type(None)):
            self.blocked.set()
            await self.release.wait()
        if isinstance(message, self.fail_type or type(None)):
            raise RuntimeError("fake Kafka send failure")
        self.messages.append(message)
        self.subject_tokens.append(subject_token)


class Harness:
    def __init__(self, directory: Path, **changes: Any) -> None:
        self.settings = replace(
            Settings(
                sandbox_id=uuid4(),
                pid_directory=directory,
                keycloak_well_known_url="https://identity.test/.well-known/openid-configuration",
                keycloak_issuer="https://identity.test",
                keycloak_client_secret="test-secret-not-logged",
                tls_cert_path=Path("/unused/cert"),
                tls_key_path=Path("/unused/key"),
                kafka_bootstrap_servers="unused.test:9092",
                timeout_seconds=1,
                startup_seconds=1,
                ack_seconds=0.3,
                poll_seconds=0.005,
                control_seconds=0.2,
            ),
            **changes,
        )
        self.keys = Keys()
        self.kube = FakeKube()
        self.store = PidStore(self.settings)
        self.guest = GuestExecutor(self.settings, self.kube, self.store)
        self.publisher = FakePublisher()
        self.service = IpcService(self.settings, self.guest, self.publisher)
        self.controller = KafkaController(self.settings, self.keys.verifier, self.service)

    @asynccontextmanager
    async def running(self, *, boot: bool = True) -> AsyncIterator[Harness]:
        self.service.start()
        try:
            if boot:
                await eventually(lambda: self.service.kafka_ready)
            yield self
        finally:
            await self.service.stop()

    def request(self, kind: str = "shell", payload: str = "echo hello") -> SandboxRequest:
        return SandboxRequest(uuid4(), uuid4(), uuid4(), kind, payload)

    async def send(self, message: Any, token: str | None = None, topic: str | None = None) -> str:
        topic = topic or self.settings.request_topic
        encode = (
            encode_ready
            if topic == READY_TOPIC
            else encode_ping
            if topic == PING_REQUEST_TOPIC
            else encode_inbound
        )
        token = self.keys.token() if token is None else token
        await self.controller.on_message(
            topic, encode(message), [("authorization", token.encode())]
        )
        return token

    def finish(self, code: int = 0, stdout: bytes = b"", stderr: bytes = b"") -> None:
        self.kube.processes[-1].frames.put_nowait(
            Frame(stdout=stdout, stderr=stderr, exit_code=code)
        )
