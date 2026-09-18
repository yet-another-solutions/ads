"""Cross-service test wiring. Only transport, identity endpoint and kube are simulated."""

from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from dataclasses import dataclass, field, replace
from io import BytesIO
from pathlib import Path
from unittest.mock import AsyncMock
from urllib.parse import parse_qs
from uuid import UUID, uuid4

import msgspec
from httpx import ASGITransport, AsyncClient

from ads_commons.sandbox import decode_inbound, decode_outbound, decode_ping, decode_ready
from ads_commons.security import SecurityContextHolder
from ads_commons_beans import JwtVerifier, JwtVerifierSettings, TokenExchange, TokenExchangeSettings
from ads_sandbox_ipc.auth import ClientCredentials
from ads_sandbox_ipc.controller import KafkaController as IpcController
from ads_sandbox_ipc.kafka import KafkaPublisher as IpcPublisher
from ads_sandbox_ipc.service import IpcService
from ads_sandbox_manager import kafka as manager_kafka
from ads_sandbox_manager.auth import IPC, MANAGER, MCP
from ads_sandbox_manager.controller import KafkaController as ManagerController
from ads_sandbox_manager.lifecycle import PING_REPLY, PING_REQUEST, RECOVER, Signal
from ads_sandbox_manager.service import READY_TOPIC, REPLY_TOPIC, REQUEST_TOPIC, TransitService
from ads_sandbox_mcp.kafka import KafkaPublisher as McpPublisher
from ads_sandbox_mcp.kafka import ReplyController
from ads_sandbox_mcp.service import ExecService, Watchdog
from ipc_support import Harness as IpcHarness
from sandbox_support import Harness as McpHarness
from sandbox_support import Keys, rpc


@dataclass
class Record:
    topic: str
    key: bytes
    value: bytes
    headers: list[tuple[str, bytes]] = field(repr=False)

    @property
    def message(self):
        if self.topic in (PING_REQUEST, PING_REPLY):
            return decode_ping(self.value)
        if self.topic == RECOVER:
            return msgspec.json.decode(self.value, type=Signal)
        if self.topic == READY_TOPIC:
            return decode_ready(self.value)
        if self.topic == REQUEST_TOPIC or self.topic.startswith("sandbox.req."):
            return decode_inbound(self.value)
        return decode_outbound(self.value)

    @property
    def token(self):
        return dict(self.headers)["authorization"].decode()


class Broker:
    """Queue encoded records, not synthesized replies; tests explicitly deliver each hop."""

    def __init__(self):
        self.queue = asyncio.Queue()
        self.records: list[Record] = []

    async def send_and_wait(self, topic, *, key, value, headers):
        record = Record(topic, key, value, list(headers))
        self.records.append(record)
        await self.queue.put(record)

    async def next(self, topic, message_type):
        record = await asyncio.wait_for(self.queue.get(), 5)
        assert record.topic == topic
        assert isinstance(record.message, message_type)
        return record


class Identity:
    """Signed JWTs and the real STE/CC adapters, with only urlopen replaced."""

    def __init__(self, monkeypatch):
        self.keys = Keys()
        self.exchanges = []
        self.client_subject = str(uuid4())
        monkeypatch.setattr("ads_commons_beans.token_exchange.urlopen", self.endpoint)
        monkeypatch.setattr("ads_sandbox_ipc.auth.urlopen", self.endpoint)
        monkeypatch.setattr("ads_sandbox_manager.auth.urlopen", self.endpoint)

    def verifier(self, client):
        return JwtVerifier(
            JwtVerifierSettings(
                "https://identity.test", client, client, "https://unused.test/jwks", None
            ),
            self.keys,
        )

    def settings(self, client):
        return TokenExchangeSettings("https://identity.test/token", client, "fixture", None)

    def exchange(self, client):
        return TokenExchange(self.settings(client), self.verifier(client))

    def endpoint(self, request, **kwargs):
        body = {key: values[0] for key, values in parse_qs(request.data.decode()).items()}
        client = body["client_id"]
        if body["grant_type"] == "client_credentials":
            assert client in (IPC, MANAGER)
            token = self.keys.token(aud=MANAGER, azp=client, sub=self.client_subject)
        else:
            assert body["grant_type"] == "urn:ietf:params:oauth:grant-type:token-exchange"
            assert body["subject_token_type"] == "urn:ietf:params:oauth:token-type:access_token"
            assert body["requested_token_type"] == "urn:ietf:params:oauth:token-type:access_token"
            # Validate the subject token for the exchanging client, not merely decode it.
            context = self.verifier(client).authenticate(body["subject_token"])
            audience = body["audience"]
            assert (client, audience) in {
                (MCP, MANAGER),
                (MANAGER, IPC),
                (IPC, MANAGER),
                (MANAGER, MCP),
            }
            token = self.keys.token(aud=audience, azp=client, sub=context.subject)
            self.exchanges.append((client, audience, body["subject_token"], token))
        return BytesIO(json.dumps({"access_token": token}).encode())


class Handshake:
    def __init__(self, manager, mcp: McpHarness, directory: Path, monkeypatch):
        self.manager = manager
        self.mcp = mcp
        self.identity = Identity(monkeypatch)
        self.broker = Broker()
        self.ipc = None
        self.tasks = []
        mcp.keys = self.identity.keys
        mcp.verifier = self.identity.verifier(MCP)
        # Keep the existing HTTP harness's runtime/scheduler doubles, but replace its
        # fake-manager service with actual wire publishers and real exchange adapters.
        mcp.service = ExecService(
            mcp.settings,
            mcp.sessions,
            mcp.repository,
            McpPublisher(self.broker, mcp.settings),
            self.identity.exchange(MCP),
            Watchdog(mcp.settings),
        )
        self.mcp_replies = ReplyController(mcp.verifier, mcp.service)

        # Real KafkaTransport.send serializes the manager key/header. Broker clients
        # are inert: rebalance/barrier behavior is covered by the slice-9 tests.
        monkeypatch.setattr(manager_kafka, "AIOKafkaProducer", lambda **_: self.broker)
        monkeypatch.setattr(manager_kafka, "AIOKafkaConsumer", lambda **_: AsyncMock())
        monkeypatch.setattr(manager_kafka, "AIOKafkaAdminClient", lambda **_: AsyncMock())
        transport = manager_kafka.KafkaTransport(manager.settings, AsyncMock())
        self.transit = TransitService(
            replace(manager.settings, ready_seconds=10, control_seconds=5),
            manager.sessions,
            manager.repository,
            manager.service,
            transport,
            self.identity.exchange(MANAGER),
            AsyncMock(),
        )
        self.manager_controller = ManagerController(
            self.transit.settings,
            self.identity.verifier(MANAGER),
            self.transit,
            AsyncMock(),
            AsyncMock(),
        )

        async def created(body):
            if body["kind"] != "Deployment" or not body["metadata"]["name"].startswith(
                "ads-sandbox-ipc-"
            ):
                return
            # Simulated scheduling boots the real IPC startup state machine.
            sandbox_id = UUID(body["metadata"]["labels"]["ads.io/sandbox-id"])
            self.ipc = IpcHarness(
                directory,
                sandbox_id=sandbox_id,
                timeout_seconds=10,
                ack_seconds=10,
                startup_seconds=10,
                control_seconds=5,
            )
            ipc = self.ipc
            ipc.publisher = IpcPublisher(
                ipc.settings,
                self.broker,
                self.identity.exchange(IPC),
                ClientCredentials(self.identity.settings(IPC), self.identity.verifier(IPC)),
            )
            ipc.service = IpcService(ipc.settings, ipc.guest, ipc.publisher)
            ipc.controller = IpcController(ipc.settings, self.identity.verifier(IPC), ipc.service)
            ipc.service.start()

        manager.kube.after_create = created

    @asynccontextmanager
    async def http(self):
        # Litestar's AsyncTestClient uses a blocking portal on another loop. Keep
        # the in-memory broker, HTTP waiter and all three services on this loop.
        app = self.mcp.app()
        async with app.lifespan():
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://testserver.local"
            ) as client:
                try:
                    yield client
                finally:
                    await self.close()

    def call(self, client, name, argument, payload, *, session_id=None):
        headers = self.mcp.headers("tools/call", name)
        if session_id:
            headers["x-ads-session-id"] = str(session_id)
        task = asyncio.create_task(
            client.post(
                "/mcp",
                headers=headers,
                json=rpc("tools/call", name=name, arguments={argument: payload}),
            )
        )
        self.tasks.append(task)
        return task, headers

    async def deliver(self, record):
        assert SecurityContextHolder.get() is None
        if record.topic == REPLY_TOPIC:
            await self.mcp_replies.on_message(record.value, record.headers)
        elif self.ipc and record.topic in (self.ipc.settings.request_topic, PING_REQUEST):
            await self.ipc.controller.on_message(record.topic, record.value, record.headers)
        else:
            await self.manager_controller.on_message(
                record.topic, record.value, record.key, record.headers
            )
        assert SecurityContextHolder.get() is None

    async def mcp_row(self, execution_id):
        async with self.mcp.sessions.begin() as db:
            return await self.mcp.repository.locked(db, execution_id)

    async def close(self):
        for task in self.tasks:
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        await self.transit.stop()
        if self.ipc:
            await self.ipc.service.stop()
