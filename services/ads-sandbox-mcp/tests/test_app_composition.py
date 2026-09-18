"""Prove ownership and failure unwinding without a broker or database server."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import replace
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, Mock

import pytest
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from dishka import Provider, Scope, make_async_container, provide
from httpx import ASGITransport, AsyncClient
from mcp.server import Server
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from ads_commons_beans import CommonsBeansProvider, JwtVerifier
from ads_sandbox_mcp.app import create_app
from ads_sandbox_mcp.controller import ToolController
from ads_sandbox_mcp.ioc import AppProvider
from ads_sandbox_mcp.kafka import KafkaRuntime, ReplyController
from ads_sandbox_mcp.runtime import McpRuntime
from ads_sandbox_mcp.scheduler import ClusterScheduler
from ads_sandbox_mcp.service import ExecService, Publisher, TokenMinter
from ads_sandbox_mcp.store import InFlightRepository
from sandbox_support import FakePublisher, FakeTokens, Keys

pytestmark = pytest.mark.anyio


class BoundaryOverrides(Provider):
    """Replace external boundaries, not the service, controllers, SDK, or app runtime."""

    def __init__(self):
        super().__init__()
        self.keys = Keys()
        self.token_minter = FakeTokens(self.keys)
        self.publication = FakePublisher(self.keys)
        self.producer_client = Mock(start=AsyncMock(), stop=AsyncMock())
        self.consumer_client = Mock(start=AsyncMock(), stop=AsyncMock())

        async def consume():
            await asyncio.Event().wait()
            yield  # pragma: no cover - no records in lifecycle-only tests.

        self.consumer_client.__aiter__ = lambda _: consume()

    @provide(scope=Scope.APP, override=True)
    def verifier(self) -> JwtVerifier:
        return self.keys.verifier()

    @provide(scope=Scope.APP, override=True)
    def tokens(self) -> TokenMinter:
        return self.token_minter

    @provide(scope=Scope.APP, override=True)
    def publisher(self) -> Publisher:
        return self.publication

    @provide(scope=Scope.APP, override=True)
    def producer(self) -> AIOKafkaProducer:
        return self.producer_client

    @provide(scope=Scope.APP, override=True)
    def consumer(self) -> AIOKafkaConsumer:
        return self.consumer_client


@pytest.mark.parametrize("input_bytes", [262144, 1_000_000])
async def test_production_graph_owns_sdk_and_disposes_engine_once(
    sandbox_settings, monkeypatch, input_bytes
):
    engine = Mock(spec=AsyncEngine, dispose=AsyncMock())
    factory = Mock(return_value=engine)
    monkeypatch.setattr("ads_sandbox_mcp.ioc.create_async_engine", factory)
    boundary = BoundaryOverrides()
    settings = replace(
        sandbox_settings, input_bytes=input_bytes, allowed_origins=("https://engine.test",)
    )
    container = make_async_container(CommonsBeansProvider(), AppProvider(settings), boundary)
    try:
        factory.assert_not_called()
        runtime = await container.get(McpRuntime)
        sdk = await container.get(Server[Any])
        tools = await container.get(ToolController)
        service = await container.get(ExecService)
        replies = await container.get(ReplyController)
        scheduler = await container.get(ClusterScheduler)
        assert runtime is await container.get(McpRuntime)
        assert runtime.sdk is sdk
        assert tools._service is service and replies._service is service
        assert runtime._kafka is await container.get(KafkaRuntime)
        assert runtime._scheduler is scheduler
        assert service._sessions is await container.get(async_sessionmaker[AsyncSession])
        assert service._repository is await container.get(InFlightRepository)
        assert service._publisher is boundary.publication
        assert service._tokens is boundary.token_minter
        assert scheduler._engine is engine
        manager = sdk.session_manager
        assert manager.json_response is True
        assert manager.stateless is True
        assert manager.max_request_body_size == max(4194304, settings.input_bytes * 6 + 65536)
        assert manager.security_settings.allowed_hosts == list(settings.allowed_hosts)
        assert manager.security_settings.allowed_origins == list(settings.allowed_origins)
        factory.assert_called_once_with(settings.database_url, pool_pre_ping=True)
        engine.dispose.assert_not_awaited()
    finally:
        await container.close()
    engine.dispose.assert_awaited_once()


class Lifecycle:
    def __init__(self, failure=None):
        self.events = []
        self.failure = failure

    def event(self, name):
        self.events.append(name)
        if name == self.failure:
            raise RuntimeError(name)

    async def kafka_start(self):
        self.event("kafka.start")

    async def kafka_stop(self):
        self.event("kafka.stop")

    async def scheduler_start(self):
        self.event("scheduler.start")

    async def scheduler_stop(self):
        self.event("scheduler.stop")

    @asynccontextmanager
    async def sdk_run(self):
        self.event("sdk.start")
        try:
            yield
        finally:
            self.event("sdk.stop")

    def runtime(self):
        self.kafka = Mock(
            start=self.kafka_start, stop=self.kafka_stop, ready=Mock(return_value=True)
        )
        return McpRuntime(
            SimpleNamespace(session_manager=SimpleNamespace(run=self.sdk_run)),
            self.kafka,
            Mock(start=self.scheduler_start, stop=self.scheduler_stop),
        )


@pytest.mark.parametrize(
    "failure,expected",
    [
        (
            None,
            [
                "kafka.start",
                "scheduler.start",
                "sdk.start",
                "body",
                "sdk.stop",
                "scheduler.stop",
                "kafka.stop",
            ],
        ),
        ("kafka.start", ["kafka.start"]),
        ("scheduler.start", ["kafka.start", "scheduler.start", "scheduler.stop", "kafka.stop"]),
        (
            "sdk.start",
            ["kafka.start", "scheduler.start", "sdk.start", "scheduler.stop", "kafka.stop"],
        ),
        (
            "body",
            [
                "kafka.start",
                "scheduler.start",
                "sdk.start",
                "body",
                "sdk.stop",
                "scheduler.stop",
                "kafka.stop",
            ],
        ),
        (
            "sdk.stop",
            [
                "kafka.start",
                "scheduler.start",
                "sdk.start",
                "body",
                "sdk.stop",
                "scheduler.stop",
                "kafka.stop",
            ],
        ),
        (
            "scheduler.stop",
            [
                "kafka.start",
                "scheduler.start",
                "sdk.start",
                "body",
                "sdk.stop",
                "scheduler.stop",
                "kafka.stop",
            ],
        ),
        (
            "kafka.stop",
            [
                "kafka.start",
                "scheduler.start",
                "sdk.start",
                "body",
                "sdk.stop",
                "scheduler.stop",
                "kafka.stop",
            ],
        ),
    ],
)
async def test_runtime_order_and_failure_unwinding(failure, expected):
    lifecycle = Lifecycle(failure)
    runtime = lifecycle.runtime()

    async def run():
        async with runtime.run():
            assert runtime.ready()
            lifecycle.event("body")

    if failure:
        with pytest.raises(RuntimeError, match=failure):
            await run()
    else:
        await run()
    assert lifecycle.events == expected


async def test_runtime_cancellation_unwinds_in_reverse_order():
    lifecycle = Lifecycle()
    entered = asyncio.Event()

    async def run():
        async with lifecycle.runtime().run():
            entered.set()
            await asyncio.Event().wait()

    task = asyncio.create_task(run())
    await asyncio.wait_for(entered.wait(), 2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert lifecycle.events == [
        "kafka.start",
        "scheduler.start",
        "sdk.start",
        "sdk.stop",
        "scheduler.stop",
        "kafka.stop",
    ]


@pytest.mark.parametrize("failure", [None, "construct", "kafka.start", "body", "scheduler.stop"])
async def test_app_closes_dishka_resources_on_every_exit(sandbox_settings, failure):
    lifecycle = Lifecycle(failure)
    runtime = lifecycle.runtime()
    keys = Keys()

    class Overrides(Provider):
        @provide(scope=Scope.APP, override=True)
        def verifier(self) -> JwtVerifier:
            return keys.verifier()

        @provide(scope=Scope.APP, override=True)
        async def engine(self) -> AsyncIterator[AsyncEngine]:
            lifecycle.event("engine.open")
            try:
                yield Mock(spec=AsyncEngine)
            finally:
                lifecycle.event("engine.close")

        @provide(scope=Scope.APP, override=True)
        def runtime(self, engine: AsyncEngine) -> McpRuntime:
            lifecycle.event("construct")
            return runtime

    app = create_app(sandbox_settings, overrides=(Overrides(),))
    assert lifecycle.events == []  # No loop-bound dependencies at assembly time.

    async def run():
        async with app.lifespan():
            assert app.state.runtime is runtime
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="https://testserver.local"
            ) as client:
                assert (await client.get("/health/live")).status_code == 200
                assert (await client.get("/health/ready")).status_code == 200
                runtime._kafka.ready.return_value = False
                response = await client.get("/health/ready")
                assert response.status_code == 503
                assert response.json() == {"status": "unavailable"}
            lifecycle.event("body")

    if failure:
        with pytest.RaisesGroup(
            pytest.RaisesExc(RuntimeError, match=failure), flatten_subgroups=True
        ):
            await run()
    else:
        await run()
    assert lifecycle.events[0] == "engine.open"
    assert lifecycle.events[-1] == "engine.close"
    assert lifecycle.events.count("engine.close") == 1


async def test_app_startup_failure_disposes_production_engine(sandbox_settings, monkeypatch):
    engine = Mock(spec=AsyncEngine, dispose=AsyncMock())
    monkeypatch.setattr("ads_sandbox_mcp.ioc.create_async_engine", lambda *a, **kw: engine)
    boundary = BoundaryOverrides()
    boundary.consumer_client.start.side_effect = RuntimeError("broker unavailable")
    app = create_app(sandbox_settings, overrides=(boundary,))
    with pytest.RaisesGroup(
        pytest.RaisesExc(RuntimeError, match="broker unavailable"), flatten_subgroups=True
    ):
        async with app.lifespan():
            pytest.fail("startup must not reach ready")
    boundary.producer_client.stop.assert_awaited_once()
    engine.dispose.assert_awaited_once()


async def test_sdk_is_app_scoped_not_shared_between_containers(sandbox_settings, monkeypatch):
    engines = []

    def engine(*args, **kwargs):
        value = Mock(spec=AsyncEngine, dispose=AsyncMock())
        engines.append(value)
        return value

    monkeypatch.setattr("ads_sandbox_mcp.ioc.create_async_engine", engine)
    first = make_async_container(
        CommonsBeansProvider(), AppProvider(sandbox_settings), BoundaryOverrides()
    )
    second = make_async_container(
        CommonsBeansProvider(), AppProvider(sandbox_settings), BoundaryOverrides()
    )
    try:
        first_sdk = await first.get(Server[Any])
        assert first_sdk is await first.get(Server[Any])
        assert first_sdk is not await second.get(Server[Any])
    finally:
        await second.close()
        await first.close()
    assert len(engines) == 2
    for value in engines:
        value.dispose.assert_awaited_once()


async def test_sdk_failure_after_database_resolution_disposes_engine(sandbox_settings, monkeypatch):
    engine = Mock(spec=AsyncEngine, dispose=AsyncMock())
    monkeypatch.setattr("ads_sandbox_mcp.ioc.create_async_engine", lambda *a, **kw: engine)
    monkeypatch.setattr(
        "ads_sandbox_mcp.ioc.Server", Mock(side_effect=RuntimeError("SDK construction failed"))
    )
    boundary = BoundaryOverrides()
    app = create_app(sandbox_settings, overrides=(boundary,))
    with pytest.RaisesGroup(
        pytest.RaisesExc(RuntimeError, match="SDK construction failed"), flatten_subgroups=True
    ):
        async with app.lifespan():
            pytest.fail("startup must not reach ready")
    boundary.producer_client.start.assert_not_awaited()
    boundary.consumer_client.start.assert_not_awaited()
    engine.dispose.assert_awaited_once()
