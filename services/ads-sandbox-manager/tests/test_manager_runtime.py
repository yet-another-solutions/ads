from __future__ import annotations

import asyncio
from dataclasses import replace
from unittest.mock import AsyncMock, Mock

import pytest
from dishka import Provider, Scope, provide
from kubernetes.client.exceptions import ApiException
from litestar.testing import AsyncTestClient
from sqlalchemy.ext.asyncio import create_async_engine

from ads_sandbox_manager.app import create_app
from ads_sandbox_manager.health import Dependencies, DependencyHealth
from ads_sandbox_manager.kafka import KafkaRuntime
from ads_sandbox_manager.kube import Kubernetes
from ads_sandbox_manager.runtime import ManagerRuntime

pytestmark = pytest.mark.anyio


def fake_kafka():
    return Mock(ready=True, start=AsyncMock(), stop=AsyncMock())


async def test_probes_transition_only_after_release_and_dependencies(baked):
    dependency = AsyncMock(spec=Dependencies)
    dependency.check.return_value = True

    class Overrides(Provider):
        @provide(scope=Scope.APP, override=True)
        def kafka(self) -> KafkaRuntime:
            return fake_kafka()

        @provide(scope=Scope.APP, override=True)
        def kube(self) -> Kubernetes:
            return baked.kube

        @provide(scope=Scope.APP, override=True)
        def deps(self) -> Dependencies:
            return dependency

    async with AsyncTestClient(create_app(baked.settings, overrides=(Overrides(),))) as http:
        runtime = http.app.state.manager
        await runtime.check()
        assert (await http.get("/health/live")).status_code == 200
        assert (await http.get("/health/ready")).status_code == 503
        assert not dependency.check.called
        baked.kube.is_released = True
        await runtime.check()
        assert (await http.get("/health/ready")).status_code == 200
        dependency.check.return_value = False
        await runtime.check()
        assert (await http.get("/health/ready")).status_code == 503
        assert (await http.get("/health/live")).status_code == 200
        assert (await http.post("/health/ready")).status_code == 405
        assert (await http.post("/ensure")).status_code == 404
        assert (await http.get("/schema")).status_code == 404
    assert not runtime.ready
    assert runtime._task is None


@pytest.mark.parametrize(
    "error",
    [
        ApiException(status=403, reason="private-token"),
        ApiException(status=409),
        ApiException(status=404),
        RuntimeError("postgresql://private-token"),
        TimeoutError("private-token"),
    ],
)
async def test_poll_errors_fail_closed_and_next_pass_recovers(manager_settings, caplog, error):
    golden, dependencies = AsyncMock(), AsyncMock()
    golden.poll.side_effect = error
    runtime = ManagerRuntime(manager_settings, golden, dependencies, fake_kafka())
    await runtime.start()
    try:
        await runtime.check()
        assert not runtime.ready
        assert not dependencies.check.called
        assert "private-token" not in caplog.text
        golden.poll.side_effect = None
        golden.poll.return_value = True
        dependencies.check.return_value = True
        await runtime.check()
        assert runtime.ready
    finally:
        await runtime.stop()


async def test_bounded_poll_process_live_and_no_stale_ready(manager_settings):
    settings = replace(manager_settings, control_seconds=0.02)
    golden, dependency = AsyncMock(), AsyncMock()
    gate = asyncio.Event()

    async def stuck():
        await gate.wait()
        return True

    golden.poll.side_effect = stuck
    runtime = ManagerRuntime(settings, golden, dependency, fake_kafka())
    await runtime.start()
    await asyncio.wait_for(runtime.check(), timeout=1)
    assert not runtime.ready
    await runtime.stop()
    assert not runtime.ready


async def test_cancel_stops_without_deleting_cluster_objects(baked):
    runtime = ManagerRuntime(baked.settings, baked.golden, AsyncMock(), fake_kafka())
    await runtime.start()
    task = runtime._task
    await runtime.start()
    assert runtime._task is task
    await runtime.stop()
    await runtime.stop()
    assert not baked.kube.calls


async def test_completed_or_stale_background_task_cannot_report_ready(manager_settings):
    runtime = ManagerRuntime(manager_settings, AsyncMock(), AsyncMock(), fake_kafka())
    runtime._ready = True
    assert not runtime.ready
    runtime._task = asyncio.create_task(asyncio.sleep(100))
    assert not runtime.ready  # No fresh completed check.
    runtime._task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await runtime._task
    assert not runtime.ready


async def test_dependency_health_uses_select_one_and_kafka_metadata_only(
    manager_settings, monkeypatch
):
    engine, connection = Mock(), AsyncMock()
    engine.connect.return_value.__aenter__ = AsyncMock(return_value=connection)
    engine.connect.return_value.__aexit__ = AsyncMock(return_value=False)
    kafka = AsyncMock()
    factory = Mock(return_value=kafka)
    monkeypatch.setattr("ads_sandbox_manager.health.AIOKafkaClient", factory)
    settings = replace(
        manager_settings,
        kafka_security_protocol="SASL_SSL",
        kafka_sasl_username="manager",
        kafka_sasl_password="fixture-secret",
    )
    health = DependencyHealth(settings, engine)
    assert await health.check()
    assert str(connection.execute.call_args.args[0]) == "SELECT 1"
    kafka.bootstrap.assert_awaited_once()
    kafka.close.assert_awaited_once()
    assert factory.call_args.kwargs["security_protocol"] == "SASL_SSL"
    assert factory.call_args.kwargs["ssl_context"].check_hostname
    assert factory.call_args.kwargs["sasl_plain_password"] == "fixture-secret"
    assert not kafka.send.called


async def test_kafka_failure_closes_client_and_postgres_failure_does_not_connect_kafka(
    manager_settings, monkeypatch
):
    engine, connection = Mock(), AsyncMock()
    engine.connect.return_value.__aenter__ = AsyncMock(return_value=connection)
    engine.connect.return_value.__aexit__ = AsyncMock(return_value=False)
    kafka = AsyncMock()
    kafka.bootstrap.side_effect = RuntimeError("offline")
    factory = Mock(return_value=kafka)
    monkeypatch.setattr("ads_sandbox_manager.health.AIOKafkaClient", factory)
    health = DependencyHealth(manager_settings, engine)
    with pytest.raises(RuntimeError, match="offline"):
        await health.check()
    kafka.close.assert_awaited_once()
    factory.reset_mock()
    connection.execute.side_effect = RuntimeError("database offline")
    with pytest.raises(RuntimeError, match="database offline"):
        await health.check()
    factory.assert_not_called()


async def test_health_against_real_postgres_without_creating_slice_eight_schema(
    manager_settings, manager_database_url, monkeypatch
):
    settings = replace(manager_settings, database_url=manager_database_url, control_seconds=5)
    kafka = AsyncMock()
    monkeypatch.setattr("ads_sandbox_manager.health.AIOKafkaClient", Mock(return_value=kafka))
    engine = create_async_engine(settings.database_url)
    try:
        assert await DependencyHealth(settings, engine).check()
        kafka.bootstrap.assert_awaited_once()
        kafka.close.assert_awaited_once()
    finally:
        await engine.dispose()
