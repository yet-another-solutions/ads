from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import httpx2
import msgspec
import pytest
from litestar.testing import TestClient
from redis.asyncio import Redis

from ads_policy.app import create_app
from ads_policy.audit import CollectingAuditSink
from ads_policy.client import HttpPolicyClient, PolicyUnavailable, UnconfiguredPolicyClient
from ads_policy.config import GovernanceSettings, Settings
from ads_policy.contract import IsolationLevel, Run, RunState
from ads_policy.run import InMemoryRunStore, RedisRunStore, RunStore
from ads_policy.service import PolicyService
from policy_helpers import run_context, run_request

TOKEN = "policy-api-token-32-bytes-long"
SETTINGS = GovernanceSettings()
ALICE = "user:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
HERMES = "key:" + "b" * 64


async def _start(store: RunStore, holder: str = ALICE) -> Run:
    return await store.start(
        subject="alice",
        context=run_context(),
        isolation_level=IsolationLevel.VM,
        policy_hash="hash",
        holder=holder,
    )


@pytest.fixture(params=["memory", "redis"])
def store(request: pytest.FixtureRequest, redis: Redis) -> RunStore:
    if request.param == "memory":
        return InMemoryRunStore()
    return RedisRunStore(redis)


@pytest.mark.anyio
async def test_runs_are_found_by_their_holder(store: RunStore) -> None:
    first = await _start(store)
    second = await _start(store)
    await _start(store, holder=HERMES)
    assert {run.id for run in await store.held_by(ALICE)} == {first.id, second.id}


@pytest.mark.anyio
async def test_the_holder_is_kept_on_the_run(store: RunStore) -> None:
    run = await _start(store)
    fetched = await store.get(run.id)
    assert fetched is not None
    assert fetched.holder == ALICE


@pytest.mark.anyio
async def test_a_run_without_a_holder_is_held_by_nobody(store: RunStore) -> None:
    await _start(store, holder="")
    assert await store.held_by("") == []


@pytest.mark.anyio
async def test_a_stranger_holds_nothing(store: RunStore) -> None:
    await _start(store)
    assert await store.held_by(HERMES) == []


@pytest.mark.anyio
async def test_an_expired_run_drops_out_of_its_holder(redis: Redis) -> None:
    store = RedisRunStore(redis)
    gone = await _start(store)
    kept = await _start(store)
    await redis.delete(f"ads:run:{gone.id}")
    assert [run.id for run in await store.held_by(ALICE)] == [kept.id]
    assert await redis.smembers(f"ads:holder:{ALICE}") == {kept.id.encode()}


@pytest.mark.anyio
async def test_the_index_lives_as_long_as_a_run(redis: Redis) -> None:
    store = RedisRunStore(redis, GovernanceSettings(run_ttl_seconds=120))
    await _start(store)
    assert 0 < await redis.ttl(f"ads:holder:{ALICE}") <= 120


@pytest.mark.anyio
async def test_held_runs_come_back_in_whatever_state_they_are(service: PolicyService) -> None:
    first = await service.start(run_request(IsolationLevel.VM, holder=ALICE))
    second = await service.start(run_request(IsolationLevel.VM, holder=ALICE))
    await service.revoke(first.id)
    await service.finish(second.id)
    states = {run.id: run.state for run in await service.held_by(ALICE)}
    assert states == {first.id: RunState.REVOKED, second.id: RunState.FINISHED}


@pytest.mark.anyio
async def test_a_finished_run_decides_nothing(service: PolicyService) -> None:
    run = await service.start(run_request(IsolationLevel.VM, holder=ALICE))
    finished = await service.finish(run.id)
    assert finished is not None
    assert finished.state is RunState.FINISHED


@pytest.mark.anyio
async def test_finishing_does_not_undo_a_revocation(service: PolicyService) -> None:
    run = await service.start(run_request(IsolationLevel.VM))
    await service.revoke(run.id)
    finished = await service.finish(run.id)
    assert finished is not None
    assert finished.state is RunState.REVOKED


@pytest.mark.anyio
async def test_finishing_an_unknown_run_says_so(service: PolicyService) -> None:
    assert await service.finish("never-opened") is None


@pytest.mark.anyio
async def test_a_run_is_looked_up_by_id(service: PolicyService) -> None:
    run = await service.start(run_request(IsolationLevel.VM))
    found = await service.run(run.id)
    assert found is not None
    assert found.id == run.id
    assert await service.run("never-opened") is None


@pytest.fixture
def api(tmp_path: Path, redis: Redis) -> Iterator[TestClient]:
    cert = tmp_path / "tls.crt"
    key = tmp_path / "tls.key"
    cert.write_text("placeholder")
    key.write_text("placeholder")
    settings = Settings(
        api_token=TOKEN,
        tls_cert_path=cert,
        tls_key_path=key,
        redis_url="redis://unused",
        amqp_url="amqp://unused",
        governance=GovernanceSettings(policy_dir=tmp_path / "missing"),
    )
    with TestClient(app=create_app(settings, redis, CollectingAuditSink())) as client:
        client.headers["authorization"] = f"Bearer {TOKEN}"
        yield client


def _open(api: TestClient, holder: str = ALICE) -> str:
    body = msgspec.to_builtins(run_request(IsolationLevel.VM, holder=holder))
    response = api.post("/policy/runs", json=body)
    assert response.status_code == 201
    return str(response.json()["id"])


def test_a_run_is_finished_over_the_api(api: TestClient) -> None:
    opened = _open(api)
    finished = api.post(f"/policy/runs/{opened}/finish")
    assert finished.status_code == 201
    assert finished.json()["state"] == RunState.FINISHED.value
    assert api.post("/policy/runs/never-opened/finish").status_code == 404


def test_held_runs_are_listed_by_holder(api: TestClient) -> None:
    opened = _open(api)
    _open(api, holder=HERMES)
    listed = api.get("/policy/runs", params={"holder": ALICE}).json()
    assert [run["id"] for run in listed] == [opened]
    assert listed[0]["holder"] == ALICE


def test_a_listing_without_a_holder_is_refused(api: TestClient) -> None:
    assert api.get("/policy/runs", params={"holder": ""}).status_code == 400
    assert api.get("/policy/runs").status_code == 400


def test_a_run_is_fetched_by_id(api: TestClient) -> None:
    opened = _open(api)
    assert api.get(f"/policy/runs/{opened}").json()["id"] == opened
    assert api.get("/policy/runs/never-opened").status_code == 404


def test_the_lookups_need_the_token(api: TestClient) -> None:
    del api.headers["authorization"]
    assert api.get("/policy/runs", params={"holder": ALICE}).status_code == 401
    assert api.get("/policy/runs/anything").status_code == 401
    assert api.post("/policy/runs/anything/finish").status_code == 401


def _client(handler: object) -> HttpPolicyClient:
    return HttpPolicyClient(
        "https://ads-policy.interlab:8081",
        TOKEN,
        denied_message=SETTINGS.denied_message,
        transport=httpx2.MockTransport(handler),  # type: ignore[arg-type]
    )


def _run(holder: str = ALICE) -> Run:
    return Run(
        id="run-1",
        subject="alice",
        context=run_context(),
        isolation_level=IsolationLevel.VM,
        policy_hash="hash",
        state=RunState.RUNNING,
        holder=holder,
    )


def test_the_client_lists_runs_by_holder() -> None:
    seen: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(request)
        return httpx2.Response(200, content=msgspec.json.encode([_run()]))

    runs = _client(handler).runs_held(ALICE)
    assert [run.id for run in runs] == ["run-1"]
    assert seen[0].url.path == "/policy/runs"
    assert seen[0].url.params["holder"] == ALICE


def test_the_client_finishes_a_run() -> None:
    seen: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(request)
        finished = msgspec.structs.replace(_run(), state=RunState.FINISHED)
        return httpx2.Response(200, content=msgspec.json.encode(finished))

    finished = _client(handler).finish_run("run-1")
    assert finished is not None
    assert finished.state is RunState.FINISHED
    assert seen[0].method == "POST"
    assert seen[0].url.path == "/policy/runs/run-1/finish"


def test_the_client_says_when_there_is_nothing_to_finish() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(404, json={"detail": "no such run"})

    assert _client(handler).finish_run("never-opened") is None


def test_the_client_says_when_a_run_is_unknown() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(404, json={"detail": "no such run"})

    assert _client(handler).run("never-opened") is None


def test_the_client_fetches_a_run() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        assert request.url.path == "/policy/runs/run-1"
        return httpx2.Response(200, content=msgspec.json.encode(_run()))

    found = _client(handler).run("run-1")
    assert found is not None
    assert found.holder == ALICE


@pytest.mark.parametrize(
    "handler",
    [
        lambda request: httpx2.Response(500),
        lambda request: httpx2.Response(200, content=b"not json"),
        lambda request: httpx2.Response(200, json={"id": 1}),
    ],
)
def test_a_lookup_that_cannot_be_answered_is_not_an_empty_answer(handler: object) -> None:
    client = _client(handler)
    with pytest.raises(PolicyUnavailable):
        client.runs_held(ALICE)
    with pytest.raises(PolicyUnavailable):
        client.run("run-1")
    with pytest.raises(PolicyUnavailable):
        client.finish_run("run-1")


def test_an_unreachable_service_is_unavailable() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        raise httpx2.ConnectError("no route", request=request)

    with pytest.raises(PolicyUnavailable):
        _client(handler).runs_held(ALICE)


def test_an_unconfigured_client_looks_nothing_up() -> None:
    client = UnconfiguredPolicyClient(SETTINGS.denied_message)
    with pytest.raises(PolicyUnavailable):
        client.runs_held(ALICE)
    with pytest.raises(PolicyUnavailable):
        client.run("run-1")
    with pytest.raises(PolicyUnavailable):
        client.finish_run("run-1")
