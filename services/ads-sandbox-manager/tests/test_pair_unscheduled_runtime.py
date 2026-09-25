# ruff: noqa: F811
from __future__ import annotations

import asyncio
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock

import pytest
from kubernetes.client.exceptions import ApiException
from sqlalchemy import delete

from ads_sandbox_manager.lifecycle_store import CleanupWork, LifecycleRepository
from ads_sandbox_manager.pair_runtime_teardown import PairRuntimeTeardown
from ads_sandbox_manager.pair_store import PairClaimLost, PairIntent
from ads_sandbox_manager.pair_unscheduled_proof import RUNTIME_ROLES, never_scheduled
from ads_sandbox_manager.store import SandboxSession
from test_kube_release import api  # noqa: F401
from test_pair_controls import controls  # noqa: F401
from test_pair_creation import build, creation  # noqa: F401
from test_pair_creator_fence import cleanup_claim
from test_pair_store import ledger, snapshot  # noqa: F401
from test_pair_volume_publication import publication as volume_publication  # noqa: F401
from test_session_objects import object_settings  # noqa: F401
from test_sessions import sessions_harness  # noqa: F401

pytestmark = pytest.mark.anyio


@pytest.fixture
async def unscheduled_runtime(creation, request):
    f = creation
    if getattr(request, "param", None) == "ipc-unissued":
        reserve = f.creator.ipc.repository.reserve

        async def stop_before_pod(db, row, owner, generation, role, payload):
            if role == "pod":
                raise RuntimeError("stop before original IPC Pod reservation")
            return await reserve(db, row, owner, generation, role, payload)

        f.creator.ipc.repository.reserve = stop_before_pod
        with pytest.raises(RuntimeError, match="before original IPC"):
            await build(f)
        f.creator.ipc.repository.reserve = reserve
    else:
        await build(f)
    f.capture, f.work, f.claim = await cleanup_claim(f)
    f.storage = AsyncMock()
    f.runtime = PairRuntimeTeardown(
        replace(f.service.settings, cleanup_seconds=60, recovery_seconds=120),
        f.h.sessions,
        f.capture.repository,
        f.adapter,
        f.storage,
    )
    f.events, f.hold_api, f.hook = [], False, None
    pair = f.capture.repository.cleanup_pair(f.work)
    f.pods = {
        role: f.remote.objects[("Pod", f.adapter._runtime_identity(pair, role)["metadata"]["name"])]
        for role in RUNTIME_ROLES
        if ("Pod", f.adapter._runtime_identity(pair, role)["metadata"]["name"]) in f.remote.objects
    }
    for pod in f.pods.values():
        pod["spec"].pop("nodeName", None)
        pod["status"] = {"phase": "Pending"}

    def remove(name, namespace, *, body, **kwargs):
        key = ("Pod", name)
        if key not in f.remote.objects:
            raise ApiException(status=404)
        pod = f.remote.objects[key]
        if body["preconditions"] != {
            "uid": pod["metadata"]["uid"],
            "resourceVersion": pod["metadata"]["resourceVersion"],
        }:
            raise ApiException(status=409)
        pod["metadata"].update(
            deletionTimestamp=datetime.now(UTC).isoformat(),
            resourceVersion=str(int(pod["metadata"]["resourceVersion"]) + 1),
        )
        reply = deepcopy(pod)
        if not f.hold_api:
            del f.remote.objects[key]
        return reply

    f.adapter.kube.core.delete_namespaced_pod.side_effect = remove
    original = f.adapter.delete_unscheduled

    async def delete_unscheduled(pair, role, captured):
        # Reservation and permanent creator fence must be visible outside the
        # caller's transaction before the destructive adapter starts.
        async with f.h.sessions.begin() as db:
            intent = await db.get(PairIntent, f.intent.generation, with_for_update=True)
            assert intent.creation_fenced
            attempt = intent.cleanup_journal["unscheduled"][role][-1]
            assert attempt["capture"] == captured and attempt["dispatch"] == "inflight"
        f.events.append(role)
        if f.hook:
            await f.hook(role)
        return await original(pair, role, captured)

    f.adapter.delete_unscheduled = delete_unscheduled
    yield f
    await f.runtime.drain()


async def release(f):
    return await f.runtime.release(f.work, recovery=f.claim)


async def journal(f):
    return (await snapshot(f, f.intent.generation)).cleanup_journal


async def test_all_original_unscheduled_pods_release_without_fabricated_node_inventory(
    unscheduled_runtime,
):
    f = unscheduled_runtime
    before = deepcopy(f.remote.objects)
    assert await release(f)
    saved = await journal(f)
    assert f.events == list(RUNTIME_ROLES)  # IPC admission excluded before private compute.
    assert all(never_scheduled(saved, role) for role in RUNTIME_ROLES)
    assert saved["node_capture"] is None and saved["ipc_capture"] is None
    assert saved["runtime_release"] is None and saved["storage_capture"] == {}
    assert not f.storage.mock_calls
    assert {key: value for key, value in before.items() if key[0] != "Pod"} == f.remote.objects
    f.runtime = PairRuntimeTeardown(
        f.runtime.settings, f.h.sessions, LifecycleRepository(), f.adapter, f.storage
    )
    assert await release(f)
    assert await journal(f) == saved and f.events == list(RUNTIME_ROLES)
    async with f.h.sessions.begin() as db:
        assert not await f.capture.repository.complete(db, f.work, datetime.now(UTC))


async def test_deleting_unscheduled_pods_exclude_admission_without_duplicate_delete(
    unscheduled_runtime,
):
    f = unscheduled_runtime
    for pod in f.pods.values():
        pod["metadata"]["deletionTimestamp"] = datetime.now(UTC).isoformat()
    assert await release(f)
    saved = await journal(f)
    assert all(saved["unscheduled"][role][-1]["dispatch"] == "observed" for role in RUNTIME_ROLES)
    assert not f.events and not f.storage.mock_calls
    f.adapter.kube.core.delete_namespaced_pod.assert_not_called()
    assert all(("Pod", pod["metadata"]["name"]) in f.remote.objects for pod in f.pods.values())


async def test_foreground_finalizer_retention_is_not_forced_or_claimed_reclaimed(
    unscheduled_runtime,
):
    f = unscheduled_runtime
    f.hold_api = True
    assert await release(f)
    assert len(f.events) == 5
    assert all(pod["metadata"]["deletionTimestamp"] for pod in f.pods.values())
    assert not f.storage.mock_calls
    assert await release(f) and len(f.events) == 5


async def test_binding_race_retains_definitive_conflict_and_does_not_claim_release(
    unscheduled_runtime,
):
    f = unscheduled_runtime

    async def assigned(role):
        pod = f.pods[role]
        pod["spec"]["nodeName"] = "worker"
        pod["metadata"]["resourceVersion"] = "99"

    f.hook = assigned
    assert not await release(f)
    saved = await journal(f)
    assert saved["unscheduled"]["ipc"][-1]["dispatch"] == "conflict"
    assert saved["unscheduled"]["ipc"][-1]["response"] is None
    assert not any(never_scheduled(saved, role) for role in RUNTIME_ROLES)
    assert f.events == ["ipc"] and not f.storage.mock_calls


async def test_unrelated_resource_version_conflict_retries_only_after_proven_rejection(
    unscheduled_runtime,
):
    f = unscheduled_runtime

    async def changed(role):
        f.pods[role]["metadata"]["resourceVersion"] = "99"
        f.hook = None

    f.hook = changed
    assert not await release(f)
    assert await release(f)
    attempts = (await journal(f))["unscheduled"]["ipc"]
    assert [a["dispatch"] for a in attempts] == ["conflict", "settled"]
    assert [a["capture"]["resource_version"] for a in attempts] == ["1", "99"]


async def test_caller_cancellation_does_not_cancel_original_delete_or_lose_its_receipt(
    unscheduled_runtime,
):
    f = unscheduled_runtime
    entered, proceed = asyncio.Event(), asyncio.Event()

    async def delayed(role):
        entered.set()
        await proceed.wait()
        f.hook = None

    f.hook = delayed
    caller = asyncio.create_task(release(f))
    try:
        await asyncio.wait_for(entered.wait(), 5)
        caller.cancel()
        with pytest.raises(asyncio.CancelledError):
            await caller
        assert f.runtime._dispatches
        proceed.set()
        await f.runtime.drain()
        assert (await journal(f))["unscheduled"]["ipc"][-1]["dispatch"] == "settled"
        assert await release(f)
        assert f.events == list(RUNTIME_ROLES)
    finally:
        proceed.set()
        if not caller.done():
            caller.cancel()
            await asyncio.gather(caller, return_exceptions=True)


@pytest.mark.parametrize("loss", ["claim", "work", "session"])
async def test_original_receipt_survives_owner_loss_without_advancing_old_cleanup(
    unscheduled_runtime, loss
):
    f = unscheduled_runtime

    async def lose(role):
        async with f.h.sessions.begin() as db:
            if loss == "claim":
                row = await db.get(SandboxSession, f.claim.session_id)
                row.status_changed_at += timedelta(microseconds=1)
            elif loss == "work":
                await db.execute(delete(CleanupWork).where(CleanupWork.work_id == f.work.work_id))
            else:
                await db.execute(
                    delete(SandboxSession).where(SandboxSession.session_id == f.claim.session_id)
                )

    f.hook = lose
    with pytest.raises(PairClaimLost):
        await release(f)
    saved = await journal(f)
    assert saved["unscheduled"]["ipc"][-1]["dispatch"] == "settled"
    assert f.events == ["ipc"] and not f.storage.mock_calls
    async with f.h.sessions.begin() as db:
        assert (
            await LifecycleRepository().pair_snapshot(db, f.row.session_id, f.row.sandbox_id)
            == saved["snapshot"]
        )


async def test_lost_response_and_404_do_not_clear_original_inflight_delete(unscheduled_runtime):
    f = unscheduled_runtime
    original = f.adapter.kube.core.delete_namespaced_pod.side_effect

    def lost(*args, **kwargs):
        original(*args, **kwargs)
        raise TimeoutError("lost original DELETE response")

    f.adapter.kube.core.delete_namespaced_pod.side_effect = lost
    with pytest.raises(TimeoutError):
        await release(f)
    before = await journal(f)
    assert before["unscheduled"]["ipc"][-1]["dispatch"] == "inflight"
    assert ("Pod", f.pods["ipc"]["metadata"]["name"]) not in f.remote.objects
    f.runtime = PairRuntimeTeardown(
        f.runtime.settings, f.h.sessions, LifecycleRepository(), f.adapter, f.storage
    )
    assert not await release(f)
    assert await journal(f) == before and f.events == ["ipc"]


@pytest.mark.parametrize("fault", ["capture", "dispatch", "response", "role"])
async def test_retained_unscheduled_proof_cannot_be_reassigned_or_fabricated(
    unscheduled_runtime, fault
):
    f = unscheduled_runtime
    assert await release(f)
    async with f.h.sessions.begin() as db:
        intent = await db.get(PairIntent, f.intent.generation)
        value = deepcopy(intent.cleanup_journal)
        item = value["unscheduled"]["ipc"][-1]
        if fault == "capture":
            item["capture"]["uid"] = "foreign"
        elif fault == "dispatch":
            item["dispatch"] = "inflight"
        elif fault == "response":
            item["response"] = None
        else:
            value["unscheduled"]["foreign"] = value["unscheduled"].pop("ipc")
        intent.cleanup_journal = value
    with pytest.raises(RuntimeError):
        async with f.h.sessions.begin() as db:
            await LifecycleRepository().pair_snapshot(db, f.row.session_id, f.row.sandbox_id)
