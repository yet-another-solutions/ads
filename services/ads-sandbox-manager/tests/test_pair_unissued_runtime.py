# ruff: noqa: F811
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from sqlalchemy import delete

from ads_sandbox_manager.lifecycle_store import CleanupWork, LifecycleRepository
from ads_sandbox_manager.pair_objects import COMPUTE_ROLES
from ads_sandbox_manager.pair_runtime_teardown import PairRuntimeTeardown
from ads_sandbox_manager.pair_store import PairClaimLost, PairIntent
from ads_sandbox_manager.store import SandboxSession
from test_kube_release import api  # noqa: F401
from test_pair_controls import controls  # noqa: F401
from test_pair_creation import creation  # noqa: F401
from test_pair_creator_fence import cleanup_claim
from test_pair_store import begin, ledger, snapshot  # noqa: F401
from test_pair_volume_publication import publication as volume_publication  # noqa: F401
from test_session_objects import object_settings  # noqa: F401
from test_sessions import sessions_harness  # noqa: F401

pytestmark = pytest.mark.anyio
UNISSUED = sorted(f"Pod/{role}" for role in COMPUTE_ROLES) + ["Pod/ipc"]


async def runtime(f):
    capture, work, claim = await cleanup_claim(f)
    f.capture, f.work, f.claim = capture, work, claim
    storage, node = AsyncMock(), AsyncMock()
    service = PairRuntimeTeardown(
        replace(f.h.settings, cleanup_seconds=60, recovery_seconds=120),
        f.h.sessions,
        capture.repository,
        f.adapter,
        storage,
        node,
    )
    return service, storage, node


async def proof(f):
    current = await snapshot(f, f.intent.generation)
    assert current.creation_fenced
    value = current.cleanup_journal
    assert value["runtime_unissued"] == UNISSUED
    assert value["runtime_release"] is None and value["node_capture"] is None
    assert value["ipc_release"] is None and value["ipc_capture"] is None
    assert value["storage_capture"] == {}
    return deepcopy(value)


@pytest.mark.parametrize("published", [False, True])
async def test_reserved_and_control_only_pairs_need_no_fabricated_runtime(controls, published):
    f = controls
    f.intent = await f.service.prepare(f.row) if published else await begin(f)
    service, storage, node = await runtime(f)
    before = deepcopy(f.remote.objects)
    assert await service.release(f.work, recovery=f.claim)
    first = await proof(f)
    assert f.remote.objects == before
    assert not storage.mock_calls and not node.mock_calls
    # Re-enter through a new repository/service without any node authority.
    restarted = PairRuntimeTeardown(
        service.settings, f.h.sessions, LifecycleRepository(), f.adapter, storage
    )
    assert await restarted.release(f.work, recovery=f.claim)
    assert await proof(f) == first
    async with f.h.sessions.begin() as db:
        assert not await f.capture.repository.complete(db, f.work, datetime.now(UTC))
        assert await db.get(CleanupWork, f.work.work_id) is not None
    assert f.remote.objects == before


@pytest.mark.parametrize("stop_after", range(1, 8))
async def test_each_settled_control_prefix_is_a_positive_no_runtime_state(controls, stop_after):
    f = controls
    f.intent = await begin(f)
    original = f.repo.dispatch
    count = 0

    async def dispatch(*args, **kwargs):
        nonlocal count
        # Stop before the next publisher reservation, not inside an API write.
        if count == stop_after:
            raise RuntimeError("stop before next control dispatch")
        result = await original(*args, **kwargs)
        count += 1
        return result

    f.repo.dispatch = dispatch
    with pytest.raises(RuntimeError, match="before next control"):
        await f.service.prepare(f.row)
    f.repo.dispatch = original
    service, storage, node = await runtime(f)
    before = deepcopy(f.remote.objects)
    assert await service.release(f.work, recovery=f.claim)
    value = await proof(f)
    assert (
        list(value["creator_snapshot"]["control_dispatch"].values()).count("settled") == stop_after
    )
    assert f.remote.objects == before
    assert not storage.mock_calls and not node.mock_calls


@pytest.mark.parametrize("stop_after", range(1, 4))
async def test_each_settled_clone_prefix_remains_unmounted(creation, stop_after):
    f = creation
    original = f.creator.volumes.repository.reserve
    count = 0

    async def reserve(*args, **kwargs):
        nonlocal count
        if count == stop_after:
            raise RuntimeError("stop before next clone reservation")
        count += 1
        return await original(*args, **kwargs)

    f.creator.volumes.repository.reserve = reserve
    with pytest.raises(RuntimeError, match="before next clone"):
        await f.creator.volumes.prepare(f.row, f.intent.generation)
    service, storage, node = await runtime(f)
    # Production cleanup captures every dispatched writer before entering the
    # runtime stage. This read-only metadata step does not imply mount/runtime
    # release and does not call the storage-release or node-owner ports below.
    assert await f.capture.capture(f.work, recovery=f.claim)
    async with f.h.sessions.begin() as db:
        f.work = await db.get(CleanupWork, f.work.work_id)
    before = deepcopy(f.remote.objects)
    assert await service.release(f.work, recovery=f.claim)
    value = await proof(f)
    assert (
        sum(
            entry["dispatch"] == "settled"
            for entry in value["creator_snapshot"]["volume_resources"].values()
        )
        == stop_after
    )
    assert f.remote.objects == before
    assert not storage.mock_calls and not node.mock_calls


@pytest.mark.parametrize("topics", [False, True])
async def test_created_unmounted_volumes_are_not_required_to_be_bound(creation, topics):
    f = creation
    await f.creator.volumes.prepare(f.row, f.intent.generation)
    if topics:
        await f.creator._topics(f.row, f.intent.generation)
    service, storage, node = await runtime(f)
    before = deepcopy(f.remote.objects)
    assert await service.release(f.work, recovery=f.claim)
    value = await proof(f)
    assert value["snapshot"]["topics_dispatch"] == ("settled" if topics else "unissued")
    assert all(v["uid"] for v in value["snapshot"]["volume_resources"].values())
    assert not storage.mock_calls and not node.mock_calls
    assert f.remote.objects == before  # Not a PVC deletion/reclamation shortcut.


async def test_ambiguous_topic_write_does_not_use_never_started_shortcut(creation):
    f = creation
    await f.creator.volumes.prepare(f.row, f.intent.generation)
    f.topics.prepare.side_effect = TimeoutError("lost original response")
    with pytest.raises(TimeoutError):
        await f.creator._topics(f.row, f.intent.generation)
    service, storage, node = await runtime(f)
    assert not await service.release(f.work, recovery=f.claim)
    current = await snapshot(f, f.intent.generation)
    assert current.creation_fenced and current.topics_dispatch == "inflight"
    assert current.cleanup_journal is None
    assert not storage.mock_calls and not node.mock_calls


@pytest.mark.parametrize("dispatch", ["inflight", "settled"])
async def test_null_uid_cannot_prove_unissued_after_dispatch(controls, dispatch):
    f = controls
    f.intent = await begin(f)
    async with f.h.sessions.begin() as db:
        current = await db.get(PairIntent, f.intent.generation)
        current.compute_dispatch = {**current.compute_dispatch, "Pod/guest": dispatch}
    service, storage, node = await runtime(f)
    assert not await service.release(f.work, recovery=f.claim)
    assert (await snapshot(f, f.intent.generation)).cleanup_journal is None
    assert not storage.mock_calls and not node.mock_calls


@pytest.mark.parametrize("delete_session", [False, True])
async def test_never_dispatched_proof_survives_cascade_but_old_claim_cannot_run(
    controls, delete_session
):
    f = controls
    f.intent = await begin(f)
    service, storage, node = await runtime(f)
    assert await service.release(f.work, recovery=f.claim)
    before = await proof(f)
    async with f.h.sessions.begin() as db:
        if delete_session:
            await db.execute(
                delete(SandboxSession).where(SandboxSession.session_id == f.row.session_id)
            )
        else:
            await db.execute(delete(CleanupWork).where(CleanupWork.work_id == f.work.work_id))
    async with f.h.sessions.begin() as db:
        assert (
            await LifecycleRepository().pair_snapshot(db, f.row.session_id, f.row.sandbox_id)
            == before["snapshot"]
        )
    assert await proof(f) == before
    with pytest.raises(PairClaimLost):
        await service.release(f.work, recovery=f.claim)
    assert not storage.mock_calls and not node.mock_calls


@pytest.mark.parametrize(
    "fault", ["missing-role", "extra-role", "duplicate", "uid", "dispatch", "fence"]
)
async def test_retained_never_dispatched_proof_rejects_tampering(controls, fault):
    f = controls
    f.intent = await begin(f)
    service, storage, node = await runtime(f)
    assert await service.release(f.work, recovery=f.claim)
    async with f.h.sessions.begin() as db:
        intent = await db.get(PairIntent, f.intent.generation)
        if fault == "uid":
            intent.compute_uids = {**intent.compute_uids, "Pod/guest": str(uuid4())}
        elif fault == "dispatch":
            intent.compute_dispatch = {**intent.compute_dispatch, "Pod/guest": "inflight"}
        elif fault == "fence":
            intent.creation_fenced = False
        else:
            value = deepcopy(intent.cleanup_journal)
            if fault == "missing-role":
                value["runtime_unissued"].pop()
            elif fault == "extra-role":
                value["runtime_unissued"].append("Pod/foreign")
            else:
                value["runtime_unissued"].append(value["runtime_unissued"][0])
            intent.cleanup_journal = value
    with pytest.raises(RuntimeError):
        async with f.h.sessions.begin() as db:
            await LifecycleRepository().pair_snapshot(db, f.row.session_id, f.row.sandbox_id)
    assert not storage.mock_calls and not node.mock_calls


async def test_stale_claim_cannot_seal_never_dispatched_proof(controls):
    f = controls
    f.intent = await begin(f)
    service, storage, node = await runtime(f)
    async with f.h.sessions.begin() as db:
        row = await db.get(SandboxSession, f.claim.session_id)
        row.status_changed_at += timedelta(microseconds=1)
    with pytest.raises(PairClaimLost):
        await service.release(f.work, recovery=f.claim)
    assert (await snapshot(f, f.intent.generation)).cleanup_journal is None
    assert not storage.mock_calls and not node.mock_calls
