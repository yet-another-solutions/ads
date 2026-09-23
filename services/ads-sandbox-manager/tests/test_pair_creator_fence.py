# ruff: noqa: F811
from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select

from ads_sandbox_manager.lifecycle_store import CleanupWork, LifecycleRepository
from ads_sandbox_manager.pair_cleanup import PairCleanupCapture
from ads_sandbox_manager.pair_controls import PairControlProvisioner
from ads_sandbox_manager.pair_store import PairClaimLost, PairIntent
from ads_sandbox_manager.store import SandboxSession
from test_kube_release import api  # noqa: F401
from test_pair_controls import controls, intent_for  # noqa: F401
from test_pair_store import begin, ledger, snapshot  # noqa: F401
from test_session_objects import object_settings  # noqa: F401
from test_sessions import row_for, sessions_harness  # noqa: F401

pytestmark = pytest.mark.anyio


async def cleanup_claim(f):
    repository = LifecycleRepository()
    async with f.h.sessions.begin() as db:
        assert await repository.recover(
            db, f.row.session_id, f.row.sandbox_id, datetime.now(UTC), 120
        )
        claim = await db.get(SandboxSession, f.row.session_id)
        work = await db.scalar(
            select(CleanupWork).where(CleanupWork.session_id == f.row.session_id)
        )
    capture = PairCleanupCapture(
        replace(f.service.settings, cleanup_seconds=60, recovery_seconds=120),
        f.h.sessions,
        repository,
        f.adapter,
    )
    return capture, work, claim


async def test_dispatch_commits_before_api_and_settles_only_after_normal_return(controls):
    f = controls
    seen = []

    async def before(pair, kind, role, uid):
        intent = await snapshot(f, pair.generation)
        assert not intent.creation_fenced
        assert intent.control_dispatch[f"{kind}/{role}"] == "inflight"
        assert list(intent.control_dispatch.values()).count("settled") == len(seen)
        seen.append((kind, role))

    f.adapter.before = before
    result = await f.service.prepare(f.row)
    assert len(seen) == 8
    assert set(result.control_dispatch.values()) == {"settled"}
    assert all(result.control_uids.values())


async def test_fence_wins_before_dispatch_and_survives_new_repository_instance(controls):
    f = controls
    intent = await begin(f)
    capture, work, claim = await cleanup_claim(f)
    await capture.capture(work, recovery=claim)
    fenced = await snapshot(f, intent.generation)
    assert fenced.creation_fenced
    assert set(fenced.control_dispatch.values()) == {"unissued"}
    assert not f.remote.created
    # Even restoring the prior creating tuple cannot erase the permanent fence.
    async with f.h.sessions.begin() as db:
        row = await db.get(SandboxSession, f.row.session_id)
        row.sandbox_id = f.row.sandbox_id
        row.status = "creating"
        row.status_changed_at = f.row.status_changed_at
        row.claimed_by = f.row.claimed_by
    restarted = PairControlProvisioner(f.service.settings, f.h.sessions, type(f.repo)(), f.adapter)
    with pytest.raises(PairClaimLost, match="fenced"):
        await restarted.prepare(f.row)
    assert not f.remote.created
    assert (await snapshot(f, intent.generation)).creation_fenced


async def test_reserved_creator_can_cross_fence_but_cannot_advance_or_hide_it(controls):
    f = controls
    started, release = asyncio.Event(), asyncio.Event()

    async def before(*args):
        started.set()
        await release.wait()

    f.adapter.before = before
    task = asyncio.create_task(f.service.prepare(f.row))
    try:
        await asyncio.wait_for(started.wait(), 5)
        intent = await intent_for(f)
        capture, work, claim = await cleanup_claim(f)
        await capture.capture(work, recovery=claim)
        fenced = await snapshot(f, intent.generation)
        assert fenced.creation_fenced
        assert fenced.control_dispatch["PodGroup/guest"] == "inflight"
        assert not f.remote.created
        release.set()
        with pytest.raises(PairClaimLost):
            await task
        settled = await snapshot(f, intent.generation)
        assert settled.creation_fenced
        assert settled.control_dispatch["PodGroup/guest"] == "settled"
        assert settled.control_uids["PodGroup/guest"] is None
        assert len(f.remote.created) == 1
        await capture.capture(work, recovery=claim)
        async with f.h.sessions.begin() as db:
            saved = await db.get(CleanupWork, work.work_id)
            assert saved.pair_snapshot["control_uids"]["PodGroup/guest"]
            assert not await capture.repository.complete(db, saved, datetime.now(UTC))
    finally:
        release.set()
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


async def test_cancelled_sdk_completion_and_late_capture_never_settle_dispatch(controls):
    f = controls
    f.remote.delay = True
    task = asyncio.create_task(f.service.prepare(f.row))
    try:
        assert await asyncio.to_thread(f.remote.started.wait, 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        intent = await intent_for(f)
        capture, work, claim = await cleanup_claim(f)
        await capture.capture(work, recovery=claim)
        fenced = await snapshot(f, intent.generation)
        assert fenced.creation_fenced
        assert fenced.control_dispatch["PodGroup/guest"] == "inflight"
        assert await f.adapter.observe(intent.binding(), "PodGroup", "guest") is None
        f.remote.release.set()
        assert await asyncio.to_thread(f.remote.finished.wait, 5)
        await capture.capture(work, recovery=claim)
        async with f.h.sessions.begin() as db:
            saved = await db.get(CleanupWork, work.work_id)
            assert saved.pair_snapshot["control_uids"]["PodGroup/guest"]
        assert (await snapshot(f, intent.generation)).control_dispatch[
            "PodGroup/guest"
        ] == "inflight"
        assert len(f.remote.created) == 1
    finally:
        f.remote.release.set()
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


async def test_lost_reply_retry_observes_without_settling_or_redispatching(controls):
    f = controls
    f.remote.lost_reply = True
    with pytest.raises(TimeoutError):
        await f.service.prepare(f.row)
    intent = await intent_for(f)
    assert intent.control_dispatch["PodGroup/guest"] == "inflight"
    result = await f.service.prepare(f.row)
    assert all(result.control_uids.values()) and len(f.remote.created) == 8
    assert result.control_dispatch["PodGroup/guest"] == "inflight"
    capture, work, claim = await cleanup_claim(f)
    await capture.capture(work, recovery=claim)
    assert (await snapshot(f, intent.generation)).control_dispatch["PodGroup/guest"] == "inflight"


async def test_early_absence_retry_never_issues_a_second_create(controls):
    f = controls
    intent = await begin(f)
    async with f.h.sessions.begin() as db:
        await f.repo.dispatch(db, f.row, f.owner, intent.generation, "PodGroup", "guest")
    f.service.settings = replace(
        f.service.settings,
        session_objects=replace(f.service.settings.session_objects, create_seconds=0.3),
    )
    with pytest.raises(TimeoutError):
        await f.service.prepare(f.row)
    assert not f.remote.created
    assert (await snapshot(f, intent.generation)).control_dispatch["PodGroup/guest"] == "inflight"


async def test_retry_rejects_spec_drift_without_recreating(controls):
    f = controls
    f.remote.lost_reply = True
    with pytest.raises(TimeoutError):
        await f.service.prepare(f.row)
    obj = next(iter(f.remote.objects.values()))
    obj["spec"] = {}
    with pytest.raises(RuntimeError, match="incompatible"):
        await f.service.prepare(f.row)
    assert len(f.remote.created) == 1


async def test_settled_binding_rollback_does_not_repeat_create(controls):
    f = controls
    original = f.repo.bind

    async def fail(*args, **kwargs):
        await original(*args, **kwargs)
        raise RuntimeError("bind rolled back")

    f.repo.bind = fail
    with pytest.raises(RuntimeError, match="rolled back"):
        await f.service.prepare(f.row)
    intent = await intent_for(f)
    assert intent.control_dispatch["PodGroup/guest"] == "settled"
    assert intent.control_uids["PodGroup/guest"] is None
    f.repo.bind = original
    result = await f.service.prepare(f.row)
    assert all(result.control_uids.values()) and len(f.remote.created) == 8


@pytest.mark.parametrize(
    "field,value",
    [
        ("creation_fenced", None),
        ("control_dispatch", {}),
        ("control_dispatch", {"PodGroup/guest": "unissued"}),
    ],
)
async def test_invalid_dispatch_evidence_never_reads_or_writes_api(controls, field, value):
    f = controls
    intent = await begin(f)
    # Exercise in-memory validation without bypassing the database NOT NULL gate.
    setattr(intent, field, value)
    with pytest.raises(RuntimeError, match="dispatch evidence"):
        f.repo._validate(intent)
    assert not f.remote.created


@pytest.mark.parametrize("field", ["project_id", "claim_owner", "claim_changed", "namespace"])
async def test_settlement_cannot_follow_changed_dispatch_identity(controls, field):
    f = controls
    intent = await begin(f)
    async with f.h.sessions.begin() as db:
        intent, dispatched = await f.repo.dispatch(
            db, f.row, f.owner, intent.generation, "PodGroup", "guest"
        )
        assert dispatched
    async with f.h.sessions.begin() as db:
        stored = await db.get(PairIntent, intent.generation)
        value = (
            stored.claim_changed + timedelta(microseconds=1)
            if field == "claim_changed"
            else "different"
            if field == "namespace"
            else uuid4()
        )
        setattr(stored, field, value)
    with pytest.raises(PairClaimLost, match="identity"):
        async with f.h.sessions.begin() as db:
            await f.repo.settle(db, intent, "PodGroup", "guest")


async def test_undispatched_control_cannot_be_settled(controls):
    f = controls
    intent = await begin(f)
    with pytest.raises(RuntimeError, match="never dispatched"):
        async with f.h.sessions.begin() as db:
            await f.repo.settle(db, intent, "PodGroup", "guest")
