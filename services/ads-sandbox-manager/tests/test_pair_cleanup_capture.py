# ruff: noqa: F811
from __future__ import annotations

import asyncio
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from kubernetes.client.exceptions import ApiException
from sqlalchemy import delete

from ads_sandbox_manager.lifecycle_store import CleanupWork
from ads_sandbox_manager.pair_cleanup import PairCleanupCapture
from ads_sandbox_manager.pair_kube import PairControlAdapter
from ads_sandbox_manager.pair_store import CONTROL_RESOURCES, PairClaimLost, resource_key
from ads_sandbox_manager.store import SandboxSession, SessionPVC
from test_kube_release import api  # noqa: F401
from test_lifecycle import life, works  # noqa: F401
from test_pair_cleanup_intent import idle_work, paired  # noqa: F401
from test_pair_controls import MemoryControlApi
from test_session_objects import object_settings  # noqa: F401
from test_sessions import row_for, sessions_harness  # noqa: F401

pytestmark = pytest.mark.anyio


class HookedObserve(PairControlAdapter):
    before = None
    after = None

    async def observe(self, pair, kind, role, uid=None):
        if self.before:
            await self.before(pair, kind, role, uid)
        result = await super().observe(pair, kind, role, uid)
        if self.after:
            await self.after(pair, kind, role, result)
        return result


@pytest.fixture
async def capture(paired, api):
    h = paired
    settings = replace(h.settings, control_seconds=10, cleanup_seconds=60)
    api.settings = settings
    h.adapter = HookedObserve(api)
    h.remote = MemoryControlApi(h.adapter)
    for kind, role in CONTROL_RESOURCES:
        await h.adapter.ensure(h.pair.binding(), kind, role)
    first = h.remote.created[0]
    h.remote.objects[first]["metadata"]["uid"] = "captured-uid"
    h.remote.created.clear()
    h.capture = PairCleanupCapture(settings, h.sessions, h.lifecycle_repository, h.adapter)
    h.lifecycle.pair_capture = h.capture
    h.work = await idle_work(h)
    await h.lifecycle.shutdown_ack(h.work.sandbox_id, h.work.state_changed)
    h.work = (await works(h))[0]
    return h


async def saved(h):
    return (await works(h))[0]


async def test_real_lifecycle_commits_each_observed_uid_and_stays_blocked(capture):
    h = capture
    steps = []

    async def before(pair, kind, role, uid):
        async with asyncio.timeout(5), h.sessions.begin() as db:
            row = await db.get(SandboxSession, pair.session_id, with_for_update=True)
            work = await db.get(CleanupWork, h.work.work_id, with_for_update=True)
            assert row.status == "shutting_down"
            assert sum(x is not None for x in work.pair_snapshot["control_uids"].values()) == max(
                1, len(steps)
            )
        steps.append((kind, role))

    h.adapter.before = before
    await h.lifecycle.execute(h.work.work_id)
    assert steps == list(CONTROL_RESOURCES)
    work = await saved(h)
    assert all(work.pair_snapshot["control_uids"].values())
    assert not h.remote.created and not h.cleanup.deleted
    assert (await row_for(h, h.row.session_id)).status == "shutting_down"
    async with h.sessions.begin() as db:
        assert not await h.lifecycle_repository.complete(db, work, datetime.now(UTC))


async def test_absence_is_not_persisted_as_release_and_late_create_is_captured(capture):
    h = capture
    old = deepcopy(h.remote.objects)
    h.remote.objects.clear()
    await h.capture.capture(h.work)
    assert (await saved(h)).pair_snapshot == h.work.pair_snapshot
    h.remote.objects = old
    await h.capture.capture(await saved(h))
    assert all((await saved(h)).pair_snapshot["control_uids"].values())
    assert not h.remote.created and not h.cleanup.deleted


async def test_missing_known_uid_is_retained_and_replacement_is_rejected(capture):
    h = capture
    await h.capture.capture(h.work)
    work = await saved(h)
    key = next(iter(h.remote.objects))
    original = h.remote.objects.pop(key)
    await h.capture.capture(work)
    assert (await saved(h)).pair_snapshot == work.pair_snapshot
    original["metadata"]["uid"] = str(uuid4())
    h.remote.objects[key] = original
    with pytest.raises(RuntimeError, match="foreign, replaced"):
        await h.capture.capture(await saved(h))
    assert (await saved(h)).pair_snapshot == work.pair_snapshot


@pytest.mark.parametrize(
    "change", ["transition", "status", "sandbox", "project", "pvc", "work", "snapshot"]
)
async def test_claim_loss_during_external_read_cannot_commit_or_advance(capture, change):
    h = capture
    calls = []

    async def after(*args):
        calls.append(args)
        async with h.sessions.begin() as db:
            row = await db.get(SandboxSession, h.row.session_id, with_for_update=True)
            work = await db.get(CleanupWork, h.work.work_id, with_for_update=True)
            if change == "transition":
                row.status_changed_at += timedelta(microseconds=1)
            elif change == "status":
                row.status = "recovering"
            elif change == "sandbox":
                row.sandbox_id = uuid4()
            elif change == "project":
                row.project_id = uuid4()
            elif change == "pvc":
                pvc = await db.get(SessionPVC, row.pvc_id, with_for_update=True)
                pvc.last_state_change += timedelta(microseconds=1)
            elif change == "work":
                await db.delete(work)
            else:
                work.pair_snapshot = {**work.pair_snapshot, "generation": str(uuid4())}

    h.adapter.after = after
    with pytest.raises(PairClaimLost):
        await h.capture.capture(h.work)
    assert len(calls) == 1
    assert not h.remote.created and not h.cleanup.deleted


async def test_failed_commit_retry_recaptures_without_creation(capture):
    h = capture
    original = h.lifecycle_repository.record_pair_control

    async def rollback(*args, **kwargs):
        await original(*args, **kwargs)
        raise RuntimeError("commit failed")

    h.lifecycle_repository.record_pair_control = rollback
    with pytest.raises(RuntimeError, match="commit failed"):
        await h.capture.capture(h.work)
    assert (await saved(h)).pair_snapshot == h.work.pair_snapshot
    h.lifecycle_repository.record_pair_control = original
    await h.capture.capture(await saved(h))
    assert all((await saved(h)).pair_snapshot["control_uids"].values())
    assert not h.remote.created


@pytest.mark.parametrize("status", [401, 403, 500])
async def test_api_failure_preserves_intent_and_never_authorizes_delete(capture, status):
    h = capture
    h.adapter.custom.get_namespaced_custom_object.side_effect = ApiException(status=status)
    with pytest.raises(ApiException):
        await h.capture.capture(h.work)
    assert (await saved(h)).pair_snapshot == h.work.pair_snapshot
    await h.lifecycle.execute(h.work.work_id)
    assert not h.cleanup.deleted and len(await works(h)) == 1


@pytest.mark.parametrize("field", ["namespace", "golden_version"])
async def test_configuration_drift_fails_before_read(capture, field):
    h = capture
    h.capture.settings = replace(
        h.capture.settings, **{field: "changed" if field == "namespace" else "v0.0.11"}
    )
    h.adapter.before = lambda *args: pytest.fail("configuration drift reached API")
    with pytest.raises(RuntimeError, match="configuration"):
        await h.capture.capture(h.work)


@pytest.mark.parametrize("mode", ["undrained", "expired", "recovery", "orphan", "missing"])
async def test_unsupported_or_stale_work_fails_before_read(capture, mode):
    h = capture
    async with h.sessions.begin() as db:
        work = await db.get(CleanupWork, h.work.work_id)
        if mode == "undrained":
            work.acknowledged = False
        elif mode == "expired":
            work.deadline = datetime.now(UTC) - timedelta(seconds=1)
        elif mode in ("recovery", "orphan"):
            work.kind = mode
        else:
            await db.execute(delete(CleanupWork).where(CleanupWork.work_id == work.work_id))
    h.adapter.before = lambda *args: pytest.fail("invalid work reached API")
    with pytest.raises(PairClaimLost):
        await h.capture.capture(h.work)


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"generation": "broken"},
    ],
)
async def test_corrupt_snapshot_stays_blocked(capture, payload):
    h = capture
    async with h.sessions.begin() as db:
        work = await db.get(CleanupWork, h.work.work_id)
        work.pair_snapshot = payload
    work = await saved(h)
    with pytest.raises(RuntimeError, match="snapshot"):
        await h.capture.capture(work)
    await h.lifecycle.execute(work.work_id)
    assert not h.cleanup.deleted and len(await works(h)) == 1


async def test_cancellation_during_read_retains_all_prior_commits(capture):
    h = capture
    seen = []
    started = asyncio.Event()

    async def before(pair, kind, role, uid):
        seen.append(resource_key(kind, role))
        if len(seen) == 3:
            started.set()
            await asyncio.Event().wait()

    h.adapter.before = before
    task = asyncio.create_task(h.capture.capture(h.work))
    await asyncio.wait_for(started.wait(), 5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    controls = (await saved(h)).pair_snapshot["control_uids"]
    assert sum(uid is not None for uid in controls.values()) == 2
    assert not h.remote.created and not h.cleanup.deleted


async def test_stale_worker_cannot_replace_an_already_captured_uid(capture):
    h = capture
    await h.capture.capture(h.work)
    with pytest.raises(PairClaimLost):
        await h.capture.capture(h.work)
    current = await saved(h)
    with pytest.raises(RuntimeError, match="replacement"):
        async with h.sessions.begin() as db:
            await h.lifecycle_repository.record_pair_control(
                db,
                current,
                "PodGroup",
                "guest",
                "replacement",
                datetime.now(UTC),
            )
    assert (await saved(h)).pair_snapshot == current.pair_snapshot


@pytest.mark.parametrize("kind", ["service", "reap"])
async def test_current_service_and_reap_claims_capture_but_do_not_complete(capture, kind):
    h = capture
    async with h.sessions.begin() as db:
        row = await db.get(SandboxSession, h.row.session_id, with_for_update=True)
        pvc = await db.get(SessionPVC, row.pvc_id, with_for_update=True)
        work = await db.get(CleanupWork, h.work.work_id)
        row.status = "service" if kind == "service" else "stopped"
        pvc.state = "detached" if kind == "service" else "destroying"
        work.kind = kind
    work = await saved(h)
    await h.lifecycle.execute(work.work_id)
    captured = await saved(h)
    assert all(captured.pair_snapshot["control_uids"].values())
    assert not h.cleanup.deleted and not h.remote.created
    async with h.sessions.begin() as db:
        assert not await h.lifecycle_repository.complete(db, captured, datetime.now(UTC))


@pytest.mark.parametrize(
    "field,value",
    [
        ("session_id", "invalid"),
        ("sandbox_id", str(uuid4())),
        ("project_id", str(uuid4())),
        ("generation", None),
        ("control_uids", {}),
        ("control_uids", {"PodGroup/guest": False}),
        ("namespace", ""),
        ("golden_version", None),
    ],
)
async def test_invalid_full_snapshot_never_reaches_api(capture, field, value):
    h = capture
    async with h.sessions.begin() as db:
        work = await db.get(CleanupWork, h.work.work_id)
        work.pair_snapshot = {**work.pair_snapshot, field: value}
    h.adapter.before = lambda *args: pytest.fail("corrupt snapshot reached API")
    with pytest.raises((RuntimeError, ValueError)):
        await h.capture.capture(await saved(h))


@pytest.mark.parametrize("uid", ["", " ", False, 12])
async def test_invalid_observer_uid_cannot_be_committed(capture, uid):
    h = capture
    with pytest.raises(ValueError):
        async with h.sessions.begin() as db:
            await h.lifecycle_repository.record_pair_control(
                db,
                h.work,
                "Service",
                "egress",
                uid,
                datetime.now(UTC),
            )
    assert (await saved(h)).pair_snapshot == h.work.pair_snapshot
