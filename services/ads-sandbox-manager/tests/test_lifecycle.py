# ruff: noqa: F811
from __future__ import annotations

import asyncio
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import pytest
from sqlalchemy import select

from ads_commons.sandbox import SandboxRequest, decode_ready
from ads_sandbox_manager.lifecycle import IDLE, ORPHAN, REAP, RECOVER, LifecycleService, Signal
from ads_sandbox_manager.lifecycle_store import CleanupWork, LifecycleRepository
from ads_sandbox_manager.service import TransitService, VerifiedExec
from ads_sandbox_manager.session_objects import ipc_name, session_name
from ads_sandbox_manager.store import SandboxSession, SessionPVC, advance
from test_session_objects import object_settings  # noqa: F401
from test_sessions import row_for, sessions_harness  # noqa: F401

pytestmark = pytest.mark.anyio


class FakeCleanup:
    def __init__(self, kube):
        self.kube = kube
        self.deleted = []
        self.release = True
        self.reclaim = True

    async def inventory(self):
        return deepcopy(list(self.kube.objects.values()))

    async def observe(self, target):
        return deepcopy(self.kube.objects.get((target["kind"], target["name"])))

    async def capture(self, target):
        obj = await self.observe(target)
        return {**target, "captured": obj is not None and obj["metadata"]["uid"] == target["uid"]}

    async def delete(self, target):
        obj = await self.observe(target)
        if obj and obj["metadata"]["uid"] == target["uid"]:
            self.deleted.append((target["kind"], target["name"], target["uid"]))
            del self.kube.objects[(target["kind"], target["name"])]

    async def released(self, target):
        return target.get("captured", False) and self.release

    async def reclaimed(self, target):
        return await self.released(target) and self.reclaim


@pytest.fixture
async def life(sessions_harness):
    h = sessions_harness
    async with h.sessions.begin() as db:
        # True orphan intents deliberately have no session foreign key.
        for work in await db.scalars(select(CleanupWork)):
            await db.delete(work)
    h.cleanup = FakeCleanup(h.kube)
    h.publisher = AsyncMock()
    h.lifecycle_repository = LifecycleRepository()
    h.lifecycle = LifecycleService(
        replace(h.settings, control_seconds=2),
        h.sessions,
        h.lifecycle_repository,
        h.cleanup,
        h.publisher,
        Mock(mint=Mock(return_value="manager-token")),
        Mock(mint=Mock(return_value=SimpleNamespace(access_token="ipc-token"))),
    )
    row = await h.service.provision(uuid4())
    async with h.sessions.begin() as db:
        assert await h.repository.mark_ready(
            db, row.sandbox_id, datetime.now(UTC), row.status_changed_at
        )
        row = await db.get(SandboxSession, row.session_id)
        pvc = await db.get(SessionPVC, row.pvc_id)
        row.last_execution_at = pvc.last_execution = datetime.now(UTC) - timedelta(hours=4)
    h.row = await row_for(h, row.session_id)
    yield h


async def works(h):
    async with h.sessions.begin() as db:
        return list(await db.scalars(select(CleanupWork)))


async def disk(h, pvc_id=None):
    async with h.sessions.begin() as db:
        return await db.get(SessionPVC, pvc_id or h.row.pvc_id)


async def idle(h):
    await h.lifecycle.admit(IDLE, Signal(h.row.session_id, h.row.sandbox_id))
    return (await works(h))[0]


async def detach(h):
    work = await idle(h)
    await h.lifecycle.shutdown_ack(h.row.sandbox_id, work.state_changed)
    await h.lifecycle.execute(work.work_id)
    assert (await row_for(h, h.row.session_id)).status == "stopped"
    return work


async def eligible(h):
    async with h.sessions.begin() as db:
        pvc = await db.get(SessionPVC, h.row.pvc_id)
        pvc.last_state_change = datetime.now(UTC) - timedelta(hours=3)


async def test_stale_resume_snapshot_cannot_follow_changed_pvc_mapping(life):
    h = life
    await detach(h)
    old = await row_for(h, h.row.session_id)
    async with h.sessions.begin() as db:
        row = await db.get(SandboxSession, h.row.session_id)
        row.pvc_id = None
        row.pvc_uid = None
    async with h.sessions.begin() as db:
        assert await h.repository.claim(db, old, uuid4(), datetime.now(UTC)) is None
    assert (await disk(h)).state == "detached"


async def test_failed_provisioning_records_failure_time_not_claim_time(life):
    h = life
    await detach(h)
    row = await h.service.provision(h.row.session_id)
    failure_time = row.status_changed_at + timedelta(seconds=60)
    async with h.sessions.begin() as db:
        updated = await h.repository.record(
            db, row, row.claimed_by, status="failed", status_changed_at=failure_time
        )
        assert updated.status_changed_at == failure_time
    pvc = await disk(h)
    assert pvc.state == "failed" and pvc.last_state_change == failure_time


async def test_recovery_handoff_contract_rebuilds_only_with_fresh_identities(life):
    h = life
    await h.lifecycle.admit(RECOVER, Signal(h.row.session_id, h.row.sandbox_id))
    work = (await works(h))[0]
    boundary = await row_for(h, h.row.session_id)
    # Fake the unbuilt slice-12 executor only: delete captured old resources,
    # confirm completion, remove the old disk record, and open provisioning.
    captured = [t for w in await works(h) for t in w.targets]
    for obj in captured:
        await h.cleanup.delete(obj)
    async with h.sessions.begin() as db:
        row = await db.get(SandboxSession, h.row.session_id)
        await db.delete(await db.get(SessionPVC, h.row.pvc_id))
        row.pvc_id = row.pvc_uid = None
        row.status = "stopped"
        row.status_changed_at = advance(row.status_changed_at, datetime.now(UTC))
        for intent in await db.scalars(select(CleanupWork)):
            await db.delete(intent)
    fresh = await h.service.provision(h.row.session_id)
    assert fresh.sandbox_id == boundary.sandbox_id != h.row.sandbox_id
    assert fresh.pvc_id != h.row.pvc_id and fresh.pvc_uid != h.row.pvc_uid
    await h.lifecycle.execute(work.work_id)  # Old worker cannot touch fresh objects.
    assert len(h.kube.objects) == 4
    assert (await row_for(h, h.row.session_id)).status == "creating"


async def test_scheduler_advisory_lock_is_cluster_wide_and_released(life):
    h = life
    entered, release = asyncio.Event(), asyncio.Event()
    count = 0

    async def operation():
        nonlocal count
        count += 1
        entered.set()
        await release.wait()

    first = asyncio.create_task(h.lifecycle._locked("test-lifecycle-scan", operation))
    await entered.wait()
    await h.lifecycle._locked("test-lifecycle-scan", operation)
    assert count == 1
    release.set()
    await first
    await h.lifecycle._locked("test-lifecycle-scan", operation)
    assert count == 2


async def test_request_waits_for_shared_service_deadline_not_own_ready_timeout(life):
    h = life
    await detach(h)
    async with h.sessions.begin() as db:
        assert await h.lifecycle_repository.service(
            db, h.row.session_id, h.row.sandbox_id, datetime.now(UTC), 10, []
        )
    service = TransitService(
        replace(h.settings, ready_seconds=0.5, control_seconds=1),
        h.sessions,
        h.repository,
        h.service,
        h.publisher,
        h.lifecycle.tokens,
        h.lifecycle,
    )
    message = SandboxRequest(uuid4(), h.row.session_id, uuid4(), "shell", "true")
    try:
        await service.accept(VerifiedExec(h.row.session_id, message, "subject", "mcp-token"))
        await asyncio.sleep(0.6)
        assert message.execution_id in service._pending
        assert not h.publisher.send.called
        async with h.sessions.begin() as db:
            row = await db.get(SandboxSession, h.row.session_id)
            row.service_deadline = datetime.now(UTC) - timedelta(seconds=1)
        await asyncio.wait_for(asyncio.gather(*service._requests.values()), 3)
        assert h.publisher.send.call_args_list[0].args[0] == RECOVER
        assert not service._pending
    finally:
        await service.stop()


async def test_idle_waits_for_exact_drain_ack_and_storage_release(life):
    h = life
    work = await idle(h)
    assert (await row_for(h, h.row.session_id)).status == "shutting_down"
    assert (await disk(h)).state == "detaching"
    await h.lifecycle.execute(work.work_id)
    message = decode_ready(h.publisher.send.call_args.args[2])
    assert message.transition == work.state_changed
    assert not h.cleanup.deleted
    for wrong in (None, work.state_changed - timedelta(microseconds=1)):
        await h.lifecycle.shutdown_ack(h.row.sandbox_id, wrong)
        assert not (await works(h))[0].acknowledged
    await h.lifecycle.shutdown_ack(h.row.sandbox_id, work.state_changed)
    h.cleanup.release = False
    await h.lifecycle.execute(work.work_id)
    assert h.cleanup.deleted[0][1] == ipc_name(h.row.sandbox_id)
    assert [kind for kind, _, _ in h.cleanup.deleted] == ["Deployment", "Deployment"]
    assert (await disk(h)).state == "detaching"
    h.cleanup.release = True
    await h.lifecycle.execute(work.work_id)
    assert (await disk(h)).state == "detached"
    assert (await disk(h)).release_evidence["uid"] == h.row.pvc_uid
    assert not await works(h)
    assert list(h.kube.objects) == [("PersistentVolumeClaim", session_name(h.row.pvc_id))]
    assert [kind for kind, _, _ in h.cleanup.deleted] == [
        "Deployment",
        "Deployment",
        "PersistentVolumeClaim",
    ]


async def test_resume_preserves_disk_reap_then_fresh_clone(life):
    h = life
    await detach(h)
    resumed = await h.service.provision(h.row.session_id)
    assert resumed.pvc_id == h.row.pvc_id and resumed.pvc_uid == h.row.pvc_uid
    async with h.sessions.begin() as db:
        assert await h.repository.mark_ready(
            db, resumed.sandbox_id, datetime.now(UTC), resumed.status_changed_at
        )
        row = await db.get(SandboxSession, h.row.session_id)
        pvc = await db.get(SessionPVC, h.row.pvc_id)
        row.last_execution_at = pvc.last_execution = datetime.now(UTC) - timedelta(hours=4)
    await detach(h)
    await eligible(h)
    await h.lifecycle.admit(REAP, Signal(h.row.session_id, h.row.sandbox_id, h.row.pvc_id))
    work = (await works(h))[0]
    assert (await disk(h)).state == "destroying"
    h.cleanup.reclaim = False
    await h.lifecycle.execute(work.work_id)
    assert await disk(h) is not None
    assert (await row_for(h, h.row.session_id)).pvc_id == h.row.pvc_id
    h.cleanup.reclaim = True
    # Restarted executor reloads durable targets; the missing PVC alone is not success.
    await h.lifecycle.execute(work.work_id)
    assert await disk(h) is None
    fresh = await h.service.provision(h.row.session_id)
    assert fresh.pvc_id != h.row.pvc_id and fresh.pvc_uid != h.row.pvc_uid
    assert fresh.status == "creating"


@pytest.mark.parametrize("recent", ["sandbox", "pvc", "detached"])
async def test_reap_requires_both_inactivity_clocks_and_continuous_detach(life, recent):
    h = life
    await detach(h)
    await eligible(h)
    async with h.sessions.begin() as db:
        row = await db.get(SandboxSession, h.row.session_id)
        pvc = await db.get(SessionPVC, h.row.pvc_id)
        if recent == "sandbox":
            row.last_execution_at = datetime.now(UTC)
        elif recent == "pvc":
            pvc.last_execution = datetime.now(UTC)
        else:
            pvc.last_state_change = datetime.now(UTC)
    await h.lifecycle.admit(REAP, Signal(h.row.session_id, h.row.sandbox_id, h.row.pvc_id))
    assert not await works(h)
    assert (await disk(h)).state == "detached"


@pytest.mark.parametrize("first", ["admission", "idle"])
async def test_execution_admission_and_idle_have_one_atomic_winner(life, first):
    h = life
    if first == "admission":
        async with h.sessions.begin() as db:
            assert await h.repository.admit(db, h.row.session_id, datetime.now(UTC))
        await h.lifecycle.admit(IDLE, Signal(h.row.session_id, h.row.sandbox_id))
        assert not await works(h)
        assert (await disk(h)).last_execution == (
            await row_for(h, h.row.session_id)
        ).last_execution_at
    else:
        await idle(h)
        async with h.sessions.begin() as db:
            assert await h.repository.admit(db, h.row.session_id, datetime.now(UTC)) is None


async def test_concurrent_idle_signals_make_one_joint_claim(life):
    h = life
    await asyncio.gather(
        *(h.lifecycle.admit(IDLE, Signal(h.row.session_id, h.row.sandbox_id)) for _ in range(8))
    )
    assert len(await works(h)) == 1


@pytest.mark.parametrize("winner", ["reap", "service", "resume"])
async def test_exclusive_stopped_claims(life, winner):
    h = life
    await detach(h)
    await eligible(h)
    r = h.lifecycle_repository
    if winner == "resume":
        assert (await h.service.provision(h.row.session_id)).status == "creating"
    else:
        async with h.sessions.begin() as db:
            if winner == "service":
                assert await r.service(
                    db, h.row.session_id, h.row.sandbox_id, datetime.now(UTC), 120, []
                )
            else:
                assert await r.reap(
                    db,
                    h.row.session_id,
                    h.row.sandbox_id,
                    h.row.pvc_id,
                    datetime.now(UTC),
                    1800,
                    7200,
                    120,
                )
        before = list(h.kube.calls)
        await h.service.provision(h.row.session_id)
        assert h.kube.calls == before
    async with h.sessions.begin() as db:
        assert (
            await r.reap(
                db,
                h.row.session_id,
                h.row.sandbox_id,
                h.row.pvc_id,
                datetime.now(UTC),
                1800,
                7200,
                120,
            )
            is None
        )
        assert (
            await r.service(db, h.row.session_id, h.row.sandbox_id, datetime.now(UTC), 120, [])
            is None
        )


async def test_stale_completion_same_state_is_fenced(life):
    h = life
    work = await idle(h)
    async with h.sessions.begin() as db:
        row = await db.get(SandboxSession, h.row.session_id)
        row.status_changed_at = advance(row.status_changed_at, row.status_changed_at)
    await h.lifecycle.shutdown_ack(h.row.sandbox_id, work.state_changed)
    await h.lifecycle.execute(work.work_id)
    assert not h.cleanup.deleted
    async with h.sessions.begin() as db:
        assert not await h.lifecycle_repository.complete(db, work, datetime.now(UTC))
    assert (await row_for(h, h.row.session_id)).status == "shutting_down"


async def test_published_failure_wins_over_late_success_and_duplicate_is_ignored(life):
    h = life
    await detach(h)
    resumed = await h.service.provision(h.row.session_id)
    async with h.sessions.begin() as db:
        assert await h.repository.mark_ready(
            db, resumed.sandbox_id, datetime.now(UTC), resumed.status_changed_at
        )
    signal = Signal(h.row.session_id, h.row.sandbox_id)
    await h.lifecycle.admit(RECOVER, signal)
    recovered = await row_for(h, h.row.session_id)
    assert recovered.status == "recovering" and recovered.sandbox_id != h.row.sandbox_id
    assert (await disk(h)).state == "failed"
    targets = deepcopy((await works(h))[0].targets)
    assert any(t["uid"] == h.row.pvc_uid for t in targets)
    await h.lifecycle.admit(RECOVER, signal)
    await h.lifecycle.admit(RECOVER, Signal(h.row.session_id, recovered.sandbox_id))
    assert len(await works(h)) == 1
    assert (await works(h))[0].targets == targets


async def test_idle_watchdog_never_converts_slow_detach_into_recovery(life):
    h = life
    work = await idle(h)
    async with h.sessions.begin() as db:
        pvc = await db.get(SessionPVC, h.row.pvc_id)
        pvc.last_state_change -= timedelta(hours=1)
        stored = await db.get(CleanupWork, work.work_id)
        stored.pvc_changed = pvc.last_state_change
        row = await db.get(SandboxSession, h.row.session_id)
        row.status_changed_at -= timedelta(hours=1)
        stored.state_changed = row.status_changed_at
        work.state_changed = row.status_changed_at
    await h.lifecycle.scan("watchdog")
    h.publisher.send.assert_not_awaited()
    assert (await row_for(h, h.row.session_id)).status == "shutting_down"
    # Slow storage release is not a failure verdict; cleanup can still complete.
    await h.lifecycle.shutdown_ack(h.row.sandbox_id, work.state_changed)
    await h.lifecycle.execute(work.work_id)
    assert (await row_for(h, h.row.session_id)).status == "stopped"


@pytest.mark.parametrize("acknowledged", [False, True])
async def test_overdue_idle_survives_restart_and_delayed_recovery_without_losing_disk(
    life, acknowledged
):
    h = life
    work = await idle(h)
    async with h.sessions.begin() as db:
        stored = await db.get(CleanupWork, work.work_id)
        stored.deadline = datetime.now(UTC) - timedelta(seconds=1)
    if acknowledged:
        await h.lifecycle.shutdown_ack(h.row.sandbox_id, work.state_changed)
    h.cleanup.release = False
    restarted = LifecycleService(
        h.lifecycle.settings,
        h.sessions,
        h.lifecycle_repository,
        h.cleanup,
        h.publisher,
        h.lifecycle.credentials,
        h.lifecycle.tokens,
    )
    await restarted.execute(work.work_id)
    await restarted.admit(RECOVER, Signal(h.row.session_id, h.row.sandbox_id))
    row = await row_for(h, h.row.session_id)
    assert row.status == "shutting_down" and row.sandbox_id == h.row.sandbox_id
    assert (row.pvc_id, row.pvc_uid) == (h.row.pvc_id, h.row.pvc_uid)
    stored = (await works(h))[0]
    assert stored.kind == "idle" and stored.deadline > datetime.now(UTC)
    assert stored.state_changed == work.state_changed and stored.pvc_changed == work.pvc_changed
    assert any(t.get("retain") and t["uid"] == h.row.pvc_uid for t in stored.targets)
    assert all(c.args[0] != RECOVER for c in h.publisher.send.call_args_list)
    if not acknowledged:
        assert not h.cleanup.deleted
    else:
        assert len(h.cleanup.deleted) == 2
    await restarted.shutdown_ack(h.row.sandbox_id, work.state_changed)
    h.cleanup.release = True
    await restarted.execute(work.work_id)
    await restarted.admit(RECOVER, Signal(h.row.session_id, h.row.sandbox_id))
    assert (await row_for(h, h.row.session_id)).status == "stopped"
    assert (await disk(h)).state == "detached"
    assert not await works(h)
    resumed = await h.service.provision(h.row.session_id)
    assert (resumed.pvc_id, resumed.pvc_uid) == (h.row.pvc_id, h.row.pvc_uid)


@pytest.mark.parametrize("failure", ["shutdown", "capture", "delete", "released"])
async def test_idle_api_and_publication_errors_preserve_retention(life, failure):
    h = life
    work = await idle(h)
    if failure == "shutdown":
        h.publisher.send.side_effect = RuntimeError("broker unavailable")
    else:
        await h.lifecycle.shutdown_ack(h.row.sandbox_id, work.state_changed)
        setattr(h.cleanup, failure, AsyncMock(side_effect=RuntimeError("API unavailable")))
    await h.lifecycle.execute(work.work_id)
    assert (await row_for(h, h.row.session_id)).status == "shutting_down"
    assert (await disk(h)).state == "detaching"
    assert (await works(h))[0].kind == "idle"
    assert all(c.args[0] != RECOVER for c in h.publisher.send.call_args_list)
    assert ("PersistentVolumeClaim", session_name(h.row.pvc_id)) in h.kube.objects


async def test_legacy_target_order_stops_both_deployments_before_waiting_on_storage(life):
    h = life
    work = await idle(h)
    async with h.sessions.begin() as db:
        stored = await db.get(CleanupWork, work.work_id)
        targets = stored.targets
        stored.targets = [targets[0], targets[2], targets[1], targets[3]]
    await h.lifecycle.shutdown_ack(h.row.sandbox_id, work.state_changed)
    original = h.cleanup.delete
    requested = []

    async def deleting(obj):
        requested.append(obj["name"])
        if obj["name"] != ipc_name(h.row.sandbox_id):
            await original(obj)

    h.cleanup.delete = deleting
    h.cleanup.released = AsyncMock(return_value=False)
    await h.lifecycle.execute(work.work_id)
    assert requested == [ipc_name(h.row.sandbox_id), session_name(h.row.sandbox_id)]
    h.cleanup.released.assert_not_awaited()
    assert (await row_for(h, h.row.session_id)).status == "shutting_down"
    h.cleanup.delete = original
    h.cleanup.released.return_value = True
    await h.lifecycle.execute(work.work_id)
    assert (await row_for(h, h.row.session_id)).status == "stopped"


async def test_idle_and_reap_schedulers_are_bounded_and_signal_only(life):
    h = life
    h.lifecycle.settings = replace(h.lifecycle.settings, lifecycle_batch=1)
    await h.lifecycle.scan("idle")
    assert h.publisher.send.call_count == 1
    assert h.publisher.send.call_args.args[0] == IDLE
    assert (await row_for(h, h.row.session_id)).status == "ready"
    await detach(h)
    await eligible(h)
    await h.lifecycle.scan("reap")
    assert h.publisher.send.call_args.args[0] == REAP
    assert (await disk(h)).state == "detached"


async def test_missing_retained_disk_never_becomes_stopped(life):
    h = life
    work = await idle(h)
    await h.lifecycle.shutdown_ack(h.row.sandbox_id, work.state_changed)
    del h.kube.objects[("PersistentVolumeClaim", session_name(h.row.pvc_id))]
    await h.lifecycle.execute(work.work_id)
    assert (await row_for(h, h.row.session_id)).status == "shutting_down"
    assert await disk(h) is not None


async def test_stopped_orphan_service_excludes_resume_and_shares_deadline(life):
    h = life
    late = deepcopy(h.kube.objects[("Deployment", ipc_name(h.row.sandbox_id))])
    await detach(h)
    h.kube.put(late)
    signal = h.lifecycle.object_signal(h.kube.objects[("Deployment", ipc_name(h.row.sandbox_id))])
    await h.lifecycle.admit(ORPHAN, signal)
    row = await row_for(h, h.row.session_id)
    assert row.status == "service"
    deadline = row.service_deadline
    await h.lifecycle.admit(ORPHAN, signal)
    assert (await row_for(h, row.session_id)).service_deadline == deadline
    assert (await h.service.provision(row.session_id)).status == "service"
    await h.lifecycle.execute((await works(h))[0].work_id)
    assert (await row_for(h, row.session_id)).status == "stopped"
    assert await disk(h) is not None


async def test_orphan_group_replacement_fencing_and_late_scan(life):
    h = life
    old_objects = deepcopy(list(h.kube.objects.values()))
    # Remove all DB ownership, retaining a completely orphaned four-object group.
    async with h.sessions.begin() as db:
        await db.delete(await db.get(SandboxSession, h.row.session_id))
    signal = h.lifecycle.object_signal(old_objects[0])
    await h.lifecycle.admit(ORPHAN, signal)
    work = (await works(h))[0]
    assert work.kind == "orphan" and len(work.targets) == 4
    await h.lifecycle.execute(work.work_id)
    assert not await works(h) and not h.kube.objects
    assert [v[0] for v in h.cleanup.deleted[:2]] == ["Deployment", "Deployment"]
    late = h.kube.put(old_objects[0])
    await h.lifecycle.scan("orphan")
    assert h.publisher.send.call_args.args[0] == ORPHAN
    await h.lifecycle.admit(ORPHAN, h.lifecycle.object_signal(late))
    work = (await works(h))[0]
    replacement = h.kube.put({**late, "metadata": {**late["metadata"], "uid": "replacement"}})
    # Fake put assigns UIDs; explicitly make the same-name replacement different.
    replacement["metadata"]["uid"] = "replacement"
    h.kube.objects[(replacement["kind"], replacement["metadata"]["name"])] = replacement
    await h.lifecycle.execute(work.work_id)
    assert (await h.cleanup.observe(work.targets[0]))["metadata"]["uid"] == "replacement"


async def test_service_deadline_does_not_refresh_on_requests_and_timeout_hands_off(life):
    h = life
    await detach(h)
    async with h.sessions.begin() as db:
        work = await h.lifecycle_repository.service(
            db, h.row.session_id, h.row.sandbox_id, datetime.now(UTC) - timedelta(seconds=10), 1, []
        )
    for _ in range(3):
        await h.lifecycle.service_expired(await row_for(h, h.row.session_id))
    assert h.publisher.send.call_count == 3
    assert all(c.args[0] == RECOVER for c in h.publisher.send.call_args_list)
    await h.lifecycle.execute(work.work_id)
    assert (await row_for(h, h.row.session_id)).status == "service"
    await h.lifecycle.admit(RECOVER, Signal(h.row.session_id, h.row.sandbox_id))
    assert (await row_for(h, h.row.session_id)).status == "recovering"
    assert all(w.kind == "recovery" for w in await works(h))


async def test_owned_and_golden_objects_are_not_orphan_candidates(life):
    h = life
    await h.lifecycle.scan("orphan")
    assert not h.publisher.send.called
    await detach(h)
    await h.lifecycle.scan("orphan")
    assert not h.publisher.send.called  # Retained session PVC remains owned.
    assert h.lifecycle.object_signal({"kind": "Job", "metadata": {}}) is None
    assert (
        h.lifecycle.object_signal(
            {
                "kind": "PersistentVolumeClaim",
                "metadata": {"name": "ads-sandbox-golden-v1", "uid": "golden", "labels": {}},
            }
        )
        is None
    )
