# ruff: noqa: F811
from __future__ import annotations

import asyncio
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from kubernetes.client.exceptions import ApiException
from sqlalchemy import delete

from ads_sandbox_manager.lifecycle import ORPHAN, RECOVER, Signal
from ads_sandbox_manager.lifecycle_store import CleanupWork
from ads_sandbox_manager.pair_store import CONTROL_RESOURCES, PairClaimLost, PairIntent
from ads_sandbox_manager.store import SandboxSession, SessionPVC
from test_kube_release import api  # noqa: F401
from test_lifecycle import life, works  # noqa: F401
from test_pair_cleanup_capture import capture, saved  # noqa: F401
from test_pair_cleanup_intent import paired  # noqa: F401
from test_ping_recovery import recovery
from test_session_objects import object_settings  # noqa: F401
from test_sessions import row_for, sessions_harness  # noqa: F401

pytestmark = pytest.mark.anyio


@pytest.fixture
async def recovering(capture):
    h = capture
    async with h.sessions.begin() as db:
        await db.execute(delete(CleanupWork))
        row = await db.get(SandboxSession, h.row.session_id)
        row.status = "ready"
        pvc = await db.get(SessionPVC, h.row.pvc_id)
        pvc.state = "attached"
    await h.lifecycle.admit(RECOVER, Signal(h.row.session_id, h.row.sandbox_id))
    h.work = await saved(h)
    h.claim = await row_for(h, h.row.session_id)
    assert h.claim.sandbox_id != h.work.sandbox_id
    return h


@pytest.fixture
async def orphan(capture):
    h = capture
    obj = next(o for o in h.kube.objects.values() if o["kind"] == "Deployment")
    async with h.sessions.begin() as db:
        await db.execute(delete(SandboxSession))
    await h.lifecycle.admit(
        ORPHAN,
        Signal(
            h.row.session_id,
            h.row.sandbox_id,
            kind="Deployment",
            name=obj["metadata"]["name"],
            uid=obj["metadata"]["uid"],
        ),
    )
    h.work = await saved(h)
    assert h.work.kind == "orphan" and h.work.session_id is None
    return h


async def test_real_recovery_captures_old_pair_without_delete_or_rebuild(recovering):
    h = recovering
    calls = []

    async def before(pair, kind, role, uid):
        async with asyncio.timeout(5), h.sessions.begin() as db:
            row = await db.get(SandboxSession, h.claim.session_id, with_for_update=True)
            work = await db.get(CleanupWork, h.work.work_id, with_for_update=True)
            assert row.sandbox_id == h.claim.sandbox_id
            assert pair.sandbox_id == h.pair.sandbox_id != row.sandbox_id
            assert sum(v is not None for v in work.pair_snapshot["control_uids"].values()) == max(
                1, len(calls)
            )
        calls.append((kind, role))

    h.adapter.before = before
    h.service.build = AsyncMock()
    await recovery(h).execute(h.row.session_id)
    assert calls == list(CONTROL_RESOURCES)
    assert all((await saved(h)).pair_snapshot["control_uids"].values())
    assert not h.remote.created and not h.cleanup.deleted and not h.kube.calls
    h.service.build.assert_not_awaited()
    assert (await row_for(h, h.row.session_id)).status == "recovering"


async def test_repeated_recovery_uses_current_claim_not_expired_old_work(recovering):
    h = recovering
    async with h.sessions.begin() as db:
        row = await db.get(SandboxSession, h.claim.session_id)
        row.status_changed_at -= timedelta(seconds=h.settings.recovery_seconds + 1)
        work = await db.get(CleanupWork, h.work.work_id)
        work.deadline = datetime.now(UTC) - timedelta(days=1)
    old = await row_for(h, h.claim.session_id)
    await h.lifecycle.admit(RECOVER, Signal(old.session_id, old.sandbox_id))
    current = await row_for(h, h.claim.session_id)
    original = next(w for w in await works(h) if w.work_id == h.work.work_id)
    with pytest.raises(PairClaimLost):
        await h.capture.capture(original, recovery=h.claim)
    await h.capture.capture(original, recovery=current)
    captured = next(w for w in await works(h) if w.work_id == h.work.work_id)
    assert all(captured.pair_snapshot["control_uids"].values())
    assert len(await works(h)) == 2
    assert not h.cleanup.deleted and not h.remote.created


@pytest.mark.parametrize(
    "change",
    [
        "boundary",
        "sandbox",
        "status",
        "project",
        "claim_owner",
        "pvc",
        "work",
        "snapshot",
        "targets",
    ],
)
async def test_recovery_claim_loss_during_read_preserves_evidence(recovering, change):
    h = recovering
    calls = []

    async def after(*args):
        calls.append(args)
        async with h.sessions.begin() as db:
            row = await db.get(SandboxSession, h.claim.session_id, with_for_update=True)
            work = await db.get(CleanupWork, h.work.work_id)
            if change == "boundary":
                row.status_changed_at += timedelta(microseconds=1)
            elif change == "sandbox":
                row.sandbox_id = uuid4()
            elif change == "status":
                row.status = "failed"
            elif change == "project":
                row.project_id = uuid4()
            elif change == "claim_owner":
                row.claimed_by = uuid4()
            elif change == "pvc":
                (await db.get(SessionPVC, h.work.pvc_id)).state = "detached"
            elif change == "work":
                await db.delete(work)
            elif change == "snapshot":
                work.pair_snapshot = {**work.pair_snapshot, "generation": str(uuid4())}
            else:
                work.targets = [{**work.targets[0], "retain": True}]

    h.adapter.after = after
    with pytest.raises(PairClaimLost):
        await h.capture.capture(h.work, recovery=h.claim)
    assert len(calls) == 1
    assert not h.cleanup.deleted and not h.remote.created


@pytest.mark.parametrize("change", ["expired", "wrong_session", "retained", "missing_pvc"])
async def test_invalid_recovery_authority_never_reads_api(recovering, change):
    h = recovering
    async with h.sessions.begin() as db:
        if change == "expired":
            row = await db.get(SandboxSession, h.claim.session_id)
            row.status_changed_at -= timedelta(seconds=h.settings.recovery_seconds + 1)
        elif change == "retained":
            work = await db.get(CleanupWork, h.work.work_id)
            work.targets = [{**work.targets[0], "retain": True}]
        elif change == "missing_pvc":
            await db.delete(await db.get(SessionPVC, h.work.pvc_id))
    claim = await row_for(h, h.claim.session_id)
    if change == "wrong_session":
        claim.session_id = uuid4()
    h.adapter.before = lambda *args: pytest.fail("invalid recovery reached API")
    with pytest.raises(PairClaimLost):
        await h.capture.capture(await saved(h), recovery=claim)


@pytest.mark.parametrize("change", ["project", "boundary", "sandbox", "targets"])
async def test_real_recovery_claim_loss_never_fails_replacement(recovering, change):
    h = recovering
    h.service.build = AsyncMock()

    async def after(*args):
        async with h.sessions.begin() as db:
            row = await db.get(SandboxSession, h.claim.session_id, with_for_update=True)
            if change == "project":
                row.project_id = uuid4()
            elif change == "boundary":
                row.status_changed_at += timedelta(microseconds=1)
            elif change == "sandbox":
                row.sandbox_id = uuid4()
            else:
                work = await db.get(CleanupWork, h.work.work_id)
                work.targets = [{**work.targets[0], "retain": True}]

    h.adapter.after = after
    await recovery(h).execute(h.claim.session_id)
    assert (await row_for(h, h.claim.session_id)).status == "recovering"
    assert (await saved(h)).pair_snapshot == h.work.pair_snapshot
    h.publisher.send.assert_not_awaited()
    h.service.build.assert_not_awaited()
    assert not h.cleanup.deleted and not h.remote.created


async def test_true_orphan_captures_and_retries_after_old_deadline_without_retirement(orphan):
    h = orphan
    async with h.sessions.begin() as db:
        work = await db.get(CleanupWork, h.work.work_id)
        work.deadline = datetime.now(UTC) - timedelta(days=1)
    calls = []

    async def before(pair, kind, role, uid):
        async with asyncio.timeout(5), h.sessions.begin() as db:
            work = await db.get(CleanupWork, h.work.work_id, with_for_update=True)
            intent = await db.get(PairIntent, pair.generation, with_for_update=True)
            assert intent.binding() == pair
            assert sum(v is not None for v in work.pair_snapshot["control_uids"].values()) == max(
                1, len(calls)
            )
        calls.append((kind, role))

    h.adapter.before = before
    await h.lifecycle.execute(h.work.work_id)
    assert calls == list(CONTROL_RESOURCES)
    h.adapter.before = None
    work = await saved(h)
    assert all(work.pair_snapshot["control_uids"].values())
    h.remote.objects.clear()
    await h.lifecycle.execute(work.work_id)
    assert (await saved(h)).pair_snapshot == work.pair_snapshot
    assert not h.cleanup.deleted and not h.remote.created
    async with h.sessions.begin() as db:
        assert not await h.lifecycle_repository.complete(db, work, datetime.now(UTC))
        assert await db.get(PairIntent, h.pair.generation)


@pytest.mark.parametrize("change", ["session", "sandbox_owner", "intent", "intent_scope", "work"])
async def test_orphan_owner_or_identity_change_during_read_blocks_commit(orphan, change):
    h = orphan
    calls = []

    async def after(*args):
        calls.append(args)
        async with h.sessions.begin() as db:
            if change in ("session", "sandbox_owner"):
                values = {
                    column.name: getattr(h.row, column.name)
                    for column in SandboxSession.__table__.columns
                }
                values.update(
                    session_id=h.row.session_id if change == "session" else uuid4(),
                    sandbox_id=uuid4() if change == "session" else h.row.sandbox_id,
                    pvc_id=None,
                )
                db.add(SandboxSession(**values))
            elif change == "intent":
                await db.delete(await db.get(PairIntent, h.pair.generation))
            elif change == "intent_scope":
                (await db.get(PairIntent, h.pair.generation)).project_id = uuid4()
            else:
                await db.delete(await db.get(CleanupWork, h.work.work_id))

    h.adapter.after = after
    with pytest.raises(PairClaimLost):
        await h.capture.capture(h.work)
    assert len(calls) == 1
    assert not h.cleanup.deleted and not h.remote.created


async def unavailable_then_retry(h, claim):
    original_snapshot = deepcopy(h.work.pair_snapshot)
    sdk = h.adapter.custom.get_namespaced_custom_object
    original_read = sdk.side_effect
    sdk.side_effect = ApiException(status=403)
    with pytest.raises(ApiException):
        await h.capture.capture(h.work, recovery=claim)
    assert (await saved(h)).pair_snapshot == original_snapshot
    sdk.side_effect = original_read
    original_record = h.lifecycle_repository.record_pair_control

    async def rollback(*args, **kwargs):
        await original_record(*args, **kwargs)
        raise RuntimeError("commit failed")

    h.lifecycle_repository.record_pair_control = rollback
    with pytest.raises(RuntimeError, match="commit failed"):
        await h.capture.capture(h.work, recovery=claim)
    assert (await saved(h)).pair_snapshot == original_snapshot
    h.lifecycle_repository.record_pair_control = original_record
    await h.capture.capture(await saved(h), recovery=claim)
    assert all((await saved(h)).pair_snapshot["control_uids"].values())
    assert not h.cleanup.deleted and not h.remote.created


async def test_recovery_api_and_commit_failure_retry(recovering):
    await unavailable_then_retry(recovering, recovering.claim)


async def test_orphan_api_and_commit_failure_retry(orphan):
    await unavailable_then_retry(orphan, None)


async def cancel_after_capture(h, claim):
    started = asyncio.Event()
    count = 0

    async def before(*args):
        nonlocal count
        count += 1
        if count == 3:
            started.set()
            await asyncio.Event().wait()

    h.adapter.before = before
    task = asyncio.create_task(h.capture.capture(h.work, recovery=claim))
    await asyncio.wait_for(started.wait(), 5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    controls = (await saved(h)).pair_snapshot["control_uids"]
    assert sum(uid is not None for uid in controls.values()) == 2
    assert not h.cleanup.deleted and not h.remote.created


async def test_recovery_cancellation_keeps_committed_evidence(recovering):
    await cancel_after_capture(recovering, recovering.claim)


async def test_orphan_cancellation_keeps_committed_evidence(orphan):
    await cancel_after_capture(orphan, None)


async def test_orphan_late_create_after_404_still_gets_captured(orphan):
    h = orphan
    objects = deepcopy(h.remote.objects)
    h.remote.objects.clear()
    await h.capture.capture(h.work)
    assert (await saved(h)).pair_snapshot == h.work.pair_snapshot
    h.remote.objects = objects
    await h.capture.capture(await saved(h))
    assert all((await saved(h)).pair_snapshot["control_uids"].values())
    assert not h.cleanup.deleted and not h.remote.created


async def test_orphan_conflicting_recovery_intent_blocks_capture(orphan):
    h = orphan
    async with h.sessions.begin() as db:
        values = {
            column.name: getattr(h.row, column.name) for column in SandboxSession.__table__.columns
        }
        values.update(session_id=uuid4(), sandbox_id=uuid4(), pvc_id=None)
        row = SandboxSession(**values)
        db.add(row)
        await db.flush()
        db.add(
            CleanupWork(
                work_id=uuid4(),
                session_id=row.session_id,
                sandbox_id=h.work.sandbox_id,
                pvc_id=None,
                kind="recovery",
                state_changed=row.status_changed_at,
                pvc_changed=None,
                deadline=datetime.now(UTC) + timedelta(seconds=60),
                acknowledged=False,
                targets=[],
                pair_snapshot=None,
            )
        )
    h.adapter.before = lambda *args: pytest.fail("recovery-owned orphan reached API")
    with pytest.raises(PairClaimLost, match="acquired an owner"):
        await h.capture.capture(h.work)
