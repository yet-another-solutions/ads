# ruff: noqa: F811
from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import delete, select, text

from ads_sandbox_manager.pair_store import PairIntent
from ads_sandbox_manager.store import SandboxSession, SessionPVC, SessionRepository
from test_kube_release import api  # noqa: F401
from test_lifecycle import life  # noqa: F401
from test_pair_cleanup_capture import capture, saved  # noqa: F401
from test_pair_cleanup_intent import paired  # noqa: F401
from test_pair_recovery_capture import orphan  # noqa: F401
from test_pair_store import begin, ledger, snapshot  # noqa: F401
from test_session_objects import object_settings  # noqa: F401
from test_sessions import row_for, sessions_harness  # noqa: F401

pytestmark = pytest.mark.anyio


async def test_legacy_cleanup_cannot_clear_an_untracked_ipc_pod_binding(life):
    h = life
    async with h.sessions.begin() as db:
        work = await h.lifecycle_repository.idle(
            db, h.row.session_id, h.row.sandbox_id, datetime.now(UTC), 60, 120
        )
        assert work is not None and work.pair_snapshot is None
        row = await db.get(SandboxSession, h.row.session_id)
        row.ipc_pod_uid = "untracked-pod"
    async with h.sessions.begin() as db:
        assert not await h.lifecycle_repository.complete(db, work, datetime.now(UTC))
    row = await row_for(h, h.row.session_id)
    assert row.status == "shutting_down" and row.ipc_pod_uid == "untracked-pod"


async def lose_session(f):
    async with f.h.sessions.begin() as db:
        await db.execute(
            delete(SandboxSession).where(SandboxSession.session_id == f.row.session_id)
        )


async def no_replacement(f, generation):
    assert await row_for(f.h, f.row.session_id) is None
    async with f.h.sessions.begin() as db:
        assert (
            await db.scalar(
                select(SessionPVC.pvc_id).where(SessionPVC.session_id == f.row.session_id)
            )
            is None
        )
        assert (await db.get(PairIntent, generation)).session_id == f.row.session_id
    assert not f.h.kube.calls


@pytest.mark.parametrize("evidence", ["unknown", "settled", "fenced", "corrupt"])
async def test_lost_session_cannot_recreate_while_any_pair_intent_survives(ledger, evidence):
    f = ledger
    intent = await begin(f)
    async with f.h.sessions.begin() as db:
        row = await db.get(PairIntent, intent.generation)
        if evidence == "settled":
            row.control_dispatch = dict.fromkeys(row.control_dispatch, "settled")
            row.control_uids = dict.fromkeys(row.control_uids, "observed-uid")
        elif evidence == "fenced":
            row.creation_fenced = True
        elif evidence == "corrupt":
            row.control_dispatch = {}
    await lose_session(f)
    # Both a fresh repository and a second request must reject without repair,
    # adoption, empty-UID inference or an automatically allocated new generation.
    f.h.service.repository = SessionRepository()
    for _ in range(2):
        with pytest.raises(RuntimeError, match="retained pair ownership"):
            await f.h.service.provision(f.row.session_id)
    await no_replacement(f, intent.generation)


async def test_foreign_project_association_does_not_release_old_session_identity(ledger):
    f = ledger
    intent = await begin(f)
    await lose_session(f)
    f.h.projects.project = uuid4()
    with pytest.raises(RuntimeError, match="retained pair ownership"):
        await f.h.service.provision(f.row.session_id)
    await no_replacement(f, intent.generation)
    assert (await snapshot(f, intent.generation)).project_id == intent.project_id


async def test_same_sandbox_cannot_be_rebound_under_a_different_session(ledger):
    f = ledger
    intent = await begin(f)
    await lose_session(f)
    other = uuid4()
    with pytest.raises(RuntimeError, match="retained pair ownership"):
        async with f.h.sessions.begin() as db:
            await f.h.repository.insert_pending(
                db,
                other,
                f.row.sandbox_id,
                f.h.settings.golden_version,
                datetime.now(UTC),
                f.row.project_id,
            )
    assert await row_for(f.h, other) is None
    await no_replacement(f, intent.generation)


@pytest.mark.parametrize("status", ["pending", "stopped"])
async def test_existing_claim_cannot_enter_legacy_builder_with_retained_pair(ledger, status):
    f = ledger
    intent = await begin(f)
    async with f.h.sessions.begin() as db:
        row = await db.get(SandboxSession, f.row.session_id)
        row.status = status
        row.claimed_by = None
        (await db.get(SessionPVC, row.pvc_id)).state = "detached"
    original = await row_for(f.h, f.row.session_id)
    with pytest.raises(RuntimeError, match="retained pair ownership"):
        if status == "stopped":
            await f.h.service.provision(original.session_id)
        else:
            async with f.h.sessions.begin() as db:
                await f.h.repository.claim(db, original, uuid4(), datetime.now(UTC))
    unchanged = await row_for(f.h, original.session_id)
    assert unchanged.status == status
    assert unchanged.status_changed_at == original.status_changed_at
    assert unchanged.claimed_by is None and unchanged.pvc_id == original.pvc_id
    async with f.h.sessions.begin() as db:
        assert (await db.get(SessionPVC, original.pvc_id)).state == "detached"
    assert (await snapshot(f, intent.generation)).binding() == intent.binding()
    assert not f.h.kube.calls


async def test_observing_existing_creating_pair_does_not_allocate_or_claim(ledger):
    f = ledger
    intent = await begin(f)
    row = await f.h.service.provision(f.row.session_id)
    assert row.sandbox_id == f.row.sandbox_id and row.status == "creating"
    assert row.claimed_by == f.owner and row.status_changed_at == f.row.status_changed_at
    assert (await snapshot(f, intent.generation)).binding() == intent.binding()
    assert not f.h.kube.calls


async def test_unrelated_session_in_same_project_still_uses_normal_provisioning(ledger):
    f = ledger
    intent = await begin(f)
    await lose_session(f)
    other = await f.h.service.provision(uuid4())
    assert other.project_id == intent.project_id
    assert other.sandbox_id != intent.sandbox_id
    assert other.pvc_uid and other.guest_deployment_uid and other.ipc_deployment_uid
    assert (await snapshot(f, intent.generation)).binding() == intent.binding()
    assert await row_for(f.h, intent.session_id) is None


async def test_concurrent_recreation_attempts_all_rollback_before_external_work(ledger):
    f = ledger
    intent = await begin(f)
    await lose_session(f)
    results = await asyncio.gather(
        *(f.h.service.provision(f.row.session_id) for _ in range(8)),
        return_exceptions=True,
    )
    assert all(
        isinstance(result, RuntimeError) and "retained pair ownership" in str(result)
        for result in results
    )
    await no_replacement(f, intent.generation)


@pytest.mark.parametrize("commit", [True, False])
async def test_insert_wait_rechecks_pair_committed_with_old_session_deletion(ledger, commit):
    f = ledger
    entered = asyncio.Event()
    pid = None
    original = f.h.repository.insert_pending

    async def tracked(db, *args, **kwargs):
        nonlocal pid
        pid = await db.scalar(text("SELECT pg_backend_pid()"))
        entered.set()
        return await original(db, *args, **kwargs)

    f.h.repository.insert_pending = tracked
    db = f.h.sessions()
    transaction = await db.begin()
    caller = None
    try:
        intent = await f.repo.begin(
            db,
            f.row,
            f.owner,
            namespace=f.h.settings.namespace,
            golden_version=f.h.settings.golden_version,
        )
        await db.execute(
            delete(SandboxSession).where(SandboxSession.session_id == f.row.session_id)
        )
        # The competing INSERT's first snapshot cannot see the uncommitted
        # intent. Prove it is actually waiting on PostgreSQL, not a fake lock.
        caller = asyncio.create_task(f.h.service.provision(f.row.session_id))
        async with asyncio.timeout(5):
            await entered.wait()
            while True:
                async with f.h.sessions.begin() as observer:
                    if await observer.scalar(text("SELECT pg_blocking_pids(:pid)"), {"pid": pid}):
                        break
                await asyncio.sleep(0.01)
        assert not caller.done() and not f.h.kube.calls
        if commit:
            await transaction.commit()
            with pytest.raises(RuntimeError, match="retained pair ownership"):
                await caller
            await no_replacement(f, intent.generation)
        else:
            await transaction.rollback()
            row = await caller
            assert row.sandbox_id == f.row.sandbox_id and row.claimed_by == f.owner
            assert await snapshot(f, intent.generation) is None
            assert not f.h.kube.calls
    finally:
        if transaction.is_active:
            await transaction.rollback()
        await db.close()
        if caller is not None:
            if not caller.done():
                caller.cancel()
            await asyncio.gather(caller, return_exceptions=True)


async def test_orphan_capture_cannot_be_overtaken_by_normal_provisioning(orphan):
    h = orphan
    attempts = []

    async def during_read(*args):
        with pytest.raises(RuntimeError, match="retained pair ownership"):
            await h.service.provision(h.row.session_id)
        attempts.append(args)

    h.adapter.before = during_read
    await h.lifecycle.execute(h.work.work_id)
    assert len(attempts) == 8
    assert await row_for(h, h.row.session_id) is None
    work = await saved(h)
    assert all(work.pair_snapshot["control_uids"].values())
    assert not h.cleanup.deleted and not h.remote.created and not h.kube.calls
    async with h.sessions.begin() as db:
        assert not await h.lifecycle_repository.complete(db, work, datetime.now(UTC))
        assert await db.get(PairIntent, h.pair.generation)
