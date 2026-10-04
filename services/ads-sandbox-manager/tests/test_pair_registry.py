# ruff: noqa: F811
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import delete, select

from ads_sandbox_manager.lifecycle import LifecycleService
from ads_sandbox_manager.lifecycle_store import CleanupWork
from ads_sandbox_manager.pair_disposal import PairDisposal
from ads_sandbox_manager.pair_registry import PairRegistry
from ads_sandbox_manager.pair_retirement import (
    PairRetirementRepository,
    retirement_kind,
)
from ads_sandbox_manager.pair_store import PairIntent
from ads_sandbox_manager.store import SandboxSession
from test_kube_release import api  # noqa: F401
from test_pair_store import ledger, snapshot  # noqa: F401
from test_pair_controls import controls  # noqa: F401
from test_pair_creation import creation  # noqa: F401
from test_pair_disposal import reap, stopped
from test_pair_teardown_world import pair_world, reconcile  # noqa: F401
from test_pair_volume_publication import publication as volume_publication  # noqa: F401
from test_session_objects import object_settings  # noqa: F401
from test_sessions import sessions_harness  # noqa: F401

pytestmark = pytest.mark.anyio


@pytest.mark.parametrize("marker", ["ads.io/project-id", "ads.io/attachment-generation", "ads.io/egress-state-id"])
def test_paired_markers_are_never_legacy_orphan_authority(marker):
    sid, sandbox, pvc = uuid4(), uuid4(), uuid4()
    obj = {
        "kind": "PersistentVolumeClaim",
        "metadata": {
            "name": "ads-sandbox-" + str(pvc),
            "uid": str(uuid4()),
            "labels": {
                "ads.io/session-id": str(sid),
                "ads.io/sandbox-id": str(sandbox),
                "app.kubernetes.io/component": "ads-sandbox",
                marker: str(uuid4()),
            },
        },
    }
    assert LifecycleService.object_signal(obj) is None
    del obj["metadata"]["labels"][marker]
    assert LifecycleService.object_signal(obj) is not None


def lose_session_sync(f):
    return f


async def lose_session(f):
    async with f.h.sessions.begin() as db:
        await db.execute(
            delete(SandboxSession).where(SandboxSession.session_id == f.row.session_id)
        )


async def test_registry_recovers_exact_orphan_after_session_and_work_loss(pair_world):
    f = pair_world
    await stopped(f)
    await lose_session(f)
    work = await reconcile(f)
    assert work.kind == "orphan" and work.session_id is None
    await f.pair_service.execute(work.work_id)
    async with f.h.sessions.begin() as db:
        assert await db.get(CleanupWork, work.work_id) is None
        assert await db.get(SandboxSession, f.row.session_id) is None
        await f.retirements.verify(db, f.intent.generation)
        kind = retirement_kind(work, f.intent)
        if kind == "orphan-retained":
            assert (await db.get(PairDisposal, f.intent.generation)).completed_at is not None
    assert not f.remote.objects


async def test_idle_work_loss_reconstructs_same_drain_and_retention_boundary(pair_world):
    f = pair_world
    async with f.h.sessions.begin() as db:
        await db.delete(await db.get(CleanupWork, f.work.work_id))
    work = await reconcile(f)
    assert work.kind == "idle" and work.acknowledged
    assert work.state_changed == f.work.state_changed and work.pvc_changed == f.work.pvc_changed
    await f.pair_service.execute(work.work_id)
    async with f.h.sessions.begin() as db:
        assert (await db.get(SandboxSession, f.row.session_id)).status == "stopped"
        await f.retirements.verify(db, f.intent.generation)
    # Retained workspace PVC is the only survivor of an idle teardown in the
    # plain-column world; guest runtimes are raw Pods (no Deployment/PV trio).
    assert len(f.remote.objects) == 1
    assert next(iter(f.remote.objects))[0] == "PersistentVolumeClaim"


async def test_retained_expiry_receipt_recovers_without_reopening_resume(pair_world):
    f = pair_world
    row = await stopped(f)
    previous = await reap(f, row)
    assert previous is not None and previous.work_id
    # Lose the exclusive receipt work; candidates() only lists workless pairs.
    async with f.h.sessions.begin() as db:
        await db.delete(await db.get(CleanupWork, previous.work_id))
    work = await reconcile(f)
    assert work is not None and work.work_id == previous.work_id
    await f.pair_service.execute(work.work_id)
    async with f.h.sessions.begin() as db:
        assert (await db.get(PairDisposal, f.intent.generation)).completed_at is not None
        assert await db.get(CleanupWork, work.work_id) is None
    assert not f.remote.objects


async def test_retired_idle_orphan_is_inventory_even_without_live_kubernetes_objects_list(
    pair_world,
):
    f = pair_world
    await stopped(f)
    await lose_session(f)
    work = await reconcile(f)
    assert work.pair_snapshot is None
    await f.pair_service.execute(work.work_id)
    async with f.h.sessions.begin() as db:
        assert (await db.get(PairDisposal, f.intent.generation)).completed_at is not None
        assert (
            await db.scalar(
                select(CleanupWork.work_id).where(CleanupWork.sandbox_id == f.intent.sandbox_id)
            )
            is None
        )
    assert not f.remote.objects


async def test_maintenance_cannot_reopen_retired_pair_as_legacy_cleanup(pair_world):
    f = pair_world
    row = await stopped(f)
    before = dict(f.remote.objects)
    async with f.h.sessions.begin() as db:
        assert (
            await f.pair_service.repository.service(
                db, row.session_id, row.sandbox_id, datetime.now(UTC), 120, f.work.targets
            )
            is None
        )
    async with f.h.sessions.begin() as db:
        current = await db.get(SandboxSession, row.session_id)
        assert current.status == "stopped" and current.pvc_id == row.pvc_id
        assert (
            await db.scalar(
                select(CleanupWork.work_id).where(CleanupWork.sandbox_id == row.sandbox_id)
            )
            is None
        )
    assert f.remote.objects == before


async def test_bounded_registry_scan_advances_past_unreconciled_oldest_entry(pair_world):
    f = pair_world
    await lose_session(f)
    registry = PairRegistry(f.pair_service.repository)
    old_id = uuid4()
    async with f.h.sessions.begin() as db:
        # Deliberately malformed retained inventory is a blocker, not permission
        # to delete anything or to monopolize every subsequent bounded scan.
        db.add(
            PairIntent(
                generation=old_id,
                session_id=uuid4(),
                sandbox_id=uuid4(),
                project_id=f.intent.project_id,
                claim_owner=uuid4(),
                claim_changed=f.intent.claim_changed - timedelta(seconds=1),
                namespace=f.intent.namespace,
                golden_version=f.intent.golden_version,
                control_uids={},
            )
        )
    async with f.h.sessions.begin() as db:
        assert await registry.candidates(db, 1) == [old_id]
        assert await registry.candidates(db, 1, after=old_id) == [f.intent.generation]
        assert await registry.candidates(db, 1, after=f.intent.generation) == [old_id]
        assert await registry.candidates(db, 1, after=uuid4()) == [old_id]
