# ruff: noqa: F811
from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy import delete, select

from ads_sandbox_manager.lifecycle import LifecycleService
from ads_sandbox_manager.lifecycle_store import CleanupWork
from ads_sandbox_manager.pair_disposal import PairDisposal
from ads_sandbox_manager.pair_registry import PairRegistry
from ads_sandbox_manager.pair_retirement import PairRetirement, PairRetirementRepository
from ads_sandbox_manager.store import SandboxSession
from test_kube_release import api  # noqa: F401
from test_node_release_wire import node_report  # noqa: F401
from test_pair_cleanup_journal import journal  # noqa: F401
from test_pair_controls import controls  # noqa: F401
from test_pair_creation import creation  # noqa: F401
from test_pair_disposal import prepare
from test_pair_resource_teardown import resources  # noqa: F401
from test_pair_runtime_teardown import lifecycle, teardown  # noqa: F401
from test_pair_store import ledger, snapshot  # noqa: F401
from test_pair_transfer import stopped
from test_pair_volume_publication import publication as volume_publication  # noqa: F401
from test_session_objects import object_settings  # noqa: F401
from test_sessions import sessions_harness  # noqa: F401

pytestmark = pytest.mark.anyio


@pytest.mark.parametrize(
    "marker", ["ads.io/project-id", "ads.io/attachment-generation", "ads.io/egress-state-id"]
)
def test_paired_markers_are_never_legacy_orphan_authority(marker):
    from uuid import uuid4

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


async def reconcile(f):
    registry = PairRegistry(f.capture.repository)
    async with f.h.sessions.begin() as db:
        assert f.intent.generation in await registry.candidates(db, 100)
        return await registry.reconcile(db, f.intent.generation, datetime.now(UTC), 120)


async def lose_session(f):
    async with f.h.sessions.begin() as db:
        await db.execute(
            delete(SandboxSession).where(SandboxSession.session_id == f.row.session_id)
        )


@pytest.mark.parametrize("resources", ["idle", "recovery"], indirect=True)
async def test_registry_recovers_exact_orphan_after_session_and_work_loss(resources):
    f = resources
    await lose_session(f)
    work = await reconcile(f)
    assert work.kind == "orphan" and work.session_id is None
    worker = lifecycle(f)
    worker.pair_resources = f.resource_stage
    await worker.execute(work.work_id)
    # A retained journal retires unchanged before its separate lifetime disposal.
    await worker.execute(work.work_id)
    async with f.h.sessions.begin() as db:
        assert await db.get(CleanupWork, work.work_id) is None
        assert await db.get(SandboxSession, f.row.session_id) is None
        saved = await PairRetirementRepository(f.capture.repository).verify(db, f.intent.generation)
        if saved.kind == "orphan-retained":
            assert (await db.get(PairDisposal, f.intent.generation)).completed_at is not None
        else:
            assert saved.kind == "orphan"
    assert not f.remote.objects


@pytest.mark.parametrize("resources", ["idle"], indirect=True)
async def test_idle_work_loss_reconstructs_same_drain_and_retention_boundary(resources):
    f = resources
    async with f.h.sessions.begin() as db:
        await db.delete(await db.get(CleanupWork, f.work.work_id))
    work = await reconcile(f)
    assert work.kind == "idle" and work.acknowledged
    assert work.state_changed == f.work.state_changed and work.pvc_changed == f.work.pvc_changed
    worker = lifecycle(f)
    worker.pair_resources = f.resource_stage
    await worker.execute(work.work_id)
    async with f.h.sessions.begin() as db:
        assert (await db.get(SandboxSession, f.row.session_id)).status == "stopped"
        assert (await db.get(PairRetirement, f.intent.generation)).kind == "idle"
    assert len(f.remote.objects) == 3


@pytest.mark.parametrize("resources", ["idle"], indirect=True)
@pytest.mark.parametrize("loss", ["work", "session"])
async def test_retained_expiry_receipt_recovers_without_reopening_resume(resources, loss):
    f = resources
    _, previous, _ = await prepare(f)
    if loss == "session":
        await lose_session(f)
    else:
        async with f.h.sessions.begin() as db:
            await db.delete(await db.get(CleanupWork, previous.work_id))
    work = await reconcile(f)
    assert work.work_id == previous.work_id
    worker = lifecycle(f)
    worker.pair_resources = f.resource_stage
    await worker.execute(work.work_id)
    async with f.h.sessions.begin() as db:
        assert (await db.get(PairDisposal, f.intent.generation)).completed_at is not None
        assert await db.get(CleanupWork, work.work_id) is None
    assert not f.remote.objects


@pytest.mark.parametrize("resources", ["idle"], indirect=True)
async def test_retired_idle_orphan_is_inventory_even_without_live_kubernetes_objects_list(
    resources,
):
    f = resources
    await stopped(f)
    await lose_session(f)
    work = await reconcile(f)
    assert work.pair_snapshot is None
    worker = lifecycle(f)
    worker.pair_resources = f.resource_stage
    await worker.execute(work.work_id)
    async with f.h.sessions.begin() as db:
        assert (await db.get(PairDisposal, f.intent.generation)).completed_at is not None
        assert (
            await db.scalar(
                select(CleanupWork.work_id).where(CleanupWork.sandbox_id == f.intent.sandbox_id)
            )
            is None
        )
    assert not f.remote.objects


@pytest.mark.parametrize("resources", ["idle"], indirect=True)
async def test_maintenance_cannot_reopen_retired_pair_as_legacy_cleanup(resources):
    f = resources
    row = await stopped(f)
    before = dict(f.remote.objects)
    async with f.h.sessions.begin() as db:
        assert (
            await f.capture.repository.service(
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
    resumed = await f.h.service.provision(row.session_id)
    assert resumed.sandbox_id == row.sandbox_id and resumed.status == "creating"
