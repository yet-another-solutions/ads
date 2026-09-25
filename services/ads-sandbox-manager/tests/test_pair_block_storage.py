# ruff: noqa: F811
from __future__ import annotations

import asyncio
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import msgspec
import pytest
from kubernetes.client.exceptions import ApiException
from sqlalchemy import delete

from ads_sandbox_manager.lifecycle_store import CleanupWork
from ads_sandbox_manager.pair_block_storage import PairBlockStorageTeardown
from ads_sandbox_manager.pair_store import PairClaimLost, PairIntent
from ads_sandbox_manager.store import SandboxSession, SessionPVC
from test_kube_release import api  # noqa: F401
from test_node_release_wire import node_report  # noqa: F401
from test_pair_cleanup_journal import journal  # noqa: F401
from test_pair_controls import controls  # noqa: F401
from test_pair_creation import creation  # noqa: F401
from test_pair_runtime_teardown import release, state, teardown  # noqa: F401
from test_pair_store import ledger, snapshot  # noqa: F401
from test_pair_volume_publication import publication as volume_publication  # noqa: F401
from test_session_objects import object_settings  # noqa: F401
from test_sessions import sessions_harness  # noqa: F401

pytestmark = pytest.mark.anyio


@pytest.fixture
async def block_storage(teardown, request):
    f = teardown
    if getattr(request, "param", None) == "idle":
        await make_idle(f)
    f.blocked = False
    assert await release(f)
    return await configure_block_storage(f)


async def make_idle(f):
    now = datetime.now(UTC)
    async with f.h.sessions.begin() as db:
        await db.execute(delete(CleanupWork).where(CleanupWork.work_id == f.work.work_id))
        row = await db.get(SandboxSession, f.row.session_id)
        row.sandbox_id, row.pvc_id, row.status = f.work.sandbox_id, f.work.pvc_id, "ready"
        row.pvc_uid = f.work.pair_snapshot["volume_resources"]["workspace"]["uid"]
        row.last_execution_at = now - timedelta(hours=4)
        pvc = await db.get(SessionPVC, f.work.pvc_id)
        pvc.state, pvc.last_execution = "attached", row.last_execution_at
        work = await f.capture.repository.idle(db, row.session_id, row.sandbox_id, now, 60, 120)
        assert work is not None
        work.acknowledged = True
    f.work, f.claim = work, None


async def configure_block_storage(f):
    """Fake external node/API seams only; keep the actual storage/repository stack."""
    f.block_stage = PairBlockStorageTeardown(f.runtime)
    f.block_busy, f.block_hook, f.block_lost = False, None, False
    f.deleted_pvs, f.block_events = set(), []
    f.block_reclaim = False
    f.block_targets = (await state(f))["storage_capture"]
    read = f.adapter.kube.core.read_persistent_volume.side_effect

    def pv(name, **kwargs):
        if name in f.deleted_pvs:
            raise ApiException(status=404)
        return read(name, **kwargs)

    f.adapter.kube.core.read_persistent_volume.side_effect = pv
    f.adapter.kube.storage.list_volume_attachment.return_value = {"items": [], "metadata": {}}
    f.adapter.kube.core.read_node.return_value = {"status": {}}

    async def observe(captured):
        f.block_events.append("observe")
        if f.block_hook:
            await f.block_hook()
        return msgspec.json.encode(
            {
                **msgspec.to_builtins(captured),
                "leftovers": {
                    "mappings": 0,
                    "mounts": 0,
                    "descriptors": int(f.block_busy),
                    "holders": 0,
                },
                "released": not f.block_busy,
            }
        )

    f.node.observe_block = observe

    def remove(name, namespace, *, body, **kwargs):
        key = ("PersistentVolumeClaim", name)
        obj = f.remote.objects.get(key)
        if obj is None:
            raise ApiException(status=404)
        assert namespace == f.adapter.namespace
        assert body["preconditions"] == {
            "uid": obj["metadata"]["uid"],
            "resourceVersion": obj["metadata"]["resourceVersion"],
        }
        f.block_events.append("delete:" + name)
        if f.block_reclaim:
            f.deleted_pvs.add(obj["spec"]["volumeName"])
        del f.remote.objects[key]
        if f.block_lost:
            f.block_lost = False
            raise TimeoutError("lost Block delete reply")
        return {}

    f.adapter.kube.core.delete_namespaced_persistent_volume_claim.side_effect = remove
    original_delete = f.storage.delete

    async def guarded_delete(target):
        assert (await state(f))["block_release"]["released"]
        await original_delete(target)

    f.storage.delete = guarded_delete
    return f


async def dispose(f):
    return await f.block_stage.dispose(f.work, recovery=f.claim)


async def test_block_reclamation_requires_runtime_kernel_and_csi_backing_receipts(block_storage):
    f = block_storage
    before = deepcopy(f.remote.objects)
    f.block_busy = True
    assert not await dispose(f)
    assert f.remote.objects == before
    f.block_busy = False
    assert not await dispose(f)
    saved = await state(f)
    assert saved["block_release"]["released"] and not saved["block_disposition"]
    assert "pv-workspace" not in f.deleted_pvs
    # The PVC is absent, but its original PV still exists: not reclaimed.
    f.deleted_pvs.add("pv-workspace")
    f.block_reclaim = True
    assert await dispose(f)
    assert (await state(f))["block_disposition"] == {
        role: "reclaimed" for role in ("workspace", "guest", "egress", "key", "state")
    }
    assert ("PersistentVolumeClaim", f.block_targets["ipc"]["name"]) in f.remote.objects
    events = list(f.block_events)
    assert await dispose(f) and f.block_events == events
    async with f.h.sessions.begin() as db:
        assert not await f.capture.repository.complete(db, f.work, datetime.now(UTC))


async def test_lost_block_delete_reply_preserves_original_receipts(block_storage):
    f = block_storage
    f.block_lost, f.block_reclaim = True, True
    with pytest.raises(TimeoutError):
        await dispose(f)
    saved = await state(f)
    assert saved["block_release"] and not saved["block_disposition"]
    assert await dispose(f)
    assert (await state(f))["block_capture"] == saved["block_capture"]
    assert len([x for x in f.block_events if x.startswith("delete:")]) == 5


@pytest.mark.parametrize("block_storage", ["idle"], indirect=True)
async def test_idle_releases_but_keeps_workspace_state_and_custody(block_storage):
    f = block_storage
    f.block_reclaim = True
    before = deepcopy(f.remote.objects)
    assert await dispose(f)
    assert (await state(f))["block_disposition"] == {
        "workspace": "retained",
        "state": "retained",
        "guest": "reclaimed",
        "egress": "reclaimed",
        "key": "reclaimed",
    }
    for role in ("workspace", "state"):
        key = ("PersistentVolumeClaim", f.block_targets[role]["name"])
        assert f.remote.objects[key] == before[key]
    for key, value in before.items():
        if key[0] == "Secret":
            assert f.remote.objects[key] == value


@pytest.mark.parametrize("fault", ["claim", "cancel", "pv", "claim-uid", "guard", "boot", "digest"])
async def test_block_boundaries_refuse_changed_ownership_and_missing_authority(
    block_storage, fault
):
    f = block_storage
    if fault in ("claim", "cancel"):

        async def hook():
            if fault == "cancel":
                raise asyncio.CancelledError
            async with f.h.sessions.begin() as db:
                row = await db.get(SandboxSession, f.claim.session_id)
                row.status_changed_at += timedelta(microseconds=1)

        f.block_hook = hook
    elif fault in ("pv", "guard"):
        original = f.adapter.kube.core.read_persistent_volume.side_effect

        def changed(name, **kwargs):
            value = original(name, **kwargs)
            if fault == "pv":
                value["metadata"]["uid"] = str(uuid4())
            else:
                value["metadata"]["finalizers"] = []
            return value

        f.adapter.kube.core.read_persistent_volume.side_effect = changed
    elif fault == "claim-uid":
        f.remote.objects[("PersistentVolumeClaim", f.block_targets["workspace"]["name"])][
            "metadata"
        ]["uid"] = str(uuid4())
    else:
        original = f.node.observe_block

        async def changed(captured):
            value = msgspec.json.decode(await original(captured))
            value["boot_id" if fault == "boot" else "inventory_sha256"] = (
                str(uuid4()) if fault == "boot" else "e" * 64
            )
            return msgspec.json.encode(value)

        f.node.observe_block = changed
    with pytest.raises((RuntimeError, PairClaimLost, asyncio.CancelledError)):
        await dispose(f)
    assert not any(x.startswith("delete:") for x in f.block_events)
    assert not (await state(f))["block_disposition"]


async def test_retained_block_proof_tampering_refused_on_reload(block_storage):
    f = block_storage
    f.block_reclaim = True
    assert await dispose(f)
    async with f.h.sessions.begin() as db:
        intent = await db.get(PairIntent, f.intent.generation)
        value = deepcopy(intent.cleanup_journal)
        value["block_capture"]["volumes"]["state"]["pv_uid"] = str(uuid4())
        intent.cleanup_journal = value
    with pytest.raises(RuntimeError, match="backing identity"):
        await dispose(f)
