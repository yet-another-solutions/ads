# ruff: noqa: F811
from __future__ import annotations

import asyncio
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import msgspec
import pytest
from kubernetes.client.exceptions import ApiException

from ads_sandbox_manager.lifecycle_store import CleanupWork
from ads_sandbox_manager.pair_ipc_storage import PairIpcStorageTeardown
from ads_sandbox_manager.pair_store import PairClaimLost, PairIntent
from ads_sandbox_manager.store import SandboxSession
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
async def ipc_storage(teardown):
    return await configure_ipc_storage(teardown)


async def configure_ipc_storage(f):
    original = f.adapter.kube.core.read_persistent_volume.side_effect

    def filesystem(name, **kwargs):
        pv = original(name, **kwargs)
        if name == "pv-ipc":
            del pv["spec"]["csi"]
            pv["spec"]["hostPath"] = {"path": "/storage/original-ipc"}
            pv["metadata"]["finalizers"] = ["kubernetes.io/pv-protection"]
        return pv

    f.adapter.kube.core.read_persistent_volume.side_effect = filesystem
    f.blocked = False
    assert await release(f)
    f.storage_stage = PairIpcStorageTeardown(f.runtime)
    f.backing_reclaimed = False
    f.storage_blocked = False
    f.storage_events = []
    f.storage_observe_hook = None
    f.lost_storage_reply = False
    f.reclaim_during_delete = False
    f.target = (await state(f))["storage_capture"]["ipc"]
    f.adapter.kube.storage.list_volume_attachment.return_value = {"items": [], "metadata": {}}
    f.adapter.kube.core.read_node.return_value = {"status": {}}

    async def observe(captured):
        f.storage_events.append("observe")
        if f.storage_observe_hook:
            await f.storage_observe_hook()
        return msgspec.json.encode(
            {
                **msgspec.to_builtins(captured),
                "observed": True,
                "released": not f.storage_blocked,
                "reclaimed": f.backing_reclaimed and not f.storage_blocked,
            }
        )

    f.node.observe_ipc_storage = observe

    def remove(name, namespace, *, body, **kwargs):
        key = ("PersistentVolumeClaim", name)
        obj = f.remote.objects.get(key)
        if obj is None:
            raise ApiException(status=404)
        assert name == f.target["name"] and namespace == f.adapter.namespace
        assert body["preconditions"] == {
            "uid": f.target["uid"],
            "resourceVersion": obj["metadata"]["resourceVersion"],
        }
        f.storage_events.append("delete")
        del f.remote.objects[key]
        if f.reclaim_during_delete:
            f.backing_reclaimed = True
        if f.lost_storage_reply:
            f.lost_storage_reply = False
            raise TimeoutError("lost original delete reply")
        return {}

    f.adapter.kube.core.delete_namespaced_persistent_volume_claim.side_effect = remove
    return f


async def dispose(f):
    return await f.storage_stage.dispose(f.work, recovery=f.claim)


async def test_api_absence_waits_for_original_inode_reclamation_and_retries(ipc_storage):
    f = ipc_storage
    before = deepcopy(f.remote.objects)
    assert not await dispose(f)
    saved = await state(f)
    assert saved["ipc_storage_release"]["released"]
    assert saved["ipc_storage_reclaimed"] is None
    assert ("PersistentVolumeClaim", f.target["name"]) not in f.remote.objects
    assert f.storage_events == ["observe", "delete", "observe"]
    assert {
        key: value
        for key, value in before.items()
        if key != ("PersistentVolumeClaim", f.target["name"])
    } == f.remote.objects
    f.storage_stage = PairIpcStorageTeardown(f.runtime)
    f.backing_reclaimed = True
    assert await dispose(f)
    assert (await state(f))["ipc_storage_reclaimed"]["reclaimed"]
    events = list(f.storage_events)
    assert await dispose(f) and f.storage_events == events
    async with f.h.sessions.begin() as db:
        assert not await f.capture.repository.complete(db, f.work, datetime.now(UTC))


async def test_reclamation_cannot_delete_before_positive_release_receipt(ipc_storage):
    f = ipc_storage
    f.storage_blocked = True
    assert not await dispose(f)
    assert (await state(f))["ipc_storage_release"] is None
    assert "delete" not in f.storage_events
    f.storage_blocked = False
    original = f.storage.delete

    async def check(target):
        assert (await state(f))["ipc_storage_release"]["released"]
        await original(target)

    f.storage.delete = check
    f.reclaim_during_delete = True
    assert await dispose(f)


async def test_lost_delete_reply_keeps_original_receipt_and_only_retries_same_identity(ipc_storage):
    f = ipc_storage
    f.lost_storage_reply = True
    with pytest.raises(TimeoutError):
        await dispose(f)
    saved = deepcopy(await state(f))
    assert saved["ipc_storage_release"] and saved["ipc_storage_reclaimed"] is None
    f.backing_reclaimed = True
    assert await dispose(f)
    assert (await state(f))["ipc_storage_capture"] == saved["ipc_storage_capture"]
    assert f.storage_events.count("delete") == 1


@pytest.mark.parametrize(
    "fault", ["claim", "cancel", "pv", "path", "replacement", "boot", "digest"]
)
async def test_unsafe_storage_boundaries_preserve_evidence_and_refuse_disposition(
    ipc_storage, fault
):
    f = ipc_storage
    if fault in ("claim", "cancel"):

        async def hook():
            if fault == "cancel":
                raise asyncio.CancelledError
            async with f.h.sessions.begin() as db:
                row = await db.get(SandboxSession, f.claim.session_id)
                row.status_changed_at += timedelta(microseconds=1)

        f.storage_observe_hook = hook
    elif fault in ("pv", "path"):
        original = f.adapter.kube.core.read_persistent_volume.side_effect

        def change(name, **kwargs):
            pv = original(name, **kwargs)
            if name == "pv-ipc":
                if fault == "pv":
                    pv["metadata"]["uid"] = str(uuid4())
                else:
                    pv["spec"]["hostPath"]["path"] = "/different"
            return pv

        f.adapter.kube.core.read_persistent_volume.side_effect = change
    elif fault == "replacement":
        f.remote.objects[("PersistentVolumeClaim", f.target["name"])]["metadata"]["uid"] = str(
            uuid4()
        )
    else:
        original_observe = f.node.observe_ipc_storage

        async def changed(captured):
            value = msgspec.json.decode(await original_observe(captured))
            value["boot_id" if fault == "boot" else "inventory_sha256"] = (
                str(uuid4()) if fault == "boot" else "e" * 64
            )
            return msgspec.json.encode(value)

        f.node.observe_ipc_storage = changed
    with pytest.raises((RuntimeError, PairClaimLost, asyncio.CancelledError)):
        await dispose(f)
    assert "delete" not in f.storage_events
    assert (await state(f))["ipc_storage_reclaimed"] is None


async def test_tampered_retained_reclamation_cannot_survive_reload(ipc_storage):
    f = ipc_storage
    f.reclaim_during_delete = True
    assert await dispose(f)
    async with f.h.sessions.begin() as db:
        intent = await db.get(PairIntent, f.intent.generation)
        value = deepcopy(intent.cleanup_journal)
        value["ipc_storage_reclaimed"]["pv_uid"] = str(uuid4())
        intent.cleanup_journal = value
    with pytest.raises(RuntimeError, match="original positive"):
        await dispose(f)
    async with f.h.sessions.begin() as db:
        assert await db.get(CleanupWork, f.work.work_id) is not None
