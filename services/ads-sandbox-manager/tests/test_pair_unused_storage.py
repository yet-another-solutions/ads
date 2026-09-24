# ruff: noqa: F811
from __future__ import annotations

import asyncio
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from kubernetes.client.exceptions import ApiException

from ads_sandbox_manager.cleanup import CleanupAdapter
from ads_sandbox_manager.pair_resource_proof import storage_complete
from ads_sandbox_manager.pair_store import PairClaimLost, PairIntent
from ads_sandbox_manager.pair_unused_storage import PairUnusedStorageTeardown
from ads_sandbox_manager.store import SandboxSession
from test_kube_release import api  # noqa: F401
from test_pair_controls import controls  # noqa: F401
from test_pair_creation import creation  # noqa: F401
from test_pair_store import ledger, snapshot  # noqa: F401
from test_pair_unissued_runtime import runtime
from test_pair_unscheduled_runtime import journal, unscheduled_runtime  # noqa: F401
from test_pair_volume_publication import publication as volume_publication  # noqa: F401
from test_session_objects import object_settings  # noqa: F401
from test_sessions import sessions_harness  # noqa: F401

pytestmark = pytest.mark.anyio


def api_storage(f, *, bound):
    now = datetime.now(UTC)
    f.class_contract = {
        "metadata": {
            "name": "sandbox-block",
            "uid": str(uuid4()),
            "creationTimestamp": (now - timedelta(days=1)).isoformat(),
        },
        "provisioner": "fixture.csi",
        "volumeBindingMode": "WaitForFirstConsumer",
    }
    f.pvs = {}
    for (kind, _), obj in f.remote.objects.items():
        if kind != "PersistentVolumeClaim":
            continue
        obj["metadata"]["creationTimestamp"] = now.isoformat()
        obj["status"] = {"phase": "Bound" if bound else "Pending"}
        if bound:
            name = "pv-" + obj["metadata"]["uid"]
            obj["spec"]["volumeName"] = name
            f.pvs[name] = {
                "metadata": {
                    "uid": str(uuid4()),
                    "finalizers": ["external-provisioner.volume.kubernetes.io/finalizer"],
                },
                "spec": {
                    "claimRef": {
                        "uid": obj["metadata"]["uid"],
                        "name": obj["metadata"]["name"],
                        "namespace": f.adapter.namespace,
                    },
                    "persistentVolumeReclaimPolicy": "Delete",
                    "csi": {"driver": "fixture.csi", "volumeHandle": name},
                },
            }
    f.storage = CleanupAdapter(f.adapter.kube)
    f.runtime.storage, f.runtime.node_owner = f.storage, None
    f.unused = PairUnusedStorageTeardown(f.runtime)
    f.deletes, f.lost_reply, f.reclaim = [], False, False
    f.adapter.kube.core.list_namespaced_pod.side_effect = lambda *a, **kw: {
        "items": [deepcopy(p) for (kind, _), p in f.remote.objects.items() if kind == "Pod"],
        "metadata": {},
    }
    f.adapter.kube.storage.list_volume_attachment.return_value = {"items": [], "metadata": {}}
    f.adapter.kube.storage.read_storage_class.side_effect = lambda *a, **kw: deepcopy(
        f.class_contract
    )

    def pv(name, **kwargs):
        if name not in f.pvs:
            raise ApiException(status=404)
        return deepcopy(f.pvs[name])

    f.adapter.kube.core.read_persistent_volume.side_effect = pv

    def remove(name, namespace, *, body, **kwargs):
        key = ("PersistentVolumeClaim", name)
        obj = f.remote.objects.get(key)
        if obj is None:
            raise ApiException(status=404)
        assert body["preconditions"] == {
            "uid": obj["metadata"]["uid"],
            "resourceVersion": obj["metadata"]["resourceVersion"],
        }
        f.deletes.append(key)
        del f.remote.objects[key]
        if f.reclaim:
            f.pvs.pop(obj["spec"].get("volumeName"), None)
        if f.lost_reply:
            f.lost_reply = False
            raise TimeoutError("lost original unused claim delete reply")
        return {}

    f.adapter.kube.core.delete_namespaced_persistent_volume_claim.side_effect = remove


@pytest.fixture
async def unused(creation, request):
    f = creation
    await f.creator.volumes.prepare(f.row, f.intent.generation)
    f.runtime, _, _ = await runtime(f)
    assert await f.runtime.release(f.work, recovery=f.claim)
    api_storage(f, bound=getattr(request, "param", None) == "bound")
    for source in (f.golden_source, *f.ca_sources.values()):
        f.remote.objects[("PersistentVolumeClaim", source["metadata"]["name"])] = deepcopy(source)
    return f


async def dispose(f):
    return await f.unused.dispose(f.work, recovery=f.claim)


async def test_sealed_unissued_consumers_and_original_wffc_contract_prove_no_backing(unused):
    f = unused
    sources = {
        key: deepcopy(obj)
        for key, obj in f.remote.objects.items()
        if key[1] in {s["metadata"]["name"] for s in (f.golden_source, *f.ca_sources.values())}
    }
    assert await dispose(f)
    saved = await journal(f)
    assert len(saved["unused_storage"]) == 4 and storage_complete(saved)
    assert all(
        value["capture"]["mode"] == "never-provisioned" and value["disposition"] == "reclaimed"
        for value in saved["unused_storage"].values()
    )
    assert saved["node_capture"] is None and saved["block_capture"] is None
    assert all(f.remote.objects[key] == obj for key, obj in sources.items())
    assert await dispose(f) and len(f.deletes) == 4


@pytest.mark.parametrize("unused", ["bound"], indirect=True)
async def test_never_mounted_bound_csi_waits_for_actual_protected_reclamation(unused):
    f = unused
    assert not await dispose(f)
    saved = await journal(f)
    assert len(saved["unused_storage"]) == 1
    original = next(iter(saved["unused_storage"].values()))
    assert original["capture"]["mode"] == "never-mounted-csi"
    assert original["disposition"] is None
    f.pvs.pop(original["capture"]["target"]["pv_name"])
    f.reclaim = True
    assert await dispose(f) and storage_complete(await journal(f))


async def test_lost_never_provisioned_delete_reply_preserves_original_contract(unused):
    f = unused
    f.lost_reply = True
    with pytest.raises(TimeoutError):
        await dispose(f)
    original = deepcopy((await journal(f))["unused_storage"])
    assert await dispose(f)
    saved = (await journal(f))["unused_storage"]
    assert all(saved[role]["capture"] == value["capture"] for role, value in original.items())
    assert len(f.deletes) == 4


@pytest.mark.parametrize(
    "fault", ["immediate", "static", "new-class", "selected", "foreign-pod", "replacement"]
)
async def test_unbound_contract_and_foreign_consumers_cannot_be_assumed_away(unused, fault):
    f = unused
    claims = [
        obj
        for (kind, _), obj in f.remote.objects.items()
        if kind == "PersistentVolumeClaim" and obj.get("status", {}).get("phase") == "Pending"
    ]
    if fault == "immediate":
        f.class_contract["volumeBindingMode"] = "Immediate"
    elif fault == "static":
        f.class_contract["provisioner"] = "kubernetes.io/no-provisioner"
    elif fault == "new-class":
        f.class_contract["metadata"]["creationTimestamp"] = (
            datetime.now(UTC) + timedelta(days=1)
        ).isoformat()
    elif fault == "selected":
        for obj in claims:
            obj["metadata"]["annotations"] = {"volume.kubernetes.io/selected-node": "worker"}
    elif fault == "replacement":
        for obj in claims:
            obj["metadata"]["uid"] = str(uuid4())
    else:
        f.remote.objects[("Pod", "foreign")] = {
            "spec": {
                "volumes": [
                    {"persistentVolumeClaim": {"claimName": obj["metadata"]["name"]}}
                    for obj in claims
                ]
            },
        }
    if fault == "foreign-pod":
        assert not await dispose(f)
    else:
        with pytest.raises(RuntimeError):
            await dispose(f)
    assert not f.deletes


@pytest.mark.parametrize("fault", ["claim", "cancel", "class-uid", "binding"])
async def test_unused_disposition_boundaries_preserve_original_receipts(unused, fault):
    f = unused
    original = f.storage.dispose_unused

    async def changed(captured):
        if fault == "cancel":
            raise asyncio.CancelledError
        if fault == "claim":
            async with f.h.sessions.begin() as db:
                row = await db.get(SandboxSession, f.claim.session_id)
                row.status_changed_at += timedelta(microseconds=1)
        elif fault == "class-uid":
            f.class_contract["metadata"]["uid"] = str(uuid4())
        else:
            f.remote.objects[("PersistentVolumeClaim", captured["target"]["name"])]["spec"][
                "volumeName"
            ] = "new-binding"
        return await original(captured)

    f.storage.dispose_unused = changed
    if fault == "binding":
        assert not await dispose(f)
    else:
        with pytest.raises((RuntimeError, PairClaimLost, asyncio.CancelledError)):
            await dispose(f)
    saved = await journal(f)
    assert all(value["disposition"] is None for value in saved["unused_storage"].values())
    assert len(f.deletes) <= (1 if fault == "claim" else 0)


async def test_never_scheduled_is_not_never_dispatched_for_unbound_provisioning(
    unscheduled_runtime,
):
    f = unscheduled_runtime
    assert await f.runtime.release(f.work, recovery=f.claim)
    api_storage(f, bound=False)
    with pytest.raises(RuntimeError, match="ambiguous"):
        await dispose(f)
    assert not f.deletes and not (await journal(f))["unused_storage"]


async def test_tampered_delayed_binding_receipt_refuses_reload(unused):
    f = unused
    assert await dispose(f)
    async with f.h.sessions.begin() as db:
        intent = await db.get(PairIntent, f.intent.generation)
        value = deepcopy(intent.cleanup_journal)
        next(iter(value["unused_storage"].values()))["capture"]["storage_class"]["binding"] = (
            "Immediate"
        )
        intent.cleanup_journal = value
    with pytest.raises(RuntimeError, match="delayed-binding"):
        await dispose(f)
