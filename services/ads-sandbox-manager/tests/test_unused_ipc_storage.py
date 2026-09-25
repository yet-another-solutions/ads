# ruff: noqa: F811
from __future__ import annotations

import asyncio
from types import SimpleNamespace
from uuid import uuid4

import msgspec
import pytest

from ads_sandbox_manager.pair_resource_proof import storage_complete
from ads_sandbox_manager.session_objects import ipc_name
from test_kube_release import api  # noqa: F401
from test_pair_controls import controls  # noqa: F401
from test_pair_creation import creation  # noqa: F401
from test_pair_store import ledger, snapshot  # noqa: F401
from test_pair_unscheduled_runtime import journal, unscheduled_runtime  # noqa: F401
from test_pair_unused_storage import api_storage, dispose
from test_pair_volume_publication import publication as volume_publication  # noqa: F401
from test_session_objects import object_settings  # noqa: F401
from test_sessions import sessions_harness  # noqa: F401

pytestmark = pytest.mark.anyio


@pytest.fixture
async def unused_filesystem(unscheduled_runtime):
    f = unscheduled_runtime
    assert await f.runtime.release(f.work, recovery=f.claim)
    api_storage(f, bound=True)
    f.reclaim = True
    f.backing_removed, f.backing_busy, f.backing_fault = False, False, None
    f.ipc_key = ("PersistentVolumeClaim", ipc_name(f.work.sandbox_id))
    pvc = f.remote.objects[f.ipc_key]
    pv = f.pvs[pvc["spec"]["volumeName"]]
    pv["metadata"]["finalizers"] = []
    pv["spec"].pop("csi")
    pv["spec"]["hostPath"] = {"path": "/storage/original-ipc"}
    pv["spec"]["nodeAffinity"] = {
        "required": {
            "nodeSelectorTerms": [
                {
                    "matchExpressions": [
                        {
                            "key": "kubernetes.io/hostname",
                            "operator": "In",
                            "values": ["application.test"],
                        }
                    ],
                }
            ]
        }
    }
    boot = str(uuid4())

    async def capture(pair, *, node, volume_uid, pv_uid):
        if f.backing_fault == "cancel":
            raise asyncio.CancelledError
        return msgspec.json.encode(
            {
                "schema": "ads-ipc-unused-storage-v1",
                "node": node,
                "namespace": f.adapter.namespace,
                "generation": str(pair.generation),
                "sandbox_id": str(pair.sandbox_id),
                "volume_uid": volume_uid,
                "pv_uid": str(uuid4()) if f.backing_fault == "pv" else pv_uid,
                "boot_id": boot,
                "inventory_sha256": "c" * 64,
                "observed": False,
                "released": False,
                "reclaimed": False,
            }
        )

    async def observe(saved):
        return msgspec.json.encode(
            {
                **msgspec.to_builtins(saved),
                "boot_id": str(uuid4()) if f.backing_fault == "boot" else boot,
                "observed": True,
                "released": not f.backing_busy,
                "reclaimed": f.backing_removed and not f.backing_busy,
            }
        )

    f.runtime.node_owner = SimpleNamespace(
        capture_unused_ipc_storage=capture, observe_unused_ipc_storage=observe
    )
    return f


@pytest.mark.parametrize("unscheduled_runtime", ["ipc-unissued", None], indirect=True)
async def test_never_started_filesystem_requires_inode_reclamation_not_pv_absence(
    unused_filesystem,
):
    f = unused_filesystem
    assert not await dispose(f)
    assert f.ipc_key not in f.remote.objects
    saved = (await journal(f))["unused_storage"]["ipc"]
    assert saved["capture"]["mode"] == "never-mounted-filesystem"
    assert saved["release"]["released"] and saved["reclaimed"] is None
    assert saved["disposition"] is None
    assert (await journal(f))["ipc_capture"] is None
    f.backing_removed = True
    assert await dispose(f) and storage_complete(await journal(f))
    saved = (await journal(f))["unused_storage"]["ipc"]
    assert saved["reclaimed"]["reclaimed"] and saved["disposition"] == "reclaimed"
    assert f.deletes.count(f.ipc_key) == 1


@pytest.mark.parametrize("fault", ["busy", "pv", "boot", "cancel"])
async def test_unused_filesystem_boundaries_keep_original_claim_and_evidence(
    unused_filesystem, fault
):
    f = unused_filesystem
    f.backing_busy = fault == "busy"
    f.backing_fault = fault
    if fault == "busy":
        assert not await dispose(f)
    else:
        with pytest.raises((RuntimeError, ValueError, asyncio.CancelledError)):
            await dispose(f)
    assert f.ipc_key in f.remote.objects and f.ipc_key not in f.deletes
    saved = (await journal(f))["unused_storage"].get("ipc")
    assert saved is None or saved["disposition"] is None
    f.backing_fault, f.backing_busy, f.backing_removed = None, False, True
    assert await dispose(f) and storage_complete(await journal(f))


async def test_lost_unused_filesystem_delete_reply_reuses_original_backing_capture(
    unused_filesystem,
):
    f = unused_filesystem
    original = f.storage.dispose_unused

    async def lost(value):
        if value["mode"] == "never-mounted-filesystem":
            f.lost_reply = True
        return await original(value)

    f.storage.dispose_unused = lost
    with pytest.raises(TimeoutError):
        await dispose(f)
    saved = (await journal(f))["unused_storage"]["ipc"]["capture"]
    f.storage.dispose_unused = original
    f.backing_removed = True
    assert await dispose(f)
    assert (await journal(f))["unused_storage"]["ipc"]["capture"] == saved
    assert f.deletes.count(f.ipc_key) == 1
