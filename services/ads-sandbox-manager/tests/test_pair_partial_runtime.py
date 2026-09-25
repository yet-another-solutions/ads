# ruff: noqa: F811
from __future__ import annotations

import asyncio
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import msgspec
import pytest
from sqlalchemy import delete

from ads_sandbox_manager.cleanup import CleanupAdapter
from ads_sandbox_manager.lifecycle_store import CleanupWork, LifecycleRepository
from ads_sandbox_manager.pair_objects import COMPUTE_ROLES
from ads_sandbox_manager.pair_runtime_teardown import PairRuntimeTeardown
from ads_sandbox_manager.pair_store import PairClaimLost, PairIntent
from ads_sandbox_manager.pair_unscheduled_proof import never_scheduled
from ads_sandbox_manager.store import SandboxSession
from test_kube_release import api  # noqa: F401
from test_node_release_wire import clear_counts
from test_pair_controls import controls  # noqa: F401
from test_pair_creation import creation  # noqa: F401
from test_pair_store import ledger, snapshot  # noqa: F401
from test_pair_unscheduled_runtime import journal, release, unscheduled_runtime  # noqa: F401
from test_pair_volume_publication import publication as volume_publication  # noqa: F401
from test_session_objects import object_settings  # noqa: F401
from test_sessions import sessions_harness  # noqa: F401

pytestmark = pytest.mark.anyio


@pytest.fixture
async def partial(unscheduled_runtime):
    f = unscheduled_runtime
    f.storage = CleanupAdapter(f.adapter.kube)
    f.assigned = ("guest",)
    f.blocked, f.ipc_blocked, f.stage_hook = False, False, None
    f.proof_events = []
    f.report = {
        "schema": "ads-partial-release-v1",
        "node": "worker",
        "namespace": f.adapter.namespace,
        "network": "ads-ptp",
        "generation": str(f.intent.generation),
        "sandbox_id": str(f.work.sandbox_id),
        "boot_id": str(uuid4()),
        "pod_uids": {},
        "inventory_sha256": "e" * 64,
        "attachment_admission_fenced": True,
        "generation_retired": False,
        "release_inventory_captured": True,
        "observed_runtime_released": False,
        "leftovers": None,
    }
    for (kind, _), obj in f.remote.objects.items():
        if kind == "PersistentVolumeClaim":
            obj["status"] = {"phase": "Pending"}
    f.ipc_report = {
        "schema": "ads-ipc-release-v1",
        "node": "application",
        "namespace": f.adapter.namespace,
        "generation": str(f.intent.generation),
        "sandbox_id": str(f.work.sandbox_id),
        "boot_id": str(uuid4()),
        "pod_uid": f.pods["ipc"]["metadata"]["uid"],
        "volume_uid": f.work.pair_snapshot["ipc_resources"]["volume"]["uid"],
        "inventory_sha256": "c" * 64,
        "release_inventory_captured": True,
        "observed_runtime_released": False,
        "leftovers": None,
    }
    f.adapter.kube.core.list_namespaced_pod.side_effect = lambda *a, **kw: {
        "items": [deepcopy(p) for (kind, _), p in f.remote.objects.items() if kind == "Pod"],
        "metadata": {},
    }
    original = f.adapter.delete_compute

    async def delete_compute(pair, role, uid, *, node):
        saved = await journal(f)
        assert saved["partial_capture"] and saved["partial_storage"]
        assert saved["partial_capture"]["pod_uids"][role] == uid
        f.proof_events.append(("delete", role))
        if f.stage_hook:
            await f.stage_hook("delete")
        return await original(pair, role, uid, node=node)

    f.adapter.delete_compute = delete_compute

    class NodeOwner:
        network = "ads-ptp"

        async def capture_partial(self, pair, *, node, pod_uids):
            saved = await journal(f)
            assert saved["partial_storage"]
            assert pair == f.intent.binding() and node == "worker"
            assert pod_uids == {role: f.pods[role]["metadata"]["uid"] for role in f.assigned}
            f.proof_events.append(("node", "capture"))
            if f.stage_hook:
                await f.stage_hook("capture")
            f.report["pod_uids"] = pod_uids
            return msgspec.json.encode(f.report)

        async def observe_partial(self, captured):
            assert captured.inventory_sha256 == f.report["inventory_sha256"]
            assert not any(
                ("Pod", f.pods[role]["metadata"]["name"]) in f.remote.objects for role in f.assigned
            )
            f.proof_events.append(("node", "observe"))
            if f.stage_hook:
                await f.stage_hook("observe")
            counts = clear_counts()
            counts["process_namespace_references"] = int(f.blocked)
            return msgspec.json.encode(
                {
                    **f.report,
                    "leftovers": counts,
                    "observed_runtime_released": not f.blocked,
                }
            )

        async def capture_ipc(self, pair, *, node, pod_uid, volume_uid):
            assert pair == f.intent.binding()
            assert (node, pod_uid, volume_uid) == (
                "application",
                f.ipc_report["pod_uid"],
                f.ipc_report["volume_uid"],
            )
            f.proof_events.append(("ipc", "capture"))
            return msgspec.json.encode(f.ipc_report)

        async def observe_ipc(self, captured):
            assert captured.inventory_sha256 == f.ipc_report["inventory_sha256"]
            f.proof_events.append(("ipc", "observe"))
            return msgspec.json.encode(
                {
                    **f.ipc_report,
                    "observed_runtime_released": not f.ipc_blocked,
                    "leftovers": {
                        "pods": 0,
                        "ready_sandboxes": 0,
                        "live_containers": 0,
                        "process_references": 0,
                        "mount_references": int(f.ipc_blocked),
                    },
                }
            )

    f.node = NodeOwner()
    f.runtime.storage, f.runtime.node_owner = f.storage, f.node
    return f


def assign(f, roles):
    f.assigned = roles
    for role in roles:
        f.pods[role]["spec"]["nodeName"] = "worker"


@pytest.mark.parametrize(
    "roles",
    [
        ("guest",),
        ("guest", "guest-relay"),
        ("guest-relay", "egress-relay"),
        tuple(COMPUTE_ROLES),
    ],
)
async def test_partial_original_inventory_and_unscheduled_peers_compose(partial, roles):
    f = partial
    assign(f, roles)
    before = deepcopy(f.remote.objects)
    assert await release(f)
    saved = await journal(f)
    assert set(saved["partial_capture"]["pod_uids"]) == set(roles)
    assert saved["partial_release"]["observed_runtime_released"]
    assert saved["node_capture"] is None and saved["runtime_release"] is None
    assert saved["ipc_capture"] is None and saved["storage_capture"] == {}
    assert all(
        never_scheduled(saved, role) for role in ("ipc", *COMPUTE_ROLES) if role not in roles
    )
    assert {k: v for k, v in before.items() if k[0] != "Pod"} == f.remote.objects
    assert f.proof_events == [
        ("node", "capture"),
        *(("delete", role) for role in COMPUTE_ROLES if role in roles),
        ("node", "observe"),
    ]
    events = list(f.proof_events)
    f.runtime = PairRuntimeTeardown(
        f.runtime.settings, f.h.sessions, LifecycleRepository(), f.adapter, f.storage, f.node
    )
    assert await release(f) and f.proof_events == events
    assert await journal(f) == saved
    async with f.h.sessions.begin() as db:
        assert not await f.capture.repository.complete(db, f.work, datetime.now(UTC))


async def test_api_absence_requires_positive_partial_runtime_observation(partial):
    f = partial
    assign(f, ("guest",))
    f.blocked = True
    assert not await release(f)
    before = await journal(f)
    assert before["partial_capture"] and before["partial_release"] is None
    assert ("Pod", f.pods["guest"]["metadata"]["name"]) not in f.remote.objects
    f.blocked = False
    assert await release(f)
    assert (await journal(f))["partial_capture"] == before["partial_capture"]
    assert f.proof_events.count(("node", "capture")) == 1


@pytest.mark.parametrize("roles", [(), ("guest",), ("guest", "egress")])
async def test_assigned_ipc_and_partial_private_compute_require_both_proofs(partial, roles):
    f = partial
    assign(f, roles)
    f.pods["ipc"]["spec"]["nodeName"] = "application"
    f.ipc_blocked = True
    assert not await release(f)
    first = await journal(f)
    assert first["ipc_capture"] and first["ipc_release"] is None
    assert not any(event[0] == "delete" for event in f.proof_events)
    f.runtime = PairRuntimeTeardown(
        f.runtime.settings, f.h.sessions, LifecycleRepository(), f.adapter, f.storage, f.node
    )
    f.ipc_blocked = False
    assert await release(f)
    saved = await journal(f)
    assert saved["ipc_capture"] == first["ipc_capture"]
    assert saved["ipc_release"]["observed_runtime_released"]
    assert bool(saved["partial_release"]) == bool(roles)
    assert f.proof_events.count(("ipc", "capture")) == 1
    if roles:
        assert f.proof_events.index(("ipc", "observe")) < f.proof_events.index(("delete", roles[0]))
        async with f.h.sessions.begin() as db:
            intent = await db.get(PairIntent, f.intent.generation)
            bad = deepcopy(intent.cleanup_journal)
            bad["ipc_release"] = None
            intent.cleanup_journal = bad
        with pytest.raises(RuntimeError, match="requires original IPC release"):
            await release(f)


@pytest.mark.parametrize("stage", ["capture", "delete", "observe"])
@pytest.mark.parametrize("loss", ["claim", "work", "session"])
async def test_partial_original_evidence_survives_claim_loss(partial, stage, loss):
    f = partial
    assign(f, ("guest",))

    async def lose(actual):
        if actual != stage:
            return
        async with f.h.sessions.begin() as db:
            if loss == "claim":
                row = await db.get(SandboxSession, f.claim.session_id)
                row.status_changed_at += timedelta(microseconds=1)
            elif loss == "work":
                await db.execute(delete(CleanupWork).where(CleanupWork.work_id == f.work.work_id))
            else:
                await db.execute(
                    delete(SandboxSession).where(SandboxSession.session_id == f.claim.session_id)
                )

    f.stage_hook = lose
    with pytest.raises(PairClaimLost):
        await release(f)
    saved = await journal(f)
    assert saved["partial_release"] is None
    assert bool(saved["partial_capture"]) == (stage != "capture")
    assert saved["partial_storage"]


@pytest.mark.parametrize("stage", ["capture", "delete", "observe"])
async def test_partial_interrupted_call_resumes_original_capture(partial, stage):
    f = partial
    assign(f, ("guest",))

    async def fail(actual):
        if actual == stage:
            raise TimeoutError

    f.stage_hook = fail
    with pytest.raises(TimeoutError):
        await release(f)
    saved = await journal(f)
    assert saved["partial_release"] is None
    f.stage_hook = None
    assert await release(f)
    if stage != "capture":
        assert (await journal(f))["partial_capture"] == saved["partial_capture"]


async def test_partial_cancelled_capture_never_authorizes_deletion(partial):
    f = partial
    assign(f, ("guest",))
    entered = asyncio.Event()

    async def block(stage):
        if stage == "capture":
            entered.set()
            await asyncio.Event().wait()

    f.stage_hook = block
    task = asyncio.create_task(release(f))
    try:
        await asyncio.wait_for(entered.wait(), 10)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert (await journal(f))["partial_capture"] is None
        assert not any(event[0] == "delete" for event in f.proof_events)
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize("fault", ["uid", "boot", "storage", "capture", "leftover"])
async def test_corrupt_retained_partial_proof_cannot_shortcut_runtime(partial, fault):
    f = partial
    assign(f, ("guest",))
    assert await release(f)
    async with f.h.sessions.begin() as db:
        intent = await db.get(PairIntent, f.intent.generation)
        saved = deepcopy(intent.cleanup_journal)
        if fault == "uid":
            saved["partial_capture"]["pod_uids"]["guest"] = str(uuid4())
        elif fault == "boot":
            saved["partial_release"]["boot_id"] = str(uuid4())
        elif fault == "storage":
            saved["partial_storage"] = {}
        elif fault == "capture":
            saved["partial_capture"] = None
        else:
            saved["partial_release"]["leftovers"]["journals"] = 1
        intent.cleanup_journal = saved
    events = list(f.proof_events)
    with pytest.raises((RuntimeError, ValueError)):
        await release(f)
    assert f.proof_events == events
