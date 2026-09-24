# ruff: noqa: F811
from __future__ import annotations

import asyncio
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock
from uuid import uuid4

import msgspec
import pytest
from kubernetes.client.exceptions import ApiException
from sqlalchemy import delete

from ads_sandbox_manager.cleanup import CleanupAdapter
from ads_sandbox_manager.ioc import AppProvider
from ads_sandbox_manager.lifecycle import LifecycleService
from ads_sandbox_manager.lifecycle_store import CleanupWork
from ads_sandbox_manager.pair_objects import COMPUTE_ROLES
from ads_sandbox_manager.pair_runtime_teardown import PairRuntimeTeardown
from ads_sandbox_manager.pair_storage_capture import storage_targets, validate_storage_capture
from ads_sandbox_manager.pair_store import PairClaimLost, PairIntent
from ads_sandbox_manager.recovery import RecoveryService
from ads_sandbox_manager.session_objects import ipc_name
from ads_sandbox_manager.store import SandboxSession, SessionPVC
from test_kube_release import api  # noqa: F401
from test_node_release_wire import clear_counts, node_report  # noqa: F401
from test_pair_cleanup_journal import journal, retained  # noqa: F401
from test_pair_controls import controls  # noqa: F401
from test_pair_creation import creation  # noqa: F401
from test_pair_store import ledger, snapshot  # noqa: F401
from test_pair_volume_publication import publication as volume_publication  # noqa: F401
from test_session_objects import object_settings  # noqa: F401
from test_sessions import sessions_harness  # noqa: F401

pytestmark = pytest.mark.anyio


async def state(f):
    return (await snapshot(f, f.intent.generation)).cleanup_journal


@pytest.fixture
async def teardown(journal):
    f = journal
    f.events, f.blocked, f.node_hook, f.storage_hook, f.delete_hook = [], True, None, None, None
    f.storage = CleanupAdapter(f.adapter.kube)
    targets = storage_targets(f.work.pair_snapshot, False)
    pvs = {}
    for role, target in targets.items():
        obj = f.remote.objects[("PersistentVolumeClaim", target["name"])]
        pv_name = f"pv-{role}"
        obj["spec"]["volumeName"] = pv_name
        obj["status"] = {"phase": "Bound"}
        pvs[pv_name] = {
            "metadata": {
                "uid": str(uuid4()),
                "finalizers": ["external-provisioner.volume.kubernetes.io/finalizer"],
            },
            "spec": {
                "claimRef": {
                    "name": target["name"],
                    "uid": target["uid"],
                    "namespace": f.adapter.namespace,
                },
                "persistentVolumeReclaimPolicy": "Delete",
                "csi": {"driver": "fixture.csi", "volumeHandle": pv_name},
            },
        }
    for (kind, _), obj in f.remote.objects.items():
        if kind == "Pod":
            obj["spec"]["nodeName"] = f.report["node"]
    # The directly owned IPC Pod remains on the configured application node.
    ipc = f.remote.objects[("Pod", ipc_name(f.work.sandbox_id))]
    ipc["spec"]["nodeName"] = "application"
    f.adapter.kube.core.list_namespaced_pod.side_effect = lambda *a, **kw: {
        "items": [deepcopy(obj) for (kind, _), obj in f.remote.objects.items() if kind == "Pod"],
        "metadata": {},
    }
    f.adapter.kube.core.read_persistent_volume.side_effect = lambda name, **kw: deepcopy(pvs[name])

    def remove(name, namespace, *, body, **kwargs):
        key = ("Pod", name)
        obj = f.remote.objects.get(key)
        if obj is None:
            raise ApiException(status=404)
        assert body["preconditions"] == {
            "uid": obj["metadata"]["uid"],
            "resourceVersion": obj["metadata"]["resourceVersion"],
        }
        del f.remote.objects[key]
        return {}

    f.adapter.kube.core.delete_namespaced_pod.side_effect = remove
    real_delete = f.adapter.delete_compute
    real_capture = f.storage.capture

    async def storage(target):
        async with asyncio.timeout(5), f.h.sessions.begin() as db:
            await db.get(SandboxSession, f.row.session_id, with_for_update=True)
            intent = await db.get(PairIntent, f.intent.generation, with_for_update=True)
            assert intent.creation_fenced and intent.cleanup_journal
        f.events.append(("storage", target["name"]))
        if f.storage_hook:
            await f.storage_hook(target)
        return await real_capture(target)

    async def delete_compute(pair, role, uid, *, node):
        async with asyncio.timeout(5), f.h.sessions.begin() as db:
            await db.get(SandboxSession, f.row.session_id, with_for_update=True)
            intent = await db.get(PairIntent, f.intent.generation, with_for_update=True)
            assert len(intent.cleanup_journal["storage_capture"]) == 6
            assert intent.cleanup_journal["node_capture"]
            assert not intent.cleanup_journal["runtime_release"]
        f.events.append(("delete", role))
        if f.delete_hook:
            await f.delete_hook(role)
        return await real_delete(pair, role, uid, node=node)

    f.storage.capture = storage
    f.adapter.delete_compute = delete_compute

    class NodeOwner:
        network = f.report["network"]

        async def fence_and_capture(self, pair, *, node):
            f.events.append(("node", "capture"))
            assert pair == f.intent.binding() and node == f.report["node"]
            async with asyncio.timeout(5), f.h.sessions.begin() as db:
                await db.get(SandboxSession, f.row.session_id, with_for_update=True)
                intent = await db.get(PairIntent, pair.generation, with_for_update=True)
                assert (
                    intent.creation_fenced and len(intent.cleanup_journal["storage_capture"]) == 6
                )
            if f.node_hook:
                await f.node_hook("capture")
            return msgspec.json.encode(f.report)

        async def observe(self, captured):
            f.events.append(("node", "observe"))
            original = await state(f)
            assert original["node_capture"]["inventory_sha256"] == captured.inventory_sha256
            assert not any(
                obj["metadata"]["uid"] in f.report["pod_uids"]
                for (kind, _), obj in f.remote.objects.items()
                if kind == "Pod"
            )
            if f.node_hook:
                await f.node_hook("observe")
            counts = clear_counts()
            counts["process_namespace_references"] = int(f.blocked)
            return msgspec.json.encode(
                {
                    **f.report,
                    "leftovers": counts,
                    "observed_runtime_released": not f.blocked,
                }
            )

    f.node = NodeOwner()
    f.runtime = PairRuntimeTeardown(
        replace(f.h.settings, cleanup_seconds=60, recovery_seconds=120),
        f.h.sessions,
        f.capture.repository,
        f.adapter,
        f.storage,
        f.node,
    )
    return f


async def release(f):
    return await f.runtime.release(f.work, recovery=f.claim)


async def test_real_ordered_teardown_preserves_storage_and_waits_for_positive_runtime(teardown):
    f = teardown
    before = deepcopy(f.remote.objects)
    assert not await release(f)
    assert [event[0] for event in f.events[:6]] == ["storage"] * 6
    assert f.events[6:] == [
        ("node", "capture"),
        *(("delete", role) for role in COMPUTE_ROLES),
        ("node", "observe"),
    ]
    saved = await state(f)
    assert saved["node_capture"] and len(saved["storage_capture"]) == 6
    assert saved["runtime_release"] is None
    assert await retained(f) == f.work.pair_snapshot
    assert all(f.remote.objects[key] == value for key, value in before.items() if key[0] != "Pod")
    assert (
        f.remote.objects[("Pod", ipc_name(f.work.sandbox_id))]
        == before[("Pod", ipc_name(f.work.sandbox_id))]
    )
    # A new service instance resumes the exact committed capture without Pods.
    f.runtime = PairRuntimeTeardown(
        f.runtime.settings,
        f.h.sessions,
        type(f.capture.repository)(),
        f.adapter,
        f.storage,
        f.node,
    )
    f.blocked = False
    assert await release(f)
    positive = await state(f)
    assert positive["node_capture"] == saved["node_capture"]
    assert positive["storage_capture"] == saved["storage_capture"]
    assert positive["runtime_release"]["observed_runtime_released"]
    assert not positive["runtime_release"]["generation_retired"]
    events = list(f.events)
    assert await release(f) and f.events == events
    async with f.h.sessions.begin() as db:
        assert not await f.capture.repository.complete(db, f.work, datetime.now(UTC))
        assert await db.get(CleanupWork, f.work.work_id) is not None


async def test_production_provider_without_node_transport_never_deletes(teardown):
    f = teardown
    f.runtime = AppProvider(f.runtime.settings).pair_runtime(
        f.runtime.settings, f.h.sessions, f.capture.repository, f.adapter.kube, f.storage
    )
    assert f.runtime.node_owner is None
    assert not await release(f)
    assert not f.events
    assert (await state(f))["node_capture"] is None
    f.adapter.kube.core.delete_namespaced_pod.assert_not_called()


@pytest.mark.parametrize("stage", ["storage", "capture", "delete", "observe"])
async def test_claim_loss_across_each_external_boundary_stops_progress(teardown, stage):
    f = teardown

    async def changed(value):
        async with f.h.sessions.begin() as db:
            row = await db.get(SandboxSession, f.claim.session_id)
            row.status_changed_at += timedelta(microseconds=1)

    if stage == "storage":
        f.storage_hook = changed
    elif stage == "delete":
        f.delete_hook = changed
    else:

        async def node_changed(value):
            if value == stage:
                await changed(value)

        f.node_hook = node_changed
    with pytest.raises(PairClaimLost):
        await release(f)
    journal = await state(f)
    assert journal["runtime_release"] is None
    if stage in ("storage", "capture"):
        assert not any(event[0] == "delete" for event in f.events)
    if stage == "delete":
        assert [event for event in f.events if event[0] == "delete"] == [("delete", "guest")]


@pytest.mark.parametrize("fault", ["absent", "unbound", "no_nodes", "pv_replaced"])
async def test_incomplete_storage_capture_prevents_node_actions_and_deletes(teardown, fault):
    f = teardown
    target = storage_targets(f.work.pair_snapshot, False)["workspace"]
    if fault == "absent":
        del f.remote.objects[("PersistentVolumeClaim", target["name"])]
    elif fault == "unbound":
        del f.remote.objects[("PersistentVolumeClaim", target["name"])]["spec"]["volumeName"]
    elif fault == "no_nodes":
        f.adapter.kube.core.list_namespaced_pod.side_effect = None
        f.adapter.kube.core.list_namespaced_pod.return_value = {"items": [], "metadata": {}}
    else:
        f.adapter.kube.core.read_persistent_volume.side_effect = None
        f.adapter.kube.core.read_persistent_volume.return_value = {"spec": {"claimRef": {}}}
    with pytest.raises(RuntimeError):
        await release(f)
    assert f.events == [("storage", target["name"])]
    assert not (await state(f))["node_capture"]


@pytest.mark.parametrize("fault", ["generation", "boot_id", "inventory_sha256", "positive"])
async def test_mismatched_or_capture_only_report_cannot_record_runtime_release(teardown, fault):
    f = teardown
    assert not await release(f)
    f.blocked = False
    if fault == "positive":
        f.node.observe = AsyncMock(return_value=msgspec.json.encode(f.report))
    else:
        f.report[fault] = "b" * 64 if fault == "inventory_sha256" else str(uuid4())
    with pytest.raises(ValueError):
        await release(f)
    assert (await state(f))["runtime_release"] is None


async def test_ambiguous_compute_delete_resumes_original_journal_without_recreating(teardown):
    f = teardown
    original = f.adapter.kube.core.delete_namespaced_pod.side_effect
    once = True

    def lost(*args, **kwargs):
        nonlocal once
        result = original(*args, **kwargs)
        if once:
            once = False
            raise TimeoutError("lost deletion reply")
        return result

    f.adapter.kube.core.delete_namespaced_pod.side_effect = lost
    with pytest.raises(TimeoutError):
        await release(f)
    first = deepcopy(await state(f))
    assert not first["runtime_release"] and first["node_capture"]
    f.blocked = False
    assert await release(f)
    assert (await state(f))["node_capture"] == first["node_capture"]
    assert (await state(f))["storage_capture"] == first["storage_capture"]
    assert sum(event == ("node", "capture") for event in f.events) == 1


async def test_api_present_stops_before_next_compute_and_positive_observer(teardown):
    f = teardown
    f.adapter.kube.core.delete_namespaced_pod.side_effect = None
    assert not await release(f)
    assert [event for event in f.events if event[0] == "delete"] == [("delete", "guest")]
    assert ("node", "observe") not in f.events
    assert (await state(f))["runtime_release"] is None


async def test_session_loss_after_compute_removal_keeps_all_release_obligations(teardown):
    f = teardown
    assert not await release(f)
    old = deepcopy(await state(f))
    async with f.h.sessions.begin() as db:
        await db.execute(
            delete(SandboxSession).where(SandboxSession.session_id == f.row.session_id)
        )
    assert await state(f) == old
    assert await retained(f) == f.work.pair_snapshot
    with pytest.raises(PairClaimLost):
        await release(f)


@pytest.mark.parametrize(
    "field,value",
    [
        ("uid", "foreign"),
        ("name", "other"),
        ("captured", False),
        ("nodes", []),
        ("nodes", ["worker", "worker"]),
        ("observed_at", "2026-01-01T00:00:00"),
        ("pv_uid", None),
        ("volume_key", ""),
        ("reclaim_guard", 1),
        ("extra", 0),
    ],
)
async def test_corrupt_storage_proof_cannot_cross_teardown_gate(teardown, field, value):
    f = teardown
    assert not await release(f)
    before = await state(f)
    evidence = {**before["storage_capture"]["workspace"], field: value}
    target = storage_targets(f.work.pair_snapshot, False)["workspace"]
    with pytest.raises(RuntimeError):
        validate_storage_capture(target, evidence)


async def test_storage_binding_is_immutable_after_capture(teardown):
    f = teardown
    assert not await release(f)
    original = (await state(f))["storage_capture"]["workspace"]
    changed = {**original, "pv_uid": str(uuid4())}
    async with f.h.sessions.begin() as db:
        with pytest.raises(PairClaimLost, match="cannot be replaced"):
            await f.capture.repository.record_pair_storage_capture(
                db,
                f.work,
                "workspace",
                changed,
                datetime.now(UTC),
                recovery=f.claim,
                recovery_seconds=120,
            )
    assert (await state(f))["storage_capture"]["workspace"] == original


@pytest.mark.parametrize("fault", ["lost_reply", "commit"])
async def test_no_compute_delete_after_uncommitted_node_capture(teardown, fault):
    f = teardown
    original = f.capture.repository.record_pair_node_capture
    if fault == "lost_reply":

        async def interrupted(stage):
            if stage == "capture":
                raise TimeoutError

        f.node_hook = interrupted
    else:

        async def interrupted_commit(*args, **kwargs):
            await original(*args, **kwargs)
            raise TimeoutError

        f.capture.repository.record_pair_node_capture = interrupted_commit
    with pytest.raises(TimeoutError):
        await release(f)
    before = await state(f)
    assert len(before["storage_capture"]) == 6 and before["node_capture"] is None
    assert not any(event[0] == "delete" for event in f.events)
    f.node_hook = None
    f.capture.repository.record_pair_node_capture = original
    f.blocked = False
    assert await release(f)
    assert (await state(f))["storage_capture"] == before["storage_capture"]


async def test_cancelled_node_call_retains_captures_and_never_reaches_deletion(teardown):
    f = teardown
    entered = asyncio.Event()

    async def blocked(stage):
        entered.set()
        await asyncio.Event().wait()

    f.node_hook = blocked
    task = asyncio.create_task(release(f))
    try:
        await asyncio.wait_for(entered.wait(), 10)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert not any(event[0] == "delete" for event in f.events)
        assert len((await state(f))["storage_capture"]) == 6
        assert (await state(f))["node_capture"] is None
    finally:
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


async def test_inflight_writer_blocks_before_storage_node_or_compute_io(teardown):
    f = teardown
    async with f.h.sessions.begin() as db:
        intent = await db.get(PairIntent, f.intent.generation)
        work = await db.get(CleanupWork, f.work.work_id)
        intent.topics_dispatch = "inflight"
        work.pair_snapshot = {**work.pair_snapshot, "topics_dispatch": "inflight"}
        f.work = work
    assert not await release(f)
    assert not f.events
    assert await state(f) is None


async def test_refresh_only_fills_previously_unknown_captured_uids(teardown):
    f = teardown
    before = deepcopy(f.work.pair_snapshot)
    before["compute_uids"]["Pod/guest"] = None
    f.work.pair_snapshot = before
    f.blocked = False
    assert await release(f)
    assert (await state(f))["snapshot"]["compute_uids"]["Pod/guest"] is not None


@pytest.mark.parametrize("field", ["uid", "payload", "topics", "targets"])
async def test_refresh_never_accepts_changed_known_identity_payload_or_claim_targets(
    teardown, field
):
    f = teardown
    async with f.h.sessions.begin() as db:
        work = await db.get(CleanupWork, f.work.work_id)
        value = deepcopy(work.pair_snapshot)
        if field == "uid":
            value["compute_uids"]["Pod/guest"] = str(uuid4())
        elif field == "payload":
            value["compute_payloads"]["guest"] = None
        elif field == "topics":
            value["topics_dispatch"] = "inflight"
        else:
            work.targets = []
        work.pair_snapshot = value
    with pytest.raises(PairClaimLost):
        await release(f)
    assert not f.events


@pytest.mark.parametrize(
    "fault", ["storage_shape", "foreign_role", "missing_storage", "missing_node", "blocked_report"]
)
async def test_corrupt_retained_release_never_shortcuts_teardown(teardown, fault):
    f = teardown
    f.blocked = False
    assert await release(f)
    async with f.h.sessions.begin() as db:
        intent = await db.get(PairIntent, f.intent.generation)
        journal = deepcopy(intent.cleanup_journal)
        if fault == "storage_shape":
            journal["storage_capture"] = []
        elif fault == "foreign_role":
            journal["storage_capture"]["foreign"] = journal["storage_capture"]["workspace"]
        elif fault == "missing_storage":
            del journal["storage_capture"]["state"]
        elif fault == "missing_node":
            journal["node_capture"] = None
        else:
            journal["runtime_release"]["leftovers"]["journals"] = 1
            journal["runtime_release"]["observed_runtime_released"] = False
        intent.cleanup_journal = journal
    events = list(f.events)
    with pytest.raises((RuntimeError, ValueError)):
        await release(f)
    assert f.events == events


def lifecycle(f):
    return LifecycleService(
        f.runtime.settings,
        f.h.sessions,
        f.capture.repository,
        f.storage,
        AsyncMock(),
        AsyncMock(),
        AsyncMock(),
        f.capture,
        f.runtime,
    )


async def test_real_recovery_entrypoint_stops_before_other_resource_retirement(teardown):
    f = teardown
    f.blocked = False
    f.h.service.build = AsyncMock()
    service = RecoveryService(
        f.runtime.settings,
        f.h.sessions,
        f.h.repository,
        lifecycle(f),
        f.h.service,
        f.topics,
    )
    await service.execute(f.row.session_id)
    assert (await state(f))["runtime_release"]["observed_runtime_released"]
    f.h.service.build.assert_not_awaited()
    async with f.h.sessions.begin() as db:
        assert (await db.get(SandboxSession, f.row.session_id)).status == "recovering"
        assert await db.get(CleanupWork, f.work.work_id) is not None
    assert ("Pod", ipc_name(f.work.sandbox_id)) in f.remote.objects


async def test_real_idle_entrypoint_preserves_retention_after_private_runtime_release(teardown):
    f = teardown
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
    f.work, f.claim, f.blocked = work, None, False
    await lifecycle(f).execute(work.work_id)
    journal = await state(f)
    assert journal["runtime_release"]["observed_runtime_released"]
    assert journal["retain_workspace"]
    assert journal["storage_capture"]["workspace"]["retain"]
    assert journal["storage_capture"]["state"]["retain"]
    async with f.h.sessions.begin() as db:
        assert (await db.get(SandboxSession, f.row.session_id)).status == "shutting_down"
        assert (await db.get(SessionPVC, work.pvc_id)).state == "detaching"
        assert await db.get(CleanupWork, work.work_id) is not None


async def test_real_orphan_entrypoint_reuses_original_node_and_storage_capture(teardown):
    f = teardown
    assert not await release(f)
    original = deepcopy(await state(f))
    async with f.h.sessions.begin() as db:
        await db.execute(
            delete(SandboxSession).where(SandboxSession.session_id == f.row.session_id)
        )
    now = datetime.now(UTC)
    async with f.h.sessions.begin() as db:
        work = CleanupWork(
            work_id=uuid4(),
            session_id=None,
            sandbox_id=f.work.sandbox_id,
            pvc_id=None,
            kind="orphan",
            state_changed=now,
            pvc_changed=None,
            deadline=now + timedelta(seconds=120),
            acknowledged=True,
            targets=[],
            pair_snapshot=await f.capture.repository.pair_snapshot(
                db, f.row.session_id, f.work.sandbox_id
            ),
        )
        db.add(work)
    f.work, f.claim, f.blocked = work, None, False
    await lifecycle(f).execute(work.work_id)
    journal = await state(f)
    assert journal["runtime_release"]["observed_runtime_released"]
    assert journal["storage_capture"] == original["storage_capture"]
    assert journal["node_capture"] == original["node_capture"]
    assert sum(event == ("node", "capture") for event in f.events) == 1
