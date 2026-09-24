# ruff: noqa: F811
from __future__ import annotations

import asyncio
from copy import deepcopy
from datetime import UTC, datetime
from functools import partial
from unittest.mock import Mock
from uuid import uuid4

import pytest

from ads_sandbox_manager.pair_ipc_inputs import IPC_ROLES, validate_ipc_resources
from ads_sandbox_manager.pair_ipc_kube import PairIpcAdapter
from ads_sandbox_manager.pair_ipc_publication import PairIpcPublication
from ads_sandbox_manager.pair_ipc_store import PairIpcRepository
from ads_sandbox_manager.pair_store import PairClaimLost, PairIntent
from ads_sandbox_manager.relay_input_kube import RelayInputAdapter
from ads_sandbox_manager.relay_input_publication import RelayInputPublication
from ads_sandbox_manager.relay_key_custody import RelayKeyCustody
from ads_sandbox_manager.relay_key_kube import RelayKeyAdapter
from ads_sandbox_manager.session_objects import ipc_name
from ads_sandbox_manager.store import SandboxSession
from test_egress_compute import runtime as egress_runtime  # noqa: F401
from test_egress_compute_publication import prepare as prepare_egress
from test_egress_compute_publication import publication as egress_publication  # noqa: F401
from test_kube_release import api  # noqa: F401
from test_pair_compute_publication import publication as compute_publication  # noqa: F401
from test_pair_controls import controls  # noqa: F401
from test_pair_creator_fence import cleanup_claim
from test_pair_relay_compute import runtime  # noqa: F401
from test_pair_store import ledger, snapshot  # noqa: F401
from test_relay_custody_cleanup import saved
from test_session_objects import object_settings  # noqa: F401
from test_sessions import row_for, sessions_harness  # noqa: F401

pytestmark = pytest.mark.anyio


@pytest.fixture
async def publication(egress_publication):
    f = egress_publication
    await prepare_egress(f)
    kube = f.adapter.kube
    keys = RelayKeyCustody(f.h.settings, f.h.sessions, f.repo, RelayKeyAdapter(kube))
    inputs = RelayInputPublication(f.h.settings, f.h.sessions, f.repo, RelayInputAdapter(kube))
    await keys.prepare(f.row, f.intent.generation)
    await inputs.prepare(f.row, f.intent.generation, f.relay)
    kube.apps = Mock()
    kube.core.read_namespaced_pod.side_effect = partial(f.remote.read, "Pod")
    kube.core.create_namespaced_pod.side_effect = f.remote.create
    f.ipc = PairIpcAdapter(f.compute)
    f.ipc_repo = PairIpcRepository(f.repo)
    f.service = PairIpcPublication(f.h.settings, f.h.sessions, f.ipc_repo, f.ipc)
    f.subject = uuid4()
    f.remote.created.clear()
    f.remote.started.clear()
    f.remote.finished.clear()
    yield f
    f.remote.release.set()
    await f.service.drain()
    await keys.drain()
    await inputs.drain()


async def prepare(f):
    return await f.service.prepare(f.row, f.intent.generation, f.subject)


def resource(f, role):
    return f.remote.objects[
        (
            "PersistentVolumeClaim" if role == "volume" else "Pod",
            ipc_name(f.row.sandbox_id),
        )
    ]


def hook_create(f, role, *, delayed=False, lost_reply=False):
    target = "PersistentVolumeClaim" if role == "volume" else "Pod"
    original = f.remote.create

    def create(*args, body, **kwargs):
        if body["kind"] == target:
            f.remote.finished.clear()
            f.remote.delay = delayed
            f.remote.lost_reply = lost_reply
        return original(*args, body=body, **kwargs)

    f.adapter.kube.core.create_namespaced_persistent_volume_claim.side_effect = create
    f.adapter.kube.core.create_namespaced_pod.side_effect = create


async def test_committed_payload_before_each_write_and_session_uid_binding(publication):
    f, steps = publication, []
    original = f.ipc.create

    async def create(intent, role):
        async with asyncio.timeout(5), f.h.sessions.begin() as db:
            row = await db.get(SandboxSession, f.row.session_id, with_for_update=True)
            current = await f.repo.snapshot(db, intent.generation)
            assert row.status == "creating"
            entry = current.ipc_resources[role]
            assert entry == intent.ipc_resources[role]
            assert entry["dispatch"] == "inflight" and entry["uid"] is None
            assert entry["payload"]["compute_uids"] == current.compute_uids
            assert entry["payload"]["control_uids"] == current.control_uids
            if role == "pod":
                assert entry["payload"]["volume_uid"] == row.ipc_pvc_uid
            steps.append(role)
        return await original(intent, role)

    f.ipc.create = create
    first = await prepare(f)
    assert steps == list(IPC_ROLES)
    row = await row_for(f.h, f.row.session_id)
    assert row.ipc_pvc_uid == resource(f, "volume")["metadata"]["uid"]
    assert row.ipc_pod_uid == resource(f, "pod")["metadata"]["uid"]
    assert row.status == "creating" and not f.h.kube.calls
    assert all(
        entry["dispatch"] == "settled" and entry["uid"] for entry in first.ipc_resources.values()
    )
    f.service = PairIpcPublication(
        f.h.settings, f.h.sessions, PairIpcRepository(f.repo), PairIpcAdapter(f.compute)
    )
    second = await prepare(f)
    assert second.ipc_resources == first.ipc_resources
    assert len(f.remote.created) == 2


async def test_concurrent_same_claim_only_one_writer_per_resource(publication):
    f = publication
    # One caller can reach the deliberate settled-volume prerequisite before
    # its sibling commits original settlement. Only that fail-closed race is allowed.
    results = await asyncio.gather(prepare(f), prepare(f), return_exceptions=True)
    for result in results:
        if isinstance(result, Exception):
            assert isinstance(result, PairClaimLost) and "settled" in str(result)
    current = await prepare(f)
    assert all(entry["uid"] for entry in current.ipc_resources.values())
    assert len(f.remote.created) == 2


@pytest.mark.parametrize("role", IPC_ROLES)
async def test_lost_reply_never_settles_or_recreates(publication, role):
    f = publication
    hook_create(f, role, lost_reply=True)
    with pytest.raises(RuntimeError, match="create failed"):
        await prepare(f)
    current = await snapshot(f, f.intent.generation)
    assert current.ipc_resources[role]["dispatch"] == "inflight"
    assert current.ipc_resources[role]["uid"] is None
    if role == "volume":
        with pytest.raises(PairClaimLost, match="settled"):
            await prepare(f)
    else:
        await prepare(f)
    after = await snapshot(f, f.intent.generation)
    assert after.ipc_resources[role]["dispatch"] == "inflight"
    assert after.ipc_resources[role]["uid"]
    assert len(f.remote.created) == (1 if role == "volume" else 2)


@pytest.mark.parametrize("role", IPC_ROLES)
@pytest.mark.parametrize("cancel_writer", [False, True])
async def test_fenced_cleanup_captures_late_ipc_without_settlement_or_release(
    publication, role, cancel_writer
):
    f = publication
    hook_create(f, role, delayed=True)
    task = asyncio.create_task(prepare(f))
    try:
        assert await asyncio.to_thread(f.remote.started.wait, 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        operations = tuple(f.service._dispatches)
        assert len(operations) == 1
        if cancel_writer:
            operations[0].cancel()
            await asyncio.gather(*operations, return_exceptions=True)
        capture, work, claim = await cleanup_claim(f)
        await capture.capture(work, recovery=claim)
        first = await saved(f, work)
        assert first.pair_snapshot["ipc_resources"][role]["uid"] is None
        f.remote.release.set()
        assert await asyncio.to_thread(f.remote.finished.wait, 5)
        await f.service.drain()
        await capture.capture(first, recovery=claim)
        final = await saved(f, work)
        assert (
            final.pair_snapshot["ipc_resources"][role]["uid"]
            == resource(f, role)["metadata"]["uid"]
        )
        assert final.pair_snapshot["ipc_resources"][role]["dispatch"] == "inflight"
        stored = await snapshot(f, f.intent.generation)
        assert stored.creation_fenced
        assert stored.ipc_resources[role]["dispatch"] == (
            "inflight" if cancel_writer else "settled"
        )
        assert stored.ipc_resources[role]["uid"] is None
        async with f.h.sessions.begin() as db:
            assert not await capture.repository.complete(db, final, datetime.now(UTC))
        with pytest.raises(PairClaimLost):
            await prepare(f)
    finally:
        f.remote.release.set()
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize("role", IPC_ROLES)
@pytest.mark.parametrize("fault", ["absent", "uid", "owner", "labels", "deleting", "spec"])
async def test_missing_replaced_or_incompatible_ipc_never_repaired(publication, role, fault):
    f = publication
    before = await prepare(f)
    obj = resource(f, role)
    if fault == "absent":
        del f.remote.objects[(obj["kind"], obj["metadata"]["name"])]
    elif fault == "uid":
        obj["metadata"]["uid"] = str(uuid4())
    elif fault == "owner":
        obj["metadata"]["ownerReferences"] = [{"uid": "foreign"}]
    elif fault == "labels":
        obj["metadata"]["labels"] = {}
    elif fault == "deleting":
        obj["metadata"]["deletionTimestamp"] = "now"
    elif role == "volume":
        obj["spec"]["dataSource"] = {"kind": "PersistentVolumeClaim", "name": "foreign"}
    else:
        obj["spec"]["containers"][0]["env"].append({"name": "FOREIGN", "value": "1"})
    with pytest.raises(RuntimeError):
        await prepare(f)
    assert (await snapshot(f, f.intent.generation)).ipc_resources == before.ipc_resources
    assert len(f.remote.created) == 2


@pytest.mark.parametrize(
    "fault", ["control", "compute", "custody", "inputs", "state", "untracked-ipc"]
)
async def test_incomplete_or_untracked_dependencies_block_before_dispatch(publication, fault):
    f = publication
    async with f.h.sessions.begin() as db:
        intent = await db.get(PairIntent, f.intent.generation)
        if fault == "control":
            intent.control_dispatch = {**intent.control_dispatch, "Service/egress": "inflight"}
        elif fault == "compute":
            intent.compute_dispatch = {**intent.compute_dispatch, "Pod/guest": "inflight"}
        elif fault == "custody":
            intent.relay_custody = {**intent.relay_custody, "dispatch": "inflight"}
        elif fault == "inputs":
            intent.relay_inputs = {
                **intent.relay_inputs,
                "guest-relay": {
                    **intent.relay_inputs["guest-relay"],
                    "dispatch": "inflight",
                },
            }
        elif fault == "state":
            intent.egress_state_id = None
        else:
            row = await db.get(SandboxSession, f.row.session_id)
            row.ipc_pvc_uid = "untracked"
    with pytest.raises(RuntimeError):
        await prepare(f)
    assert not f.remote.created


@pytest.mark.parametrize("role", IPC_ROLES)
async def test_session_identity_drift_after_io_cannot_bind(publication, role):
    f, original = publication, publication.ipc.create

    async def create(intent, member):
        uid = await original(intent, member)
        if member == role:
            async with f.h.sessions.begin() as db:
                row = await db.get(SandboxSession, f.row.session_id)
                setattr(row, "ipc_pvc_uid" if role == "volume" else "ipc_pod_uid", "foreign")
        return uid

    f.ipc.create = create
    with pytest.raises(RuntimeError, match="replacement"):
        await prepare(f)
    entry = (await snapshot(f, f.intent.generation)).ipc_resources[role]
    assert entry["uid"] is None and entry["dispatch"] == "settled"


async def test_cleanup_metadata_drift_and_absence_preserve_uid_and_original_payload(publication):
    f = publication
    before = await prepare(f)
    capture, work, claim = await cleanup_claim(f)
    for role in IPC_ROLES:
        obj = resource(f, role)
        obj["metadata"]["deletionTimestamp"] = "now"
        obj["spec"] = {"foreign": "still-owned"}
    await capture.capture(work, recovery=claim)
    first = await saved(f, work)
    assert first.pair_snapshot["ipc_resources"] == before.ipc_resources
    for role in IPC_ROLES:
        obj = resource(f, role)
        del f.remote.objects[(obj["kind"], obj["metadata"]["name"])]
    await capture.capture(first, recovery=claim)
    final = await saved(f, work)
    assert final.pair_snapshot["ipc_resources"] == before.ipc_resources
    async with f.h.sessions.begin() as db:
        assert not await capture.repository.complete(db, final, datetime.now(UTC))
    assert len(f.remote.created) == 2


async def test_api_defaults_do_not_expand_ipc_authority(publication):
    f = publication
    before = await prepare(f)
    volume = resource(f, "volume")
    volume["spec"]["volumeName"] = "assigned-pv"
    pod = resource(f, "pod")
    spec = pod["spec"]
    spec.update(
        nodeName="application",
        dnsPolicy="ClusterFirst",
        schedulerName="default-scheduler",
        restartPolicy="Always",
        terminationGracePeriodSeconds=30,
        serviceAccount="sandbox-ipc",
    )
    for volume in spec["volumes"]:
        if "secret" in volume:
            volume["secret"]["defaultMode"] = 0o644
        elif "persistentVolumeClaim" in volume:
            volume["persistentVolumeClaim"]["readOnly"] = False
    container = spec["containers"][0]
    container.update(
        imagePullPolicy="IfNotPresent",
        terminationMessagePath="/dev/termination-log",
        terminationMessagePolicy="File",
    )
    container["ports"][0]["protocol"] = "TCP"
    container["resources"]["requests"] = deepcopy(container["resources"]["limits"])
    for key in ("livenessProbe", "readinessProbe"):
        container[key].update(
            initialDelaySeconds=0,
            timeoutSeconds=1,
            periodSeconds=10,
            successThreshold=1,
            failureThreshold=3,
        )
    after = await prepare(f)
    assert after.ipc_resources == before.ipc_resources
    assert len(f.remote.created) == 2


@pytest.mark.parametrize("role", IPC_ROLES)
@pytest.mark.parametrize("fault", ["settlement", "binding"])
async def test_failed_commit_preserves_original_dispatch_and_payload(publication, role, fault):
    f = publication
    method = "settle" if fault == "settlement" else "bind"
    original = getattr(f.ipc_repo, method)

    async def fail(*args):
        result = await original(*args)
        member = args[2] if fault == "settlement" else args[4]
        if member == role:
            raise RuntimeError("commit failed")
        return result

    setattr(f.ipc_repo, method, fail)
    with pytest.raises(RuntimeError, match="commit failed"):
        await prepare(f)
    before = await snapshot(f, f.intent.generation)
    entry = before.ipc_resources[role]
    assert entry["uid"] is None
    assert entry["dispatch"] == ("inflight" if fault == "settlement" else "settled")
    setattr(f.ipc_repo, method, original)
    if role == "volume" and fault == "settlement":
        with pytest.raises(PairClaimLost, match="settled"):
            await prepare(f)
    else:
        await prepare(f)
    after = (await snapshot(f, f.intent.generation)).ipc_resources[role]
    assert after["payload"] == entry["payload"] and after["dispatch"] == entry["dispatch"]
    assert after["uid"] == resource(f, role)["metadata"]["uid"]
    assert len(f.remote.created) == (1 if role == "volume" and fault == "settlement" else 2)


@pytest.mark.parametrize("target", ["Pod", "Service", "Secret"])
@pytest.mark.parametrize("late", [False, True])
async def test_actual_dependency_replacement_blocks_publication_and_binding(
    publication, target, late
):
    f = publication

    def replace():
        obj = next(value for (kind, _), value in f.remote.objects.items() if kind == target)
        obj["metadata"]["uid"] = str(uuid4())

    if late:
        original = f.remote.create

        def create(*args, **kwargs):
            result = original(*args, **kwargs)
            replace()
            return result

        f.adapter.kube.core.create_namespaced_persistent_volume_claim.side_effect = create
    else:
        replace()
    with pytest.raises(RuntimeError):
        await prepare(f)
    current = await snapshot(f, f.intent.generation)
    assert current.ipc_resources["volume"]["dispatch"] == "inflight"
    assert current.ipc_resources["volume"]["uid"] is None
    assert current.ipc_resources["pod"]["dispatch"] == "unissued"
    assert len(f.remote.created) == int(late)


@pytest.mark.parametrize(
    "fault",
    [
        "account",
        "token",
        "host",
        "sidecar",
        "annotation",
        "protocol",
        "mode",
        "probe",
        "revision",
        "audience",
        "token-lifetime",
        "token-mount",
        "automount",
        "restart",
        "selector",
    ],
)
async def test_additive_or_noncanonical_pod_defaults_rejected(publication, fault):
    f = publication
    before = await prepare(f)
    obj = resource(f, "pod")
    spec = obj["spec"]
    container = spec["containers"][0]
    if fault == "account":
        spec["serviceAccount"] = "foreign"
    elif fault == "token":
        spec["volumes"].append(
            {
                "name": "foreign-token",
                "projected": {
                    "sources": [
                        {
                            "serviceAccountToken": {
                                "audience": "foreign",
                                "path": "token",
                            }
                        }
                    ]
                },
            }
        )
    elif fault == "host":
        spec["hostNetwork"] = True
    elif fault == "sidecar":
        spec["containers"].append(deepcopy(container))
    elif fault == "annotation":
        obj["metadata"]["annotations"] = {"inject": "true"}
    elif fault == "protocol":
        container["ports"][0]["protocol"] = "UDP"
    elif fault == "mode":
        next(v["secret"] for v in spec["volumes"] if "secret" in v)["defaultMode"] = 0o777
    elif fault == "probe":
        container["readinessProbe"]["successThreshold"] = 2
    elif fault == "revision":
        obj["metadata"]["annotations"] = {"deployment.kubernetes.io/revision": "01"}
    elif fault in ("audience", "token-lifetime"):
        token = next(v for v in spec["volumes"] if v["name"] == "kube-api")["projected"]["sources"][
            0
        ]["serviceAccountToken"]
        token["audience" if fault == "audience" else "expirationSeconds"] = (
            "foreign" if fault == "audience" else 86400
        )
    elif fault == "token-mount":
        container["volumeMounts"][-1]["readOnly"] = False
    elif fault == "automount":
        spec["automountServiceAccountToken"] = True
    elif fault == "restart":
        spec["restartPolicy"] = "Never"
    else:
        spec["nodeSelector"] = {"foreign": "true"}
    with pytest.raises(RuntimeError, match="incompatible"):
        await prepare(f)
    assert (await snapshot(f, f.intent.generation)).ipc_resources == before.ipc_resources
    assert len(f.remote.created) == 2


async def test_legacy_ipc_uid_cannot_be_adopted_as_a_pod_uid(publication):
    f = publication
    async with f.h.sessions.begin() as db:
        row = await db.get(SandboxSession, f.row.session_id)
        row.ipc_deployment_uid = "legacy-uid"
    with pytest.raises(PairClaimLost, match="legacy IPC Deployment"):
        await prepare(f)
    assert not f.remote.created


async def test_missing_ipc_pod_never_recreated_by_a_restarted_publisher(publication):
    f = publication
    before = await prepare(f)
    del f.remote.objects[("Pod", ipc_name(f.row.sandbox_id))]
    f.service = PairIpcPublication(f.h.settings, f.h.sessions, f.ipc_repo, f.ipc)
    with pytest.raises(RuntimeError, match="disappeared"):
        await prepare(f)
    assert (await snapshot(f, f.intent.generation)).ipc_resources == before.ipc_resources
    assert len(f.remote.created) == 2
    f.adapter.kube.apps.create_namespaced_deployment.assert_not_called()


async def test_committed_subject_change_is_not_an_in_place_update(publication):
    f = publication
    before = await prepare(f)
    f.subject = uuid4()
    with pytest.raises(RuntimeError, match="payload changed"):
        await prepare(f)
    assert (await snapshot(f, f.intent.generation)).ipc_resources == before.ipc_resources
    assert len(f.remote.created) == 2


@pytest.mark.parametrize("fault", ["payload", "uid", "dispatch"])
async def test_cleanup_rejects_changed_committed_ipc_ownership(publication, fault):
    f = publication
    await prepare(f)
    capture, work, claim = await cleanup_claim(f)
    async with f.h.sessions.begin() as db:
        intent = await db.get(PairIntent, f.intent.generation)
        resources = deepcopy(intent.ipc_resources)
        entry = resources["pod"]
        if fault == "payload":
            entry["payload"]["ads_service_subject"] = str(uuid4())
        elif fault == "uid":
            entry["uid"] = str(uuid4())
        else:
            entry["dispatch"] = "inflight"
        intent.ipc_resources = resources
    with pytest.raises(PairClaimLost, match="ownership changed"):
        await capture.capture(work, recovery=claim)
    assert (await saved(f, work)).pair_snapshot == work.pair_snapshot


@pytest.mark.parametrize("fault", ["extra", "missing", "uid", "dispatch", "payload", "unissued"])
def test_corrupt_ipc_evidence_rejected(fault):
    from ads_sandbox_manager.pair_ipc_inputs import new_ipc_resources

    value = new_ipc_resources()
    if fault == "extra":
        value["extra"] = {}
    elif fault == "missing":
        del value["volume"]
    elif fault == "uid":
        value["volume"]["uid"] = "foreign"
    elif fault == "dispatch":
        value["volume"]["dispatch"] = "finished"
    elif fault == "payload":
        value["volume"] = {"uid": None, "dispatch": "inflight", "payload": {}}
    else:
        value["pod"]["payload"] = {}
    with pytest.raises(RuntimeError):
        validate_ipc_resources(value)
