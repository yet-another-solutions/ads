# ruff: noqa: F811
from __future__ import annotations

import asyncio
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from functools import partial
from uuid import UUID, uuid4

import pytest

from ads_sandbox_manager.objects import JOB_UID
from ads_sandbox_manager.pair_compute import PrivateGuestRuntime
from ads_sandbox_manager.pair_compute_inputs import (
    PUBLISHED_COMPUTE_ROLES,
    compute_manifest,
    guest_payload,
    validate_payload,
)
from ads_sandbox_manager.pair_compute_kube import PairComputeAdapter
from ads_sandbox_manager.pair_compute_publication import PairComputePublication
from ads_sandbox_manager.pair_objects import pair_name
from ads_sandbox_manager.pair_store import PairClaimLost, PairIntent
from ads_sandbox_manager.session_objects import ca_consumer_pvc, session_pvc
from ads_sandbox_manager.store import SandboxSession
from test_kube_release import api  # noqa: F401
from test_pair_controls import controls  # noqa: F401
from test_pair_creator_fence import cleanup_claim
from test_pair_relay_compute import runtime  # noqa: F401
from test_pair_store import ledger, snapshot  # noqa: F401
from test_relay_custody_cleanup import saved
from test_session_objects import object_settings  # noqa: F401
from test_sessions import row_for, sessions_harness  # noqa: F401

pytestmark = pytest.mark.anyio


@pytest.fixture
async def publication(controls, runtime):
    f = controls
    settings = f.service.settings
    f.h.settings = settings
    f.intent = await f.service.prepare(f.row)
    source = {
        "metadata": {
            "name": "public-source",
            "uid": str(uuid4()),
            "labels": {JOB_UID: str(uuid4())},
        },
        "spec": {"resources": {"requests": {"storage": "1Mi"}}},
    }
    workspace = session_pvc(
        settings, f.row.session_id, f.row.sandbox_id, f.row.golden_version, "2Gi", f.row.pvc_id
    )
    public = ca_consumer_pvc(
        settings, f.row.session_id, f.row.sandbox_id, f.row.golden_version, "guest", source
    )
    for body in (workspace, public):
        f.remote.create(body=body)
    async with f.h.sessions.begin() as db:
        row = await db.get(SandboxSession, f.row.session_id)
        row.pvc_uid = f.remote.read("PersistentVolumeClaim", workspace["metadata"]["name"])[
            "metadata"
        ]["uid"]
        row.ca_attempt = UUID(source["metadata"]["labels"][JOB_UID])
        row.ca_sources = {"public": source["metadata"]["uid"], "private": str(uuid4())}
        row.ca_clones = {
            "guest": f.remote.read("PersistentVolumeClaim", public["metadata"]["name"])["metadata"][
                "uid"
            ],
            "egress": str(uuid4()),
            "key": str(uuid4()),
        }
    f.row = await row_for(f.h, f.row.session_id)
    kube = f.adapter.kube
    kube.core.read_namespaced_persistent_volume_claim.side_effect = partial(
        f.remote.read, "PersistentVolumeClaim"
    )
    kube.core.create_namespaced_pod.side_effect = f.remote.create
    f.compute = PairComputeAdapter(kube, f.adapter)
    f.service = PairComputePublication(settings, f.h.sessions, f.repo, f.compute)
    f.guest, f.relay = PrivateGuestRuntime("kata-private", runtime.transport_mtu), runtime
    f.remote.created.clear()
    f.remote.finished.clear()
    yield f
    f.remote.release.set()
    await f.service.drain()


async def publish(f):
    return await f.service.prepare(f.row, f.intent.generation, f.guest, f.relay)


def pod(f, role="guest"):
    return f.remote.objects[("Pod", pair_name(f.intent.binding(), role))]


async def test_payloads_and_one_shot_dispatch_commit_before_io_without_ready(publication):
    f = publication
    original, seen = f.compute.create, []

    async def create(pair, role, payload, control_uids):
        async with asyncio.timeout(5), f.h.sessions.begin() as db:
            current = await db.get(SandboxSession, f.row.session_id, with_for_update=True)
            intent = await f.repo.snapshot(db, pair.generation)
            assert current.status == "creating"
            assert intent.compute_payloads[role] == payload
            assert payload["control_uids"] == intent.control_uids == control_uids
            assert intent.compute_dispatch[f"Pod/{role}"] == "inflight"
            assert intent.compute_uids[f"Pod/{role}"] is None
        seen.append(role)
        return await original(pair, role, payload, control_uids)

    f.compute.create = create
    result = await publish(f)
    assert seen == list(PUBLISHED_COMPUTE_ROLES)
    assert len(f.remote.created) == 3
    for role in PUBLISHED_COMPUTE_ROLES:
        assert result.compute_uids[f"Pod/{role}"] == pod(f, role)["metadata"]["uid"]
        assert result.compute_dispatch[f"Pod/{role}"] == "settled"
        assert result.compute_payloads[role]["manifest"]["spec"] == pod(f, role)["spec"]
    assert result.compute_dispatch["Pod/egress"] == "unissued"
    assert result.compute_uids["Pod/egress"] is None
    assert result.compute_payloads["egress"] is None
    assert (await row_for(f.h, f.row.session_id)).status == "creating"
    assert not f.h.kube.calls
    f.adapter.kube.core.create_namespaced_secret.assert_not_called()
    f.adapter.kube.core.delete_namespaced_pod.assert_not_called()


async def test_concurrent_and_restarted_publication_never_recreates(publication):
    f = publication
    results = await asyncio.gather(*(publish(f) for _ in range(4)))
    f.service = PairComputePublication(f.h.settings, f.h.sessions, type(f.repo)(), f.compute)
    again = await publish(f)
    assert all(r.compute_uids == again.compute_uids for r in results)
    assert len(f.remote.created) == 3


@pytest.mark.parametrize("target", ["control", "workspace", "ca"])
@pytest.mark.parametrize("change", ["absent", "uid", "labels", "owner", "deleting", "spec"])
async def test_exact_dependencies_required_without_recreation(publication, target, change):
    f = publication
    kind = "Service" if target == "control" else "PersistentVolumeClaim"
    keys = [k for k in f.remote.objects if k[0] == kind]
    key = keys[-1] if target == "ca" else keys[0]
    body = f.remote.objects[key]
    if change == "absent":
        del f.remote.objects[key]
    elif change == "uid":
        body["metadata"]["uid"] = str(uuid4())
    elif change == "labels":
        body["metadata"]["labels"] = {}
    elif change == "owner":
        body["metadata"]["ownerReferences"] = [{"uid": "foreign"}]
    elif change == "deleting":
        body["metadata"]["deletionTimestamp"] = "now"
    elif target == "control":
        body["spec"]["externalIPs"] = ["1.2.3.4"]
    else:
        body["spec"]["volumeMode"] = "Filesystem"
    with pytest.raises(RuntimeError):
        await publish(f)
    assert not f.remote.created
    assert (await snapshot(f, f.intent.generation)).compute_dispatch["Pod/guest"] == "inflight"


@pytest.mark.parametrize("role", PUBLISHED_COMPUTE_ROLES)
@pytest.mark.parametrize("change", ["absent", "uid", "spec", "annotations", "owner"])
async def test_bound_pod_loss_replacement_or_extra_authority_is_not_repaired(
    publication, role, change
):
    f = publication
    before = await publish(f)
    body = pod(f, role)
    if change == "absent":
        del f.remote.objects[("Pod", body["metadata"]["name"])]
    elif change == "uid":
        body["metadata"]["uid"] = str(uuid4())
    elif change == "spec":
        body["spec"]["hostNetwork"] = True
    elif change == "annotations":
        body["metadata"]["annotations"] = {"untrusted-hook": "enabled"}
    else:
        body["metadata"]["ownerReferences"] = [{"uid": "replacement-controller"}]
    with pytest.raises(RuntimeError):
        await publish(f)
    after = await snapshot(f, f.intent.generation)
    assert after.compute_uids == before.compute_uids
    assert after.compute_payloads == before.compute_payloads
    assert len(f.remote.created) == 3


@pytest.mark.parametrize("failure", ["lost-reply", "settlement", "binding"])
async def test_failed_completion_preserves_payload_and_never_reissues(publication, failure):
    f = publication
    method = "settle_compute" if failure == "settlement" else "bind_compute"
    original = getattr(f.repo, method)

    async def fail(*args, **kwargs):
        await original(*args, **kwargs)
        raise RuntimeError("commit failure")

    if failure == "lost-reply":
        f.remote.lost_reply = True
    else:
        setattr(f.repo, method, fail)
    with pytest.raises((RuntimeError, TimeoutError)):
        await publish(f)
    before = await snapshot(f, f.intent.generation)
    assert before.compute_payloads["guest"] is not None
    assert before.compute_uids["Pod/guest"] is None
    expected = "settled" if failure == "binding" else "inflight"
    assert before.compute_dispatch["Pod/guest"] == expected
    setattr(f.repo, method, original)
    after = await publish(f)
    assert after.compute_payloads["guest"] == before.compute_payloads["guest"]
    assert after.compute_dispatch["Pod/guest"] == expected
    assert len(f.remote.created) == 3


@pytest.mark.parametrize("cancel_operation", [False, True])
async def test_cancellation_retains_original_and_cleanup_owns_late_uid(
    publication, cancel_operation
):
    f = publication
    f.remote.delay = True
    task = asyncio.create_task(publish(f))
    try:
        assert await asyncio.to_thread(f.remote.started.wait, 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        operations = tuple(f.service._dispatches)
        assert len(operations) == 1
        if cancel_operation:
            operations[0].cancel()
            await asyncio.gather(*operations, return_exceptions=True)
        capture, work, claim = await cleanup_claim(f)
        await capture.capture(work, recovery=claim)
        before = await saved(f, work)
        assert before.pair_snapshot["compute_uids"]["Pod/guest"] is None
        assert before.pair_snapshot["compute_payloads"]["guest"] is not None
        assert (await snapshot(f, f.intent.generation)).creation_fenced
        f.remote.release.set()
        assert await asyncio.to_thread(f.remote.finished.wait, 5)
        await f.service.drain()
        await capture.capture(before, recovery=claim)
        after = await saved(f, work)
        assert after.pair_snapshot["compute_uids"]["Pod/guest"] == pod(f)["metadata"]["uid"]
        assert after.pair_snapshot["compute_payloads"] == before.pair_snapshot["compute_payloads"]
        stored = await snapshot(f, f.intent.generation)
        assert stored.compute_uids["Pod/guest"] is None
        assert stored.compute_dispatch["Pod/guest"] == (
            "inflight" if cancel_operation else "settled"
        )
        assert stored.compute_dispatch["Pod/guest-relay"] == "unissued"
        async with f.h.sessions.begin() as db:
            assert not await capture.repository.complete(db, after, datetime.now(UTC))
        assert len(f.remote.created) == 1
    finally:
        f.remote.release.set()
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize("field", ["pvc_uid", "ca_clones", "control_uids", "claimed_by"])
async def test_changed_dependencies_or_claim_after_api_cannot_bind(publication, field):
    f = publication
    original = f.compute.create

    async def create(*args):
        uid = await original(*args)
        async with f.h.sessions.begin() as db:
            if field == "control_uids":
                intent = await db.get(PairIntent, f.intent.generation)
                intent.control_uids = {**intent.control_uids, "Service/egress": "changed"}
            else:
                row = await db.get(SandboxSession, f.row.session_id)
                setattr(
                    row,
                    field,
                    {
                        "pvc_uid": "changed",
                        "ca_clones": {**row.ca_clones, "guest": "changed"},
                        "claimed_by": uuid4(),
                    }[field],
                )
        return uid

    f.compute.create = create
    with pytest.raises(PairClaimLost):
        await publish(f)
    stored = await snapshot(f, f.intent.generation)
    assert stored.compute_uids["Pod/guest"] is None
    assert stored.compute_dispatch["Pod/guest"] == "settled"
    assert len(f.remote.created) == 1


@pytest.mark.parametrize("change", ["runtime", "image", "control", "volume"])
async def test_committed_inputs_cannot_be_reinterpreted_on_retry(publication, change):
    f = publication
    before = await publish(f)
    if change == "runtime":
        f.guest = replace(f.guest, runtime_class="different-private")
    elif change == "image":
        settings = replace(
            f.h.settings,
            session_objects=replace(f.h.settings.session_objects, guest_image="different:1"),
        )
        f.service.settings = settings
    else:
        async with f.h.sessions.begin() as db:
            if change == "control":
                row = await db.get(PairIntent, f.intent.generation)
                row.control_uids = {**row.control_uids, "Service/egress": "changed"}
            else:
                row = await db.get(SandboxSession, f.row.session_id)
                row.pvc_uid = "changed"
    with pytest.raises(RuntimeError):
        await publish(f)
    assert (await snapshot(f, f.intent.generation)).compute_payloads == before.compute_payloads
    assert len(f.remote.created) == 3


async def test_cleanup_fence_rejects_changed_committed_payload(publication):
    f = publication
    await publish(f)
    capture, work, claim = await cleanup_claim(f)
    async with f.h.sessions.begin() as db:
        intent = await db.get(PairIntent, f.intent.generation)
        values = deepcopy(intent.compute_payloads)
        values["guest"]["pvc_uid"] = "changed"
        intent.compute_payloads = values
    with pytest.raises(PairClaimLost, match="cleanup payload"):
        await capture.capture(work, recovery=claim)
    assert not (await snapshot(f, f.intent.generation)).creation_fenced


async def test_api_defaults_do_not_expand_execution_authority(publication):
    f = publication
    result = await publish(f)
    for role in PUBLISHED_COMPUTE_ROLES:
        body = pod(f, role)
        spec = body["spec"]
        spec.update(
            nodeName="sandbox-node",
            schedulerName="default-scheduler",
            serviceAccountName="default",
            serviceAccount="default",
            securityContext={},
            priority=0,
            preemptionPolicy="PreemptLowerPriority",
        )
        spec.setdefault("dnsPolicy", "ClusterFirst")
        spec["tolerations"].append(
            {
                "key": "node.kubernetes.io/not-ready",
                "operator": "Exists",
                "effect": "NoExecute",
                "tolerationSeconds": 300,
            }
        )
        container = spec["containers"][0]
        container.update(
            terminationMessagePath="/dev/termination-log",
            terminationMessagePolicy="File",
            imagePullPolicy="IfNotPresent",
        )
        probe = container.get("readinessProbe", container.get("livenessProbe"))
        for key, value in {
            "initialDelaySeconds": 0,
            "timeoutSeconds": 1,
            "periodSeconds": 10,
            "successThreshold": 1,
            "failureThreshold": 3,
        }.items():
            probe.setdefault(key, value)
        if role == "guest":
            container["resources"]["requests"] = deepcopy(container["resources"]["limits"])
            spec["volumes"][0]["persistentVolumeClaim"]["readOnly"] = False
        # Kubernetes quantity canonicalization must not change the committed input.
        container["resources"]["limits"]["cpu"] = "2000m" if role == "guest" else "1"
    assert (await publish(f)).compute_uids == result.compute_uids
    assert len(f.remote.created) == 3


@pytest.mark.parametrize(
    "field,value",
    [
        ("runtime", {"runtime_class": "kata-private", "transport_mtu": True}),
        ("pvc_id", "not-a-uuid"),
        ("ca_attempt", ""),
        ("ca_guest_uid", False),
        ("control_uids", {}),
        ("manifest", []),
    ],
)
async def test_malformed_payload_does_not_reserve_dispatch(publication, field, value):
    f = publication
    payload = guest_payload(f.row, f.guest)
    payload["control_uids"] = dict(f.intent.control_uids)
    payload["manifest"] = compute_manifest(f.h.settings, f.intent.binding(), "guest", payload)
    payload[field] = value
    with pytest.raises(RuntimeError, match="payload"):
        async with f.h.sessions.begin() as db:
            await f.repo.reserve_compute(db, f.row, f.owner, f.intent.generation, "guest", payload)
    assert (await snapshot(f, f.intent.generation)).compute_dispatch["Pod/guest"] == "unissued"
    assert not f.remote.created
    with pytest.raises(RuntimeError):
        validate_payload("egress", payload)


async def test_unbound_volumes_and_mtu_mismatch_fail_before_reservation(publication):
    f = publication
    f.guest = replace(f.guest, transport_mtu=f.guest.transport_mtu - 1)
    with pytest.raises(ValueError, match="MTU"):
        await publish(f)
    f.guest = replace(f.guest, transport_mtu=f.relay.transport_mtu)
    async with f.h.sessions.begin() as db:
        row = await db.get(SandboxSession, f.row.session_id)
        row.pvc_uid = None
    with pytest.raises(ValueError, match="volume"):
        await publish(f)
    assert not f.remote.created
    assert (await snapshot(f, f.intent.generation)).compute_payloads["guest"] is None


async def test_ambiguous_absent_pod_stays_inflight_after_observer_timeout(publication):
    f = publication
    original = f.compute.create

    async def lost(*args):
        raise TimeoutError("write outcome unknown")

    f.compute.create = lost
    with pytest.raises(TimeoutError):
        await publish(f)
    before = await snapshot(f, f.intent.generation)
    f.compute.create = original
    f.service.settings = replace(
        f.service.settings,
        session_objects=replace(f.service.settings.session_objects, create_seconds=0.2),
    )
    with pytest.raises(TimeoutError):
        await publish(f)
    after = await snapshot(f, f.intent.generation)
    assert after.compute_payloads == before.compute_payloads
    assert after.compute_uids["Pod/guest"] is None
    assert after.compute_dispatch["Pod/guest"] == "inflight"
    assert not f.remote.created


async def test_payload_only_rollback_and_prior_payloadless_dispatch_do_not_create(publication):
    f = publication
    payload = guest_payload(f.row, f.guest)
    payload["control_uids"] = dict(f.intent.control_uids)
    payload["manifest"] = compute_manifest(f.h.settings, f.intent.binding(), "guest", payload)
    with pytest.raises(RuntimeError, match="rollback"):
        async with f.h.sessions.begin() as db:
            await f.repo.reserve_compute(db, f.row, f.owner, f.intent.generation, "guest", payload)
            raise RuntimeError("rollback")
    assert (await snapshot(f, f.intent.generation)).compute_payloads["guest"] is None
    async with f.h.sessions.begin() as db:
        await f.repo.dispatch_compute(db, f.row, f.owner, f.intent.generation, "guest")
    with pytest.raises(RuntimeError, match="no committed payload"):
        await publish(f)
    assert not f.remote.created


async def test_reservation_wait_is_bounded_before_api(publication):
    f = publication
    f.service.settings = replace(f.service.settings, control_seconds=0.1)
    async with f.h.sessions.begin() as db:
        await db.get(SandboxSession, f.row.session_id, with_for_update=True)
        with pytest.raises(TimeoutError):
            await publish(f)
    stored = await snapshot(f, f.intent.generation)
    assert stored.compute_payloads["guest"] is None
    assert stored.compute_dispatch["Pod/guest"] == "unissued"
    assert not f.remote.created


@pytest.mark.parametrize(
    "field,value",
    [
        ("hostPID", True),
        ("hostIPC", True),
        ("automountServiceAccountToken", True),
        ("initContainers", [{"name": "injected"}]),
        ("runtimeClassName", "untrusted"),
    ],
)
async def test_extra_pod_authority_is_rejected(publication, field, value):
    f = publication
    await publish(f)
    body = pod(f, "guest-relay")
    body["spec"][field] = value
    with pytest.raises(RuntimeError, match="incompatible"):
        await publish(f)
    assert len(f.remote.created) == 3


async def test_creator_fence_wins_before_any_compute_reservation(publication):
    f = publication
    capture, work, claim = await cleanup_claim(f)
    await capture.capture(work, recovery=claim)
    with pytest.raises(PairClaimLost):
        await publish(f)
    assert not f.remote.created
    stored = await snapshot(f, f.intent.generation)
    assert stored.creation_fenced and set(stored.compute_payloads.values()) == {None}
