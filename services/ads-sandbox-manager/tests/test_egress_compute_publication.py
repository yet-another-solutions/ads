# ruff: noqa: F811
from __future__ import annotations

import asyncio
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from functools import partial
from uuid import uuid4

import pytest
from sqlalchemy import delete

from ads_sandbox_manager.config import CaSettings
from ads_sandbox_manager.egress_compute_inputs import egress_payload
from ads_sandbox_manager.egress_compute_publication import EgressComputePublication
from ads_sandbox_manager.egress_state_kube import EgressStateAdapter, identity
from ads_sandbox_manager.egress_state_publication import EgressStatePublication
from ads_sandbox_manager.egress_state_store import (
    EgressState,
    EgressStateRepository,
    state_snapshot,
)
from ads_sandbox_manager.objects import JOB_UID
from ads_sandbox_manager.pair_compute_inputs import compute_manifest, validate_payload
from ads_sandbox_manager.pair_store import PairClaimLost, PairIntent
from ads_sandbox_manager.session_objects import ca_consumer_name, ca_consumer_pvc
from ads_sandbox_manager.store import SandboxSession
from test_egress_compute import runtime as egress_runtime  # noqa: F401
from test_kube_release import api  # noqa: F401
from test_pair_compute_publication import pod, publish  # noqa: F401
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
async def publication(compute_publication, egress_runtime):
    f = compute_publication
    await publish(f)
    settings = replace(f.h.settings, ca=CaSettings("registry.test/ca:v1", "signer", "extra"))
    f.h.settings = f.adapter.kube.settings = settings
    core = f.adapter.kube.core
    core.read_namespaced_secret.side_effect = partial(f.remote.read, "Secret")
    core.create_namespaced_secret.side_effect = f.remote.create
    core.create_namespaced_persistent_volume_claim.side_effect = f.remote.create
    async with f.h.sessions.begin() as db:
        await db.execute(delete(EgressState))
        row = await db.get(SandboxSession, f.row.session_id)
        clones = dict(row.ca_clones)
        for member, source in (("egress", "public"), ("key", "private")):
            body = ca_consumer_pvc(
                settings,
                row.session_id,
                row.sandbox_id,
                row.golden_version,
                member,
                {
                    "metadata": {
                        "name": source + "-source",
                        "uid": row.ca_sources[source],
                        "labels": {JOB_UID: str(row.ca_attempt)},
                    },
                    "spec": {"resources": {"requests": {"storage": "1Mi"}}},
                },
            )
            clones[member] = f.remote.create(body=body)["metadata"]["uid"]
        row.ca_clones = clones
    f.row = await row_for(f.h, f.row.session_id)
    f.states = EgressStateRepository(f.repo)
    resources = EgressStatePublication(
        settings, f.h.sessions, f.states, EgressStateAdapter(f.adapter.kube)
    )
    f.state = await resources.prepare(f.row, f.intent.generation, storage_bytes=1024**3)
    f.service = EgressComputePublication(settings, f.h.sessions, f.repo, f.compute)
    f.runtime = egress_runtime
    f.remote.created.clear()
    f.remote.started.clear()
    f.remote.finished.clear()
    yield f
    f.remote.release.set()
    await f.service.drain()
    await resources.drain()
    async with f.h.sessions.begin() as db:
        await db.execute(delete(EgressState))


async def prepare(f):
    return await f.service.prepare(f.row, f.intent.generation, f.runtime)


async def test_payload_reservation_commits_before_unlocked_io_and_no_ready(publication):
    f, seen = publication, []
    original = f.compute.create

    async def create(pair, role, payload, controls):
        async with asyncio.timeout(5), f.h.sessions.begin() as db:
            row = await db.get(SandboxSession, f.row.session_id, with_for_update=True)
            intent = await f.repo.snapshot(db, pair.generation)
            assert row.status == "creating"
            assert payload == intent.compute_payloads["egress"]
            assert controls == intent.control_uids == payload["control_uids"]
            assert intent.compute_dispatch["Pod/egress"] == "inflight"
            assert intent.compute_uids["Pod/egress"] is None
            assert payload["state"] == state_snapshot(f.state)
            environment = {
                entry["name"]: entry
                for entry in payload["manifest"]["spec"]["containers"][0]["env"]
            }
            assert (
                environment["ADS_SANDBOX_EGRESS_WRAPPING_KEY_B64"]["valueFrom"]["secretKeyRef"][
                    "key"
                ]
                == "wrapping.b64"
            )
            seen.append(role)
        return await original(pair, role, payload, controls)

    f.compute.create = create
    first = await prepare(f)
    assert seen == ["egress"]
    assert first.compute_dispatch["Pod/egress"] == "settled"
    assert first.compute_uids["Pod/egress"] == pod(f, "egress")["metadata"]["uid"]
    assert (await row_for(f.h, f.row.session_id)).status == "creating"
    f.service = EgressComputePublication(f.h.settings, f.h.sessions, f.repo, f.compute)
    second = await prepare(f)
    assert second.compute_payloads == first.compute_payloads
    assert second.compute_uids == first.compute_uids
    assert len(f.remote.created) == 1 and not f.h.kube.calls


async def test_concurrent_creators_share_one_original_write(publication):
    f = publication
    left, right = await asyncio.gather(prepare(f), prepare(f))
    assert left.compute_uids == right.compute_uids
    assert len(f.remote.created) == 1


@pytest.mark.parametrize("fault", ["lost-reply", "settlement", "binding"])
async def test_failed_write_or_commit_never_reissues_or_forges_settlement(publication, fault):
    f = publication
    method = "settle_compute" if fault == "settlement" else "bind_compute"
    original = getattr(f.repo, method)

    async def fail(*args):
        await original(*args)
        raise RuntimeError("commit failed")

    if fault == "lost-reply":
        f.remote.lost_reply = True
    else:
        setattr(f.repo, method, fail)
    with pytest.raises((RuntimeError, TimeoutError)):
        await prepare(f)
    before = await snapshot(f, f.intent.generation)
    assert before.compute_uids["Pod/egress"] is None
    assert before.compute_dispatch["Pod/egress"] == (
        "settled" if fault == "binding" else "inflight"
    )
    setattr(f.repo, method, original)
    after = await prepare(f)
    assert after.compute_payloads == before.compute_payloads
    assert after.compute_dispatch == before.compute_dispatch
    assert after.compute_uids["Pod/egress"]
    assert len(f.remote.created) == 1


@pytest.mark.parametrize("cancel_writer", [False, True])
async def test_cancellation_cleanup_owns_late_pod_without_release(publication, cancel_writer):
    f = publication
    f.remote.delay = True
    task = asyncio.create_task(prepare(f))
    try:
        assert await asyncio.to_thread(f.remote.started.wait, 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        operations = tuple(f.service.writes._dispatches)
        assert len(operations) == 1
        if cancel_writer:
            operations[0].cancel()
            await asyncio.gather(*operations, return_exceptions=True)
        capture, work, claim = await cleanup_claim(f)
        await capture.capture(work, recovery=claim)
        first = await saved(f, work)
        assert first.pair_snapshot["compute_uids"]["Pod/egress"] is None
        assert first.pair_snapshot["compute_payloads"]["egress"] is not None
        assert first.pair_snapshot["egress_state"] == state_snapshot(f.state)
        f.remote.release.set()
        assert await asyncio.to_thread(f.remote.finished.wait, 5)
        await f.service.drain()
        await capture.capture(work, recovery=claim)
        second = await saved(f, work)
        assert (
            second.pair_snapshot["compute_uids"]["Pod/egress"]
            == pod(f, "egress")["metadata"]["uid"]
        )
        current = await snapshot(f, f.intent.generation)
        assert current.creation_fenced and current.compute_uids["Pod/egress"] is None
        assert current.compute_dispatch["Pod/egress"] == (
            "inflight" if cancel_writer else "settled"
        )
        # Compute dispatch is retained in PairIntent, not copied into CleanupWork.
        assert second.pair_snapshot["compute_payloads"] == first.pair_snapshot["compute_payloads"]
        async with f.h.sessions.begin() as db:
            assert not await capture.repository.complete(db, second, datetime.now(UTC))
        assert len(f.remote.created) == 1
        with pytest.raises(PairClaimLost):
            await prepare(f)
    finally:
        f.remote.release.set()
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize("target", ["control", "state-key", "state-volume", "ca-egress", "ca-key"])
@pytest.mark.parametrize("fault", ["absent", "uid", "labels", "deleting", "spec"])
async def test_dependency_drift_cannot_publish_or_repair(publication, target, fault):
    f = publication
    if target == "control":
        key = next(k for k in f.remote.objects if k[0] == "Service")
    elif target.startswith("state-"):
        role = target.removeprefix("state-")
        key = (
            "Secret" if role == "key" else "PersistentVolumeClaim",
            identity(f.state, role)["metadata"]["name"],
        )
    else:
        key = (
            "PersistentVolumeClaim",
            ca_consumer_name(f.row.sandbox_id, target.removeprefix("ca-")),
        )
    obj = f.remote.objects[key]
    if fault == "absent":
        del f.remote.objects[key]
    elif fault == "uid":
        obj["metadata"]["uid"] = str(uuid4())
    elif fault == "labels":
        obj["metadata"]["labels"] = {}
    elif fault == "deleting":
        obj["metadata"]["deletionTimestamp"] = "now"
    elif key[0] == "Service":
        obj["spec"]["externalIPs"] = ["1.2.3.4"]
    elif key[0] == "Secret":
        obj["data"] = {"wrapping.b64": "malformed"}
    else:
        obj["spec"]["volumeMode"] = "Filesystem"
    with pytest.raises((RuntimeError, ValueError)):
        await prepare(f)
    assert not f.remote.created
    current = await snapshot(f, f.intent.generation)
    assert current.compute_dispatch["Pod/egress"] == "inflight"
    assert current.compute_uids["Pod/egress"] is None


@pytest.mark.parametrize("fault", ["absent", "uid", "annotations", "spec", "owner"])
async def test_bound_egress_pod_is_not_recreated_or_adopted(publication, fault):
    f = publication
    before = await prepare(f)
    obj = pod(f, "egress")
    if fault == "absent":
        del f.remote.objects[("Pod", obj["metadata"]["name"])]
    elif fault == "uid":
        obj["metadata"]["uid"] = str(uuid4())
    elif fault == "annotations":
        obj["metadata"]["annotations"] = {"hook": "foreign"}
    elif fault == "spec":
        obj["spec"]["containers"][0]["env"].append({"name": "FOREIGN", "value": "authority"})
    else:
        obj["metadata"]["ownerReferences"] = [{"uid": "foreign"}]
    with pytest.raises(RuntimeError):
        await prepare(f)
    after = await snapshot(f, f.intent.generation)
    assert after.compute_payloads == before.compute_payloads
    assert after.compute_uids == before.compute_uids
    assert len(f.remote.created) == 1


@pytest.mark.parametrize(
    "fault", ["anchor", "state", "key_uid", "volume_uid", "fingerprint", "ca", "source"]
)
async def test_sql_dependency_drift_after_io_cannot_bind(publication, fault):
    f, original = publication, publication.compute.create

    async def create(*args):
        uid = await original(*args)
        async with f.h.sessions.begin() as db:
            state = await db.get(EgressState, f.state.state_id)
            if fault == "anchor":
                intent = await db.get(PairIntent, f.intent.generation)
                intent.egress_state_id = uuid4()
            elif fault == "state":
                await db.delete(state)
            elif fault in ("key_uid", "volume_uid"):
                setattr(state, fault, str(uuid4()))
            elif fault == "fingerprint":
                state.key_fingerprint = "f" * 64
            else:
                row = await db.get(SandboxSession, f.row.session_id)
                if fault == "ca":
                    row.ca_clones = {**row.ca_clones, "key": str(uuid4())}
                else:
                    row.ca_sources = {**row.ca_sources, "private": str(uuid4())}
        return uid

    f.compute.create = create
    with pytest.raises((PairClaimLost, RuntimeError)):
        await prepare(f)
    current = await snapshot(f, f.intent.generation)
    assert current.compute_uids["Pod/egress"] is None
    assert current.compute_dispatch["Pod/egress"] == "settled"
    assert len(f.remote.created) == 1


async def test_custody_drift_during_pod_read_fails_observation(publication):
    f = publication
    await prepare(f)
    original = f.adapter.kube.core.read_namespaced_pod.side_effect

    def read(*args, **kwargs):
        result = original(*args, **kwargs)
        del f.remote.objects[("Secret", identity(f.state, "key")["metadata"]["name"])]
        return result

    f.adapter.kube.core.read_namespaced_pod.side_effect = read
    with pytest.raises(RuntimeError, match="disappeared"):
        await prepare(f)
    assert len(f.remote.created) == 1


@pytest.mark.parametrize("fault", ["mtu", "runtime", "lost-volume"])
async def test_transport_contract_and_lost_storage_fail_closed(publication, fault):
    f = publication
    if fault == "mtu":
        f.runtime = replace(f.runtime, transport_mtu=1500)
    elif fault == "runtime":
        f.runtime = replace(f.runtime, runtime_class=f.guest.runtime_class)
    else:
        obj = f.remote.objects[
            ("PersistentVolumeClaim", identity(f.state, "volume")["metadata"]["name"])
        ]
        obj["status"] = {"phase": "Lost"}
    with pytest.raises((RuntimeError, ValueError)):
        await prepare(f)
    assert not f.remote.created


@pytest.mark.parametrize("fault", ["extra", "state", "subject", "ca", "manifest"])
async def test_committed_payload_exact_shape_and_manifest(publication, fault):
    f = publication
    result = await prepare(f)
    payload = deepcopy(result.compute_payloads["egress"])
    if fault == "extra":
        payload["credential"] = "not-allowed"
    elif fault == "state":
        payload["state"]["volume_uid"] = None
    elif fault == "subject":
        payload["runtime"]["ipc_service_subject"] = "bad"
    elif fault == "ca":
        payload["ca_clones"]["key"] = ""
    else:
        payload["manifest"]["spec"]["hostNetwork"] = True
    with pytest.raises((RuntimeError, ValueError)):
        validate_payload("egress", payload)
        compute_manifest(f.h.settings, result.binding(), "egress", payload)
    assert len(f.remote.created) == 1


async def test_changed_trusted_runtime_cannot_rewrite_committed_pod(publication):
    f = publication
    before = await prepare(f)
    f.runtime = replace(f.runtime, cpu_millis=2000)
    with pytest.raises(RuntimeError, match="payload changed"):
        await prepare(f)
    assert (await snapshot(f, f.intent.generation)).compute_payloads == before.compute_payloads
    assert len(f.remote.created) == 1


async def test_missing_anchor_cannot_reserve_or_generate_anything(publication):
    f = publication
    async with f.h.sessions.begin() as db:
        intent = await db.get(PairIntent, f.intent.generation)
        intent.egress_state_id = None
    with pytest.raises(PairClaimLost, match="anchor"):
        await prepare(f)
    assert not f.remote.created


async def test_payload_requires_complete_nonempty_ca_evidence(publication):
    f = publication
    f.row.ca_sources = {"public": ""}
    with pytest.raises(ValueError, match="CA identities"):
        egress_payload(f.row, f.state, f.runtime)
