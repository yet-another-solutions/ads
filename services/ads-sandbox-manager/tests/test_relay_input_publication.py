# ruff: noqa: F811
from __future__ import annotations

import asyncio
import base64
import json
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from functools import partial
from unittest.mock import patch
from uuid import uuid4

import pytest
from kubernetes.client.exceptions import ApiException

from ads_sandbox_manager.pair_compute import relay_pod
from ads_sandbox_manager.pair_kube import PairControlAdapter
from ads_sandbox_manager.pair_objects import control_service
from ads_sandbox_manager.pair_store import PairClaimLost, PairIntent
from ads_sandbox_manager.relay_input_kube import RelayInputAdapter
from ads_sandbox_manager.relay_input_publication import RelayInputPublication
from ads_sandbox_manager.relay_inputs import INPUT_ROLES, input_identity
from ads_sandbox_manager.relay_keys import RelayKeys, custody_secret
from ads_sandbox_manager.store import SandboxSession
from test_kube_release import api  # noqa: F401
from test_pair_controls import MemoryControlApi
from test_pair_creator_fence import cleanup_claim
from test_pair_relay_compute import runtime  # noqa: F401
from test_pair_store import begin, ledger, snapshot  # noqa: F401
from test_relay_custody_cleanup import saved
from test_session_objects import object_settings  # noqa: F401
from test_sessions import row_for, sessions_harness  # noqa: F401

pytestmark = pytest.mark.anyio


@pytest.fixture
async def publication(ledger, api, runtime):
    f = ledger
    f.h.settings = replace(f.h.settings, control_seconds=10)
    api.settings = f.h.settings
    f.adapter = PairControlAdapter(api)
    f.remote = MemoryControlApi(f.adapter)
    api.core.read_namespaced_secret.side_effect = partial(f.remote.read, "Secret")
    api.core.create_namespaced_secret.side_effect = f.remote.create
    f.inputs = RelayInputAdapter(api)
    f.service = RelayInputPublication(f.h.settings, f.h.sessions, f.repo, f.inputs)
    f.runtime = runtime
    f.intent = await begin(f)
    f.keys = RelayKeys.generate()
    pair = f.intent.binding()
    custody = custody_secret(f.h.settings, pair, f.keys)
    f.remote.create(body=custody)
    custody = f.remote.read("Secret", custody["metadata"]["name"])
    service = control_service(f.h.settings, pair, "egress-relay")
    f.remote.create(body=service)
    service = f.remote.read("Service", service["metadata"]["name"])
    async with f.h.sessions.begin() as db:
        await f.repo.reserve_relay_keys(db, f.row, f.owner, pair.generation, f.keys.public_keys())
        await f.repo.bind_relay_keys(
            db, f.row, f.owner, pair.generation, custody["metadata"]["uid"]
        )
        await f.repo.bind(
            db,
            f.row,
            f.owner,
            pair.generation,
            "Service",
            "egress-relay",
            service["metadata"]["uid"],
        )
        for role in INPUT_ROLES:
            pod = relay_pod(f.h.settings, pair, role, runtime)
            f.remote.create(body=pod)
            pod = f.remote.read("Pod", pod["metadata"]["name"])
            await f.repo.bind_compute(
                db, f.row, f.owner, pair.generation, role, pod["metadata"]["uid"]
            )
    f.remote.created.clear()
    yield f
    f.remote.release.set()


async def publish(f):
    return await f.service.prepare(f.row, f.intent.generation, f.runtime)


def remote_input(f, role="guest-relay"):
    name = input_identity(f.h.settings, f.intent.binding(), role)["metadata"]["name"]
    return f.remote.objects[("Secret", name)]


async def test_committed_payload_precedes_io_and_each_relay_gets_only_its_key(publication):
    f = publication
    original = f.inputs.create
    seen = []

    async def create(pair, role, payload):
        async with f.h.sessions.begin() as db:
            await db.get(SandboxSession, f.row.session_id, with_for_update=True)
            intent = await f.repo.snapshot(db, pair.generation)
            assert intent.relay_inputs[role] == {
                "payload": payload,
                "uid": None,
                "dispatch": "inflight",
            }
            assert payload["pod_uids"] == {r: intent.compute_uids[f"Pod/{r}"] for r in INPUT_ROLES}
            assert payload["service_uid"] == intent.control_uids["Service/egress-relay"]
            assert payload["custody_uid"] == intent.relay_custody["uid"]
        seen.append(role)
        return await original(pair, role, payload)

    f.inputs.create = create
    result = await publish(f)
    assert seen == list(INPUT_ROLES) and len(f.remote.created) == 2
    for role in INPUT_ROLES:
        entry = result.relay_inputs[role]
        body = remote_input(f, role)
        assert entry["uid"] == body["metadata"]["uid"] and entry["dispatch"] == "settled"
        assert body["immutable"] is True and body["type"] == "Opaque"
        assert set(body["data"]) == {"config.json", "wg.key"}
        assert body["data"]["wg.key"] == f.keys.secret_data()[role.removesuffix("-relay") + ".key"]
        assert (
            json.loads(base64.b64decode(body["data"]["config.json"]))
            == entry["payload"]["configuration"]
        )
        assert body["data"]["wg.key"] not in json.dumps(result.relay_inputs)
    assert (await row_for(f.h, f.row.session_id)).status == "creating"


async def test_concurrent_and_restarted_publish_never_create_twice_or_regenerate(publication):
    f = publication
    with patch.object(RelayKeys, "generate", side_effect=AssertionError("must not regenerate")):
        results = await asyncio.gather(*(publish(f) for _ in range(6)))
        f.service = RelayInputPublication(f.h.settings, f.h.sessions, type(f.repo)(), f.inputs)
        restarted = await publish(f)
    assert all(r.relay_inputs == restarted.relay_inputs for r in results)
    assert len(f.remote.created) == 2


@pytest.mark.parametrize("target", ["pod", "service", "custody"])
@pytest.mark.parametrize("mutation", ["uid", "labels", "deleting", "absent"])
async def test_dependency_identity_replacement_or_loss_blocks_publication(
    publication, target, mutation
):
    f = publication
    kind = {"pod": "Pod", "service": "Service", "custody": "Secret"}[target]
    key = next(k for k in f.remote.objects if k[0] == kind)
    body = f.remote.objects[key]
    if mutation == "absent":
        del f.remote.objects[key]
    elif mutation == "deleting":
        body["metadata"]["deletionTimestamp"] = "now"
    elif mutation == "labels":
        body["metadata"]["labels"] = {}
    else:
        body["metadata"]["uid"] = str(uuid4())
    with pytest.raises(RuntimeError):
        await publish(f)
    assert not f.remote.created


@pytest.mark.parametrize("mutation", ["selector", "ports", "externalIPs", "ipv6", "owner"])
async def test_service_must_be_exact_and_numeric_ipv4(publication, mutation):
    f = publication
    body = next(v for k, v in f.remote.objects.items() if k[0] == "Service")
    if mutation == "owner":
        body["metadata"]["ownerReferences"] = [{"uid": "foreign"}]
    elif mutation == "ipv6":
        body["spec"]["clusterIP"] = "2001:db8::1"
    else:
        body["spec"][mutation] = [] if mutation == "ports" else {"foreign": "value"}
    with pytest.raises((ValueError, RuntimeError)):
        await publish(f)
    assert not f.remote.created


@pytest.mark.parametrize("mutation", ["uid", "mutable", "data", "extra", "stringData", "deleting"])
async def test_restart_rejects_changed_inputs_without_patch_or_recreate(publication, mutation):
    f = publication
    await publish(f)
    body = remote_input(f)
    if mutation == "uid":
        body["metadata"]["uid"] = str(uuid4())
    elif mutation == "mutable":
        body["immutable"] = False
    elif mutation == "data":
        body["data"]["wg.key"] = f.keys.secret_data()["egress.key"]
    elif mutation == "extra":
        body["data"]["foreign"] = "value"
    elif mutation == "stringData":
        body["stringData"] = {"injected": "value"}
    else:
        body["metadata"]["deletionTimestamp"] = "now"
    with pytest.raises(RuntimeError):
        await publish(f)
    assert len(f.remote.created) == 2
    f.adapter.kube.core.patch_namespaced_secret.assert_not_called()


async def test_runtime_and_service_address_drift_cannot_change_committed_payload(publication):
    f = publication
    before = await publish(f)
    with pytest.raises(RuntimeError, match="runtime changed"):
        await f.service.prepare(f.row, f.intent.generation, replace(f.runtime, packet_rate=200))
    service = next(v for k, v in f.remote.objects.items() if k[0] == "Service")
    service["spec"]["clusterIP"] = "10.2.3.5"
    with pytest.raises(RuntimeError, match="address changed"):
        await publish(f)
    assert (await snapshot(f, f.intent.generation)).relay_inputs == before.relay_inputs
    assert len(f.remote.created) == 2


async def test_lost_reply_remains_inflight_even_after_restart_observation(publication):
    f = publication
    f.remote.lost_reply = True
    with pytest.raises(RuntimeError, match="create failed"):
        await publish(f)
    intent = await snapshot(f, f.intent.generation)
    assert intent.relay_inputs["guest-relay"]["dispatch"] == "inflight"
    assert intent.relay_inputs["guest-relay"]["uid"] is None
    result = await publish(f)
    assert result.relay_inputs["guest-relay"]["dispatch"] == "inflight"
    assert result.relay_inputs["guest-relay"]["uid"] == remote_input(f)["metadata"]["uid"]
    assert len(f.remote.created) == 2


async def test_failed_settlement_remains_inflight_and_observers_never_clear_it(publication):
    f = publication
    original = f.repo.settle_relay_input

    async def fail(*args):
        raise RuntimeError("settlement failed")

    f.repo.settle_relay_input = fail
    with pytest.raises(RuntimeError, match="settlement failed"):
        await publish(f)
    f.repo.settle_relay_input = original
    result = await publish(f)
    assert result.relay_inputs["guest-relay"]["dispatch"] == "inflight"
    assert result.relay_inputs["guest-relay"]["uid"]
    assert len(f.remote.created) == 2


async def test_cancelled_caller_retains_original_completion_without_advancing(publication):
    f = publication
    f.remote.delay = True
    task = asyncio.create_task(publish(f))
    try:
        assert await asyncio.to_thread(f.remote.started.wait, 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        f.remote.release.set()
        await f.service.drain()
        result = await snapshot(f, f.intent.generation)
        assert result.relay_inputs["guest-relay"]["dispatch"] == "settled"
        assert result.relay_inputs["guest-relay"]["uid"] is None
        assert result.relay_inputs["egress-relay"]["dispatch"] == "unissued"
        assert len(f.remote.created) == 1
    finally:
        f.remote.release.set()
        await asyncio.gather(task, return_exceptions=True)


async def test_cleanup_fences_then_captures_late_publication_without_retirement(publication):
    f = publication
    f.remote.delay = True
    task = asyncio.create_task(publish(f))
    try:
        assert await asyncio.to_thread(f.remote.started.wait, 5)
        capture, work, claim = await cleanup_claim(f)
        await capture.capture(work, recovery=claim)
        current = await saved(f, work)
        assert current.pair_snapshot["relay_inputs"]["guest-relay"]["uid"] is None
        assert (await snapshot(f, f.intent.generation)).creation_fenced
        f.remote.release.set()
        with pytest.raises(PairClaimLost):
            await task
        await capture.capture(current, recovery=claim)
        current = await saved(f, work)
        entry = current.pair_snapshot["relay_inputs"]["guest-relay"]
        assert entry["uid"] == remote_input(f)["metadata"]["uid"]
        assert entry["dispatch"] == "inflight"  # Snapshot does not forge settlement.
        assert len(f.remote.created) == 1
        # Lost API visibility never erases cleanup ownership.
        del f.remote.objects[("Secret", remote_input(f)["metadata"]["name"])]
        await capture.capture(current, recovery=claim)
        assert (await saved(f, work)).pair_snapshot == current.pair_snapshot
        f.adapter.kube.core.delete_namespaced_secret.assert_not_called()
    finally:
        f.remote.release.set()
        await asyncio.gather(task, return_exceptions=True)


async def test_claim_loss_during_dependency_observation_cannot_reserve_or_publish(publication):
    f = publication
    original = f.inputs.dependencies

    async def change(*args):
        result = await original(*args)
        async with f.h.sessions.begin() as db:
            row = await db.get(SandboxSession, f.row.session_id)
            row.claimed_by = uuid4()
        return result

    f.inputs.dependencies = change
    with pytest.raises(PairClaimLost):
        await publish(f)
    assert not f.remote.created
    assert all(
        entry["dispatch"] == "unissued"
        for entry in (await snapshot(f, f.intent.generation)).relay_inputs.values()
    )


@pytest.mark.parametrize("operation", ["read", "create", "cleanup"])
async def test_secret_sdk_errors_are_sanitized(publication, operation):
    f = publication
    await publish(f)
    entry = (await snapshot(f, f.intent.generation)).relay_inputs["guest-relay"]
    error = ApiException(status=403, reason="SENSITIVE")
    if operation == "create":
        f.adapter.kube.core.create_namespaced_secret.side_effect = error
    else:
        f.adapter.kube.core.read_namespaced_secret.side_effect = error
    with pytest.raises(RuntimeError) as raised:
        if operation == "create":
            await f.inputs.create(f.intent.binding(), "guest-relay", entry["payload"])
        elif operation == "read":
            await f.inputs.observe(
                f.intent.binding(), "guest-relay", entry["payload"], entry["uid"]
            )
        else:
            await f.adapter.observe_relay_input(f.intent.binding(), "guest-relay", entry["uid"])
    assert "SENSITIVE" not in str(raised.value)
    assert raised.value.__suppress_context__


@pytest.mark.parametrize("mutation", ["extra", "payload", "dispatch", "uid", "missing"])
async def test_corrupt_durable_input_evidence_is_not_repaired(publication, mutation):
    f = publication
    await publish(f)
    async with f.h.sessions.begin() as db:
        intent = await db.get(PairIntent, f.intent.generation)
        value = deepcopy(intent.relay_inputs)
        if mutation == "extra":
            value["foreign"] = {}
        elif mutation == "missing":
            del value["guest-relay"]
        elif mutation == "payload":
            value["guest-relay"]["payload"]["configuration"]["peer_key"] = "changed"
        else:
            value["guest-relay"][mutation] = False
        intent.relay_inputs = value
    with pytest.raises(RuntimeError, match="corrupt"):
        await publish(f)
    assert len(f.remote.created) == 2


async def test_bound_missing_input_is_never_recreated(publication):
    f = publication
    before = await publish(f)
    del f.remote.objects[("Secret", remote_input(f)["metadata"]["name"])]
    with pytest.raises(RuntimeError, match="disappeared"):
        await publish(f)
    assert (await snapshot(f, f.intent.generation)).relay_inputs == before.relay_inputs
    assert len(f.remote.created) == 2


async def test_early_absence_and_original_timeout_leave_inflight_obligation(publication):
    f = publication
    f.service.settings = replace(f.service.settings, control_seconds=0.1)
    f.remote.delay = True
    task = asyncio.create_task(publish(f))
    try:
        assert await asyncio.to_thread(f.remote.started.wait, 5)
        with pytest.raises(TimeoutError):
            await task
        before = await snapshot(f, f.intent.generation)
        assert before.relay_inputs["guest-relay"]["dispatch"] == "inflight"
        assert before.relay_inputs["guest-relay"]["uid"] is None
        assert not f.remote.created
        f.remote.release.set()
        assert await asyncio.to_thread(f.remote.finished.wait, 5)
        f.service.settings = f.h.settings
        result = await publish(f)
        assert result.relay_inputs["guest-relay"]["dispatch"] == "inflight"
        assert result.relay_inputs["guest-relay"]["uid"] == remote_input(f)["metadata"]["uid"]
        assert len(f.remote.created) == 2
    finally:
        f.remote.release.set()
        await asyncio.gather(task, return_exceptions=True)


async def test_cleanup_rechecks_claim_after_input_read(publication):
    f = publication
    f.remote.lost_reply = True
    with pytest.raises(RuntimeError):
        await publish(f)
    capture, work, claim = await cleanup_claim(f)
    original = f.adapter.observe_relay_input

    async def change(*args):
        result = await original(*args)
        async with f.h.sessions.begin() as db:
            row = await db.get(SandboxSession, claim.session_id)
            row.sandbox_id = uuid4()
        return result

    f.adapter.observe_relay_input = change
    with pytest.raises(PairClaimLost):
        await capture.capture(work, recovery=claim)
    assert (await saved(f, work)).pair_snapshot["relay_inputs"]["guest-relay"]["uid"] is None


async def test_cleanup_input_replacement_and_changed_payload_are_refused(publication):
    f = publication
    await publish(f)
    capture, work, claim = await cleanup_claim(f)
    remote_input(f)["metadata"]["uid"] = str(uuid4())
    with pytest.raises(RuntimeError, match="replaced"):
        await capture.capture(work, recovery=claim)
    async with f.h.sessions.begin() as db:
        intent = await db.get(PairIntent, f.intent.generation)
        entries = deepcopy(intent.relay_inputs)
        entries["guest-relay"]["payload"]["service_uid"] = "foreign"
        intent.relay_inputs = entries
    with pytest.raises(PairClaimLost, match="payload changed"):
        await capture.capture(work, recovery=claim)
    f.adapter.kube.core.delete_namespaced_secret.assert_not_called()


async def test_cleanup_complete_remains_blocked_with_all_input_uids_and_settled_writes(publication):
    f = publication
    await publish(f)
    capture, work, claim = await cleanup_claim(f)
    await capture.capture(work, recovery=claim)
    current = await saved(f, work)
    assert all(e["uid"] for e in current.pair_snapshot["relay_inputs"].values())
    async with f.h.sessions.begin() as db:
        assert not await capture.repository.complete(db, current, datetime.now(UTC))
    assert (await snapshot(f, f.intent.generation)).creation_fenced


@pytest.mark.parametrize(
    "change", ["namespace", "golden_version", "custody_uid", "pod_uid", "service_uid"]
)
async def test_committed_scope_cannot_be_reinterpreted(publication, change):
    f = publication
    await publish(f)
    async with f.h.sessions.begin() as db:
        intent = await db.get(PairIntent, f.intent.generation)
        if change in ("namespace", "golden_version"):
            setattr(intent, change, "foreign")
        elif change == "custody_uid":
            intent.relay_custody = {**intent.relay_custody, "uid": "foreign"}
        elif change == "pod_uid":
            intent.compute_uids = {**intent.compute_uids, "Pod/guest-relay": str(uuid4())}
        else:
            intent.control_uids = {**intent.control_uids, "Service/egress-relay": "foreign"}
    with pytest.raises(RuntimeError):
        await publish(f)
    assert len(f.remote.created) == 2
