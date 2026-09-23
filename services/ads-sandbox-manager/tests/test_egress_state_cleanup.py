# ruff: noqa: F811
from __future__ import annotations

import json
from copy import deepcopy
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from kubernetes.client.exceptions import ApiException
from sqlalchemy import delete, update

from ads_sandbox_manager.egress_state_kube import key_secret, state_volume
from ads_sandbox_manager.egress_state_objects import identity
from ads_sandbox_manager.egress_state_store import (
    EgressState,
    EgressStateRepository,
    state_from_snapshot,
    state_snapshot,
)
from ads_sandbox_manager.pair_store import PairClaimLost, PairIntent
from ads_sandbox_manager.store import SandboxSession
from test_kube_release import api  # noqa: F401
from test_pair_controls import controls  # noqa: F401
from test_pair_creator_fence import cleanup_claim
from test_pair_store import begin, ledger  # noqa: F401
from test_relay_custody_cleanup import saved
from test_session_objects import object_settings  # noqa: F401
from test_sessions import sessions_harness  # noqa: F401

pytestmark = pytest.mark.anyio


@pytest.fixture
async def persistent(controls):
    f = controls
    async with f.h.sessions.begin() as db:
        await db.execute(delete(EgressState))
    f.pair = await begin(f)
    f.states = EgressStateRepository(f.repo)
    async with f.h.sessions.begin() as db:
        f.state, f.key = await f.states.reserve(
            db, f.row, f.owner, f.pair.generation, storage_bytes=1024**3
        )
    body = key_secret(f.state, f.key)
    body["metadata"].update(uid="wrapping-uid", resourceVersion="1")
    f.resources = {body["metadata"]["name"]: body}

    def read(name, namespace, **kwargs):
        assert namespace == f.state.namespace
        if name not in f.resources:
            raise ApiException(status=404)
        return deepcopy(f.resources[name])

    f.adapter.kube.core.read_namespaced_secret.side_effect = read
    f.adapter.kube.core.read_namespaced_persistent_volume_claim.side_effect = read
    yield f
    async with f.h.sessions.begin() as db:
        await db.execute(delete(EgressState))


async def reserve_volume(f, *, bind=False):
    async with f.h.sessions.begin() as db:
        f.state = await f.states.bind(
            db, f.row, f.owner, f.pair.generation, f.state.state_id, "key", "wrapping-uid"
        )
        await f.states.settle(db, f.state, "key")
        f.state, dispatched = await f.states.reserve_volume(
            db, f.row, f.owner, f.pair.generation, f.state.state_id
        )
        assert dispatched
        if bind:
            f.state = await f.states.bind(
                db, f.row, f.owner, f.pair.generation, f.state.state_id, "volume", "state-pvc-uid"
            )
    body = state_volume(f.state)
    body["metadata"].update(uid="state-pvc-uid", resourceVersion="1")
    f.resources[body["metadata"]["name"]] = body


@pytest.mark.parametrize("volume", [False, True])
async def test_capture_commits_nonsecret_uid_only_after_fence_and_outside_sql(persistent, volume):
    f = persistent
    if volume:
        await reserve_volume(f)
    capture, work, claim = await cleanup_claim(f)
    initial = deepcopy(work.pair_snapshot["egress_state"])
    steps = []
    original = f.adapter.observe_egress_state

    async def observe(snapshot, role, uid):
        async with f.h.sessions.begin() as db:
            await db.get(SandboxSession, claim.session_id, with_for_update=True)
            pair = await db.get(PairIntent, f.pair.generation)
            assert pair.creation_fenced
            current = await saved(f, work)
            if role == "volume":
                assert current.pair_snapshot["egress_state"]["key_uid"] == "wrapping-uid"
        steps.append(role)
        return await original(snapshot, role, uid)

    f.adapter.observe_egress_state = observe
    await capture.capture(work, recovery=claim)
    current = await saved(f, work)
    stored = current.pair_snapshot["egress_state"]
    assert stored["key_uid"] == "wrapping-uid"
    assert stored["volume_uid"] == ("state-pvc-uid" if volume else None)
    assert steps == (["key", "volume"] if volume else ["key"])
    for role in ("key", "volume"):
        assert stored[f"{role}_dispatch"] == initial[f"{role}_dispatch"]
    assert f.key.value.hex() not in json.dumps(stored)
    assert not {"data", "value", "private_key"}.intersection(stored)
    async with f.h.sessions.begin() as db:
        assert not await capture.repository.complete(db, current, datetime.now(UTC))
    f.adapter.kube.core.create_namespaced_secret.assert_not_called()
    f.adapter.kube.core.delete_namespaced_secret.assert_not_called()
    f.adapter.kube.core.create_namespaced_persistent_volume_claim.assert_not_called()
    f.adapter.kube.core.delete_namespaced_persistent_volume_claim.assert_not_called()


async def test_absence_keeps_known_uids_and_late_creation_remains_captureable(persistent):
    f = persistent
    await reserve_volume(f)
    capture, work, claim = await cleanup_claim(f)
    resources = f.resources
    f.resources = {}
    await capture.capture(work, recovery=claim)
    current = await saved(f, work)
    assert current.pair_snapshot["egress_state"]["key_uid"] == "wrapping-uid"
    assert current.pair_snapshot["egress_state"]["volume_uid"] is None
    f.resources = resources
    await capture.capture(current, recovery=claim)
    current = await saved(f, work)
    assert current.pair_snapshot["egress_state"]["volume_uid"] == "state-pvc-uid"
    f.resources = {}
    await capture.capture(current, recovery=claim)
    assert (await saved(f, work)).pair_snapshot == current.pair_snapshot
    assert current.pair_snapshot["egress_state"]["volume_dispatch"] == "inflight"


async def test_owned_deleting_corrupt_resources_are_cleanup_obligations_not_loaded(persistent):
    f = persistent
    await reserve_volume(f)
    for body in f.resources.values():
        body["metadata"]["deletionTimestamp"] = "now"
        if body["kind"] == "Secret":
            body["data"] = {"anything": "deliberately not a key"}
            body["immutable"] = False
        else:
            body["spec"] = {"volumeMode": "Filesystem"}
    capture, work, claim = await cleanup_claim(f)
    await capture.capture(work, recovery=claim)
    state = (await saved(f, work)).pair_snapshot["egress_state"]
    assert state["key_uid"] == "wrapping-uid" and state["volume_uid"] == "state-pvc-uid"
    assert "anything" not in json.dumps(state)


@pytest.mark.parametrize("role", ["key", "volume"])
async def test_replacement_uid_is_not_adopted(persistent, role):
    f = persistent
    await reserve_volume(f, bind=True)
    f.resources[identity(f.state, role)["metadata"]["name"]]["metadata"]["uid"] = "foreign"
    capture, work, claim = await cleanup_claim(f)
    with pytest.raises(RuntimeError, match="foreign, replaced"):
        await capture.capture(work, recovery=claim)
    assert (await saved(f, work)).pair_snapshot["egress_state"][f"{role}_uid"] != "foreign"


@pytest.mark.parametrize(
    "field", ["project_id", "key_fingerprint", "storage_bytes", "claim_owner", "creator_generation"]
)
async def test_drifted_reservation_is_rejected_before_external_capture(persistent, field):
    f = persistent
    capture, work, claim = await cleanup_claim(f)
    changes = {
        "project_id": uuid4(),
        "key_fingerprint": "0" * 64,
        "storage_bytes": 4096,
        "claim_owner": uuid4(),
        "creator_generation": uuid4(),
    }
    async with f.h.sessions.begin() as db:
        await db.execute(
            update(EgressState)
            .where(EgressState.state_id == f.state.state_id)
            .values(**{field: changes[field]})
        )
    with pytest.raises(PairClaimLost):
        await capture.capture(work, recovery=claim)
    f.adapter.kube.core.read_namespaced_secret.assert_not_called()


@pytest.mark.parametrize("fault", ["claim", "state", "missing-state"])
async def test_claim_and_state_are_revalidated_after_external_read(persistent, fault):
    f = persistent
    capture, work, claim = await cleanup_claim(f)
    original = f.adapter.observe_egress_state

    async def observe(*args):
        uid = await original(*args)
        async with f.h.sessions.begin() as db:
            if fault == "claim":
                row = await db.get(SandboxSession, claim.session_id)
                row.sandbox_id = uuid4()
            elif fault == "state":
                state = await db.get(EgressState, f.state.state_id)
                state.key_fingerprint = "f" * 64
            else:
                await db.execute(
                    delete(EgressState).where(EgressState.state_id == f.state.state_id)
                )
        return uid

    f.adapter.observe_egress_state = observe
    with pytest.raises(PairClaimLost):
        await capture.capture(work, recovery=claim)
    assert (await saved(f, work)).pair_snapshot["egress_state"]["key_uid"] is None


async def test_late_original_completion_is_allowed_but_observation_never_settles(persistent):
    f = persistent
    capture, work, claim = await cleanup_claim(f)
    async with f.h.sessions.begin() as db:
        await f.states.settle(db, f.state, "key")
    await capture.capture(work, recovery=claim)
    current = await saved(f, work)
    assert current.pair_snapshot["egress_state"]["key_dispatch"] == "inflight"
    async with f.h.sessions.begin() as db:
        state = await db.get(EgressState, f.state.state_id)
        assert state.key_dispatch == "settled" and state.key_uid is None
        assert not await capture.repository.complete(db, current, datetime.now(UTC))


async def test_dispatch_regression_or_new_dispatch_after_capture_is_refused(persistent):
    f = persistent
    await reserve_volume(f)
    capture, work, claim = await cleanup_claim(f)
    async with f.h.sessions.begin() as db:
        state = await db.get(EgressState, f.state.state_id)
        state.volume_dispatch = "unissued"
    with pytest.raises(PairClaimLost, match="dispatch changed"):
        await capture.capture(work, recovery=claim)


async def test_recording_is_stale_work_fenced_and_never_replaces_uid(persistent):
    f = persistent
    capture, work, claim = await cleanup_claim(f)
    await capture.capture(work, recovery=claim)
    current = await saved(f, work)
    with pytest.raises(PairClaimLost, match="work changed"):
        async with f.h.sessions.begin() as db:
            await capture.repository.record_egress_state(
                db,
                work,
                "key",
                "wrapping-uid",
                datetime.now(UTC),
                recovery=claim,
                recovery_seconds=120,
            )
    with pytest.raises(RuntimeError, match="replacement"):
        async with f.h.sessions.begin() as db:
            await capture.repository.record_egress_state(
                db,
                current,
                "key",
                "foreign",
                datetime.now(UTC),
                recovery=claim,
                recovery_seconds=120,
            )
    with pytest.raises(RuntimeError, match="never dispatched"):
        async with f.h.sessions.begin() as db:
            await capture.repository.record_egress_state(
                db,
                current,
                "volume",
                "foreign",
                datetime.now(UTC),
                recovery=claim,
                recovery_seconds=120,
            )


async def test_snapshot_roundtrip_keeps_only_typed_nonsecret_fields(persistent):
    value = state_snapshot(persistent.state)
    assert state_snapshot(state_from_snapshot(value)) == value
    assert value["state_id"] == str(persistent.state.state_id)
    assert value["claim_changed"] == persistent.state.claim_changed.isoformat()


@pytest.mark.parametrize(
    "change",
    [
        {"state_id": 42},
        {"state_id": "bad"},
        {"claim_changed": "bad"},
        {"claim_changed": "2026-01-01T00:00:00"},
        {"claim_changed": "2026-01-01T00:00:00Z"},
        {"private_key": "not permitted"},
        {"volume_dispatch": "inflight"},
    ],
)
async def test_corrupt_snapshot_cannot_be_repaired_or_read(persistent, change):
    value = {**state_snapshot(persistent.state), **change}
    with pytest.raises(RuntimeError):
        state_from_snapshot(value)
    with pytest.raises(RuntimeError):
        await persistent.adapter.observe_egress_state(value, "key", None)
    persistent.adapter.kube.core.read_namespaced_secret.assert_not_called()


async def test_cleanup_api_error_is_redacted_and_does_not_record_absence(persistent):
    f = persistent
    capture, work, claim = await cleanup_claim(f)
    f.adapter.kube.core.read_namespaced_secret.side_effect = ApiException(
        status=500, reason="private-material"
    )
    with pytest.raises(RuntimeError, match="observation failed") as error:
        await capture.capture(work, recovery=claim)
    assert "private-material" not in str(error.value)
    assert (await saved(f, work)).pair_snapshot["egress_state"]["key_uid"] is None


async def test_unexpected_creator_uid_after_snapshot_is_not_a_capture_update(persistent):
    f = persistent
    capture, work, claim = await cleanup_claim(f)
    async with f.h.sessions.begin() as db:
        state = await db.get(EgressState, f.state.state_id)
        state.key_uid = "unexpected-late-binding"
    with pytest.raises(PairClaimLost, match="UID changed"):
        await capture.capture(work, recovery=claim)
    assert (await saved(f, work)).pair_snapshot["egress_state"]["key_uid"] is None


@pytest.mark.parametrize("field", ["session_id", "project_id", "namespace", "creator_generation"])
async def test_cleanup_snapshot_scope_cannot_point_at_another_reservation(persistent, field):
    f = persistent
    capture, work, _ = await cleanup_claim(f)
    value = deepcopy(work.pair_snapshot)
    value["egress_state"][field] = "other-namespace" if field == "namespace" else str(uuid4())
    work.pair_snapshot = value
    with pytest.raises(RuntimeError, match="state identity changed"):
        capture.repository.cleanup_pair(work)


@pytest.mark.parametrize("fault", ["role", "uid", "namespace"])
async def test_invalid_metadata_observation_never_reads_api(persistent, fault):
    f = persistent
    snapshot, role, uid = state_snapshot(f.state), "key", None
    if fault == "role":
        role = "guest"
    elif fault == "uid":
        uid = ""
    else:
        snapshot["namespace"] = "other-namespace"
    with pytest.raises((RuntimeError, ValueError)):
        await f.adapter.observe_egress_state(snapshot, role, uid)
    f.adapter.kube.core.read_namespaced_secret.assert_not_called()


@pytest.mark.parametrize("fault", ["role", "uid"])
async def test_invalid_capture_record_is_rejected_before_transaction_use(persistent, fault):
    f = persistent
    capture, work, claim = await cleanup_claim(f)
    with pytest.raises(ValueError):
        async with f.h.sessions.begin() as db:
            await capture.repository.record_egress_state(
                db,
                work,
                "guest" if fault == "role" else "key",
                "" if fault == "uid" else None,
                datetime.now(UTC),
                recovery=claim,
                recovery_seconds=120,
            )
