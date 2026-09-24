# ruff: noqa: F811
from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from sqlalchemy import delete, inspect

from ads_sandbox_manager.lifecycle import IDLE, ORPHAN, RECOVER, Signal
from ads_sandbox_manager.lifecycle_store import CleanupWork, sandbox_targets
from ads_sandbox_manager.pair_store import (
    CONTROL_RESOURCES,
    PairIntent,
    new_compute_uids,
    resource_key,
)
from ads_sandbox_manager.store import SandboxSession, SessionPVC
from test_lifecycle import life, works  # noqa: F401
from test_ping_recovery import recovery
from test_session_objects import object_settings  # noqa: F401
from test_sessions import row_for, sessions_harness  # noqa: F401

pytestmark = pytest.mark.anyio


@pytest.fixture
async def paired(life):
    h = life
    # Runtime/compute are existing lifecycle fakes. Seed their captured pair
    # ownership; this fixture does not pretend the pair is live or fully ready.
    h.pair = PairIntent(
        generation=uuid4(),
        session_id=h.row.session_id,
        sandbox_id=h.row.sandbox_id,
        project_id=h.row.project_id,
        claim_owner=h.row.claimed_by,
        claim_changed=h.row.created_at,
        namespace=h.settings.namespace,
        golden_version=h.settings.golden_version,
        control_uids={
            resource_key(kind, role): "captured-uid" if index == 0 else None
            for index, (kind, role) in enumerate(CONTROL_RESOURCES)
        },
        compute_uids={**new_compute_uids(), "Pod/guest": "captured-guest-pod"},
    )
    async with h.sessions.begin() as db:
        await db.execute(delete(PairIntent))
        db.add(h.pair)
    h.kube.calls.clear()
    yield h
    async with h.sessions.begin() as db:
        await db.execute(delete(PairIntent))


def assert_capture(work, h):
    assert work.pair_snapshot == {
        "generation": str(h.pair.generation),
        "session_id": str(h.pair.session_id),
        "sandbox_id": str(h.pair.sandbox_id),
        "project_id": str(h.pair.project_id),
        "claim_owner": str(h.pair.claim_owner),
        "claim_changed": h.pair.claim_changed.isoformat(),
        "namespace": h.pair.namespace,
        "golden_version": h.pair.golden_version,
        "control_uids": h.pair.control_uids,
        "compute_uids": h.pair.compute_uids,
        "control_dispatch": h.pair.control_dispatch,
        "compute_dispatch": h.pair.compute_dispatch,
        "relay_custody": h.pair.relay_custody,
        "relay_inputs": h.pair.relay_inputs,
        "compute_payloads": h.pair.compute_payloads,
        "egress_state_id": None,
        "egress_state": None,
        "ipc_resources": h.pair.ipc_resources,
        "volume_resources": h.pair.volume_resources,
        "topics_dispatch": h.pair.topics_dispatch,
    }
    assert len(work.pair_snapshot["control_uids"]) == 8
    assert list(work.pair_snapshot["control_uids"].values()).count(None) == 7
    assert work.pair_snapshot["compute_uids"]["Pod/guest"] == "captured-guest-pod"


async def idle_work(h):
    await h.lifecycle.admit(IDLE, Signal(h.row.session_id, h.row.sandbox_id))
    return (await works(h))[0]


async def test_idle_captures_pair_with_workspace_retention_and_requires_drain(paired):
    h = paired
    work = await idle_work(h)
    assert_capture(work, h)
    assert any(t.get("retain") for t in work.targets)
    await h.lifecycle.execute(work.work_id)
    assert h.publisher.send.await_count == 1  # Existing authenticated drain path.
    assert not h.cleanup.deleted
    assert (await row_for(h, h.row.session_id)).status == "shutting_down"
    await h.lifecycle.shutdown_ack(work.sandbox_id, work.state_changed)
    h.cleanup.capture = AsyncMock(side_effect=AssertionError("legacy capture must not start"))
    await h.lifecycle.execute(work.work_id)
    h.cleanup.capture.assert_not_awaited()
    assert not h.cleanup.deleted
    assert len(await works(h)) == 1


async def test_repository_completion_cannot_erase_pair_from_stale_work_snapshot(paired):
    h = paired
    work = await idle_work(h)
    work.pair_snapshot = None  # A stale detached worker does not control the DB record.
    async with h.sessions.begin() as db:
        assert not await h.lifecycle_repository.complete(db, work, datetime.now(UTC))
    assert_capture((await works(h))[0], h)
    assert (await row_for(h, h.row.session_id)).status == "shutting_down"
    async with h.sessions.begin() as db:
        assert (await db.get(SessionPVC, h.row.pvc_id)).state == "detaching"


async def test_recovery_captures_before_sandbox_rotation_and_does_not_use_legacy_executor(paired):
    h = paired
    await h.lifecycle.admit(RECOVER, Signal(h.row.session_id, h.row.sandbox_id))
    current = await row_for(h, h.row.session_id)
    assert current.sandbox_id != h.pair.sandbox_id and current.status == "recovering"
    work = (await works(h))[0]
    assert_capture(work, h)
    h.service.build = AsyncMock()
    await recovery(h).execute(h.row.session_id)
    h.service.build.assert_not_awaited()
    assert not h.cleanup.deleted and not h.kube.calls
    assert len(await works(h)) == 1
    assert (await row_for(h, h.row.session_id)).status == "recovering"


async def test_repeated_recovery_preserves_original_snapshot_instead_of_later_uid_mapping(paired):
    h = paired
    await h.lifecycle.admit(RECOVER, Signal(h.row.session_id, h.row.sandbox_id))
    first = (await works(h))[0]
    captured = deepcopy(first.pair_snapshot)
    async with h.sessions.begin() as db:
        row = await db.get(SandboxSession, h.row.session_id)
        row.status_changed_at -= timedelta(seconds=h.settings.recovery_seconds + 1)
        original = await db.get(PairIntent, h.pair.generation)
        original.control_uids = {**original.control_uids, "PodGroup/guest": "later-value"}
    current = await row_for(h, h.row.session_id)
    await h.lifecycle.admit(RECOVER, Signal(current.session_id, current.sandbox_id))
    pending = await works(h)
    assert len(pending) == 2
    assert next(w for w in pending if w.work_id == first.work_id).pair_snapshot == captured
    await recovery(h).execute(current.session_id)
    assert not h.cleanup.deleted and not h.kube.calls
    assert len(await works(h)) == 2


@pytest.mark.parametrize("kind", ["service", "reap"])
async def test_other_lifecycle_claims_capture_pair_before_work_is_committed(paired, kind):
    h = paired
    now = datetime.now(UTC)
    async with h.sessions.begin() as db:
        row = await db.get(SandboxSession, h.row.session_id)
        pvc = await db.get(SessionPVC, h.row.pvc_id)
        row.status, pvc.state = "stopped", "detached"
        pvc.last_state_change = now - timedelta(hours=3)
        if kind == "service":
            work = await h.lifecycle_repository.service(
                db,
                row.session_id,
                row.sandbox_id,
                now,
                30,
                [sandbox_targets(row, retain=True)[0]],
            )
        else:
            work = await h.lifecycle_repository.reap(
                db,
                row.session_id,
                row.sandbox_id,
                pvc.pvc_id,
                now,
                h.settings.idle_seconds,
                h.settings.detached_seconds,
                30,
            )
        assert work is not None
    assert_capture(work, h)
    await h.lifecycle.execute(work.work_id)
    assert not h.cleanup.deleted and not h.kube.calls
    assert len(await works(h)) == 1


async def test_true_orphan_keeps_pair_ownership_after_session_row_deletion(paired):
    h = paired
    obj = next(o for o in h.kube.objects.values() if o["kind"] == "Deployment")
    async with h.sessions.begin() as db:
        await db.execute(
            delete(SandboxSession).where(SandboxSession.session_id == h.row.session_id)
        )
    message = Signal(
        h.row.session_id,
        h.row.sandbox_id,
        kind="Deployment",
        name=obj["metadata"]["name"],
        uid=obj["metadata"]["uid"],
    )
    await h.lifecycle.admit(ORPHAN, message)
    work = (await works(h))[0]
    assert work.kind == "orphan" and work.session_id is None
    assert_capture(work, h)
    await h.lifecycle.execute(work.work_id)
    assert not h.cleanup.deleted
    assert len(await works(h)) == 1
    async with h.sessions.begin() as db:
        assert await db.get(PairIntent, h.pair.generation) is not None


async def test_foreign_pair_identity_rolls_back_whole_lifecycle_claim(paired):
    h = paired
    async with h.sessions.begin() as db:
        pair = await db.get(PairIntent, h.pair.generation)
        pair.session_id = uuid4()
    with pytest.raises(RuntimeError, match="identity mismatch"):
        await idle_work(h)
    assert not await works(h)
    assert (await row_for(h, h.row.session_id)).status == "ready"
    async with h.sessions.begin() as db:
        assert (await db.get(SessionPVC, h.row.pvc_id)).state == "attached"


@pytest.mark.parametrize("payload", [{}, {"generation": "broken"}])
async def test_malformed_pair_snapshot_is_not_treated_as_no_pair(paired, payload):
    h = paired
    work = await idle_work(h)
    await h.lifecycle.shutdown_ack(work.sandbox_id, work.state_changed)
    async with h.sessions.begin() as db:
        stored = await db.get(CleanupWork, work.work_id)
        stored.pair_snapshot = payload
    await h.lifecycle.execute(work.work_id)
    assert not h.cleanup.deleted and not h.kube.calls
    async with h.sessions.begin() as db:
        assert not await h.lifecycle_repository.complete(db, work, datetime.now(UTC))
    assert len(await works(h)) == 1


async def test_fresh_schema_contains_captured_pair_field_without_new_claim_epoch(paired):
    h = paired
    async with h.engine.connect() as db:
        columns = await db.run_sync(lambda c: inspect(c).get_columns("cleanup_work"))
    names = {c["name"] for c in columns}
    assert names == set(CleanupWork.__table__.columns.keys())
    assert "pair_snapshot" in names
    assert not {"service_claim_id", "epoch", "token", "authorization", "private_key"} & names
