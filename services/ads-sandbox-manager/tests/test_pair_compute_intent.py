# ruff: noqa: F811
from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import delete, inspect

from ads_sandbox_manager.lifecycle_store import CleanupWork
from ads_sandbox_manager.pair_store import (
    COMPUTE_ROLES,
    PairClaimLost,
    PairIntent,
    PairIntentRepository,
    compute_key,
    new_compute_dispatch,
    new_compute_uids,
)
from ads_sandbox_manager.store import SandboxSession
from test_kube_release import api  # noqa: F401
from test_pair_controls import controls  # noqa: F401
from test_pair_creator_fence import cleanup_claim
from test_pair_store import begin, ledger, snapshot  # noqa: F401
from test_session_objects import object_settings  # noqa: F401
from test_sessions import row_for, sessions_harness  # noqa: F401

pytestmark = pytest.mark.anyio


async def reserve(f, generation, role="guest"):
    async with f.h.sessions.begin() as db:
        return await f.repo.dispatch_compute(db, f.row, f.owner, generation, role)


async def test_all_four_compute_intents_commit_atomically_with_control_intent(ledger):
    f = ledger
    async with f.h.sessions.begin() as db:
        intent = await f.repo.begin(
            db,
            f.row,
            f.owner,
            namespace=f.h.settings.namespace,
            golden_version=f.h.settings.golden_version,
        )
        assert intent.compute_uids == new_compute_uids()
        assert intent.compute_dispatch == new_compute_dispatch()
        assert await snapshot(f, intent.generation) is None
    stored = await snapshot(f, intent.generation)
    assert stored.compute_uids == new_compute_uids()
    assert stored.compute_dispatch == new_compute_dispatch()
    assert len(stored.control_uids) == 8 and len(stored.compute_uids) == 4
    assert not f.h.kube.calls


@pytest.mark.parametrize("role", COMPUTE_ROLES)
async def test_concurrent_compute_reservation_has_one_winner_and_no_reissue(ledger, role):
    f = ledger
    intent = await begin(f)
    results = await asyncio.gather(*(reserve(f, intent.generation, role) for _ in range(8)))
    assert sum(dispatched for _, dispatched in results) == 1
    stored = await snapshot(f, intent.generation)
    assert stored.compute_dispatch[compute_key(role)] == "inflight"
    assert stored.compute_uids[compute_key(role)] is None
    assert set(stored.control_dispatch.values()) == {"unissued"}
    f.repo = PairIntentRepository()
    assert not (await reserve(f, intent.generation, role))[1]
    assert not f.h.kube.calls


@pytest.mark.parametrize("role", COMPUTE_ROLES)
async def test_compute_binding_and_settlement_are_distinct_immutable_steps(ledger, role):
    f = ledger
    intent = await begin(f)
    issued, _ = await reserve(f, intent.generation, role)
    async with f.h.sessions.begin() as db:
        await f.repo.bind_compute(db, f.row, f.owner, intent.generation, role, "owned-pod")
    assert (await snapshot(f, intent.generation)).compute_dispatch[compute_key(role)] == "inflight"
    async with f.h.sessions.begin() as db:
        await f.repo.settle_compute(db, issued, role)
        await f.repo.settle_compute(db, issued, role)
        await f.repo.bind_compute(db, f.row, f.owner, intent.generation, role, "owned-pod")
    with pytest.raises(RuntimeError, match="replacement"):
        async with f.h.sessions.begin() as db:
            await f.repo.bind_compute(db, f.row, f.owner, intent.generation, role, "foreign-pod")
    stored = await snapshot(f, intent.generation)
    assert stored.compute_uids[compute_key(role)] == "owned-pod"
    assert stored.compute_dispatch[compute_key(role)] == "settled"
    assert not (await reserve(f, intent.generation, role))[1]


@pytest.mark.parametrize("operation", ["dispatch", "bind", "settle"])
async def test_compute_transaction_rollback_preserves_prior_evidence(ledger, operation):
    f = ledger
    intent = await begin(f)
    if operation != "dispatch":
        intent, _ = await reserve(f, intent.generation)
    before = await snapshot(f, intent.generation)
    with pytest.raises(RuntimeError, match="rollback"):
        async with f.h.sessions.begin() as db:
            if operation == "dispatch":
                await f.repo.dispatch_compute(db, f.row, f.owner, intent.generation, "guest")
            elif operation == "bind":
                await f.repo.bind_compute(db, f.row, f.owner, intent.generation, "guest", "uid")
            else:
                await f.repo.settle_compute(db, intent, "guest")
            raise RuntimeError("rollback")
    after = await snapshot(f, intent.generation)
    assert after.compute_uids == before.compute_uids
    assert after.compute_dispatch == before.compute_dispatch


@pytest.mark.parametrize("role", ["ipc", "other", "", "../guest"])
async def test_unknown_compute_roles_never_get_dispatch_or_binding(ledger, role):
    f = ledger
    intent = await begin(f)
    with pytest.raises(ValueError, match="compute role"):
        await reserve(f, intent.generation, role)
    with pytest.raises(ValueError, match="compute role"):
        async with f.h.sessions.begin() as db:
            await f.repo.bind_compute(db, f.row, f.owner, intent.generation, role, "uid")
    with pytest.raises(ValueError, match="compute role"):
        async with f.h.sessions.begin() as db:
            await f.repo.settle_compute(db, intent, role)
    assert (await snapshot(f, intent.generation)).compute_dispatch == new_compute_dispatch()


@pytest.mark.parametrize("uid", ["", " ", False, 12])
async def test_compute_binding_rejects_invalid_uid(ledger, uid):
    f = ledger
    intent = await begin(f)
    with pytest.raises(ValueError, match="compute UID"):
        async with f.h.sessions.begin() as db:
            await f.repo.bind_compute(db, f.row, f.owner, intent.generation, "guest", uid)
    assert (await snapshot(f, intent.generation)).compute_uids == new_compute_uids()


async def test_undispatched_compute_cannot_be_settled(ledger):
    f = ledger
    intent = await begin(f)
    with pytest.raises(RuntimeError, match="never dispatched"):
        async with f.h.sessions.begin() as db:
            await f.repo.settle_compute(db, intent, "guest")


@pytest.mark.parametrize("field", ["claim_owner", "claim_changed", "namespace", "project_id"])
async def test_compute_settlement_refuses_changed_original_identity(ledger, field):
    f = ledger
    intent = await begin(f)
    original, _ = await reserve(f, intent.generation)
    async with f.h.sessions.begin() as db:
        stored = await db.get(PairIntent, intent.generation)
        value = (
            (stored.claim_changed + timedelta(microseconds=1))
            if field == "claim_changed"
            else ("changed" if field == "namespace" else uuid4())
        )
        setattr(stored, field, value)
    with pytest.raises(PairClaimLost, match="identity changed"):
        async with f.h.sessions.begin() as db:
            await f.repo.settle_compute(db, original, "guest")
    assert (await snapshot(f, intent.generation)).compute_dispatch["Pod/guest"] == "inflight"


@pytest.mark.parametrize(
    "field,value",
    [
        ("compute_uids", None),
        ("compute_uids", {}),
        ("compute_uids", {"Pod/guest": "uid"}),
        ("compute_uids", {**new_compute_uids(), "Pod/guest": False}),
        ("compute_uids", {**new_compute_uids(), "Pod/guest": " "}),
        ("compute_dispatch", None),
        ("compute_dispatch", {}),
        ("compute_dispatch", {**new_compute_dispatch(), "Pod/guest": "absent"}),
        ("compute_dispatch", {**new_compute_dispatch(), "Pod/guest": False}),
    ],
)
async def test_corrupt_compute_evidence_fails_closed(ledger, field, value):
    f = ledger
    intent = await begin(f)
    setattr(intent, field, value)
    with pytest.raises(RuntimeError, match="compute evidence"):
        f.repo._validate(intent)
    assert not f.h.kube.calls


async def test_cleanup_fence_blocks_compute_even_if_old_claim_tuple_returns(controls):
    f = controls
    intent = await begin(f)
    capture, work, claim = await cleanup_claim(f)
    await capture.capture(work, recovery=claim)
    async with f.h.sessions.begin() as db:
        row = await db.get(SandboxSession, f.row.session_id)
        row.sandbox_id, row.status = f.row.sandbox_id, "creating"
        row.status_changed_at, row.claimed_by = f.row.status_changed_at, f.owner
    f.repo = PairIntentRepository()
    for role in COMPUTE_ROLES:
        with pytest.raises(PairClaimLost, match="fenced"):
            await reserve(f, intent.generation, role)
        with pytest.raises(PairClaimLost, match="fenced"):
            async with f.h.sessions.begin() as db:
                await f.repo.bind_compute(db, f.row, f.owner, intent.generation, role, "late")
    stored = await snapshot(f, intent.generation)
    assert stored.creation_fenced and stored.compute_dispatch == new_compute_dispatch()


@pytest.mark.parametrize("settles", [True, False])
async def test_late_compute_capture_is_not_settlement_or_retirement(controls, settles):
    f = controls
    intent = await begin(f)
    original, _ = await reserve(f, intent.generation)
    capture, work, claim = await cleanup_claim(f)
    await capture.capture(work, recovery=claim)
    if settles:
        # Simulate only the original invocation's normal return; no fake
        # production Kubernetes creator or completed runtime is introduced.
        async with f.h.sessions.begin() as db:
            await f.repo.settle_compute(db, original, "guest")
    with pytest.raises(PairClaimLost):
        async with f.h.sessions.begin() as db:
            await f.repo.bind_compute(db, f.row, f.owner, intent.generation, "guest", "late-pod")
    async with f.h.sessions.begin() as db:
        work = await db.get(CleanupWork, work.work_id)
        assert work.pair_snapshot["compute_uids"]["Pod/guest"] is None
        work = await capture.repository.record_pair_compute(
            db,
            work,
            "guest",
            "late-pod",
            datetime.now(UTC),
            recovery=claim,
            recovery_seconds=120,
        )
    async with f.h.sessions.begin() as db:
        work = await capture.repository.record_pair_compute(
            db,
            work,
            "guest",
            None,
            datetime.now(UTC),
            recovery=claim,
            recovery_seconds=120,
        )
        assert work.pair_snapshot["compute_uids"]["Pod/guest"] == "late-pod"
        assert not await capture.repository.complete(db, work, datetime.now(UTC))
    with pytest.raises(RuntimeError, match="replacement"):
        async with f.h.sessions.begin() as db:
            await capture.repository.record_pair_compute(
                db,
                work,
                "guest",
                "replacement",
                datetime.now(UTC),
                recovery=claim,
                recovery_seconds=120,
            )
    stored = await snapshot(f, intent.generation)
    assert stored.compute_dispatch["Pod/guest"] == ("settled" if settles else "inflight")
    assert stored.compute_uids["Pod/guest"] is None and stored.creation_fenced
    assert not f.remote.created and not f.h.kube.calls


async def test_recovery_snapshot_preserves_compute_uids_after_later_ledger_change(controls):
    f = controls
    intent = await begin(f)
    async with f.h.sessions.begin() as db:
        await f.repo.bind_compute(db, f.row, f.owner, intent.generation, "egress", "original-pod")
    capture, work, claim = await cleanup_claim(f)
    assert work.pair_snapshot["compute_uids"]["Pod/egress"] == "original-pod"
    async with f.h.sessions.begin() as db:
        stored = await db.get(PairIntent, intent.generation)
        stored.compute_uids = {**stored.compute_uids, "Pod/egress": "later-mapping"}
    await capture.capture(work, recovery=claim)
    async with f.h.sessions.begin() as db:
        retained = await db.get(CleanupWork, work.work_id)
        assert retained.pair_snapshot["compute_uids"]["Pod/egress"] == "original-pod"


@pytest.mark.parametrize("uid", ["", " ", False, 12])
async def test_cleanup_compute_capture_rejects_invalid_uid(controls, uid):
    f = controls
    await begin(f)
    capture, work, claim = await cleanup_claim(f)
    with pytest.raises(ValueError, match="compute UID"):
        async with f.h.sessions.begin() as db:
            await capture.repository.record_pair_compute(
                db,
                work,
                "guest",
                uid,
                datetime.now(UTC),
                recovery=claim,
                recovery_seconds=120,
            )
    async with f.h.sessions.begin() as db:
        assert (await db.get(CleanupWork, work.work_id)).pair_snapshot == work.pair_snapshot


async def test_stale_recovery_cannot_record_compute_uid(controls):
    f = controls
    await begin(f)
    capture, work, claim = await cleanup_claim(f)
    async with f.h.sessions.begin() as db:
        current = await db.get(SandboxSession, claim.session_id)
        current.status_changed_at += timedelta(microseconds=1)
    with pytest.raises(PairClaimLost):
        async with f.h.sessions.begin() as db:
            await capture.repository.record_pair_compute(
                db,
                work,
                "guest",
                "late",
                datetime.now(UTC),
                recovery=claim,
                recovery_seconds=120,
            )
    async with f.h.sessions.begin() as db:
        assert (await db.get(CleanupWork, work.work_id)).pair_snapshot == work.pair_snapshot


@pytest.mark.parametrize("value", [{}, {**new_compute_uids(), "Pod/guest": False}])
async def test_corrupt_cleanup_compute_snapshot_never_reaches_api(controls, value):
    f = controls
    await begin(f)
    capture, work, claim = await cleanup_claim(f)
    async with f.h.sessions.begin() as db:
        work = await db.get(CleanupWork, work.work_id)
        work.pair_snapshot = {**work.pair_snapshot, "compute_uids": value}
    with pytest.raises(RuntimeError, match="scope or controls"):
        await capture.capture(work, recovery=claim)
    assert not f.remote.created


async def test_deleted_session_keeps_compute_ownership_and_missing_intent_cannot_settle(ledger):
    f = ledger
    intent = await begin(f)
    original, _ = await reserve(f, intent.generation)
    async with f.h.sessions.begin() as db:
        await db.execute(
            delete(SandboxSession).where(SandboxSession.session_id == f.row.session_id)
        )
    assert (await snapshot(f, intent.generation)).compute_dispatch["Pod/guest"] == "inflight"
    with pytest.raises(PairClaimLost):
        await reserve(f, intent.generation)
    async with f.h.sessions.begin() as db:
        await db.delete(await db.get(PairIntent, intent.generation))
    with pytest.raises(PairClaimLost, match="missing"):
        async with f.h.sessions.begin() as db:
            await f.repo.settle_compute(db, original, "guest")


async def test_fresh_compute_schema_is_required_and_nonnullable(ledger):
    async with ledger.h.engine.connect() as db:
        columns = await db.run_sync(lambda c: inspect(c).get_columns("sandbox_pair_intent"))
    actual = {column["name"]: column for column in columns}
    assert set(actual) == set(PairIntent.__table__.columns.keys())
    assert not actual["compute_uids"]["nullable"]
    assert not actual["compute_dispatch"]["nullable"]
