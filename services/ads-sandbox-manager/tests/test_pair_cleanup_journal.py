# ruff: noqa: F811
from __future__ import annotations

import asyncio
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import msgspec
import pytest
from sqlalchemy import delete, inspect

from ads_sandbox_manager.lifecycle_store import CleanupWork, LifecycleRepository
from ads_sandbox_manager.pair_cleanup import PairCleanupCapture
from ads_sandbox_manager.pair_store import PairClaimLost, PairIntent
from ads_sandbox_manager.store import SandboxSession, SessionPVC
from test_kube_release import api  # noqa: F401
from test_node_release_wire import node_report  # noqa: F401
from test_pair_cleanup_writers import WRITERS
from test_pair_controls import controls  # noqa: F401
from test_pair_creation import build, creation  # noqa: F401
from test_pair_creator_fence import cleanup_claim
from test_pair_store import ledger, snapshot  # noqa: F401
from test_pair_volume_publication import publication as volume_publication  # noqa: F401
from test_relay_custody_cleanup import saved
from test_session_objects import object_settings  # noqa: F401
from test_sessions import sessions_harness  # noqa: F401

pytestmark = pytest.mark.anyio


@pytest.fixture
async def journal(creation, node_report):
    f = creation
    await build(f)
    capture, work, claim = await cleanup_claim(f)
    f.capture, f.work, f.claim = capture, work, claim
    f.report = {
        **node_report,
        "generation": str(f.intent.generation),
        "sandbox_id": str(f.row.sandbox_id),
        "namespace": f.adapter.namespace,
        "pod_uids": list(work.pair_snapshot["compute_uids"].values()),
    }
    return f


async def record(f, report=None, **kwargs):
    async with f.h.sessions.begin() as db:
        await f.capture.repository.record_pair_node_capture(
            db,
            f.work,
            msgspec.json.encode(f.report if report is None else report),
            datetime.now(UTC),
            node=f.report["node"],
            network=f.report["network"],
            recovery=f.claim,
            recovery_seconds=120,
            **kwargs,
        )


async def retained(f):
    async with f.h.sessions.begin() as db:
        return await LifecycleRepository().pair_snapshot(db, f.row.session_id, f.row.sandbox_id)


async def test_capture_seals_original_ownership_and_node_report_is_idempotent(journal):
    f = journal
    assert await f.capture.capture(f.work, recovery=f.claim)
    sealed = (await snapshot(f, f.intent.generation)).cleanup_journal
    assert sealed["snapshot"] == f.work.pair_snapshot
    assert sealed["targets"] == f.work.targets and not sealed["retain_workspace"]
    assert sealed["node_capture"] is None
    await record(f)
    first = deepcopy((await snapshot(f, f.intent.generation)).cleanup_journal)
    await record(f, {**f.report, "pod_uids": list(reversed(f.report["pod_uids"]))})
    assert (await snapshot(f, f.intent.generation)).cleanup_journal == first
    assert await retained(f) == f.work.pair_snapshot
    assert (await saved(f, f.work)).pair_snapshot == f.work.pair_snapshot
    async with f.h.sessions.begin() as db:
        assert not await f.capture.repository.complete(db, f.work, datetime.now(UTC))


@pytest.mark.parametrize("delete_session", [False, True])
async def test_journal_survives_work_and_session_loss_without_api_reads(journal, delete_session):
    f = journal
    await record(f)
    expected = deepcopy((await snapshot(f, f.intent.generation)).cleanup_journal)
    async with f.h.sessions.begin() as db:
        if delete_session:
            await db.execute(
                delete(SandboxSession).where(SandboxSession.session_id == f.row.session_id)
            )
        else:
            await db.execute(delete(CleanupWork).where(CleanupWork.work_id == f.work.work_id))
    f.remote.objects.clear()  # API absence cannot replace the stored evidence.
    assert await retained(f) == f.work.pair_snapshot
    assert (await snapshot(f, f.intent.generation)).cleanup_journal == expected
    async with f.h.sessions.begin() as db:
        assert await db.get(CleanupWork, f.work.work_id) is None
    with pytest.raises(PairClaimLost):
        await record(f)


async def test_late_captured_uid_survives_cascade_without_rewriting_creator(journal):
    f = journal
    key = "Pod/guest"
    uid = f.work.pair_snapshot["compute_uids"][key]
    async with f.h.sessions.begin() as db:
        intent = await db.get(PairIntent, f.intent.generation)
        intent.compute_uids = {**intent.compute_uids, key: None}
        work = await db.get(CleanupWork, f.work.work_id)
        value = deepcopy(work.pair_snapshot)
        value["compute_uids"][key] = None
        value["compute_dispatch"][key] = "inflight"
        work.pair_snapshot = value
    f.work = await saved(f, f.work)
    assert await f.capture.capture(f.work, recovery=f.claim)
    current = await saved(f, f.work)
    assert current.pair_snapshot["compute_uids"][key] == uid
    assert current.pair_snapshot["compute_dispatch"][key] == "inflight"
    original = await snapshot(f, f.intent.generation)
    assert original.compute_uids[key] is None
    assert original.compute_dispatch[key] == "settled"
    async with f.h.sessions.begin() as db:
        await db.execute(
            delete(SandboxSession).where(SandboxSession.session_id == f.row.session_id)
        )
    assert (await retained(f))["compute_uids"][key] == uid
    assert (await retained(f))["compute_dispatch"][key] == "inflight"


@pytest.mark.parametrize("field,role", WRITERS)
async def test_no_journal_is_sealed_for_any_ambiguous_writer(journal, field, role):
    from ads_sandbox_manager.egress_state_store import EgressState

    f = journal
    async with f.h.sessions.begin() as db:
        intent = await db.get(PairIntent, f.intent.generation)
        work = await db.get(CleanupWork, f.work.work_id)
        captured = deepcopy(work.pair_snapshot)
        if field == "state":
            state = await db.get(EgressState, intent.egress_state_id)
            setattr(state, f"{role}_dispatch", "inflight")
            captured["egress_state"][f"{role}_dispatch"] = "inflight"
            if role == "key":
                state.volume_dispatch, state.volume_uid = "unissued", None
                captured["egress_state"].update(volume_dispatch="unissued", volume_uid=None)
        elif field == "topics_dispatch":
            intent.topics_dispatch = captured[field] = "inflight"
        elif field == "relay_custody":
            intent.relay_custody = {**intent.relay_custody, "dispatch": "inflight"}
            captured[field]["dispatch"] = "inflight"
        else:
            value = deepcopy(getattr(intent, field))
            if field.endswith("_dispatch"):
                value[role] = captured[field][role] = "inflight"
            else:
                value[role]["dispatch"] = captured[field][role]["dispatch"] = "inflight"
            setattr(intent, field, value)
        work.pair_snapshot = captured
    f.work = await saved(f, f.work)
    with pytest.raises(PairClaimLost, match="not settled"):
        await record(f)
    assert (await snapshot(f, f.intent.generation)).cleanup_journal is None


@pytest.mark.parametrize("field", ["boot_id", "inventory_sha256", "network", "node", "pod_uids"])
async def test_original_node_inventory_cannot_be_replaced(journal, field):
    f = journal
    await record(f)
    before = deepcopy((await snapshot(f, f.intent.generation)).cleanup_journal)
    changed = {
        **f.report,
        field: {
            "boot_id": str(uuid4()),
            "inventory_sha256": "b" * 64,
            "network": "other",
            "node": "other",
            "pod_uids": [str(uuid4()) for _ in range(4)],
        }[field],
    }
    with pytest.raises((PairClaimLost, ValueError)):
        await record(f, changed)
    assert (await snapshot(f, f.intent.generation)).cleanup_journal == before


@pytest.mark.parametrize("fault", ["claim", "work", "snapshot", "deadline", "raw"])
async def test_claim_and_payload_failures_do_not_commit_a_partial_journal(journal, fault):
    f = journal
    async with f.h.sessions.begin() as db:
        work = await db.get(CleanupWork, f.work.work_id)
        if fault == "claim":
            row = await db.get(SandboxSession, f.claim.session_id)
            row.status_changed_at += timedelta(microseconds=1)
        elif fault == "work":
            await db.delete(work)
        elif fault == "snapshot":
            work.pair_snapshot = {**work.pair_snapshot, "project_id": str(uuid4())}
        elif fault == "deadline":
            row = await db.get(SandboxSession, f.claim.session_id)
            row.status_changed_at -= timedelta(minutes=10)
    with pytest.raises((PairClaimLost, ValueError)):
        await record(f, {} if fault == "raw" else None)
    assert (await snapshot(f, f.intent.generation)).cleanup_journal is None


@pytest.mark.parametrize(
    "fault", ["clear_uid", "new_uid", "payload", "dispatch", "fence", "shape", "report"]
)
async def test_sealed_journal_rejects_ledger_drift_and_corruption(journal, fault):
    f = journal
    await record(f)
    async with f.h.sessions.begin() as db:
        intent = await db.get(PairIntent, f.intent.generation)
        if fault in ("clear_uid", "new_uid"):
            intent.compute_uids = {
                **intent.compute_uids,
                "Pod/guest": None if fault == "clear_uid" else str(uuid4()),
            }
        elif fault == "payload":
            intent.compute_payloads = {**intent.compute_payloads, "guest": None}
        elif fault == "dispatch":
            intent.topics_dispatch = "inflight"
        elif fault == "fence":
            intent.creation_fenced = False
        else:
            value = deepcopy(intent.cleanup_journal)
            if fault == "shape":
                value["extra"] = True
            else:
                value["node_capture"]["generation"] = str(uuid4())
            intent.cleanup_journal = value
    with pytest.raises((RuntimeError, ValueError)):
        await retained(f)


async def test_fresh_schema_has_retained_journal_without_cascade(journal):
    f = journal
    async with f.h.engine.connect() as db:
        columns, foreign_keys = await db.run_sync(
            lambda c: (
                inspect(c).get_columns("sandbox_pair_intent"),
                inspect(c).get_foreign_keys("sandbox_pair_intent"),
            )
        )
    assert {c["name"] for c in columns} == set(PairIntent.__table__.columns.keys())
    assert next(c for c in columns if c["name"] == "cleanup_journal")["nullable"]
    assert not foreign_keys


async def test_concurrent_different_inventory_captures_preserve_the_first(journal):
    f = journal
    other = {**f.report, "boot_id": str(uuid4())}
    results = await asyncio.gather(record(f), record(f, other), return_exceptions=True)
    assert sum(result is None for result in results) == 1
    assert sum(isinstance(result, PairClaimLost) for result in results) == 1
    stored = (await snapshot(f, f.intent.generation)).cleanup_journal
    assert stored["node_capture"]["boot_id"] in (f.report["boot_id"], other["boot_id"])


async def test_node_capture_transaction_rollback_preserves_the_previous_checkpoint(journal):
    f = journal
    assert await f.capture.capture(f.work, recovery=f.claim)
    first = deepcopy((await snapshot(f, f.intent.generation)).cleanup_journal)
    with pytest.raises(RuntimeError, match="interrupted commit"):
        async with f.h.sessions.begin() as db:
            await f.capture.repository.record_pair_node_capture(
                db,
                f.work,
                msgspec.json.encode(f.report),
                datetime.now(UTC),
                node=f.report["node"],
                network=f.report["network"],
                recovery=f.claim,
                recovery_seconds=120,
            )
            raise RuntimeError("interrupted commit")
    assert (await snapshot(f, f.intent.generation)).cleanup_journal == first
    await record(f)
    assert (await snapshot(f, f.intent.generation)).cleanup_journal["node_capture"]


async def test_idle_retention_and_original_targets_survive_new_orphan_claim(creation):
    f = creation
    await build(f)
    repository = LifecycleRepository()
    now = datetime.now(UTC)
    async with f.h.sessions.begin() as db:
        assert await f.h.repository.mark_ready(db, f.row.sandbox_id, now, f.row.status_changed_at)
        row = await db.get(SandboxSession, f.row.session_id)
        pvc = await db.get(SessionPVC, row.pvc_id)
        row.last_execution_at = pvc.last_execution = now - timedelta(hours=4)
        work = await repository.idle(db, row.session_id, row.sandbox_id, now, 60, 120)
        assert work is not None
    capture = PairCleanupCapture(
        replace(f.service.settings, cleanup_seconds=60), f.h.sessions, repository, f.adapter
    )
    with pytest.raises(PairClaimLost):
        await capture.capture(work)
    assert (await snapshot(f, f.intent.generation)).cleanup_journal is None
    async with f.h.sessions.begin() as db:
        (await db.get(CleanupWork, work.work_id)).acknowledged = True
    assert await capture.capture(work)
    original = deepcopy((await snapshot(f, f.intent.generation)).cleanup_journal)
    assert original["retain_workspace"]
    assert any(item.get("retain") for item in original["targets"])
    async with f.h.sessions.begin() as db:
        await db.execute(
            delete(SandboxSession).where(SandboxSession.session_id == f.row.session_id)
        )
    restored = await retained(f)
    restored["control_uids"].clear()  # Return values cannot mutate the durable copy.
    assert (await retained(f))["control_uids"]
    async with f.h.sessions.begin() as db:
        orphan = CleanupWork(
            work_id=uuid4(),
            session_id=None,
            sandbox_id=f.row.sandbox_id,
            pvc_id=None,
            kind="orphan",
            state_changed=now,
            pvc_changed=None,
            deadline=now + timedelta(seconds=120),
            acknowledged=True,
            targets=[],
            pair_snapshot=await repository.pair_snapshot(db, f.row.session_id, f.row.sandbox_id),
        )
        db.add(orphan)
    async with f.h.sessions.begin() as db:
        assert await repository.seal_pair_cleanup(db, orphan, datetime.now(UTC))
    assert (await snapshot(f, f.intent.generation)).cleanup_journal == original
    assert original["retain_workspace"]  # Orphan reclassification cannot discard retention.
