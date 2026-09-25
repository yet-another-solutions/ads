# ruff: noqa: F811
from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select

from ads_sandbox_manager.lifecycle_store import CleanupWork
from ads_sandbox_manager.pair_retirement import PairRetirement, PairRetirementRepository
from ads_sandbox_manager.pair_store import PairIntent
from ads_sandbox_manager.recovery import RecoveryService
from ads_sandbox_manager.store import SandboxSession, SessionPVC
from test_kube_release import api  # noqa: F401
from test_node_release_wire import node_report  # noqa: F401
from test_pair_cleanup_journal import journal  # noqa: F401
from test_pair_controls import controls  # noqa: F401
from test_pair_creation import creation  # noqa: F401
from test_pair_resource_teardown import resources  # noqa: F401
from test_pair_runtime_teardown import lifecycle, teardown  # noqa: F401
from test_pair_store import ledger, snapshot  # noqa: F401
from test_pair_volume_publication import publication as volume_publication  # noqa: F401
from test_session_objects import object_settings  # noqa: F401
from test_sessions import sessions_harness  # noqa: F401

pytestmark = pytest.mark.anyio


def recovery(f):
    worker = lifecycle(f)
    worker.pair_resources = f.resource_stage
    return RecoveryService(
        f.runtime.settings, f.h.sessions, f.h.repository, worker, f.h.service, f.topics
    )


async def original(f):
    async with f.h.sessions.begin() as db:
        row = await db.get(SandboxSession, f.row.session_id)
        old = await db.get(PairIntent, f.intent.generation)
        return row, old


async def test_real_destructive_recovery_retires_then_builds_fresh_pair(resources):
    f = resources
    current, old = await original(f)
    old_state = old.egress_state_id
    await recovery(f).execute(current.session_id)
    async with f.h.sessions.begin() as db:
        row = await db.get(SandboxSession, current.session_id)
        assert row.status == "creating" and row.sandbox_id != old.sandbox_id
        assert row.pvc_id != f.work.pvc_id and row.ipc_pod_uid
        assert await db.get(SessionPVC, f.work.pvc_id) is None
        assert await db.get(CleanupWork, f.work.work_id) is None
        saved = await PairRetirementRepository(f.capture.repository).verify(db, old.generation)
        assert saved.kind == "recovery" and saved.journal["topic_disposition"] == "deleted"
        new = await db.scalar(
            select(PairIntent).where(
                PairIntent.session_id == row.session_id, PairIntent.retired_at.is_(None)
            )
        )
        assert new is not None and new.generation != old.generation
        assert new.retained_from is None and new.egress_state_id != old_state
        assert new.relay_custody["public_keys"] != old.relay_custody["public_keys"]
        assert not await f.h.repository.mark_ready(
            db, old.sandbox_id, datetime.now(UTC), old.claim_changed
        )
        assert await f.h.repository.mark_ready(
            db, row.sandbox_id, datetime.now(UTC), row.status_changed_at
        )


@pytest.mark.parametrize("fault", ["topics", "claim", "retirement"])
async def test_recovery_never_builds_fresh_before_all_terminal_proof_commits(resources, fault):
    f = resources
    before = len(f.remote.created)
    if fault == "topics":
        f.topic_disposal.remove.return_value = False
    elif fault == "claim":
        async with f.h.sessions.begin() as db:
            row = await db.get(SandboxSession, f.row.session_id)
            row.status_changed_at += timedelta(microseconds=1)
        # Execute the stale in-memory claim, not a newly observed claim.
        with pytest.raises(RuntimeError):
            await recovery(f)._execute(f.claim, [f.work])
        assert len(f.remote.created) == before
        return
    else:
        old = f.topic_disposal.remove

        async def corrupt(sandbox_id):
            result = await old(sandbox_id)
            async with f.h.sessions.begin() as db:
                intent = await db.get(PairIntent, f.intent.generation)
                value = deepcopy(intent.cleanup_journal)
                value["block_disposition"] = {}
                intent.cleanup_journal = value
            return result

        f.topic_disposal.remove = corrupt
    await recovery(f).execute(f.row.session_id)
    assert len(f.remote.created) == before
    async with f.h.sessions.begin() as db:
        assert await db.get(PairRetirement, f.intent.generation) is None
        assert await db.get(SessionPVC, f.work.pvc_id) is not None
        assert await db.get(CleanupWork, f.work.work_id) is not None


async def test_recovery_retry_carries_unissued_interim_identity_without_legacy_deletion(resources):
    f = resources
    async with f.h.sessions.begin() as db:
        row = await db.get(SandboxSession, f.row.session_id)
        old_time = row.status_changed_at - timedelta(seconds=240)
        row.status_changed_at = old_time
        assert await f.capture.repository.recover(
            db, row.session_id, row.sandbox_id, datetime.now(UTC), 120
        )
    await recovery(f).execute(f.row.session_id)
    async with f.h.sessions.begin() as db:
        row = await db.get(SandboxSession, f.row.session_id)
        assert row.status == "creating"
        assert (
            await db.scalar(
                select(CleanupWork.work_id).where(CleanupWork.session_id == row.session_id)
            )
            is None
        )
        assert await PairRetirementRepository(f.capture.repository).verify(db, f.intent.generation)


async def test_fresh_admission_refuses_surviving_original_pvc_without_retirement(resources):
    f = resources
    async with f.h.sessions.begin() as db:
        row = await db.get(SandboxSession, f.row.session_id)
        row.status = "stopped"
        row.status_changed_at = datetime.now(UTC)
    with pytest.raises(RuntimeError):
        async with f.h.sessions.begin() as db:
            await f.h.repository.claim(db, row, uuid4(), datetime.now(UTC), paired=True)
