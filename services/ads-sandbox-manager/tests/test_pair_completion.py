# ruff: noqa: F811
"""Paired recovery completion, ported to the O2 plain-column world.

The legacy journal/`resources` fixture stack is gone. Destructive recovery
is built through LifecycleRepository.recover() itself — the same sanctioned
entry the RECOVER signal uses — over a fully built ready pair. Completion
proof is plain columns (intent.retired_at + creation_fenced), never a
journal, and the fresh claim must pass require_destroyed_history.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from sqlalchemy import select

from ads_sandbox_manager.lifecycle_store import (
    CleanupWork,
    LifecycleRepository,
    sandbox_targets,
)
from ads_sandbox_manager.pair_disposal import PairDisposalRepository
from ads_sandbox_manager.pair_registry import PairRegistry
from ads_sandbox_manager.pair_retirement import PairRetirementRepository
from ads_sandbox_manager.pair_store import PairIntent
from ads_sandbox_manager.pair_teardown import PairTeardown
from ads_sandbox_manager.recovery import RecoveryService
from ads_sandbox_manager.store import SandboxSession, SessionPVC
from test_kube_release import api  # noqa: F401
from test_pair_controls import controls  # noqa: F401
from test_pair_creation import creation  # noqa: F401
from test_pair_store import ledger, snapshot  # noqa: F401
from test_pair_teardown_world import FakeTeardownKube, lifecycle
from test_pair_volume_publication import publication as volume_publication  # noqa: F401
from test_session_objects import object_settings  # noqa: F401
from test_sessions import row_for, sessions_harness  # noqa: F401

pytestmark = pytest.mark.anyio


@pytest.fixture
async def ready_world(creation):
    """Built ready pair with the full teardown/capture wiring, pre-idle."""
    f = creation
    row = await f.h.service.build(f.row, resume=False)
    now = datetime.now(UTC)
    async with f.h.sessions.begin() as db:
        assert await f.h.repository.mark_ready(db, row.sandbox_id, now, row.status_changed_at)
    async with f.h.sessions.begin() as db:
        f.intent = await db.scalar(
            select(PairIntent).where(PairIntent.session_id == f.row.session_id)
        )
    f.teardown_kube = FakeTeardownKube(f.remote)
    f.teardown = PairTeardown(f.h.settings, f.h.sessions, LifecycleRepository(), f.teardown_kube)
    f.pair_service = lifecycle(f)
    f.capture = f.pair_service.pair_capture
    f.retirements = PairRetirementRepository(f.pair_service.repository)
    f.disposals = PairDisposalRepository(f.pair_service.repository)
    f.registry = PairRegistry(f.pair_service.repository)
    yield f


def recovery(f):
    return RecoveryService(
        f.h.settings,
        f.h.sessions,
        f.h.repository,
        f.pair_service,
        f.h.service,
        f.topics,
    )


async def condemn(f):
    """Ready world → destructive recovery via the sanctioned recover() entry."""
    now = datetime.now(UTC)
    async with f.h.sessions.begin() as db:
        row = await db.get(SandboxSession, f.row.session_id)
        assert await f.pair_service.repository.recover(
            db, row.session_id, row.sandbox_id, now, 120
        )
    async with f.h.sessions.begin() as db:
        f.claim = await db.get(SandboxSession, f.row.session_id)
        f.work = await db.scalar(
            select(CleanupWork).where(CleanupWork.session_id == f.row.session_id)
        )
        assert f.work.kind == "recovery" and f.work.pair_snapshot is not None
    return f.intent.generation


async def stored_works(f):
    async with f.h.sessions.begin() as db:
        return list(
            await db.scalars(
                select(CleanupWork).where(CleanupWork.session_id == f.row.session_id)
            )
        )


async def test_real_destructive_recovery_retires_then_builds_fresh_pair(ready_world):
    f = ready_world
    old_generation = await condemn(f)
    original_sandbox = f.row.sandbox_id  # Read before recover() rotated it.
    async with f.h.sessions.begin() as db:
        old = await db.get(PairIntent, old_generation)
        old_state, old_custody = old.egress_state_id, old.relay_custody["public_keys"]
        old_pvc_id = f.work.pvc_id
    before = len(f.remote.created)
    await recovery(f).execute(f.row.session_id)
    assert len(f.remote.created) > before
    async with f.h.sessions.begin() as db:
        row = await db.get(SandboxSession, f.row.session_id)
        assert row.status == "creating" and row.sandbox_id != original_sandbox
        assert row.pvc_id != old_pvc_id and row.ipc_pod_uid
        assert await db.get(SessionPVC, old_pvc_id) is None
        assert await db.get(CleanupWork, f.work.work_id) is None
        verified = await PairRetirementRepository(f.pair_service.repository).verify(
            db, old_generation
        )
        assert verified["retired_at"] is not None
        new = await db.scalar(
            select(PairIntent).where(
                PairIntent.session_id == row.session_id, PairIntent.retired_at.is_(None)
            )
        )
        assert new is not None and new.generation != old_generation
        assert new.retained_from is None and new.egress_state_id != old_state
        assert new.relay_custody["public_keys"] != old_custody
        assert not await f.h.repository.mark_ready(
            db, original_sandbox, datetime.now(UTC), old.claim_changed
        )
        assert await f.h.repository.mark_ready(
            db, row.sandbox_id, datetime.now(UTC), row.status_changed_at
        )


@pytest.mark.parametrize("fault", ["capture", "claim", "retirement"])
async def test_recovery_never_builds_fresh_before_all_terminal_proof_commits(
    ready_world, fault, monkeypatch
):
    f = ready_world
    await condemn(f)
    before = len(f.remote.created)
    old_pvc_id = f.work.pvc_id
    if fault == "capture":
        monkeypatch.setattr(f.pair_service.pair_capture, "capture", AsyncMock(return_value=False))
        await recovery(f).execute(f.row.session_id)
    elif fault == "claim":
        stale = f.claim
        async with f.h.sessions.begin() as db:
            row = await db.get(SandboxSession, f.row.session_id)
            row.status_changed_at += timedelta(microseconds=1)
        # Execute the stale in-memory claim, not a newly observed claim.
        with pytest.raises(RuntimeError):
            await recovery(f)._execute(stale, [f.work])
    else:
        async def refused(self, db, expected, now, **kwargs):
            return False

        monkeypatch.setattr(PairRetirementRepository, "retire", refused)
        await recovery(f).execute(f.row.session_id)
    assert len(f.remote.created) == before
    async with f.h.sessions.begin() as db:
        assert await db.get(SessionPVC, old_pvc_id) is not None
    assert await stored_works(f)


async def test_recovery_retry_carries_unissued_interim_identity_without_legacy_deletion(
    ready_world,
):
    f = ready_world
    old_generation = await condemn(f)
    # A crashed first attempt rotated to an interim identity that never built:
    # no PairIntent, no EgressState, a snapshotless recovery work, all uids None.
    async with f.h.sessions.begin() as db:
        row = await db.get(SandboxSession, f.row.session_id)
        row.sandbox_id = uuid4()
        db.add(
            CleanupWork(
                work_id=uuid4(),
                session_id=row.session_id,
                sandbox_id=row.sandbox_id,
                pvc_id=None,
                kind="recovery",
                state_changed=row.status_changed_at,
                pvc_changed=None,
                deadline=datetime.now(UTC) + timedelta(seconds=120),
                targets=sandbox_targets(row, retain=False),
                acknowledged=False,
                pair_snapshot=None,
            )
        )
    await recovery(f).execute(f.row.session_id)
    async with f.h.sessions.begin() as db:
        row = await db.get(SandboxSession, f.row.session_id)
        assert row.status == "creating"
        assert list(await stored_works(f)) == []
        # The fresh build created exactly one new generation for the interim
        # identity; the original generation stayed retired.
        generations = list(
            await db.scalars(
                select(PairIntent.generation).where(PairIntent.session_id == row.session_id)
            )
        )
        assert set(generations) == {old_generation,
            await db.scalar(
                select(PairIntent.generation).where(
                    PairIntent.session_id == row.session_id,
                    PairIntent.retired_at.is_(None),
                )
            )
        }
        assert await PairRetirementRepository(f.pair_service.repository).verify(
            db, old_generation
        )


async def test_fresh_admission_refuses_surviving_original_pvc_without_retirement(
    ready_world,
):
    f = ready_world
    async with f.h.sessions.begin() as db:
        row = await db.get(SandboxSession, f.row.session_id)
        row.status = "stopped"
        row.status_changed_at = datetime.now(UTC)
    with pytest.raises(RuntimeError):
        async with f.h.sessions.begin() as db:
            current = await db.get(SandboxSession, f.row.session_id)
            await f.h.repository.claim(db, current, uuid4(), datetime.now(UTC), paired=True)
