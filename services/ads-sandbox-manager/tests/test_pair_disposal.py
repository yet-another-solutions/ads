# ruff: noqa: F811
"""O2 retained expiry: exclusive whole-lifetime disposal of retired storage."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import delete, select

from ads_sandbox_manager.lifecycle_store import CleanupWork
from ads_sandbox_manager.pair_disposal import PairDisposal
from ads_sandbox_manager.pair_store import PairClaimLost
from ads_sandbox_manager.store import SandboxSession, SessionPVC
from test_kube_release import api  # noqa: F401
from test_pair_controls import controls  # noqa: F401
from test_pair_creation import build, creation  # noqa: F401
from test_pair_store import ledger, snapshot  # noqa: F401
from test_pair_teardown_world import (
    pair_world,  # noqa: F401  (pytest fixture injection, mirrors HEAD imports)
    reconcile,
    retire,
)
from test_pair_volume_publication import publication as volume_publication  # noqa: F401
from test_session_objects import object_settings  # noqa: F401
from test_sessions import row_for, sessions_harness  # noqa: F401

pytestmark = pytest.mark.anyio


async def reap(f, row):
    async with f.h.sessions.begin() as db:
        return await f.pair_service.repository.reap(
            db, row.session_id, row.sandbox_id, row.pvc_id, datetime.now(UTC), 0, 0, 120
        )


async def stopped(f):
    await retire(f)
    return await row_for(f.h, f.row.session_id)


async def claim(f, row):
    async with f.h.sessions.begin() as db:
        return await f.h.repository.claim(db, row, uuid4(), datetime.now(UTC), paired=True)


async def test_reap_opens_exclusive_disposal_and_finish_ends_whole_lifetime(pair_world):
    f = pair_world
    row = await stopped(f)
    work = await reap(f, row)
    assert work is not None and work.kind == "reap"
    async with f.h.sessions.begin() as db:
        receipt = await f.disposals.verify(db, f.intent.generation)
        assert receipt.completed_at is None
    await f.pair_service.execute(work.work_id)
    async with f.h.sessions.begin() as db:
        receipt = await f.disposals.verify(db, f.intent.generation)
        assert receipt.completed_at is not None
        assert await db.get(SessionPVC, row.pvc_id) is None
        assert await db.get(CleanupWork, work.work_id) is None
        current = await db.get(SandboxSession, row.session_id)
        assert current.status == "stopped" and current.pvc_id is None
        assert current.sandbox_id != row.sandbox_id
        await f.retirements.verify(db, f.intent.generation)
    assert not f.remote.objects
    # A fresh paired admission starts a new sandbox lifetime on the same session.
    resumed = await claim(f, await row_for(f.h, row.session_id))
    assert resumed is not None


async def test_expiry_and_resume_serialize_on_original_session_and_workspace(pair_world):
    f = pair_world
    row = await stopped(f)
    results = await asyncio.gather(claim(f, row), reap(f, row), return_exceptions=True)
    claim_result, reap_result = results
    if not isinstance(claim_result, BaseException) and claim_result is not None:
        # The claim won; the reap must have found the PVC attaching (not detached).
        assert reap_result is None or isinstance(reap_result, BaseException)
    else:
        assert isinstance(claim_result, PairClaimLost) or claim_result is None
        assert isinstance(reap_result, CleanupWork)


async def test_disposal_finish_requires_original_ownership_under_faults(pair_world):
    f = pair_world
    row = await stopped(f)
    work = await reap(f, row)
    async with f.h.sessions.begin() as db:
        value = await db.get(SandboxSession, row.session_id)
        value.status_changed_at += timedelta(microseconds=1)
    with pytest.raises(PairClaimLost):
        async with f.h.sessions.begin() as db:
            await f.disposals.finish(db, work, datetime.now(UTC))
    async with f.h.sessions.begin() as db:
        receipt = await db.get(PairDisposal, f.intent.generation)
        assert receipt.completed_at is None
        assert await db.get(CleanupWork, work.work_id) is not None


async def test_lost_reap_work_recovers_same_exclusive_receipt(pair_world):
    f = pair_world
    row = await stopped(f)
    work = await reap(f, row)
    async with f.h.sessions.begin() as db:
        await db.delete(await db.get(CleanupWork, work.work_id))
    recovered = await reconcile(f)
    assert recovered is not None and recovered.kind == "reap"
    assert recovered.work_id == work.work_id
    await f.pair_service.execute(recovered.work_id)
    async with f.h.sessions.begin() as db:
        receipt = await f.disposals.verify(db, f.intent.generation)
        assert receipt.completed_at is not None
        assert await db.get(CleanupWork, recovered.work_id) is None
    assert not f.remote.objects


async def test_retired_orphan_without_session_reconciles_and_disposes(pair_world):
    f = pair_world
    row = await stopped(f)
    async with f.h.sessions.begin() as db:
        await db.execute(delete(SandboxSession).where(SandboxSession.session_id == row.session_id))
    work = await reconcile(f)
    assert work is not None and work.kind == "orphan" and work.session_id is None
    assert work.pair_snapshot is None
    await f.pair_service.execute(work.work_id)
    async with f.h.sessions.begin() as db:
        receipt = await f.disposals.verify(db, f.intent.generation)
        assert receipt.completed_at is not None
        assert (
            await db.scalar(
                select(CleanupWork.work_id).where(CleanupWork.sandbox_id == f.intent.sandbox_id)
            )
            is None
        )
    assert not f.remote.objects


async def test_maintenance_cannot_reopen_retired_pair_as_legacy_cleanup(pair_world):
    f = pair_world
    row = await stopped(f)
    before = dict(f.remote.objects)
    async with f.h.sessions.begin() as db:
        assert (
            await f.pair_service.repository.service(
                db,
                row.session_id,
                row.sandbox_id,
                datetime.now(UTC),
                120,
                [],
            )
            is None
        )
    async with f.h.sessions.begin() as db:
        current = await db.get(SandboxSession, row.session_id)
        assert current.status == "stopped" and current.pvc_id == row.pvc_id
        assert (
            await db.scalar(
                select(CleanupWork.work_id).where(CleanupWork.sandbox_id == row.sandbox_id)
            )
            is None
        )
    assert f.remote.objects == before
