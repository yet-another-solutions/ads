# ruff: noqa: F811
from __future__ import annotations

import asyncio
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import msgspec
import pytest

from ads_sandbox_manager.lifecycle_store import CleanupWork
from ads_sandbox_manager.pair_disposal import (
    PairDisposal,
    PairDisposalRepository,
    PairRetainedDisposal,
)
from ads_sandbox_manager.pair_retirement import PairRetirementRepository
from ads_sandbox_manager.pair_store import PairClaimLost
from ads_sandbox_manager.store import SandboxSession, SessionPVC
from test_kube_release import api  # noqa: F401
from test_node_release_wire import node_report  # noqa: F401
from test_pair_cleanup_journal import journal  # noqa: F401
from test_pair_controls import controls  # noqa: F401
from test_pair_creation import creation  # noqa: F401
from test_pair_resource_teardown import resources  # noqa: F401
from test_pair_runtime_teardown import lifecycle, teardown  # noqa: F401
from test_pair_store import ledger, snapshot  # noqa: F401
from test_pair_transfer import claim, stopped
from test_pair_volume_publication import publication as volume_publication  # noqa: F401
from test_session_objects import object_settings  # noqa: F401
from test_sessions import sessions_harness  # noqa: F401

pytestmark = pytest.mark.anyio


async def reap(f, row):
    async with f.h.sessions.begin() as db:
        return await f.capture.repository.reap(
            db, row.session_id, row.sandbox_id, row.pvc_id, datetime.now(UTC), 0, 0, 120
        )


async def prepare(f):
    row = await stopped(f)
    work = await reap(f, row)
    assert work is not None
    return row, work, PairRetainedDisposal(f.resource_stage)


@pytest.mark.parametrize("resources", ["idle"], indirect=True)
async def test_actual_idle_entrypoint_reaches_retirement_and_reap_ends_whole_lifetime(resources):
    f = resources
    service = lifecycle(f)
    service.pair_resources = f.resource_stage
    await service.execute(f.work.work_id)
    async with f.h.sessions.begin() as db:
        row = await db.get(SandboxSession, f.row.session_id)
        assert row.status == "stopped"
        saved = await PairRetirementRepository(f.capture.repository).verify(db, f.intent.generation)
        old_journal = deepcopy(saved.journal)
        assert await db.get(CleanupWork, f.work.work_id) is None
    work = await reap(f, row)
    assert work is not None
    before = len(f.remote.created)
    await service.execute(work.work_id)
    async with f.h.sessions.begin() as db:
        receipt = await PairDisposalRepository(f.capture.repository).verify(db, f.intent.generation)
        assert receipt.completed_at is not None
        assert set(receipt.dispositions) == {"workspace", "state", "key", "topics"}
        assert await db.get(SessionPVC, row.pvc_id) is None
        assert await db.get(CleanupWork, work.work_id) is None
        current = await db.get(SandboxSession, row.session_id)
        assert current.status == "stopped" and current.pvc_id is None
        assert current.sandbox_id != row.sandbox_id
        saved = await PairRetirementRepository(f.capture.repository).verify(db, f.intent.generation)
        assert saved.journal == old_journal
        await PairRetirementRepository(f.capture.repository).require_destroyed_history(db, current)
    assert not f.remote.objects and len(f.remote.created) == before
    f.topic_disposal.remove.assert_awaited_once_with(row.sandbox_id)
    assert await claim(f, current) is not None


@pytest.mark.parametrize("resources", ["idle"], indirect=True)
async def test_expiry_and_resume_serialize_on_original_session_and_workspace(resources):
    f = resources
    row = await stopped(f)
    result = await asyncio.gather(claim(f, row), reap(f, row), return_exceptions=True)
    if getattr(result[0], "status", None) == "creating":
        assert result[1] is None
        async with f.h.sessions.begin() as db:
            assert await db.get(PairDisposal, f.intent.generation) is None
    else:
        assert isinstance(result[0], PairClaimLost) or result[0] is None
        assert isinstance(result[1], CleanupWork)
        assert await PairRetainedDisposal(f.resource_stage).dispose(result[1])


@pytest.mark.parametrize("resources", ["idle"], indirect=True)
async def test_lost_original_delete_and_reclaim_lag_resume_without_changing_retirement(resources):
    f = resources
    _, work, stage = await prepare(f)
    f.block_lost = True
    with pytest.raises(TimeoutError):
        await stage.dispose(work)
    assert await stage.dispose(work)
    deletes = [event for event in f.block_events if event.startswith("delete:")]
    assert len(deletes) == len(set(deletes))
    async with f.h.sessions.begin() as db:
        assert (await stage.repository.verify(db, f.intent.generation)).completed_at


@pytest.mark.parametrize("resources", ["idle"], indirect=True)
@pytest.mark.parametrize("fault", ["busy", "proof", "pv", "claim", "cancel", "reclaim"])
async def test_expiry_keeps_original_evidence_under_external_and_claim_faults(resources, fault):
    f = resources
    row, work, stage = await prepare(f)
    before = deepcopy(f.remote.objects)
    if fault == "busy":
        f.block_busy = True
    elif fault == "proof":
        original = f.node.observe_block

        async def replaced(value):
            result = msgspec.json.decode(await original(value))
            result["boot_id"] = str(uuid4())
            return msgspec.json.encode(result)

        f.node.observe_block = replaced
    elif fault == "pv":
        original = f.adapter.kube.core.read_persistent_volume.side_effect

        def changed(name, **kwargs):
            value = deepcopy(original(name, **kwargs))
            value["metadata"]["uid"] = str(uuid4())
            return value

        f.adapter.kube.core.read_persistent_volume.side_effect = changed
    elif fault in ("claim", "cancel"):

        async def hook():
            if fault == "cancel":
                raise asyncio.CancelledError
            async with f.h.sessions.begin() as db:
                current = await db.get(SandboxSession, row.session_id)
                current.status_changed_at += timedelta(microseconds=1)

        f.block_hook = hook
    else:
        f.block_reclaim = False
    if fault in ("busy", "reclaim"):
        assert not await stage.dispose(work)
    else:
        with pytest.raises((RuntimeError, asyncio.CancelledError)):
            await stage.dispose(work)
    if fault != "reclaim":
        assert f.remote.objects == before
    async with f.h.sessions.begin() as db:
        receipt = await db.get(PairDisposal, f.intent.generation)
        assert receipt.completed_at is None and not receipt.dispositions
        assert await db.get(CleanupWork, work.work_id)
    if fault == "claim":
        assert await claim(f, row) is None
    else:
        with pytest.raises(PairClaimLost):
            await claim(f, row)


@pytest.mark.parametrize("resources", ["idle"], indirect=True)
async def test_timeout_cannot_supersede_expiry_and_lost_work_never_reenables_transfer(resources):
    f = resources
    row, work, _ = await prepare(f)
    async with f.h.sessions.begin() as db:
        assert not await f.capture.repository.recover(
            db, row.session_id, row.sandbox_id, datetime.now(UTC) + timedelta(days=1), 120
        )
        await db.delete(await db.get(CleanupWork, work.work_id))
    with pytest.raises(PairClaimLost):
        await claim(f, row)
    async with f.h.sessions.begin() as db:
        assert await db.get(PairDisposal, f.intent.generation) is not None
