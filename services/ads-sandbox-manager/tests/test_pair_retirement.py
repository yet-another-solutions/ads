# ruff: noqa: F811
from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import delete, select

from ads_sandbox_manager.lifecycle_store import CleanupWork
from ads_sandbox_manager.pair_retirement import PairRetirement, PairRetirementRepository
from ads_sandbox_manager.pair_store import PairClaimLost, PairIntent, PairIntentRepository
from ads_sandbox_manager.store import SandboxSession
from test_kube_release import api  # noqa: F401
from test_node_release_wire import node_report  # noqa: F401
from test_pair_cleanup_journal import journal  # noqa: F401
from test_pair_controls import controls  # noqa: F401
from test_pair_creation import creation  # noqa: F401
from test_pair_resource_teardown import dispose, resources  # noqa: F401
from test_pair_runtime_teardown import state, teardown  # noqa: F401
from test_pair_store import ledger, snapshot  # noqa: F401
from test_pair_volume_publication import publication as volume_publication  # noqa: F401
from test_session_objects import object_settings  # noqa: F401
from test_sessions import sessions_harness  # noqa: F401

pytestmark = pytest.mark.anyio


async def retire(f, db):
    return await PairRetirementRepository(f.capture.repository).retire(
        db,
        f.work,
        datetime.now(UTC),
        recovery=f.claim,
        recovery_seconds=f.runtime.settings.recovery_seconds,
    )


@pytest.mark.parametrize("resources", ["idle", "recovery"], indirect=True)
async def test_terminal_tombstone_survives_work_and_session_loss(resources):
    f = resources
    assert await dispose(f)
    original = await state(f)
    async with f.h.sessions.begin() as db:
        saved = await retire(f, db)
        assert saved is not None and saved.journal == original
        assert saved.kind == f.work.kind and saved.work_id == f.work.work_id
    async with f.h.sessions.begin() as db:
        again = await retire(f, db)
        assert again is not None and again.retired_at == saved.retired_at
        await db.execute(
            delete(SandboxSession).where(SandboxSession.session_id == f.row.session_id)
        )
    async with f.h.sessions.begin() as db:
        assert await db.get(CleanupWork, f.work.work_id) is None
        verified = await PairRetirementRepository(f.capture.repository).verify(
            db, f.intent.generation
        )
        assert verified.journal == original and verified.retired_at == saved.retired_at
        intent = await db.get(PairIntent, f.intent.generation)
        assert intent.creation_fenced and intent.retired_at == saved.retired_at
    with pytest.raises(PairClaimLost):
        await dispose(f)


async def test_retirement_and_lifecycle_transaction_roll_back_together(resources):
    f = resources
    assert await dispose(f)
    with pytest.raises(RuntimeError, match="abort transition"):
        async with f.h.sessions.begin() as db:
            assert await retire(f, db)
            raise RuntimeError("abort transition")
    async with f.h.sessions.begin() as db:
        assert await db.get(PairRetirement, f.intent.generation) is None
        assert (await db.get(PairIntent, f.intent.generation)).retired_at is None
        assert await retire(f, db)


async def test_incomplete_terminal_obligation_does_not_retire(resources):
    f = resources
    async with f.h.sessions.begin() as db:
        assert await retire(f, db) is None
        assert await db.get(PairRetirement, f.intent.generation) is None
    assert await dispose(f)
    async with f.h.sessions.begin() as db:
        assert await retire(f, db)


@pytest.mark.parametrize("fault", ["claim", "snapshot", "writer", "runtime", "storage", "topics"])
async def test_retirement_rechecks_original_claim_and_every_proof(resources, fault):
    f = resources
    assert await dispose(f)
    async with f.h.sessions.begin() as db:
        intent = await db.get(PairIntent, f.intent.generation)
        value = deepcopy(intent.cleanup_journal)
        if fault == "claim":
            row = await db.get(SandboxSession, f.row.session_id)
            row.status_changed_at += timedelta(microseconds=1)
        elif fault == "snapshot":
            intent.control_uids = {**intent.control_uids, "Service/egress": str(uuid4())}
        elif fault == "writer":
            intent.control_dispatch = {**intent.control_dispatch, "Service/egress": "inflight"}
        elif fault == "runtime":
            value["runtime_release"] = None
        elif fault == "storage":
            value["block_disposition"] = {}
        else:
            value["topic_disposition"] = None
        intent.cleanup_journal = value
    if fault in ("topics", "writer", "snapshot"):
        async with f.h.sessions.begin() as db:
            assert await retire(f, db) is None
    else:
        with pytest.raises(RuntimeError):
            async with f.h.sessions.begin() as db:
                await retire(f, db)
    async with f.h.sessions.begin() as db:
        assert await db.get(PairRetirement, f.intent.generation) is None


@pytest.mark.parametrize("fault", ["digest", "journal", "creator", "disposition", "fence"])
async def test_tombstone_validation_rejects_tampering(resources, fault):
    f = resources
    assert await dispose(f)
    async with f.h.sessions.begin() as db:
        assert await retire(f, db)
    async with f.h.sessions.begin() as db:
        saved = await db.get(PairRetirement, f.intent.generation)
        intent = await db.get(PairIntent, f.intent.generation)
        if fault == "digest":
            saved.journal_sha256 = "0" * 64
        elif fault == "journal":
            saved.journal = {**saved.journal, "topic_disposition": None}
        elif fault == "creator":
            intent.claim_owner = uuid4()
        elif fault == "disposition":
            saved.kind = "idle"
        else:
            intent.creation_fenced = False
    with pytest.raises(RuntimeError):
        async with f.h.sessions.begin() as db:
            await PairRetirementRepository(f.capture.repository).verify(db, f.intent.generation)


async def test_retired_creator_cannot_reenter_or_settle_original_writes(resources):
    f = resources
    assert await dispose(f)
    async with f.h.sessions.begin() as db:
        assert await retire(f, db)
    with pytest.raises(PairClaimLost, match="retired"):
        async with f.h.sessions.begin() as db:
            await PairIntentRepository().settle(db, f.intent, "Service", "egress")
    async with f.h.sessions.begin() as db:
        generations = list(await db.scalars(select(PairIntent.generation)))
        assert generations == [f.intent.generation]
        assert await db.get(PairRetirement, f.intent.generation)
