# ruff: noqa: F811
from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from sqlalchemy import delete, select

from ads_sandbox_manager.egress_state_store import EgressState, EgressStateRepository
from ads_sandbox_manager.lifecycle_store import CleanupWork
from ads_sandbox_manager.pair_retirement import PairRetirement, PairRetirementRepository
from ads_sandbox_manager.pair_store import PairClaimLost, PairIntent, PairIntentRepository
from ads_sandbox_manager.store import SandboxSession
from test_kube_release import api  # noqa: F401
from test_pair_controls import controls  # noqa: F401
from test_pair_creation import creation  # noqa: F401
from test_pair_creator_fence import cleanup_claim
from test_pair_store import ledger, snapshot  # noqa: F401
from test_pair_volume_publication import publication as volume_publication  # noqa: F401
from test_session_objects import object_settings  # noqa: F401
from test_sessions import sessions_harness  # noqa: F401

pytestmark = pytest.mark.anyio


@pytest.fixture
async def retired(creation):
    """Build a ready pair, recover it, and reach the retirement boundary."""
    from test_pair_creation import build

    f = creation
    await build(f)
    capture, work, claim = await cleanup_claim(f)
    f.capture, f.work, f.claim = capture, work, claim
    async with f.h.sessions.begin() as db:
        f.intent = await db.scalar(
            select(PairIntent).where(PairIntent.session_id == f.row.session_id)
        )
    return f


async def retire(f, db):
    return await PairRetirementRepository(f.capture.repository).retire(
        db,
        f.work,
        datetime.now(UTC),
        recovery=f.claim,
        recovery_seconds=f.capture.settings.recovery_seconds,
    )


async def test_retirement_sets_fence_and_retired_at_only(retired):
    f = retired
    async with f.h.sessions.begin() as db:
        assert await retire(f, db) is True
        intent = await db.get(PairIntent, f.intent.generation)
        assert intent.retired_at is not None
        assert intent.creation_fenced
        assert intent.cleanup_journal is None
        assert await db.get(PairRetirement, f.intent.generation) is None
    async with f.h.sessions.begin() as db:
        # Idempotent: a second retire keeps the original timestamp.
        first = (await db.get(PairIntent, f.intent.generation)).retired_at
        assert await retire(f, db) is True
        assert (await db.get(PairIntent, f.intent.generation)).retired_at == first
        await db.execute(
            delete(SandboxSession).where(SandboxSession.session_id == f.row.session_id)
        )
    async with f.h.sessions.begin() as db:
        assert await db.get(CleanupWork, f.work.work_id) is None
        verified = await PairRetirementRepository(f.capture.repository).verify(
            db, f.intent.generation
        )
        assert verified["retired_at"] is not None


async def test_retirement_and_lifecycle_transaction_roll_back_together(retired):
    f = retired
    with pytest.raises(RuntimeError, match="abort transition"):
        async with f.h.sessions.begin() as db:
            assert await retire(f, db)
            raise RuntimeError("abort transition")
    async with f.h.sessions.begin() as db:
        assert await db.get(PairRetirement, f.intent.generation) is None
        assert (await db.get(PairIntent, f.intent.generation)).retired_at is None
        assert await retire(f, db)


async def test_unsettled_writers_block_retirement(retired):
    f = retired
    async with f.h.sessions.begin() as db:
        intent = await db.get(PairIntent, f.intent.generation)
        intent.control_dispatch = {**intent.control_dispatch, "Service/egress": "inflight"}
    async with f.h.sessions.begin() as db:
        assert await retire(f, db) is False
    async with f.h.sessions.begin() as db:
        assert (await db.get(PairIntent, f.intent.generation)).retired_at is None


async def test_retired_creator_cannot_reenter_or_settle_original_writes(retired):
    f = retired
    async with f.h.sessions.begin() as db:
        assert await retire(f, db)
    with pytest.raises(PairClaimLost, match="retired"):
        async with f.h.sessions.begin() as db:
            await PairIntentRepository().settle(db, f.intent, "Service", "egress")
    async with f.h.sessions.begin() as db:
        generations = list(await db.scalars(select(PairIntent.generation)))
        assert generations == [f.intent.generation]


async def test_retired_state_writer_records_return_after_pair_row_loss(retired):
    f = retired
    async with f.h.sessions.begin() as db:
        assert await retire(f, db)
        state = await db.get(EgressState, UUID(str(f.work.pair_snapshot["egress_state_id"])))
        assert state is not None
        await db.execute(delete(PairIntent).where(PairIntent.generation == f.intent.generation))
    # The independently retained original state reservation still records
    # its original invocation's normal return after pair row loss; with no
    # tombstones the retirement evidence dies with the pair row itself.
    async with f.h.sessions.begin() as db:
        await EgressStateRepository(PairIntentRepository()).settle(db, state, "key")
    async with f.h.sessions.begin() as db:
        assert (await db.get(EgressState, state.state_id)).key_dispatch == "settled"


async def test_retired_untracked_generation_is_not_a_live_creator_fence(retired):
    f = retired
    async with f.h.sessions.begin() as db:
        assert await retire(f, db)
        intent = await db.get(PairIntent, f.intent.generation)
        intent.creation_fenced = False
    async with f.h.sessions.begin() as db:
        with pytest.raises(PairClaimLost):
            await PairRetirementRepository(f.capture.repository).verify(db, f.intent.generation)
        # The fence is part of the durable record; restore it.
        intent = await db.get(PairIntent, f.intent.generation)
        intent.creation_fenced = True
