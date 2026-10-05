# ruff: noqa: F811
"""O2 retained transfer: plain-column retirement feeds exclusive inheritance."""

from __future__ import annotations

import asyncio
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select

from ads_sandbox_manager.egress_state_store import (
    EgressState,
    EgressStateRepository,
    state_snapshot,
)
from ads_sandbox_manager.pair_store import PairClaimLost, PairIntent, PairIntentRepository
from ads_sandbox_manager.pair_transfer import PairTransfer, PairTransferRepository
from ads_sandbox_manager.store import SandboxSession, SessionPVC
from test_kube_release import api  # noqa: F401
from test_pair_controls import controls  # noqa: F401
from test_pair_creation import build, creation  # noqa: F401
from test_pair_store import ledger, snapshot  # noqa: F401
from test_pair_teardown_world import pair_world, retire  # noqa: F401
from test_pair_volume_publication import publication as volume_publication  # noqa: F401
from test_session_objects import object_settings  # noqa: F401
from test_sessions import row_for, sessions_harness  # noqa: F401

pytestmark = pytest.mark.anyio


async def stopped(f):
    await retire(f)
    async with f.h.sessions.begin() as db:
        return await db.get(SandboxSession, f.row.session_id)


async def claim(f, row):
    async with f.h.sessions.begin() as db:
        return await f.h.repository.claim(db, row, uuid4(), datetime.now(UTC), paired=True)


async def begin(f, row):
    async with f.h.sessions.begin() as db:
        return await PairIntentRepository().begin(
            db,
            row,
            row.claimed_by,
            namespace=f.adapter.namespace,
            golden_version=f.adapter.golden_version,
            resume=True,
        )


async def test_idle_transfer_preserves_exact_state_workspace_and_creator(pair_world):
    f = pair_world
    await retire(f)
    remote = deepcopy(f.remote.objects)
    row = await row_for(f.h, f.row.session_id)
    current = await claim(f, row)
    assert current is not None
    new = await begin(f, current)
    assert new.generation != f.intent.generation and new.retained_from == f.intent.generation
    assert new.sandbox_id == f.intent.sandbox_id
    assert new.egress_state_id == UUID(f.work.pair_snapshot["egress_state_id"])
    assert (
        new.volume_resources["workspace"]["uid"]
        == f.work.pair_snapshot["volume_resources"]["workspace"]["uid"]
    )
    async with f.h.sessions.begin() as db:
        receipt = await PairTransferRepository(f.pair_service.repository).verify(db, new)
        assert receipt.predecessor == f.intent.generation
        original = await db.get(EgressState, new.egress_state_id)
        assert state_snapshot(original) == f.work.pair_snapshot["egress_state"]
        state, key = await EgressStateRepository(PairIntentRepository()).reserve(
            db,
            current,
            current.claimed_by,
            new.generation,
            storage_bytes=original.storage_bytes,
        )
        assert key is None and state.state_id == original.state_id
        await f.retirements.verify(db, f.intent.generation)
        assert (
            len(list(await db.scalars(select(PairIntent).where(PairIntent.retired_at.is_(None)))))
            == 1
        )
    assert f.remote.objects == remote
    assert (await begin(f, current)).generation == new.generation


async def test_competing_resumes_share_one_claim_and_one_transfer(pair_world):
    f = pair_world
    await retire(f)
    row = await row_for(f.h, f.row.session_id)
    first, second = await asyncio.gather(claim(f, row), claim(f, row))
    assert (first is None) != (second is None)
    current = first or second
    left, right = await asyncio.gather(begin(f, current), begin(f, current))
    assert left.generation == right.generation
    async with f.h.sessions.begin() as db:
        receipts = list(
            await db.scalars(
                select(PairTransfer).where(PairTransfer.sandbox_id == f.row.sandbox_id)
            )
        )
        assert len(receipts) == 1


async def test_transfer_refuses_changed_retained_identity_or_lifetime(pair_world):
    f = pair_world
    await retire(f)
    row = await row_for(f.h, f.row.session_id)
    async with f.h.sessions.begin() as db:
        value = await db.get(SessionPVC, row.pvc_id)
        value.uid = str(uuid4())
    with pytest.raises(RuntimeError):
        await claim(f, row)
    async with f.h.sessions.begin() as db:
        assert (
            await db.scalar(
                select(PairTransfer.generation).where(PairTransfer.sandbox_id == row.sandbox_id)
            )
            is None
        )


async def test_transfer_refuses_reaping_workspace(pair_world):
    f = pair_world
    await retire(f)
    row = await row_for(f.h, f.row.session_id)
    async with f.h.sessions.begin() as db:
        value = await db.get(SessionPVC, row.pvc_id)
        value.state = "destroying"
    with pytest.raises(RuntimeError):
        await claim(f, row)
    async with f.h.sessions.begin() as db:
        assert (
            await db.scalar(
                select(PairTransfer.generation).where(PairTransfer.sandbox_id == row.sandbox_id)
            )
            is None
        )


async def test_transfer_refuses_changed_owner_or_lifetime(pair_world):
    f = pair_world
    await retire(f)
    row = await row_for(f.h, f.row.session_id)
    async with f.h.sessions.begin() as db:
        value = await db.get(SandboxSession, row.session_id)
        value.project_id = uuid4()
    with pytest.raises(RuntimeError):
        await claim(f, row)


async def test_transfer_refuses_lost_claim_lifetime(pair_world):
    f = pair_world
    await retire(f)
    row = await row_for(f.h, f.row.session_id)
    async with f.h.sessions.begin() as db:
        value = await db.get(SandboxSession, row.session_id)
        value.status_changed_at += timedelta(microseconds=1)
    assert await claim(f, row) is None


async def test_legacy_claim_and_fresh_builder_cannot_adopt_retired_resources(pair_world):
    f = pair_world
    await retire(f)
    row = await row_for(f.h, f.row.session_id)
    with pytest.raises(RuntimeError, match="retained"):
        async with f.h.sessions.begin() as db:
            await f.h.repository.claim(db, row, uuid4(), datetime.now(UTC))
    current = await claim(f, row)
    with pytest.raises(PairClaimLost, match="transfer"):
        async with f.h.sessions.begin() as db:
            await PairIntentRepository().begin(
                db,
                current,
                current.claimed_by,
                namespace=f.adapter.namespace,
                golden_version=f.adapter.golden_version,
            )
    assert await begin(f, current)
