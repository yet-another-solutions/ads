# ruff: noqa: F811
from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from ads_sandbox_manager.egress_state_store import EgressState
from ads_sandbox_manager.lifecycle_store import CleanupWork
from ads_sandbox_manager.pair_store import (
    CONTROL_RESOURCES,
    PairClaimLost,
    PairIntent,
    resource_key,
)
from test_kube_release import api  # noqa: F401
from test_pair_controls import controls  # noqa: F401
from test_pair_creation import build, creation  # noqa: F401
from test_pair_creator_fence import cleanup_claim
from test_pair_store import begin, ledger, snapshot  # noqa: F401
from test_pair_volume_publication import publication as volume_publication  # noqa: F401
from test_relay_custody_cleanup import saved
from test_session_objects import object_settings  # noqa: F401
from test_sessions import sessions_harness  # noqa: F401

pytestmark = pytest.mark.anyio
WRITERS = (
    [("control_dispatch", resource_key(*item)) for item in CONTROL_RESOURCES]
    + [
        ("compute_dispatch", f"Pod/{role}")
        for role in ("guest", "guest-relay", "egress-relay", "egress")
    ]
    + [("relay_inputs", role) for role in ("guest-relay", "egress-relay")]
    + [("volume_resources", role) for role in ("workspace", "guest", "egress", "key")]
    + [("ipc_resources", role) for role in ("volume", "deployment")]
    + [("relay_custody", None), ("topics_dispatch", None), ("state", "volume"), ("state", "key")]
)


async def check(f, capture, work, claim):
    async with f.h.sessions.begin() as db:
        return await capture.repository.pair_writers_settled(
            db, work, datetime.now(UTC), recovery=claim, recovery_seconds=120
        )


async def test_full_pair_settles_without_claiming_release_or_erasing_snapshots(creation):
    f = creation
    await build(f)
    created = tuple(f.remote.created)
    capture, work, claim = await cleanup_claim(f)
    initial = deepcopy(work.pair_snapshot)
    assert await capture.capture(work, recovery=claim)
    current = await saved(f, work)
    assert current.pair_snapshot == initial
    assert (await snapshot(f, f.intent.generation)).creation_fenced
    assert await check(f, capture, current, claim)
    async with f.h.sessions.begin() as db:
        assert not await capture.repository.complete(db, current, datetime.now(UTC))
        intent = await db.get(PairIntent, f.intent.generation)
        assert intent is not None
        assert await db.get(EgressState, intent.egress_state_id) is not None
    assert tuple(f.remote.created) == created


@pytest.mark.parametrize("field,role", WRITERS)
async def test_each_inflight_writer_blocks_even_with_every_uid_captured(creation, field, role):
    f = creation
    await build(f)
    async with f.h.sessions.begin() as db:
        intent = await db.get(PairIntent, f.intent.generation)
        if field == "state":
            state = await db.get(EgressState, intent.egress_state_id)
            if role == "key":
                state.key_dispatch = "inflight"
                state.volume_dispatch, state.volume_uid = "unissued", None
            else:
                state.volume_dispatch = "inflight"
        elif field == "topics_dispatch":
            intent.topics_dispatch = "inflight"
        elif field == "relay_custody":
            intent.relay_custody = {**intent.relay_custody, "dispatch": "inflight"}
        else:
            value = deepcopy(getattr(intent, field))
            if field.endswith("_dispatch"):
                value[role] = "inflight"
            else:
                value[role]["dispatch"] = "inflight"
            setattr(intent, field, value)
    capture, work, claim = await cleanup_claim(f)
    assert not await capture.capture(work, recovery=claim)
    current = await saved(f, work)
    assert not await check(f, capture, current, claim)
    assert all(current.pair_snapshot["control_uids"].values())
    assert all(current.pair_snapshot["compute_uids"].values())
    assert current.pair_snapshot == work.pair_snapshot


@pytest.mark.parametrize(
    "field", ["claim_owner", "claim_changed", "control_dispatch", "compute_dispatch"]
)
async def test_creator_scope_or_dispatch_cannot_change_after_capture(creation, field):
    f = creation
    await build(f)
    capture, work, claim = await cleanup_claim(f)
    async with f.h.sessions.begin() as db:
        intent = await db.get(PairIntent, f.intent.generation)
        if field == "claim_owner":
            intent.claim_owner = uuid4()
        elif field == "claim_changed":
            intent.claim_changed += timedelta(microseconds=1)
        else:
            entries = dict(getattr(intent, field))
            entries[next(iter(entries))] = "unissued"
            setattr(intent, field, entries)
    if field.startswith("claim_"):
        with pytest.raises(PairClaimLost):
            await check(f, capture, work, claim)
    else:
        assert not await check(f, capture, work, claim)
    assert (await saved(f, work)).pair_snapshot == work.pair_snapshot


@pytest.mark.parametrize("family", ["control", "compute"])
async def test_settled_missing_uid_and_unissued_observed_uid_are_not_positive(creation, family):
    f = creation
    await build(f)
    capture, work, claim = await cleanup_claim(f)
    async with f.h.sessions.begin() as db:
        intent = await db.get(PairIntent, f.intent.generation)
        stored = await db.get(CleanupWork, work.work_id)
        key = next(iter(getattr(intent, f"{family}_uids")))
        setattr(intent, f"{family}_uids", {**getattr(intent, f"{family}_uids"), key: None})
        value = deepcopy(stored.pair_snapshot)
        value[f"{family}_uids"][key] = None
        stored.pair_snapshot = value
    current = await saved(f, work)
    assert not await check(f, capture, current, claim)
    async with f.h.sessions.begin() as db:
        intent = await db.get(PairIntent, f.intent.generation)
        stored = await db.get(CleanupWork, work.work_id)
        setattr(
            intent, f"{family}_dispatch", {**getattr(intent, f"{family}_dispatch"), key: "unissued"}
        )
        value = deepcopy(stored.pair_snapshot)
        value[f"{family}_dispatch"][key] = "unissued"
        value[f"{family}_uids"][key] = "observed-without-dispatch"
        stored.pair_snapshot = value
    assert not await check(f, capture, await saved(f, work), claim)


async def test_fenced_never_dispatched_pair_has_no_writer_but_is_not_retired(controls):
    f = controls
    intent = await begin(f)
    capture, work, claim = await cleanup_claim(f)
    assert await capture.capture(work, recovery=claim)
    assert not f.remote.created
    assert (await snapshot(f, intent.generation)).creation_fenced
    async with f.h.sessions.begin() as db:
        assert not await capture.repository.complete(db, await saved(f, work), datetime.now(UTC))
