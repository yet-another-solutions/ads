# ruff: noqa: F811
from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import delete, inspect, select, update
from sqlalchemy.exc import IntegrityError

from ads_sandbox_manager.pair_store import (
    CONTROL_RESOURCES,
    PairClaimLost,
    PairIntent,
    PairIntentRepository,
    resource_key,
)
from ads_sandbox_manager.store import SandboxSession
from test_session_objects import object_settings  # noqa: F401
from test_sessions import row_for, sessions_harness  # noqa: F401

pytestmark = pytest.mark.anyio


@pytest.fixture
async def ledger(sessions_harness):
    h = sessions_harness
    repository = PairIntentRepository()
    sid, owner = uuid4(), uuid4()
    async with h.sessions.begin() as db:
        await db.execute(delete(PairIntent))
        await h.repository.insert_pending(
            db, sid, uuid4(), h.settings.golden_version, datetime.now(UTC), h.projects.project
        )
        row = await h.repository.get(db, sid)
        row = await h.repository.claim(db, row, owner, datetime.now(UTC))
        assert row is not None
    yield SimpleNamespace(h=h, repo=repository, row=row, owner=owner)
    async with h.sessions.begin() as db:
        await db.execute(delete(PairIntent))


async def begin(f):
    async with f.h.sessions.begin() as db:
        return await f.repo.begin(
            db,
            f.row,
            f.owner,
            namespace=f.h.settings.namespace,
            golden_version=f.h.settings.golden_version,
        )


async def snapshot(f, generation):
    async with f.h.sessions.begin() as db:
        return await f.repo.snapshot(db, generation)


async def test_intent_is_atomic_visible_only_after_commit_and_stable_on_restart(ledger):
    f = ledger
    async with f.h.sessions.begin() as db:
        intent = await f.repo.begin(
            db, f.row, f.owner, namespace="ads-sandbox", golden_version="v0.0.33"
        )
        assert await snapshot(f, intent.generation) is None
    reloaded = await snapshot(f, intent.generation)
    assert reloaded.binding() == intent.binding()
    assert reloaded.session_id == f.row.session_id
    assert reloaded.project_id == f.row.project_id
    assert reloaded.claim_owner == f.owner
    assert reloaded.claim_changed == f.row.status_changed_at
    assert reloaded.namespace == "ads-sandbox"
    assert reloaded.golden_version == "v0.0.33"
    assert reloaded.control_uids == {
        resource_key(kind, role): None for kind, role in CONTROL_RESOURCES
    }
    async with f.h.sessions.begin() as db:
        again = await PairIntentRepository().begin(
            db, f.row, f.owner, namespace="ads-sandbox", golden_version="v0.0.33"
        )
    assert again.generation == intent.generation
    assert (await row_for(f.h, f.row.session_id)).status == "creating"
    assert not f.h.kube.calls  # FakeTopics also records every action here.


async def test_concurrent_same_claim_gets_one_generation(ledger):
    f = ledger
    left, right = await asyncio.gather(begin(f), begin(f))
    assert left.generation == right.generation
    async with f.h.sessions.begin() as db:
        assert len(list(await db.scalars(select(PairIntent)))) == 1


async def test_rollback_does_not_publish_intent(ledger):
    f = ledger
    with pytest.raises(RuntimeError, match="rollback"):
        async with f.h.sessions.begin() as db:
            intent = await f.repo.begin(
                db, f.row, f.owner, namespace="fixture", golden_version="v0.0.33"
            )
            generation = intent.generation
            raise RuntimeError("rollback")
    assert await snapshot(f, generation) is None
    assert (await begin(f)).generation != generation


@pytest.mark.parametrize("kind,role", CONTROL_RESOURCES)
async def test_uid_binding_is_committed_idempotent_and_never_replaced(ledger, kind, role):
    f = ledger
    intent = await begin(f)
    key = resource_key(kind, role)
    async with f.h.sessions.begin() as db:
        await f.repo.bind(db, f.row, f.owner, intent.generation, kind, role, "observed-uid")
        assert (await snapshot(f, intent.generation)).control_uids[key] is None
    async with f.h.sessions.begin() as db:
        await f.repo.bind(db, f.row, f.owner, intent.generation, kind, role, "observed-uid")
    with pytest.raises(RuntimeError, match="replacement"):
        async with f.h.sessions.begin() as db:
            await f.repo.bind(db, f.row, f.owner, intent.generation, kind, role, "foreign-uid")
    assert (await snapshot(f, intent.generation)).control_uids[key] == "observed-uid"


async def test_bind_requires_preexisting_generation_and_rollback_preserves_unknown(ledger):
    f = ledger
    with pytest.raises(PairClaimLost, match="missing"):
        async with f.h.sessions.begin() as db:
            await f.repo.bind(db, f.row, f.owner, uuid4(), "Service", "egress", "uid")
    intent = await begin(f)
    with pytest.raises(RuntimeError, match="rollback"):
        async with f.h.sessions.begin() as db:
            await f.repo.bind(db, f.row, f.owner, intent.generation, "Service", "egress", "uid")
            raise RuntimeError("rollback")
    assert (await snapshot(f, intent.generation)).control_uids["Service/egress"] is None


@pytest.mark.parametrize("field", ["status", "sandbox_id", "project_id", "claimed_by", "time"])
async def test_stale_claim_cannot_begin_or_bind_even_when_state_name_repeats(ledger, field):
    f = ledger
    intent = await begin(f)
    changes = {
        "status": {"status": "recovering"},
        "sandbox_id": {"sandbox_id": uuid4()},
        "project_id": {"project_id": uuid4()},
        "claimed_by": {"claimed_by": uuid4()},
        "time": {"status_changed_at": f.row.status_changed_at + timedelta(microseconds=1)},
    }
    async with f.h.sessions.begin() as db:
        await db.execute(
            update(SandboxSession)
            .where(SandboxSession.session_id == f.row.session_id)
            .values(**changes[field])
        )
    with pytest.raises(PairClaimLost):
        await begin(f)
    with pytest.raises(PairClaimLost):
        async with f.h.sessions.begin() as db:
            await f.repo.bind(db, f.row, f.owner, intent.generation, "Service", "egress", "late")
    assert all(uid is None for uid in (await snapshot(f, intent.generation)).control_uids.values())


async def test_same_transaction_identity_map_does_not_erase_expected_claim_fence(ledger):
    f = ledger
    async with f.h.sessions.begin() as db:
        expected = await db.get(SandboxSession, f.row.session_id)
        await db.execute(
            update(SandboxSession)
            .where(SandboxSession.session_id == f.row.session_id)
            .values(status_changed_at=expected.status_changed_at + timedelta(microseconds=1))
            .execution_options(synchronize_session=False)
        )
        with pytest.raises(PairClaimLost):
            await f.repo.begin(db, expected, f.owner, namespace="fixture", golden_version="v0.0.33")


async def test_prior_generation_cannot_be_reused_by_later_claim(ledger):
    f = ledger
    old = await begin(f)
    async with f.h.sessions.begin() as db:
        row = await db.get(SandboxSession, f.row.session_id)
        row.claimed_by = uuid4()
        row.status_changed_at += timedelta(seconds=1)
    f.row = await row_for(f.h, f.row.session_id)
    f.owner = f.row.claimed_by
    with pytest.raises(PairClaimLost, match="retirement"):
        await begin(f)
    assert await snapshot(f, old.generation) is not None


async def test_replaced_sandbox_has_new_generation_without_erasing_old_intent(ledger):
    f = ledger
    old = await begin(f)
    async with f.h.sessions.begin() as db:
        row = await db.get(SandboxSession, f.row.session_id)
        row.sandbox_id = uuid4()
        row.claimed_by = uuid4()
        row.status_changed_at += timedelta(seconds=1)
    f.row = await row_for(f.h, f.row.session_id)
    f.owner = f.row.claimed_by
    new = await begin(f)
    assert new.generation != old.generation
    assert (await snapshot(f, old.generation)).sandbox_id == old.sandbox_id
    with pytest.raises(PairClaimLost):
        async with f.h.sessions.begin() as db:
            await f.repo.bind(db, f.row, f.owner, old.generation, "Service", "egress", "late")


async def test_deleted_session_does_not_destroy_ownership_or_allow_adoption(ledger):
    f = ledger
    old = await begin(f)
    async with f.h.sessions.begin() as db:
        await db.execute(
            delete(SandboxSession).where(SandboxSession.session_id == f.row.session_id)
        )
    assert await snapshot(f, old.generation) is not None
    with pytest.raises(PairClaimLost):
        await begin(f)


@pytest.mark.parametrize("field", ["namespace", "golden_version"])
async def test_builder_drift_does_not_change_persisted_manifest_identity(ledger, field):
    f = ledger
    intent = await begin(f)
    config = {"namespace": intent.namespace, "golden_version": intent.golden_version}
    config[field] = "changed"
    with pytest.raises(RuntimeError, match="configuration changed"):
        async with f.h.sessions.begin() as db:
            await f.repo.begin(db, f.row, f.owner, **config)


@pytest.mark.parametrize("mode", ["missing", "extra", "empty", "non-string"])
async def test_corrupt_intent_is_not_repaired_or_reported_complete(ledger, mode):
    f = ledger
    intent = await begin(f)
    async with f.h.sessions.begin() as db:
        row = await db.get(PairIntent, intent.generation)
        uids = dict(row.control_uids)
        if mode == "missing":
            del uids["Service/egress"]
        elif mode == "extra":
            uids["foreign"] = "uid"
        else:
            uids["Service/egress"] = "" if mode == "empty" else 42
        row.control_uids = uids
    with pytest.raises(RuntimeError, match="corrupt"):
        await snapshot(f, intent.generation)
    with pytest.raises(RuntimeError, match="corrupt"):
        await begin(f)


@pytest.mark.parametrize(
    "kind,role,uid",
    [
        ("Secret", "egress", "uid"),
        ("Service", "ipc", "uid"),
        ("Service", "egress", ""),
        ("Service", "egress", " "),
    ],
)
async def test_invalid_bind_inputs_fail_without_mutation(ledger, kind, role, uid):
    f = ledger
    intent = await begin(f)
    with pytest.raises(ValueError):
        async with f.h.sessions.begin() as db:
            await f.repo.bind(db, f.row, f.owner, intent.generation, kind, role, uid)
    assert all(uid is None for uid in (await snapshot(f, intent.generation)).control_uids.values())


async def test_database_enforces_single_sandbox_intent_and_schema_contains_no_credentials(ledger):
    f = ledger
    intent = await begin(f)
    with pytest.raises(IntegrityError):
        async with f.h.sessions.begin() as db:
            db.add(
                PairIntent(
                    **{
                        c.name: getattr(intent, c.name)
                        for c in PairIntent.__table__.columns
                        if c.name != "generation"
                    },
                    generation=uuid4(),
                )
            )
    async with f.h.engine.connect() as db:
        columns = await db.run_sync(lambda c: inspect(c).get_columns("sandbox_pair_intent"))
        fks = await db.run_sync(lambda c: inspect(c).get_foreign_keys("sandbox_pair_intent"))
    assert {c["name"] for c in columns} == set(PairIntent.__table__.columns.keys())
    assert not fks  # Ownership records survive session deletion and replacement.
    assert not {"token", "authorization", "secret", "key", "policy", "ready"} & {
        c["name"] for c in columns
    }


async def test_concurrent_uid_results_cannot_overwrite_each_other(ledger):
    f = ledger
    intent = await begin(f)

    async def bind(uid):
        async with f.h.sessions.begin() as db:
            return await f.repo.bind(
                db, f.row, f.owner, intent.generation, "Service", "egress", uid
            )

    results = await asyncio.gather(bind("first"), bind("second"), return_exceptions=True)
    assert sum(isinstance(result, RuntimeError) for result in results) == 1
    winner = next(result for result in results if isinstance(result, PairIntent))
    assert (await snapshot(f, intent.generation)).control_uids == winner.control_uids
