# ruff: noqa: F811
from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import delete, inspect, select, update

from ads_sandbox_manager.egress_state_store import EgressState, EgressStateRepository, WrappingKey
from ads_sandbox_manager.pair_store import PairClaimLost, PairIntent
from ads_sandbox_manager.store import SandboxSession
from test_pair_store import begin, ledger  # noqa: F401
from test_session_objects import object_settings  # noqa: F401
from test_sessions import row_for, sessions_harness  # noqa: F401

pytestmark = pytest.mark.anyio


@pytest.fixture
async def state_store(ledger):
    f = ledger
    async with f.h.sessions.begin() as db:
        await db.execute(delete(EgressState))
    pair = await begin(f)
    yield SimpleNamespace(f=f, repo=EgressStateRepository(f.repo), pair=pair)
    async with f.h.sessions.begin() as db:
        await db.execute(delete(EgressState))


async def reserve(h, storage_bytes=1024**3):
    f = h.f
    async with f.h.sessions.begin() as db:
        return await h.repo.reserve(
            db, f.row, f.owner, h.pair.generation, storage_bytes=storage_bytes
        )


async def snapshot(h, state_id):
    async with h.f.h.sessions.begin() as db:
        return await h.repo.snapshot(db, state_id)


async def bind(h, state, role, uid):
    f = h.f
    async with f.h.sessions.begin() as db:
        return await h.repo.bind(db, f.row, f.owner, h.pair.generation, state.state_id, role, uid)


async def settle(h, state, role):
    async with h.f.h.sessions.begin() as db:
        await h.repo.settle(db, state, role)


async def volume(h, state):
    f = h.f
    async with f.h.sessions.begin() as db:
        return await h.repo.reserve_volume(db, f.row, f.owner, h.pair.generation, state.state_id)


async def test_reservation_commits_identity_and_key_only_once(state_store, monkeypatch):
    h, calls = state_store, []

    def key(size):
        calls.append(size)
        return b"k" * size

    monkeypatch.setattr("ads_sandbox_manager.egress_state_store.secrets.token_bytes", key)
    results = await asyncio.gather(reserve(h), reserve(h))
    state = results[0][0]
    assert results[1][0].state_id == state.state_id
    assert calls == [32]
    private = next(k for _, k in results if k is not None)
    assert sum(k is not None for _, k in results) == 1
    assert private.value == b"k" * 32
    assert state.key_fingerprint == private.fingerprint
    assert repr(private) == "WrappingKey()"
    assert state.state_id != h.pair.generation
    assert state.creator_generation == h.pair.generation
    assert state.storage_bytes == 1024**3
    assert state.key_dispatch == "inflight"
    assert state.volume_dispatch == "unissued"
    assert state.key_uid is None and state.volume_uid is None
    h.repo = EgressStateRepository(h.f.repo)
    restarted, key_again = await reserve(h)
    assert restarted.state_id == state.state_id and key_again is None
    assert calls == [32]
    async with h.f.h.sessions.begin() as db:
        assert len(list(await db.scalars(select(EgressState)))) == 1
        columns = inspect(EgressState).columns.keys()
        assert "value" not in columns and "private_key" not in columns
        assert all(getattr(restarted, col) != private.value for col in columns)
        foreign_keys = await db.run_sync(
            lambda session: inspect(session.connection()).get_foreign_keys("sandbox_egress_state")
        )
        assert not foreign_keys
    assert not h.f.h.kube.calls


async def test_rollback_and_visibility_before_external_dispatch(state_store):
    h, f = state_store, state_store.f
    with pytest.raises(RuntimeError, match="rollback"):
        async with f.h.sessions.begin() as db:
            state, key = await h.repo.reserve(
                db, f.row, f.owner, h.pair.generation, storage_bytes=4096
            )
            assert key is not None
            assert await snapshot(h, state.state_id) is None
            raise RuntimeError("rollback")
    assert await snapshot(h, state.state_id) is None
    fresh, new_key = await reserve(h, 4096)
    assert fresh.state_id != state.state_id
    assert new_key is not None and new_key.fingerprint != key.fingerprint


@pytest.mark.parametrize("size", [0, -1, True, 1.5, "1024", 2**63])
async def test_invalid_capacity_cannot_reserve_or_generate(state_store, size, monkeypatch):
    def forbidden(*args):
        pytest.fail("invalid storage reached key generation")

    monkeypatch.setattr("ads_sandbox_manager.egress_state_store.secrets.token_bytes", forbidden)
    with pytest.raises(ValueError, match="storage"):
        await reserve(state_store, size)


async def test_reserved_capacity_and_fingerprint_cannot_be_replaced(state_store, monkeypatch):
    h = state_store
    state, _ = await reserve(h)

    def forbidden(*args):
        pytest.fail("reserved key was regenerated")

    monkeypatch.setattr("ads_sandbox_manager.egress_state_store.secrets.token_bytes", forbidden)
    with pytest.raises(RuntimeError, match="storage reservation changed"):
        await reserve(h, 4096)
    again, key = await reserve(h)
    assert key is None and again.key_fingerprint == state.key_fingerprint


async def test_uid_observation_does_not_settle_ambiguous_key_write(state_store):
    h = state_store
    state, _ = await reserve(h)
    state = await bind(h, state, "key", "secret-uid")
    assert state.key_dispatch == "inflight"
    with pytest.raises(RuntimeError, match="bound and settled"):
        await volume(h, state)
    again, key = await reserve(h)
    assert key is None and again.key_dispatch == "inflight"
    await settle(h, state, "key")
    await settle(h, state, "key")  # Original completion is idempotent.
    state, dispatch = await volume(h, state)
    assert dispatch and state.volume_dispatch == "inflight"
    state, dispatch = await volume(h, state)
    assert not dispatch
    state = await bind(h, state, "volume", "volume-uid")
    assert state.volume_dispatch == "inflight"
    await settle(h, state, "volume")
    current = await snapshot(h, state.state_id)
    assert current.key_uid == "secret-uid" and current.volume_uid == "volume-uid"
    assert current.key_dispatch == current.volume_dispatch == "settled"


async def test_settlement_without_uid_is_not_custody_or_volume_authority(state_store):
    h = state_store
    state, _ = await reserve(h)
    await settle(h, state, "key")
    with pytest.raises(RuntimeError, match="bound and settled"):
        await volume(h, state)
    with pytest.raises(RuntimeError, match="never dispatched"):
        await bind(h, state, "volume", "unexpected")
    with pytest.raises(RuntimeError, match="never dispatched"):
        await settle(h, state, "volume")


@pytest.mark.parametrize("role", ["key", "volume"])
async def test_uid_binding_is_idempotent_but_never_replaces(state_store, role):
    h = state_store
    state, _ = await reserve(h)
    if role == "volume":
        state = await bind(h, state, "key", "custody")
        await settle(h, state, "key")
        state, _ = await volume(h, state)
    state = await bind(h, state, role, "original")
    assert getattr(await bind(h, state, role, "original"), f"{role}_uid") == "original"
    with pytest.raises(RuntimeError, match="replacement"):
        await bind(h, state, role, "replacement")
    assert getattr(await snapshot(h, state.state_id), f"{role}_uid") == "original"


@pytest.mark.parametrize(
    "field", ["status", "sandbox_id", "project_id", "claimed_by", "status_changed_at", "fence"]
)
async def test_lost_claim_blocks_reservation_and_binding_but_not_original_completion(
    state_store, field
):
    h, f = state_store, state_store.f
    state, _ = await reserve(h)
    changes = {
        "status": "recovering",
        "sandbox_id": uuid4(),
        "project_id": uuid4(),
        "claimed_by": uuid4(),
        "status_changed_at": f.row.status_changed_at + timedelta(microseconds=1),
    }
    async with f.h.sessions.begin() as db:
        if field == "fence":
            await db.execute(
                update(PairIntent)
                .where(PairIntent.generation == h.pair.generation)
                .values(creation_fenced=True)
            )
        else:
            await db.execute(
                update(SandboxSession)
                .where(SandboxSession.session_id == f.row.session_id)
                .values(**{field: changes[field]})
            )
    with pytest.raises(PairClaimLost):
        await reserve(h)
    with pytest.raises(PairClaimLost):
        await bind(h, state, "key", "late")
    with pytest.raises(PairClaimLost):
        await volume(h, state)
    await settle(h, state, "key")
    saved = await snapshot(h, state.state_id)
    assert saved.key_dispatch == "settled" and saved.key_uid is None


@pytest.mark.parametrize("role", ["key", "volume", "unsupported"])
async def test_invalid_uid_or_role_never_binds(state_store, role):
    h = state_store
    state, _ = await reserve(h)
    with pytest.raises(ValueError):
        await bind(h, state, role, " ")
    if role == "unsupported":
        with pytest.raises(ValueError):
            await settle(h, state, role)


async def test_missing_reservation_cannot_bind(state_store):
    with pytest.raises(PairClaimLost, match="missing"):
        await bind(state_store, SimpleNamespace(state_id=uuid4()), "key", "uid")


@pytest.mark.parametrize(
    "change",
    [
        {"key_fingerprint": "invalid"},
        {"key_dispatch": "unissued"},
        {"key_uid": ""},
        {"volume_uid": "not-issued"},
        {"volume_dispatch": "inflight"},
        {"storage_bytes": 0},
    ],
)
async def test_corrupt_records_fail_closed_without_regeneration(state_store, change, monkeypatch):
    h = state_store
    state, _ = await reserve(h)
    async with h.f.h.sessions.begin() as db:
        await db.execute(
            update(EgressState).where(EgressState.state_id == state.state_id).values(**change)
        )

    def forbidden(*args):
        pytest.fail("corrupt reservation regenerated a key")

    monkeypatch.setattr("ads_sandbox_manager.egress_state_store.secrets.token_bytes", forbidden)
    with pytest.raises(RuntimeError, match="corrupt"):
        await reserve(h)
    with pytest.raises(RuntimeError, match="corrupt"):
        await snapshot(h, state.state_id)


@pytest.mark.parametrize("field", ["key_fingerprint", "creator_generation", "storage_bytes"])
async def test_original_completion_cannot_settle_changed_scope(state_store, field):
    h = state_store
    state, _ = await reserve(h)
    values = {"key_fingerprint": "1" * 64, "creator_generation": uuid4(), "storage_bytes": 4096}
    async with h.f.h.sessions.begin() as db:
        await db.execute(
            update(EgressState)
            .where(EgressState.state_id == state.state_id)
            .values(**{field: values[field]})
        )
    with pytest.raises(PairClaimLost, match="identity changed"):
        await settle(h, state, "key")


async def test_identity_map_refresh_cannot_erase_original_completion_scope(state_store):
    h = state_store
    state, _ = await reserve(h)
    async with h.f.h.sessions.begin() as db:
        expected = await db.get(EgressState, state.state_id)
        await db.execute(
            update(EgressState)
            .where(EgressState.state_id == state.state_id)
            .values(key_fingerprint="2" * 64)
            .execution_options(synchronize_session=False)
        )
        with pytest.raises(PairClaimLost, match="identity changed"):
            await h.repo.settle(db, expected, "key")


async def test_volume_completion_requires_original_custody_uid(state_store):
    h = state_store
    state, _ = await reserve(h)
    state = await bind(h, state, "key", "original")
    await settle(h, state, "key")
    state, _ = await volume(h, state)
    async with h.f.h.sessions.begin() as db:
        await db.execute(
            update(EgressState)
            .where(EgressState.state_id == state.state_id)
            .values(key_uid="foreign")
        )
    with pytest.raises(PairClaimLost, match="custody changed"):
        await settle(h, state, "volume")
    assert (await snapshot(h, state.state_id)).volume_dispatch == "inflight"


async def test_deleted_reservation_is_not_reconstructed_by_completion(state_store):
    h = state_store
    state, _ = await reserve(h)
    async with h.f.h.sessions.begin() as db:
        await db.execute(delete(EgressState).where(EgressState.state_id == state.state_id))
    with pytest.raises(PairClaimLost, match="identity changed"):
        await settle(h, state, "key")
    assert await snapshot(h, state.state_id) is None


async def test_binding_rollback_retains_unknown_and_inflight(state_store):
    h, f = state_store, state_store.f
    state, _ = await reserve(h)
    with pytest.raises(RuntimeError, match="rollback"):
        async with f.h.sessions.begin() as db:
            await h.repo.bind(
                db, f.row, f.owner, h.pair.generation, state.state_id, "key", "not-committed"
            )
            raise RuntimeError("rollback")
    saved = await snapshot(h, state.state_id)
    assert saved.key_uid is None and saved.key_dispatch == "inflight"


async def test_state_blocks_stopped_claim_even_without_pair_row(state_store):
    h, f = state_store, state_store.f
    await reserve(h)
    async with f.h.sessions.begin() as db:
        await db.execute(delete(PairIntent))
        await db.execute(
            update(SandboxSession)
            .where(SandboxSession.session_id == f.row.session_id)
            .values(status="stopped")
        )
    row = await row_for(f.h, f.row.session_id)
    with pytest.raises(RuntimeError, match="retained egress state"):
        async with f.h.sessions.begin() as db:
            await f.h.repository.claim(db, row, uuid4(), datetime.now(UTC))
    assert (await row_for(f.h, f.row.session_id)).status == "stopped"


async def test_retained_state_survives_deleted_session_and_pair_and_blocks_readmission(state_store):
    h, f = state_store, state_store.f
    state, _ = await reserve(h)
    async with f.h.sessions.begin() as db:
        await db.execute(delete(PairIntent))
        await db.execute(delete(SandboxSession))
    assert (await snapshot(h, state.state_id)).key_fingerprint == state.key_fingerprint
    for session_id, sandbox_id in [(f.row.session_id, uuid4()), (uuid4(), f.row.sandbox_id)]:
        with pytest.raises(RuntimeError, match="retained egress state"):
            async with f.h.sessions.begin() as db:
                await f.h.repository.insert_pending(
                    db,
                    session_id,
                    sandbox_id,
                    f.row.golden_version,
                    datetime.now(UTC),
                    f.row.project_id,
                )
    assert await row_for(f.h, f.row.session_id) is None
    await settle(h, state, "key")
    assert (await snapshot(h, state.state_id)).key_dispatch == "settled"


async def test_later_generation_cannot_adopt_or_replace_persistent_identity(state_store):
    h, f = state_store, state_store.f
    state, _ = await reserve(h)
    async with f.h.sessions.begin() as db:
        await db.execute(delete(PairIntent))
    # Deleting pair history is not a release/transfer API. Even this forced
    # simulation must not authorize regeneration of persistent state.
    h.pair = await begin(f)
    with pytest.raises(PairClaimLost, match="ownership"):
        await reserve(h)
    assert (await snapshot(h, state.state_id)).creator_generation == state.creator_generation


@pytest.mark.parametrize("value", [b"", b"x" * 31, b"x" * 33, "x" * 32, bytearray(32)])
async def test_key_format_rejects_invalid_material_without_echo(value):
    with pytest.raises(ValueError, match="256-bit") as error:
        WrappingKey(value)
    assert str(value) not in str(error.value)
