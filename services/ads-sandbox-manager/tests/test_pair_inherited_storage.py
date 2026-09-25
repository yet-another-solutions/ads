# ruff: noqa: F811
from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
from uuid import uuid4

import msgspec
import pytest
from sqlalchemy import select

from ads_sandbox_manager.cleanup import CleanupAdapter
from ads_sandbox_manager.lifecycle_store import CleanupWork
from ads_sandbox_manager.pair_retirement import PairRetirementRepository
from ads_sandbox_manager.pair_store import PairIntent
from ads_sandbox_manager.pair_unused_storage import PairUnusedStorageTeardown
from ads_sandbox_manager.store import SandboxSession
from test_kube_release import api  # noqa: F401
from test_node_release_wire import node_report  # noqa: F401
from test_pair_cleanup_journal import journal  # noqa: F401
from test_pair_completion import recovery
from test_pair_controls import controls  # noqa: F401
from test_pair_creation import creation  # noqa: F401
from test_pair_resource_teardown import resources  # noqa: F401
from test_pair_resume import prepared
from test_pair_runtime_teardown import state, teardown  # noqa: F401
from test_pair_store import ledger, snapshot  # noqa: F401
from test_pair_volume_publication import publication as volume_publication  # noqa: F401
from test_session_objects import object_settings  # noqa: F401
from test_sessions import sessions_harness  # noqa: F401

pytestmark = pytest.mark.anyio


async def failed_resume(f):
    row = await prepared(f)
    prior = f.intent.generation
    prepare = f.creator.controls.prepare

    async def interrupted(*args, **kwargs):
        raise RuntimeError("interrupted after retained validation before new dispatch")

    f.creator.controls.prepare = interrupted
    with pytest.raises(RuntimeError, match="before new dispatch"):
        await f.h.service.provision(row.session_id)
    f.creator.controls.prepare = prepare
    async with f.h.sessions.begin() as db:
        f.intent = await db.scalar(
            select(PairIntent).where(
                PairIntent.sandbox_id == row.sandbox_id, PairIntent.retired_at.is_(None)
            )
        )
        assert f.intent.retained_from == prior
        assert all(value == "unissued" for value in f.intent.compute_dispatch.values())
        assert await f.capture.repository.recover(
            db, row.session_id, row.sandbox_id, datetime.now(UTC), 120
        )
        f.claim = await db.get(SandboxSession, row.session_id)
        f.work = await db.scalar(
            select(CleanupWork).where(
                CleanupWork.session_id == row.session_id, CleanupWork.kind == "recovery"
            )
        )
    # Use the actual adapter without the old full-runtime fixture's assertions.
    f.storage = f.runtime.storage = CleanupAdapter(f.adapter.kube)
    assert await f.capture.capture(f.work, recovery=f.claim)
    assert await f.runtime.release(f.work, recovery=f.claim)
    return prior


@pytest.mark.parametrize("resources", ["idle"], indirect=True)
async def test_failed_resume_composes_old_release_before_fresh_destructive_recovery(resources):
    f = resources
    prior = await failed_resume(f)
    condemned = f.intent.generation
    assert await PairUnusedStorageTeardown(f.runtime).dispose(f.work, recovery=f.claim)
    saved = await state(f)
    assert saved["node_capture"] is None and saved["block_capture"] is None
    for role in ("workspace", "state"):
        value = saved["unused_storage"][role]
        assert value["capture"]["mode"] == "retired-inherited-csi"
        assert value["capture"]["previous"]["generation"] == str(prior)
        assert value["capture"]["target"]["nodes"]
        assert value["release"]["generation"] == str(prior)
        assert value["disposition"] == "reclaimed"
    await recovery(f).execute(f.row.session_id)
    async with f.h.sessions.begin() as db:
        row = await db.get(SandboxSession, f.row.session_id)
        assert row.status == "creating" and row.sandbox_id != f.intent.sandbox_id
        assert (
            await PairRetirementRepository(f.capture.repository).verify(db, condemned)
        ).kind == "recovery"
        assert (
            await PairRetirementRepository(f.capture.repository).verify(db, prior)
        ).kind == "idle"


@pytest.mark.parametrize("resources", ["idle"], indirect=True)
@pytest.mark.parametrize("fault", ["busy", "boot", "replacement"])
async def test_inherited_storage_never_assumes_old_or_new_runtime_history(resources, fault):
    f = resources
    await failed_resume(f)
    before = deepcopy(f.remote.objects)
    if fault == "busy":
        f.block_busy = True
    elif fault == "boot":
        observe = f.node.observe_block

        async def wrong(captured):
            value = msgspec.json.decode(await observe(captured))
            value["boot_id"] = str(uuid4())
            return msgspec.json.encode(value)

        f.node.observe_block = wrong
    else:
        for (kind, _), obj in f.remote.objects.items():
            if kind == "PersistentVolumeClaim":
                obj["metadata"]["uid"] = str(uuid4())
        before = deepcopy(f.remote.objects)
    stage = PairUnusedStorageTeardown(f.runtime)
    if fault == "busy":
        assert not await stage.dispose(f.work, recovery=f.claim)
    else:
        with pytest.raises((RuntimeError, ValueError)):
            await stage.dispose(f.work, recovery=f.claim)
    assert f.remote.objects == before
    saved = await state(f)
    assert all(entry["disposition"] is None for entry in saved["unused_storage"].values())
