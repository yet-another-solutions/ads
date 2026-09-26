# ruff: noqa: F811
from __future__ import annotations

import asyncio
from dataclasses import replace
from uuid import uuid4

import pytest
from sqlalchemy import select

from ads_sandbox_manager.lifecycle_store import CleanupWork
from ads_sandbox_manager.pair_controls import PairControlProvisioner
from ads_sandbox_manager.pair_store import PairIntent
from test_kube_release import api  # noqa: F401
from test_pair_controls import controls, intent_for  # noqa: F401
from test_pair_creator_fence import cleanup_claim
from test_pair_store import ledger, snapshot  # noqa: F401
from test_session_objects import object_settings  # noqa: F401
from test_sessions import row_for, sessions_harness  # noqa: F401

pytestmark = pytest.mark.anyio


async def cancelled_caller(f):
    f.remote.delay = True
    caller = asyncio.create_task(f.service.prepare(f.row))
    assert await asyncio.to_thread(f.remote.started.wait, 5)
    caller.cancel()
    with pytest.raises(asyncio.CancelledError):
        await caller
    assert len(f.service._dispatches) == 1
    intent = await intent_for(f)
    assert intent.control_dispatch["PodGroup/guest"] == "inflight"
    assert not f.remote.created
    return intent


async def release_and_drain(f):
    f.remote.release.set()
    await f.service.drain()
    assert not f.service._dispatches


async def test_cancelled_caller_retains_only_original_operation_and_settlement(controls):
    f = controls
    try:
        intent = await cancelled_caller(f)
        f.remote.release.set()
        await f.service.drain()
        saved = await snapshot(f, intent.generation)
        assert saved.control_dispatch["PodGroup/guest"] == "settled"
        assert saved.control_uids["PodGroup/guest"] is None
        assert list(saved.control_dispatch.values()).count("unissued") == 7
        assert len(f.remote.created) == 1
        assert (await row_for(f.h, f.row.session_id)).status == "creating"
        assert not f.service._dispatches
    finally:
        await release_and_drain(f)


async def test_late_original_return_settles_after_cleanup_fence_without_advancing(controls):
    f = controls
    try:
        intent = await cancelled_caller(f)
        capture, work, claim = await cleanup_claim(f)
        await capture.capture(work, recovery=claim)
        fenced = await snapshot(f, intent.generation)
        assert fenced.creation_fenced
        assert fenced.control_dispatch["PodGroup/guest"] == "inflight"
        f.remote.release.set()
        await f.service.drain()
        settled = await snapshot(f, intent.generation)
        assert settled.creation_fenced
        assert settled.control_dispatch["PodGroup/guest"] == "settled"
        assert settled.control_uids["PodGroup/guest"] is None
        await capture.capture(work, recovery=claim)
        async with f.h.sessions.begin() as db:
            stored = await db.get(CleanupWork, work.work_id)
            assert stored.pair_snapshot["control_uids"]["PodGroup/guest"]
            assert not await capture.repository.complete(db, stored, stored.deadline)
        assert (await row_for(f.h, claim.session_id)).status == "recovering"
        assert len(f.remote.created) == 1
    finally:
        await release_and_drain(f)


async def test_caller_timeout_does_not_discard_original_completion(controls):
    f = controls
    f.service.settings = replace(
        f.service.settings,
        session_objects=replace(f.service.settings.session_objects, create_seconds=1),
    )
    f.remote.delay = True
    caller = asyncio.create_task(f.service.prepare(f.row))
    try:
        assert await asyncio.to_thread(f.remote.started.wait, 5)
        with pytest.raises(TimeoutError):
            await caller
        intent = await intent_for(f)
        assert intent.control_dispatch["PodGroup/guest"] == "inflight"
        f.remote.release.set()
        await f.service.drain()
        assert (await snapshot(f, intent.generation)).control_dispatch[
            "PodGroup/guest"
        ] == "settled"
        assert len(f.remote.created) == 1
    finally:
        f.remote.release.set()
        if not caller.done():
            caller.cancel()
        await asyncio.gather(caller, return_exceptions=True)
        await f.service.drain()


@pytest.mark.parametrize("failure", ["api", "commit", "identity"])
async def test_detached_failure_preserves_inflight_and_is_not_retried(controls, failure):
    f = controls
    if failure == "api":
        f.remote.lost_reply = True
    try:
        intent = await cancelled_caller(f)
        if failure == "commit":
            original = f.repo.settle

            async def rollback(*args, **kwargs):
                await original(*args, **kwargs)
                raise RuntimeError("settlement commit failed")

            f.repo.settle = rollback
        elif failure == "identity":
            async with f.h.sessions.begin() as db:
                (await db.get(PairIntent, intent.generation)).claim_owner = uuid4()
        f.remote.release.set()
        await f.service.drain()
        saved = await snapshot(f, intent.generation)
        assert saved.control_dispatch["PodGroup/guest"] == "inflight"
        assert saved.control_uids["PodGroup/guest"] is None
        assert len(f.remote.created) == 1
        assert not f.service._dispatches
    finally:
        await release_and_drain(f)


async def test_draining_timeout_does_not_cancel_original_operation(controls):
    f = controls
    original_settings = f.service.settings
    try:
        intent = await cancelled_caller(f)
        f.service.settings = replace(f.service.settings, control_seconds=0.05)
        with pytest.raises(TimeoutError):
            await f.service.drain()
        assert len(f.service._dispatches) == 1
        assert (await snapshot(f, intent.generation)).control_dispatch[
            "PodGroup/guest"
        ] == "inflight"
        f.service.settings = original_settings
        f.remote.release.set()
        await f.service.drain()
        assert (await snapshot(f, intent.generation)).control_dispatch[
            "PodGroup/guest"
        ] == "settled"
    finally:
        f.service.settings = original_settings
        await release_and_drain(f)


async def test_cancelled_drain_does_not_cancel_original_operation(controls):
    f = controls
    try:
        intent = await cancelled_caller(f)
        join = asyncio.create_task(f.service.drain())
        await asyncio.sleep(0)
        join.cancel()
        with pytest.raises(asyncio.CancelledError):
            await join
        assert len(f.service._dispatches) == 1
        f.remote.release.set()
        await f.service.drain()
        assert (await snapshot(f, intent.generation)).control_dispatch[
            "PodGroup/guest"
        ] == "settled"
    finally:
        await release_and_drain(f)


@pytest.mark.parametrize("setup_delay", [0, 0.4])
async def test_retained_operation_has_its_own_deadline_and_late_sdk_is_ambiguous(
    controls, setup_delay
):
    f = controls
    original_dispatch = f.service._dispatch
    original_begin = f.repo.begin

    async def begin(*args, **kwargs):
        await asyncio.sleep(setup_delay)
        return await original_begin(*args, **kwargs)

    async def dispatch(*args, **kwargs):
        # Start the short retained-operation budget at that operation's entry,
        # not before the unrelated durable intent/dispatch transactions.
        f.service.settings = replace(f.service.settings, control_seconds=0.3)
        return await original_dispatch(*args, **kwargs)

    f.repo.begin = begin
    f.service._dispatch = dispatch
    try:
        intent = await cancelled_caller(f)
        operation = next(iter(f.service._dispatches))
        async with asyncio.timeout(5):
            await asyncio.wait((operation,))
        assert isinstance(operation.exception(), TimeoutError)
        assert not f.remote.finished.is_set()
        assert not f.service._dispatches
        f.remote.release.set()
        assert await asyncio.to_thread(f.remote.finished.wait, 5)
        saved = await snapshot(f, intent.generation)
        assert saved.control_dispatch["PodGroup/guest"] == "inflight"
        assert saved.control_uids["PodGroup/guest"] is None
        assert len(f.remote.created) == 1
    finally:
        await release_and_drain(f)


async def test_operation_loss_and_service_restart_do_not_invent_settlement(controls):
    f = controls
    try:
        intent = await cancelled_caller(f)
        original = next(iter(f.service._dispatches))
        original.cancel()
        await asyncio.gather(original, return_exceptions=True)
        f.remote.release.set()
        assert await asyncio.to_thread(f.remote.finished.wait, 5)
        restarted = PairControlProvisioner(
            f.service.settings, f.h.sessions, type(f.repo)(), f.adapter
        )
        result = await restarted.prepare(f.row)
        await restarted.drain()
        assert result.generation == intent.generation
        assert all(result.control_uids.values())
        assert result.control_dispatch["PodGroup/guest"] == "inflight"
        assert len(f.remote.created) == 8
    finally:
        await release_and_drain(f)


async def test_no_active_dispatch_drain_is_empty_and_has_no_database_effect(controls):
    f = controls
    await f.service.drain()
    async with f.h.sessions.begin() as db:
        assert await db.scalar(select(PairIntent)) is None
    assert not f.remote.created
