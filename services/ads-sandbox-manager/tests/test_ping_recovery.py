# ruff: noqa: F811
from __future__ import annotations

import asyncio
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock
from uuid import uuid4

import msgspec
import pytest
from sqlalchemy import select

from ads_commons.sandbox import SandboxPing, decode_ping
from ads_sandbox_manager.lifecycle import PING_REQUEST, RECOVER, Signal
from ads_sandbox_manager.lifecycle_store import CleanupWork
from ads_sandbox_manager.recovery import RecoveryService
from ads_sandbox_manager.session_objects import SESSION, ipc_name, session_name
from ads_sandbox_manager.store import PingProbe, SandboxSession, SessionPVC, advance
from test_lifecycle import detach, disk, eligible, idle, life, works  # noqa: F401
from test_session_objects import object_settings  # noqa: F401
from test_sessions import row_for, sessions_harness  # noqa: F401

pytestmark = pytest.mark.anyio


def recovery(h):
    return RecoveryService(
        h.lifecycle.settings, h.sessions, h.repository, h.lifecycle, h.service, h.topics
    )


async def condemn(h, sandbox_id=None):
    await h.lifecycle.admit(RECOVER, Signal(h.row.session_id, sandbox_id or h.row.sandbox_id))
    return await row_for(h, h.row.session_id)


async def age_ping(h):
    async with h.sessions.begin() as db:
        row = await db.get(SandboxSession, h.row.session_id)
        row.last_ping_at = datetime.now(UTC) - timedelta(seconds=40)
        row.last_ping_sent_at = None
        for probe in await db.scalars(
            select(PingProbe).where(PingProbe.sandbox_id == row.sandbox_id)
        ):
            if probe.published_at is not None:
                probe.published_at = datetime.now(UTC) - timedelta(seconds=31)


async def test_ping_uses_fresh_service_ste_and_correlates_once_across_replicas(life):
    h = life
    before = await row_for(h, h.row.session_id)
    await h.lifecycle.ping_scan()
    call = h.publisher.send.call_args
    ping = decode_ping(call.args[2])
    assert call.args[:2] == (PING_REQUEST, h.row.sandbox_id)
    h.lifecycle.tokens.mint.assert_called_once_with("ads-sandbox-ipc", "manager-token")
    assert call.args[3] == "ipc-token"
    assert ping.sandbox_id == h.row.sandbox_id
    async with h.sessions.begin() as db:
        assert (await db.get(PingProbe, ping.ping_id)).published_at is not None
    assert (await row_for(h, h.row.session_id)).last_ping_at == before.last_ping_at
    await h.lifecycle.ping_reply(SandboxPing(uuid4(), ping.sandbox_id))
    await h.lifecycle.ping_reply(SandboxPing(ping.ping_id, uuid4()))
    assert (await row_for(h, h.row.session_id)).last_ping_at == before.last_ping_at
    # A fresh service instance can accept another replica's request correlation.
    other = deepcopy(h.lifecycle.settings)
    from ads_sandbox_manager.lifecycle import LifecycleService

    replica = LifecycleService(
        other,
        h.sessions,
        h.lifecycle_repository,
        h.cleanup,
        h.publisher,
        h.lifecycle.credentials,
        h.lifecycle.tokens,
    )
    await replica.ping_reply(ping)
    after = await row_for(h, h.row.session_id)
    assert after.last_ping_at > before.last_ping_at
    assert after.last_execution_at == before.last_execution_at
    await replica.ping_reply(ping)
    assert (await row_for(h, h.row.session_id)).last_ping_at == after.last_ping_at
    async with h.sessions.begin() as db:
        assert await db.get(PingProbe, ping.ping_id) is None


async def test_ping_interval_delayed_reply_and_expired_probe(life):
    h = life
    await h.lifecycle.ping_scan()
    first = decode_ping(h.publisher.send.call_args.args[2])
    h.publisher.reset_mock()
    await h.lifecycle.ping_scan()
    h.publisher.send.assert_not_awaited()
    async with h.sessions.begin() as db:
        row = await db.get(SandboxSession, h.row.session_id)
        row.last_ping_sent_at -= timedelta(seconds=11)
    await h.lifecycle.ping_scan()
    second = decode_ping(h.publisher.send.call_args.args[2])
    assert second.ping_id != first.ping_id
    await h.lifecycle.ping_reply(first)  # Older outstanding probes are still valid.
    before = (await row_for(h, h.row.session_id)).last_ping_at
    async with h.sessions.begin() as db:
        probe = await db.get(PingProbe, second.ping_id)
        probe.sent_at -= timedelta(seconds=40)
    await h.lifecycle.ping_reply(second)
    assert (await row_for(h, h.row.session_id)).last_ping_at == before


@pytest.mark.parametrize(
    "status", ["pending", "creating", "shutting_down", "stopped", "service", "failed", "recovering"]
)
async def test_nonready_is_never_pinged_or_refreshed(life, status):
    h = life
    await h.lifecycle.ping_scan()
    ping = decode_ping(h.publisher.send.call_args.args[2])
    async with h.sessions.begin() as db:
        row = await db.get(SandboxSession, h.row.session_id)
        row.status = status
        row.last_ping_sent_at = None
    before = (await row_for(h, h.row.session_id)).last_ping_at
    h.publisher.reset_mock()
    await h.lifecycle.ping_scan()
    await h.lifecycle.ping_reply(ping)
    h.publisher.send.assert_not_awaited()
    assert (await row_for(h, h.row.session_id)).last_ping_at == before


async def test_published_ping_timeout_condemns_id_even_after_late_valid_reply(life):
    h = life
    await h.lifecycle.ping_scan()
    ping = decode_ping(h.publisher.send.call_args.args[2])
    await age_ping(h)
    await h.lifecycle.ping_scan()
    call = h.publisher.send.call_args
    assert call.args[0] == RECOVER and call.args[3] == "manager-token"
    signal = msgspec.json.decode(call.args[2], type=Signal)
    await h.lifecycle.ping_reply(ping)
    assert (await row_for(h, h.row.session_id)).status == "ready"
    await h.lifecycle.admit(RECOVER, signal)
    boundary = await row_for(h, h.row.session_id)
    assert boundary.status == "recovering" and boundary.sandbox_id != ping.sandbox_id
    await h.lifecycle.ping_reply(ping)
    assert (await row_for(h, h.row.session_id)).last_ping_at is None


async def test_unpublished_ping_verdict_can_be_lost_without_recovery(life):
    h = life
    await h.lifecycle.ping_scan()
    ping = decode_ping(h.publisher.send.call_args.args[2])
    await age_ping(h)
    h.publisher.send.side_effect = RuntimeError("broker unavailable")
    with pytest.raises(RuntimeError):
        await h.lifecycle.ping_scan()
    await h.lifecycle.ping_reply(ping)
    assert (await row_for(h, h.row.session_id)).status == "ready"
    assert not await works(h)


async def test_ping_never_publishes_without_successful_service_exchange(life):
    h = life
    h.lifecycle.tokens.mint.return_value.access_token = None
    with pytest.raises(RuntimeError, match="no token"):
        await h.lifecycle.ping_scan()
    h.publisher.send.assert_not_awaited()
    assert (await row_for(h, h.row.session_id)).last_ping_at == h.row.last_ping_at
    async with h.sessions.begin() as db:
        assert not list(await db.scalars(select(PingProbe)))


@pytest.mark.parametrize("failure", ["credentials", "exchange", "publication", "cancel"])
async def test_unsent_probe_never_becomes_death_after_repeated_failures(life, failure):
    h = life
    failing = {
        "credentials": h.lifecycle.credentials.mint,
        "exchange": h.lifecycle.tokens.mint,
        "publication": h.publisher.send,
        "cancel": h.publisher.send,
    }[failure]
    error = asyncio.CancelledError if failure == "cancel" else RuntimeError
    failing.side_effect = error("unavailable")
    for _ in range(2):
        await age_ping(h)
        with pytest.raises(error):
            await h.lifecycle.ping_scan()
        assert (await row_for(h, h.row.session_id)).status == "ready"
        async with h.sessions.begin() as db:
            assert not list(await db.scalars(select(PingProbe)))
    assert all(call.args[0] == PING_REQUEST for call in h.publisher.send.call_args_list)
    failing.side_effect = None
    await age_ping(h)
    await h.lifecycle.ping_scan()
    assert h.publisher.send.call_args.args[0] == PING_REQUEST


async def test_restart_ignores_unconfirmed_probe_and_times_out_confirmed_send(life):
    h = life
    old = datetime.now(UTC) - timedelta(seconds=60)
    pending_id = uuid4()
    async with h.sessions.begin() as db:
        db.add(PingProbe(ping_id=pending_id, sandbox_id=h.row.sandbox_id, sent_at=old))
    await age_ping(h)
    await h.lifecycle.ping_scan()
    assert h.publisher.send.call_args.args[0] == PING_REQUEST
    async with h.sessions.begin() as db:
        assert await db.get(PingProbe, pending_id) is None
    await age_ping(h)
    from ads_sandbox_manager.lifecycle import LifecycleService

    restarted = LifecycleService(
        h.lifecycle.settings,
        h.sessions,
        h.lifecycle_repository,
        h.cleanup,
        h.publisher,
        h.lifecycle.credentials,
        h.lifecycle.tokens,
    )
    await restarted.ping_scan()
    assert h.publisher.send.call_args.args[0] == RECOVER


async def test_ping_reply_before_publication_commit_is_not_lost(life):
    h = life

    async def immediate_reply(topic, key, raw, token):
        assert topic == PING_REQUEST
        await h.lifecycle.ping_reply(decode_ping(raw))

    h.publisher.send.side_effect = immediate_reply
    await h.lifecycle.ping_scan()
    assert (await row_for(h, h.row.session_id)).last_ping_at > h.row.last_ping_at
    async with h.sessions.begin() as db:
        assert not list(await db.scalars(select(PingProbe)))


async def test_fresh_reply_supersedes_older_published_timeout(life):
    h = life
    await h.lifecycle.ping_scan()
    ping = decode_ping(h.publisher.send.call_args.args[2])
    await age_ping(h)
    async with h.sessions.begin() as db:
        old = datetime.now(UTC) - timedelta(seconds=40)
        db.add(
            PingProbe(ping_id=uuid4(), sandbox_id=h.row.sandbox_id, sent_at=old, published_at=old)
        )
    await h.lifecycle.ping_reply(ping)
    await h.lifecycle.ping_scan()
    assert h.publisher.send.call_args.args[0] == PING_REQUEST


async def test_expired_reply_cannot_erase_confirmed_timeout_evidence(life):
    h = life
    await h.lifecycle.ping_scan()
    ping = decode_ping(h.publisher.send.call_args.args[2])
    await age_ping(h)
    async with h.sessions.begin() as db:
        probe = await db.get(PingProbe, ping.ping_id)
        probe.sent_at = datetime.now(UTC) - timedelta(seconds=35)
    await h.lifecycle.ping_reply(ping)
    await h.lifecycle.ping_scan()
    assert h.publisher.send.call_args.args[0] == RECOVER


async def test_shutdown_uses_service_subject_without_user_holder(life):
    h = life
    work = await idle(h)
    await h.lifecycle.execute(work.work_id)
    h.lifecycle.tokens.mint.assert_called_once_with("ads-sandbox-ipc", "manager-token")
    assert h.publisher.send.call_args.args[3] == "ipc-token"


async def test_recovery_does_not_discard_unaccounted_pvc_record(life):
    h = life
    await condemn(h)
    extra = uuid4()
    async with h.sessions.begin() as db:
        db.add(
            SessionPVC(
                pvc_id=extra,
                session_id=h.row.session_id,
                sandbox_id=uuid4(),
                uid="unaccounted",
                state="failed",
                last_execution=datetime.now(UTC),
                last_state_change=datetime.now(UTC),
            )
        )
    await recovery(h).execute(h.row.session_id)
    assert (await row_for(h, h.row.session_id)).status == "failed"
    assert await disk(h, extra) is not None and await disk(h) is not None
    assert await works(h)
    assert h.publisher.send.call_args.args[0] == RECOVER


async def test_recovery_deadline_failure_preserves_intent_and_emits_retry(life):
    h = life
    boundary = await condemn(h)
    async with h.sessions.begin() as db:
        row = await db.get(SandboxSession, h.row.session_id)
        row.status_changed_at -= timedelta(seconds=601)
    await recovery(h).execute(h.row.session_id)
    current = await row_for(h, h.row.session_id)
    assert current.status == "failed" and current.sandbox_id == boundary.sandbox_id
    assert not h.cleanup.deleted and await disk(h) is not None and await works(h)
    assert h.publisher.send.call_args.args[0] == RECOVER


async def test_recovery_discards_old_disk_and_rebuilds_only_claimed_boundary(life):
    h = life
    old = h.row
    boundary = await condemn(h)
    assert await h.service.provision(old.session_id) is not None
    assert len(h.kube.objects) == 4  # Ordinary provision cannot steal recovery.
    await recovery(h).run_once()
    fresh = await row_for(h, old.session_id)
    assert fresh.status == "creating"
    assert fresh.sandbox_id == boundary.sandbox_id != old.sandbox_id
    assert fresh.pvc_id != old.pvc_id and fresh.pvc_uid != old.pvc_uid
    assert await disk(h, old.pvc_id) is None and not await works(h)
    assert len(h.kube.objects) == 4
    assert len(h.cleanup.deleted) == 4
    events = h.kube.calls
    assert events.index(("delete-topics", str(old.sandbox_id))) < events.index(
        ("topics-and-seek", str(fresh.sandbox_id))
    )
    async with h.sessions.begin() as db:
        assert not await h.repository.mark_ready(
            db, old.sandbox_id, datetime.now(UTC), old.status_changed_at
        )
        assert await h.repository.mark_ready(
            db, fresh.sandbox_id, datetime.now(UTC), fresh.status_changed_at
        )
    await recovery(h).run_once()
    assert (await row_for(h, old.session_id)).status == "ready"


async def test_recovery_retains_reap_evidence_until_reclamation_then_restarts(life):
    h = life
    await detach(h)
    await eligible(h)
    from ads_sandbox_manager.lifecycle import REAP

    await h.lifecycle.admit(REAP, Signal(h.row.session_id, h.row.sandbox_id, h.row.pvc_id))
    h.cleanup.reclaim = False
    await h.lifecycle.execute((await works(h))[0].work_id)
    assert ("PersistentVolumeClaim", session_name(h.row.pvc_id)) not in h.kube.objects
    boundary = await condemn(h)
    await recovery(h).execute(h.row.session_id)
    assert (await row_for(h, h.row.session_id)).status == "recovering"
    assert await disk(h) is not None
    h.cleanup.reclaim = True
    await recovery(h).execute(h.row.session_id)  # Restart resumes saved, missing-PVC evidence.
    fresh = await row_for(h, h.row.session_id)
    assert fresh.status == "creating" and fresh.sandbox_id == boundary.sandbox_id
    assert fresh.pvc_id != h.row.pvc_id


async def test_recovery_missing_bound_pvc_without_evidence_fails_closed(life):
    h = life
    del h.kube.objects[("PersistentVolumeClaim", session_name(h.row.pvc_id))]
    await condemn(h)
    await recovery(h).execute(h.row.session_id)
    assert (await row_for(h, h.row.session_id)).status == "recovering"
    assert await disk(h) is not None
    assert await works(h)


@pytest.mark.parametrize("foreign", [False, True])
async def test_recovery_captures_created_but_uncommitted_uid_without_adopting_foreign(
    life, foreign
):
    h = life
    name = ipc_name(h.row.sandbox_id)
    obj = h.kube.objects[("Deployment", name)]
    if foreign:
        obj["metadata"]["labels"][SESSION] = str(uuid4())
    async with h.sessions.begin() as db:
        row = await db.get(SandboxSession, h.row.session_id)
        row.ipc_deployment_uid = None
    await condemn(h)
    await recovery(h).execute(h.row.session_id)
    if foreign:
        assert (await row_for(h, h.row.session_id)).status == "failed"
        assert not h.cleanup.deleted
        assert h.kube.objects[("Deployment", name)] == obj
    else:
        assert (await row_for(h, h.row.session_id)).status == "creating"
        assert ("Deployment", name, obj["metadata"]["uid"]) in h.cleanup.deleted


async def test_recovery_timeout_rotates_again_and_carries_unfinished_targets(life):
    h = life
    first = await condemn(h)
    h.cleanup.release = False
    await recovery(h).execute(h.row.session_id)
    targets = [deepcopy(t) for w in await works(h) for t in w.targets]
    await condemn(h, first.sandbox_id)  # Duplicate active recovery.
    assert (await row_for(h, h.row.session_id)).sandbox_id == first.sandbox_id
    async with h.sessions.begin() as db:
        row = await db.get(SandboxSession, h.row.session_id)
        row.status_changed_at -= timedelta(seconds=601)
    await h.lifecycle.scan("watchdog")
    signal = msgspec.json.decode(h.publisher.send.call_args.args[2], type=Signal)
    await h.lifecycle.admit(RECOVER, signal)
    second = await row_for(h, h.row.session_id)
    assert second.sandbox_id != first.sandbox_id
    carried = [obj for w in await works(h) for obj in w.targets]
    assert all(t in carried for t in targets)
    h.cleanup.release = True
    await recovery(h).execute(h.row.session_id)
    fresh = await row_for(h, h.row.session_id)
    assert fresh.status == "creating" and fresh.sandbox_id == second.sandbox_id
    assert fresh.pvc_id != h.row.pvc_id


async def test_stale_recovery_cannot_complete_or_fail_replacement(life):
    h = life
    first = await condemn(h)
    executor = recovery(h)
    original = h.topics.remove

    async def replace_boundary(sandbox):
        async with h.sessions.begin() as db:
            row = await db.get(SandboxSession, h.row.session_id)
            row.status = "failed"
            row.status_changed_at = advance(row.status_changed_at, datetime.now(UTC))
        await condemn(h, first.sandbox_id)
        return await original(sandbox)

    h.topics.remove = replace_boundary
    await executor.execute(h.row.session_id)
    second = await row_for(h, h.row.session_id)
    assert second.status == "recovering" and second.sandbox_id != first.sandbox_id
    assert not h.cleanup.deleted
    h.topics.remove = original
    await recovery(h).execute(h.row.session_id)
    assert (await row_for(h, h.row.session_id)).sandbox_id == second.sandbox_id
    assert (await row_for(h, h.row.session_id)).status == "creating"


async def test_orphan_scanner_cannot_steal_recovery_targets(life):
    h = life
    await condemn(h)
    await h.lifecycle.scan("orphan")
    h.publisher.send.assert_not_awaited()
    assert all(w.kind == "recovery" for w in await works(h))


async def test_restart_after_delete_before_progress_save_uses_persisted_capture(life):
    h = life
    await condemn(h)
    executor = recovery(h)
    original = h.cleanup.delete
    interrupted = False

    async def crash(obj):
        nonlocal interrupted
        await original(obj)
        if obj["kind"] == "PersistentVolumeClaim" and not interrupted:
            interrupted = True
            raise asyncio.CancelledError

    h.cleanup.delete = crash
    with pytest.raises(asyncio.CancelledError):
        await executor.execute(h.row.session_id)
    assert (await row_for(h, h.row.session_id)).status == "recovering"
    h.cleanup.delete = original
    await recovery(h).execute(h.row.session_id)
    assert (await row_for(h, h.row.session_id)).status == "creating"
    assert not await works(h)


async def test_topic_deletion_must_be_observed_before_kube_cleanup(life):
    h = life
    await condemn(h)
    h.topics.remove = AsyncMock(return_value=False)
    await recovery(h).execute(h.row.session_id)
    assert not h.cleanup.deleted and len(h.kube.objects) == 4
    h.topics.remove.return_value = True
    await recovery(h).execute(h.row.session_id)
    assert (await row_for(h, h.row.session_id)).status == "creating"


async def test_legacy_recovery_cannot_override_retained_workspace(life):
    h = life
    work = await idle(h)
    # Emulate an old manager's committed idle-to-recovery conversion, including
    # its rotated identity and cleared mapping. The retained target is still authority.
    async with h.sessions.begin() as db:
        row = await db.get(SandboxSession, h.row.session_id)
        row.status = "recovering"
        row.sandbox_id = uuid4()
        row.pvc_id = row.pvc_uid = None
        stored = await db.get(CleanupWork, work.work_id)
        stored.kind = "recovery"
    before = deepcopy(h.kube.objects)
    current = await row_for(h, h.row.session_id)
    await recovery(h).execute(h.row.session_id)
    await condemn(h, current.sandbox_id)
    assert h.kube.objects == before and not h.cleanup.deleted
    assert any(t.get("retain") for w in await works(h) for t in w.targets)
    assert await disk(h) is not None
    assert (await row_for(h, h.row.session_id)).sandbox_id == current.sandbox_id
    assert not any(call[0] == "delete-topics" for call in h.kube.calls)


async def test_recovery_requests_all_compute_deletions_before_waiting(life):
    h = life
    await condemn(h)
    original = h.cleanup.delete
    requested = []

    async def deleting(obj):
        requested.append(obj["name"])
        if obj["name"] != ipc_name(h.row.sandbox_id):
            await original(obj)

    h.cleanup.delete = deleting
    h.cleanup.released = AsyncMock(return_value=False)
    await recovery(h).execute(h.row.session_id)
    assert requested == [ipc_name(h.row.sandbox_id), session_name(h.row.sandbox_id)]
    h.cleanup.released.assert_not_awaited()
    assert (await row_for(h, h.row.session_id)).status == "recovering"
    assert await disk(h) is not None
    h.cleanup.delete = original
    h.cleanup.released.return_value = True
    await recovery(h).execute(h.row.session_id)
    assert (await row_for(h, h.row.session_id)).status == "creating"


@pytest.mark.parametrize("status", ["pending", "creating", "shutting_down", "failed", "recovering"])
async def test_watchdog_signals_stalled_sandboxes_even_without_pvc(life, status):
    h = life
    async with h.sessions.begin() as db:
        row = await db.get(SandboxSession, h.row.session_id)
        row.status = status
        row.status_changed_at -= timedelta(hours=1)
        row.pvc_id = row.pvc_uid = None
    await h.lifecycle.scan("watchdog")
    if status == "shutting_down":
        h.publisher.send.assert_not_awaited()
    else:
        assert any(c.args[0] == RECOVER for c in h.publisher.send.call_args_list)
    assert (await row_for(h, h.row.session_id)).status == status


async def test_recovery_replicas_serialize_external_work(life):
    h = life
    await condemn(h)
    gate, entered = asyncio.Event(), asyncio.Event()
    original = h.topics.remove

    async def blocked(sandbox):
        entered.set()
        await gate.wait()
        return await original(sandbox)

    h.topics.remove = blocked
    first = asyncio.create_task(recovery(h).run_once())
    try:
        await asyncio.wait_for(entered.wait(), 3)
        await recovery(h).run_once()
        assert not h.cleanup.deleted
        gate.set()
        await asyncio.wait_for(first, 5)
    finally:
        gate.set()
        await asyncio.gather(first, return_exceptions=True)
    assert len(h.cleanup.deleted) == 4
    assert (await row_for(h, h.row.session_id)).status == "creating"
