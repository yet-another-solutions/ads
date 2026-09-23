# ruff: noqa: F811
from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from kubernetes.client.exceptions import ApiException

from ads_sandbox_manager.lifecycle_store import CleanupWork
from ads_sandbox_manager.pair_store import PairClaimLost
from ads_sandbox_manager.relay_keys import RelayKeys, custody_secret
from ads_sandbox_manager.store import SandboxSession
from test_kube_release import api  # noqa: F401
from test_pair_controls import controls  # noqa: F401
from test_pair_creator_fence import cleanup_claim
from test_pair_store import begin, ledger, snapshot  # noqa: F401
from test_session_objects import object_settings  # noqa: F401
from test_sessions import row_for, sessions_harness  # noqa: F401

pytestmark = pytest.mark.anyio


async def reserved(f):
    intent = await begin(f)
    keys = RelayKeys.generate()
    async with f.h.sessions.begin() as db:
        original, _ = await f.repo.reserve_relay_keys(
            db, f.row, f.owner, intent.generation, keys.public_keys()
        )
    body = custody_secret(f.adapter.kube.settings, intent.binding(), keys)
    body["metadata"].update(uid="custody-uid", resourceVersion="1")
    f.adapter.kube.core.read_namespaced_secret.return_value = body
    return original, keys, body


async def saved(f, work):
    async with f.h.sessions() as db:
        return await db.get(CleanupWork, work.work_id)


@pytest.mark.parametrize("late", [False, True])
async def test_cleanup_captures_exact_custody_after_fence_without_private_keys(controls, late):
    f = controls
    original, keys, body = await reserved(f)
    if not late:
        async with f.h.sessions.begin() as db:
            await f.repo.bind_relay_keys(db, f.row, f.owner, original.generation, "custody-uid")
    capture, work, claim = await cleanup_claim(f)
    if late:
        f.adapter.kube.core.read_namespaced_secret.side_effect = ApiException(status=404)
        await capture.capture(work, recovery=claim)
        work = await saved(f, work)
        assert work.pair_snapshot["relay_custody"]["uid"] is None
        f.adapter.kube.core.read_namespaced_secret.side_effect = None
    await capture.capture(work, recovery=claim)
    current = await saved(f, work)
    assert current.pair_snapshot["relay_custody"] == {
        "public_keys": keys.public_keys(),
        "uid": "custody-uid",
        "dispatch": "inflight",
    }
    assert "data" not in current.pair_snapshot
    stored = await snapshot(f, original.generation)
    assert stored.creation_fenced
    assert stored.relay_custody["dispatch"] == "inflight"
    with pytest.raises(PairClaimLost):
        async with f.h.sessions.begin() as db:
            await f.repo.bind_relay_keys(db, f.row, f.owner, original.generation, "custody-uid")
    async with f.h.sessions.begin() as db:
        await f.repo.settle_relay_keys(db, original)  # Only original normal completion.
        assert not await capture.repository.complete(db, current, datetime.now(UTC))
    assert (await snapshot(f, original.generation)).relay_custody["dispatch"] == "settled"
    f.adapter.kube.core.delete_namespaced_secret.assert_not_called()


async def test_absent_custody_read_never_erases_recorded_uid(controls):
    f = controls
    original, _, _ = await reserved(f)
    async with f.h.sessions.begin() as db:
        await f.repo.bind_relay_keys(db, f.row, f.owner, original.generation, "custody-uid")
    capture, work, claim = await cleanup_claim(f)
    f.adapter.kube.core.read_namespaced_secret.side_effect = ApiException(status=404)
    await capture.capture(work, recovery=claim)
    assert (await saved(f, work)).pair_snapshot["relay_custody"]["uid"] == "custody-uid"
    assert (await snapshot(f, original.generation)).relay_custody["dispatch"] == "inflight"


async def test_custody_capture_rechecks_claim_after_external_read(controls):
    f = controls
    await reserved(f)
    capture, work, claim = await cleanup_claim(f)
    original = f.adapter.observe_relay_custody

    async def change(pair, uid):
        result = await original(pair, uid)
        async with f.h.sessions.begin() as db:
            row = await db.get(SandboxSession, claim.session_id)
            row.sandbox_id = uuid4()
        return result

    f.adapter.observe_relay_custody = change
    with pytest.raises(PairClaimLost):
        await capture.capture(work, recovery=claim)
    assert (await saved(f, work)).pair_snapshot["relay_custody"]["uid"] is None


async def test_custody_public_identity_change_blocks_cleanup_fence(controls):
    f = controls
    original, _, _ = await reserved(f)
    capture, work, claim = await cleanup_claim(f)
    async with f.h.sessions.begin() as db:
        stored = await db.get(type(original), original.generation)
        stored.relay_custody = {
            **stored.relay_custody,
            "public_keys": RelayKeys.generate().public_keys(),
        }
    with pytest.raises(PairClaimLost, match="custody cleanup identity"):
        await capture.capture(work, recovery=claim)
    f.adapter.kube.core.read_namespaced_secret.assert_not_called()


async def test_custody_capture_refuses_replacement_and_stale_work(controls):
    f = controls
    await reserved(f)
    capture, work, claim = await cleanup_claim(f)
    await capture.capture(work, recovery=claim)
    current = await saved(f, work)
    with pytest.raises(RuntimeError, match="replacement"):
        async with f.h.sessions.begin() as db:
            await capture.repository.record_relay_custody(
                db, current, "foreign", datetime.now(UTC), recovery=claim, recovery_seconds=120
            )
    with pytest.raises(PairClaimLost, match="work changed"):
        async with f.h.sessions.begin() as db:
            await capture.repository.record_relay_custody(
                db, work, "custody-uid", datetime.now(UTC), recovery=claim, recovery_seconds=120
            )
