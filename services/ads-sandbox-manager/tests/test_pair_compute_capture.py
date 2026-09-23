# ruff: noqa: F811
from __future__ import annotations

import asyncio
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from kubernetes.client.exceptions import ApiException
from sqlalchemy import delete

from ads_sandbox_manager.lifecycle import ORPHAN, RECOVER, Signal
from ads_sandbox_manager.lifecycle_store import CleanupWork
from ads_sandbox_manager.pair_kube import PairControlAdapter
from ads_sandbox_manager.pair_objects import COMPUTE_ROLES, PairBinding, compute_identity
from ads_sandbox_manager.pair_store import PairClaimLost, PairIntent, compute_key
from ads_sandbox_manager.store import SandboxSession, SessionPVC
from test_kube_release import api  # noqa: F401
from test_lifecycle import life, works  # noqa: F401
from test_pair_cleanup_capture import capture, saved  # noqa: F401
from test_pair_cleanup_intent import paired  # noqa: F401
from test_ping_recovery import recovery
from test_session_objects import object_settings  # noqa: F401
from test_sessions import row_for, sessions_harness  # noqa: F401

pytestmark = pytest.mark.anyio


def observed(settings, pair, role, uid):
    body = compute_identity(settings, pair, role)
    body["metadata"].update(uid=uid, resourceVersion="9")
    # Identity capture deliberately does not treat spec/status as authority.
    body["spec"] = {"unexpected": "drift"}
    body["status"] = {"phase": "Failed"}
    return body


@pytest.fixture
def compute_api(api):
    pair = PairBinding(uuid4(), uuid4(), uuid4(), uuid4())
    return PairControlAdapter(api), pair


@pytest.mark.parametrize("role", COMPUTE_ROLES)
@pytest.mark.parametrize("terminating", [False, True])
async def test_exact_compute_read_captures_identity_not_runtime_or_readiness(
    compute_api, role, terminating
):
    adapter, pair = compute_api
    body = observed(adapter.kube.settings, pair, role, "pod-uid")
    if terminating:
        body["metadata"]["deletionTimestamp"] = "now"
    read = adapter.kube.core.read_namespaced_pod
    read.return_value = body
    assert await adapter.observe_compute(pair, role) == "pod-uid"
    assert await adapter.observe_compute(pair, role, "pod-uid") == "pod-uid"
    assert read.call_args.args == (body["metadata"]["name"], adapter.namespace)
    assert read.call_args.kwargs == {"_request_timeout": adapter.kube.settings.control_seconds}
    assert {call[0] for call in adapter.kube.core.mock_calls} == {"read_namespaced_pod"}
    assert "spec" not in compute_identity(adapter.kube.settings, pair, role)


@pytest.mark.parametrize(
    "change",
    [
        "uid",
        "name",
        "namespace",
        "resourceVersion",
        "ownerReferences",
        "kind",
        "apiVersion",
        "ads.io/session-id",
        "ads.io/sandbox-id",
        "ads.io/project-id",
        "ads.io/attachment-generation",
        "app.kubernetes.io/component",
        "ads.io/golden-version",
    ],
)
async def test_foreign_compute_never_captured(compute_api, change):
    adapter, pair = compute_api
    body = observed(adapter.kube.settings, pair, "guest", "pod-uid")
    if change in ("kind", "apiVersion"):
        body[change] = "foreign"
    elif change == "ownerReferences":
        body["metadata"][change] = [{"kind": "ReplicaSet", "uid": "controller"}]
    elif change == "resourceVersion":
        del body["metadata"][change]
    elif change in ("uid", "name", "namespace"):
        body["metadata"][change] = "foreign"
    else:
        assert change in body["metadata"]["labels"]
        body["metadata"]["labels"][change] = "foreign"
    adapter.kube.core.read_namespaced_pod.return_value = body
    with pytest.raises(RuntimeError, match="foreign, replaced"):
        await adapter.observe_compute(pair, "guest", "pod-uid")


@pytest.mark.parametrize("uid", ["", " ", False, 123])
async def test_invalid_recorded_compute_uid_fails_before_api(compute_api, uid):
    adapter, pair = compute_api
    with pytest.raises(ValueError, match="UID"):
        await adapter.observe_compute(pair, "guest", uid)
    assert not adapter.kube.core.mock_calls


@pytest.mark.parametrize("field", ["uid", "resourceVersion"])
@pytest.mark.parametrize("value", [None, False, 7, "", " "])
async def test_malformed_observed_identity_never_becomes_ownership(compute_api, field, value):
    adapter, pair = compute_api
    body = observed(adapter.kube.settings, pair, "guest", "pod-uid")
    body["metadata"][field] = value
    adapter.kube.core.read_namespaced_pod.return_value = body
    with pytest.raises(RuntimeError, match="unfenced"):
        await adapter.observe_compute(pair, "guest")


@pytest.mark.parametrize("role", ["ipc", "Deployment", "../guest", ""])
async def test_compute_scope_is_fixed_before_api(compute_api, role):
    adapter, pair = compute_api
    with pytest.raises(ValueError, match="role"):
        await adapter.observe_compute(pair, role)
    assert not adapter.kube.core.mock_calls


@pytest.mark.parametrize("status", [401, 403, 409, 500])
async def test_compute_api_failure_is_not_absence(compute_api, status):
    adapter, pair = compute_api
    adapter.kube.core.read_namespaced_pod.side_effect = ApiException(status=status)
    with pytest.raises(ApiException):
        await adapter.observe_compute(pair, "guest")


async def test_compute_404_and_timeout_are_not_success_or_release(compute_api):
    adapter, pair = compute_api
    adapter.kube.core.read_namespaced_pod.side_effect = ApiException(status=404)
    assert await adapter.observe_compute(pair, "guest", "known-uid") is None
    adapter.kube.core.read_namespaced_pod.side_effect = TimeoutError
    with pytest.raises(TimeoutError):
        await adapter.observe_compute(pair, "guest")
    assert {call[0] for call in adapter.kube.core.mock_calls} == {"read_namespaced_pod"}


@pytest.fixture(params=["normal", "recovery", "orphan"])
async def compute_capture(capture, request):
    h = capture
    h.mode = request.param
    h.claim = None
    if h.mode == "recovery":
        async with h.sessions.begin() as db:
            await db.execute(delete(CleanupWork))
            row = await db.get(SandboxSession, h.row.session_id)
            row.status = "ready"
            (await db.get(SessionPVC, h.row.pvc_id)).state = "attached"
        await h.lifecycle.admit(RECOVER, Signal(h.row.session_id, h.row.sandbox_id))
        h.claim = await row_for(h, h.row.session_id)
        h.work = await saved(h)
    elif h.mode == "orphan":
        obj = next(o for o in h.kube.objects.values() if o["kind"] == "Deployment")
        async with h.sessions.begin() as db:
            await db.execute(delete(SandboxSession))
        await h.lifecycle.admit(
            ORPHAN,
            Signal(
                h.row.session_id,
                h.row.sandbox_id,
                kind="Deployment",
                name=obj["metadata"]["name"],
                uid=obj["metadata"]["uid"],
            ),
        )
        h.work = await saved(h)
    for role in COMPUTE_ROLES:
        uid = "captured-guest-pod" if role == "guest" else f"owned-{role}"
        body = observed(h.settings, h.pair.binding(), role, uid)
        h.remote.objects[("Pod", body["metadata"]["name"])] = body
    async with h.sessions.begin() as db:
        intent = await db.get(PairIntent, h.pair.generation)
        intent.compute_dispatch = {compute_key(role): "inflight" for role in COMPUTE_ROLES}
    return h


async def run_capture(h):
    await h.capture.capture(await saved(h), recovery=h.claim)


async def assert_blocked(h):
    work = await saved(h)
    assert not h.remote.created and not h.cleanup.deleted and not h.kube.calls
    async with h.sessions.begin() as db:
        intent = await db.get(PairIntent, h.pair.generation)
        assert intent.creation_fenced
        assert set(intent.compute_dispatch.values()) == {"inflight"}
        assert not await h.lifecycle_repository.complete(db, work, datetime.now(UTC))
    return work


async def test_real_entry_points_commit_each_compute_uid_and_remain_blocked(compute_capture):
    h = compute_capture
    steps = []

    async def before(pair, role, uid):
        # Real row locks during SDK I/O prove SQL does not span the read.
        async with asyncio.timeout(5), h.sessions.begin() as db:
            work = await db.get(CleanupWork, h.work.work_id, with_for_update=True)
            intent = await db.get(PairIntent, pair.generation, with_for_update=True)
            assert intent.creation_fenced
            assert pair == h.pair.binding()
            assert sum(v is not None for v in work.pair_snapshot["compute_uids"].values()) == max(
                1, len(steps)
            )
            assert all(work.pair_snapshot["control_uids"].values())
        steps.append(role)

    h.adapter.before_compute = before
    h.service.build = AsyncMock()
    if h.claim:
        await recovery(h).execute(h.row.session_id)
        h.service.build.assert_not_awaited()
        assert (await row_for(h, h.row.session_id)).status == "recovering"
    else:
        await h.lifecycle.execute(h.work.work_id)
    assert steps == list(COMPUTE_ROLES)
    assert all((await assert_blocked(h)).pair_snapshot["compute_uids"].values())


async def test_compute_absence_late_appearance_and_replacement_preserve_ownership(compute_capture):
    h = compute_capture
    pods = {key: h.remote.objects.pop(key) for key in tuple(h.remote.objects) if key[0] == "Pod"}
    await run_capture(h)
    assert (await saved(h)).pair_snapshot["compute_uids"] == h.work.pair_snapshot["compute_uids"]
    h.remote.objects.update(pods)
    await run_capture(h)
    captured = deepcopy((await saved(h)).pair_snapshot)
    for key in pods:
        h.remote.objects.pop(key)
    await run_capture(h)
    assert (await saved(h)).pair_snapshot == captured
    h.remote.objects.update(pods)
    next(iter(pods.values()))["metadata"]["uid"] = "replacement"
    with pytest.raises(RuntimeError, match="replaced"):
        await run_capture(h)
    assert (await assert_blocked(h)).pair_snapshot == captured


@pytest.mark.parametrize("change", ["claim", "snapshot", "pvc", "configuration"])
async def test_compute_claim_or_configuration_loss_cannot_commit_or_advance(
    compute_capture, change
):
    h = compute_capture
    calls = []

    async def after(pair, role, uid):
        calls.append(role)
        async with h.sessions.begin() as db:
            work = await db.get(CleanupWork, h.work.work_id, with_for_update=True)
            if change == "configuration":
                h.capture.settings = replace(h.capture.settings, namespace="changed")
            elif change == "snapshot":
                work.pair_snapshot = {**work.pair_snapshot, "generation": str(uuid4())}
            elif change == "pvc":
                if h.mode == "orphan":
                    work.pvc_id = uuid4()
                else:
                    pvc = await db.get(SessionPVC, h.row.pvc_id, with_for_update=True)
                    if h.mode == "recovery":
                        pvc.state = "attached"
                    else:
                        pvc.last_state_change += timedelta(microseconds=1)
            elif h.mode == "orphan":
                await db.delete(work)
            else:
                row = await db.get(SandboxSession, h.row.session_id, with_for_update=True)
                row.status_changed_at += timedelta(microseconds=1)

    h.adapter.after_compute = after
    with pytest.raises((PairClaimLost, RuntimeError)):
        await run_capture(h)
    assert calls == ["guest"]
    assert not h.remote.created and not h.cleanup.deleted


async def test_compute_failed_commit_retries_observation_not_create(compute_capture):
    h = compute_capture
    original = h.lifecycle_repository.record_pair_compute

    # Fail on egress, after the guest observation is already durable.
    async def rollback(db, expected, role, *args, **kwargs):
        result = await original(db, expected, role, *args, **kwargs)
        if role == "egress":
            raise RuntimeError("commit failed")
        return result

    h.lifecycle_repository.record_pair_compute = rollback
    with pytest.raises(RuntimeError, match="commit failed"):
        await run_capture(h)
    compute = (await saved(h)).pair_snapshot["compute_uids"]
    assert compute["Pod/guest"] == "captured-guest-pod" and compute["Pod/egress"] is None
    h.lifecycle_repository.record_pair_compute = original
    await run_capture(h)
    assert all((await assert_blocked(h)).pair_snapshot["compute_uids"].values())


async def test_compute_cancelled_read_keeps_prior_commit_and_restart_recaptures(compute_capture):
    h = compute_capture
    started = asyncio.Event()

    async def before(pair, role, uid):
        if role == "guest-relay":
            started.set()
            await asyncio.Event().wait()

    h.adapter.before_compute = before
    task = asyncio.create_task(run_capture(h))
    try:
        await asyncio.wait_for(started.wait(), 5)
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    compute = (await saved(h)).pair_snapshot["compute_uids"]
    assert compute["Pod/egress"] == "owned-egress" and compute["Pod/guest-relay"] is None
    h.adapter.before_compute = None
    h.capture = type(h.capture)(
        h.capture.settings, h.sessions, type(h.lifecycle_repository)(), h.adapter
    )
    await run_capture(h)
    assert all((await assert_blocked(h)).pair_snapshot["compute_uids"].values())


async def test_compute_api_denial_never_reaches_destructive_cleanup(compute_capture):
    h = compute_capture
    h.adapter.kube.core.read_namespaced_pod.side_effect = ApiException(status=403)
    with pytest.raises(ApiException):
        await run_capture(h)
    assert (await saved(h)).pair_snapshot["compute_uids"] == h.work.pair_snapshot["compute_uids"]
    await assert_blocked(h)
