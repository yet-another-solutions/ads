# ruff: noqa: F811
from __future__ import annotations

import asyncio
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from functools import partial
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import pytest
from sqlalchemy import delete, select

from ads_sandbox_manager.egress_state_store import EgressState
from ads_sandbox_manager.lifecycle_store import CleanupWork, LifecycleRepository, sandbox_targets
from ads_sandbox_manager.pair_creation import PairCreation
from ads_sandbox_manager.pair_store import PairClaimLost, PairIntent
from ads_sandbox_manager.store import SandboxSession, SessionPVC
from test_kube_release import api  # noqa: F401
from test_manager_config import (
    configure,
    manager_tls,  # noqa: F401
    pair_inputs,
)
from test_pair_controls import controls  # noqa: F401
from test_pair_creator_fence import cleanup_claim
from test_pair_store import ledger, snapshot  # noqa: F401
from test_pair_volume_publication import publication as volume_publication  # noqa: F401
from test_relay_custody_cleanup import saved
from test_session_objects import object_settings  # noqa: F401
from test_sessions import row_for, sessions_harness  # noqa: F401

pytestmark = pytest.mark.anyio


@pytest.fixture
async def creation(volume_publication, monkeypatch):
    f = volume_publication
    settings = replace(
        f.h.settings,
        keycloak_issuer="https://identity.test",
        keycloak_well_known_url="https://identity.test/.well-known/openid-configuration",
        ads_service_subject=uuid4(),
        pair_inputs=pair_inputs(),
        session_objects=replace(f.h.settings.session_objects, create_seconds=60),
    )
    f.h.settings = f.adapter.kube.settings = settings
    kube = f.adapter.kube
    kube.core.create_namespaced_pod.side_effect = f.remote.create
    kube.core.read_namespaced_secret.side_effect = partial(f.remote.read, "Secret")
    kube.core.create_namespaced_secret.side_effect = f.remote.create
    kube.apps = Mock()
    kube.apps.read_namespaced_deployment.side_effect = partial(f.remote.read, "Deployment")
    kube.apps.create_namespaced_deployment.side_effect = f.remote.create

    # Both established SDK calling conventions remain real above the fake API.
    def pvc_create(namespace, *args, body=None, **kwargs):
        return f.remote.create(namespace, body=body if body is not None else args[0], **kwargs)

    kube.core.create_namespaced_persistent_volume_claim.side_effect = pvc_create
    monkeypatch.setattr(
        "ads_sandbox_manager.pair_creation.PairControlAdapter", lambda kube: f.adapter
    )
    f.topics = AsyncMock()
    f.creator = PairCreation(settings, f.h.sessions, kube, f.golden, f.ca, f.topics)
    f.h.service.settings = settings
    f.h.service.pair_creation = f.creator
    yield f
    f.remote.release.set()
    await f.creator.drain()
    async with f.h.sessions.begin() as db:
        await db.execute(delete(EgressState))


async def build(f):
    return await f.h.service.build(f.row, resume=False)


async def test_existing_provisioner_uses_full_pair_and_only_ipc_ready_admits(creation):
    f = creation
    sid = uuid4()
    observed = []

    async def topics(sandbox):
        async with f.h.sessions.begin() as db:
            intent = await db.scalar(select(PairIntent).where(PairIntent.sandbox_id == sandbox))
            assert intent.topics_dispatch == "inflight"
            assert not any(intent.compute_uids.values())
            observed.append(sandbox)

    f.topics.prepare.side_effect = topics
    row = await f.h.service.provision(sid)
    assert observed == [row.sandbox_id] and row.status == "creating"
    assert row.guest_deployment_uid is None
    assert row.ipc_deployment_uid is None
    assert row.ipc_pod_uid and row.pvc_uid and len(row.ca_clones) == 3
    assert len(f.remote.created) == 23
    assert not any(kind == "Deployment" for kind, _ in f.remote.objects)
    f.adapter.kube.apps.create_namespaced_deployment.assert_not_called()
    async with f.h.sessions.begin() as db:
        intent = await db.scalar(select(PairIntent).where(PairIntent.session_id == sid))
        assert intent.topics_dispatch == "settled"
        assert all(intent.compute_uids.values())
        assert await f.h.repository.mark_ready(
            db, row.sandbox_id, datetime.now(UTC), row.status_changed_at
        )
    ready = await row_for(f.h, sid)
    assert ready.status == "ready"
    async with f.h.sessions.begin() as db:
        assert (await db.get(SessionPVC, ready.pvc_id)).state == "attached"
    assert not f.h.kube.calls  # Legacy fake Kubernetes and topics were never used.


async def test_restart_reuses_committed_pair_without_writes_or_topic_replay(creation):
    f = creation
    first = await build(f)
    count = len(f.remote.created)
    f.h.service.pair_creation = PairCreation(
        f.h.settings, f.h.sessions, f.adapter.kube, f.golden, f.ca, f.topics
    )
    second = await build(f)
    assert second.ipc_pod_uid == first.ipc_pod_uid
    assert len(f.remote.created) == count
    f.topics.prepare.assert_awaited_once()


async def test_untracked_ipc_pod_never_enters_legacy_claim_ready_or_cleanup(creation):
    f = creation
    row = await build(f)
    uid = row.ipc_pod_uid
    async with f.h.sessions.begin() as db:
        before = set(await db.scalars(select(CleanupWork.work_id)))
        await db.execute(delete(PairIntent))
        await db.execute(delete(EgressState))
    async with f.h.sessions.begin() as db:
        assert not await f.h.repository.mark_ready(
            db, row.sandbox_id, datetime.now(UTC), row.status_changed_at
        )
    with pytest.raises(RuntimeError, match="Pod binding blocks legacy"):
        async with f.h.sessions.begin() as db:
            await f.h.repository._require_unpaired(db, row.session_id, row.sandbox_id)
    with pytest.raises(RuntimeError, match="no retained generation"):
        async with f.h.sessions.begin() as db:
            await LifecycleRepository().work(
                db,
                row,
                await db.get(SessionPVC, row.pvc_id),
                "idle",
                datetime.now(UTC),
                120,
                sandbox_targets(row, retain=True),
            )
    assert (await row_for(f.h, row.session_id)).ipc_pod_uid == uid
    async with f.h.sessions.begin() as db:
        assert set(await db.scalars(select(CleanupWork.work_id))) == before


async def test_cleanup_rejects_changed_session_pod_uid_before_rotating_identity(creation):
    f = creation
    row = await build(f)
    async with f.h.sessions.begin() as db:
        current = await db.get(SandboxSession, row.session_id)
        current.ipc_pod_uid = "foreign"
    with pytest.raises(RuntimeError, match="Pod session identity changed"):
        async with f.h.sessions.begin() as db:
            await LifecycleRepository().recover(
                db, row.session_id, row.sandbox_id, datetime.now(UTC), 120
            )
    current = await row_for(f.h, row.session_id)
    assert current.sandbox_id == row.sandbox_id and current.ipc_pod_uid == "foreign"


@pytest.mark.parametrize("replacement", [False, True])
async def test_ipc_ready_between_final_bind_and_creator_return(creation, replacement):
    f, original = creation, creation.creator.ipc.prepare

    async def prepare(*args, **kwargs):
        intent = await original(*args, **kwargs)
        async with f.h.sessions.begin() as db:
            assert await f.h.repository.mark_ready(
                db,
                f.row.sandbox_id,
                datetime.now(UTC),
                f.row.status_changed_at,
            )
            if replacement:
                row = await db.get(SandboxSession, f.row.session_id)
                row.claimed_by = uuid4()
        return intent

    f.creator.ipc.prepare = prepare
    if replacement:
        with pytest.raises(PairClaimLost):
            await f.creator.build(f.row, resume=False)
    else:
        assert (await build(f)).status == "ready"
    assert (await row_for(f.h, f.row.session_id)).status == "ready"


@pytest.mark.parametrize(
    "failed",
    ["controls", "volumes", "topics", "compute", "keys", "inputs", "state", "egress", "ipc"],
)
async def test_every_creation_failure_stops_later_stages_and_retains_claim_evidence(
    creation, failed
):
    f, seen = creation, []
    order = ["controls", "volumes", "topics", "compute", "keys", "inputs", "state", "egress", "ipc"]
    for stage in order:
        component = f.topics if stage == "topics" else getattr(f.creator, stage)
        original = component.prepare

        async def prepare(*args, stage=stage, original=original, **kwargs):
            seen.append(stage)
            if stage == failed:
                raise RuntimeError("fixture stage failure")
            return await original(*args, **kwargs)

        component.prepare = prepare
    with pytest.raises(RuntimeError, match="stage failure"):
        await build(f)
    assert seen == order[: order.index(failed) + 1]
    assert (await row_for(f.h, f.row.session_id)).status == "failed"
    current = await snapshot(f, f.intent.generation)
    assert current is not None
    assert current.topics_dispatch == (
        "inflight"
        if failed == "topics"
        else "unissued"
        if failed in ("controls", "volumes")
        else "settled"
    )
    assert not f.h.kube.calls


async def test_failed_topic_write_remains_inflight_and_never_starts_compute(creation):
    f = creation
    f.topics.prepare.side_effect = RuntimeError("broker unavailable")
    with pytest.raises(RuntimeError):
        await f.creator.build(f.row, resume=False)
    current = await snapshot(f, f.intent.generation)
    assert current.topics_dispatch == "inflight"
    assert not any(current.compute_uids.values())
    f.topics.prepare.side_effect = None
    with pytest.raises(PairClaimLost, match="ambiguous"):
        await f.creator.build(f.row, resume=False)
    f.topics.prepare.assert_awaited_once()
    assert len(f.remote.created) == 4


@pytest.mark.parametrize("cancel_writer", [False, True])
async def test_late_topic_writer_survives_caller_but_cannot_cross_cleanup(creation, cancel_writer):
    f = creation
    entered, release = asyncio.Event(), asyncio.Event()

    async def topics(_):
        entered.set()
        await release.wait()

    f.topics.prepare.side_effect = topics
    task = asyncio.create_task(f.creator.build(f.row, resume=False))
    try:
        await asyncio.wait_for(entered.wait(), 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        operations = tuple(f.creator._dispatches)
        assert len(operations) == 1
        if cancel_writer:
            operations[0].cancel()
            await asyncio.gather(*operations, return_exceptions=True)
        capture, work, claim = await cleanup_claim(f)
        await capture.capture(work, recovery=claim)
        release.set()
        await f.creator.drain()
        current = await snapshot(f, f.intent.generation)
        assert current.creation_fenced
        assert current.topics_dispatch == ("inflight" if cancel_writer else "settled")
        assert not any(current.compute_uids.values())
        final = await saved(f, work)
        assert final.pair_snapshot["topics_dispatch"] == "inflight"
        assert await capture.capture(final, recovery=claim) is (not cancel_writer)
        assert (await saved(f, work)).pair_snapshot["topics_dispatch"] == "inflight"
        async with f.h.sessions.begin() as db:
            assert not await capture.repository.complete(db, final, datetime.now(UTC))
    finally:
        release.set()
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize(
    "fault",
    [
        "topics",
        "control",
        "compute",
        "custody",
        "inputs",
        "volumes",
        "ipc",
        "state",
        "legacy",
        "fenced",
    ],
)
async def test_authenticated_ready_cannot_bypass_incomplete_or_ambiguous_pair(creation, fault):
    f = creation
    row = await build(f)
    async with f.h.sessions.begin() as db:
        intent = await db.get(PairIntent, f.intent.generation)
        if fault == "topics":
            intent.topics_dispatch = "inflight"
        elif fault == "control":
            intent.control_dispatch = {**intent.control_dispatch, "Service/egress": "inflight"}
        elif fault == "compute":
            intent.compute_dispatch = {**intent.compute_dispatch, "Pod/egress": "inflight"}
        elif fault == "custody":
            intent.relay_custody = {**intent.relay_custody, "dispatch": "inflight"}
        elif fault == "inputs":
            entries = deepcopy(intent.relay_inputs)
            entries["guest-relay"]["dispatch"] = "inflight"
            intent.relay_inputs = entries
        elif fault in ("volumes", "ipc"):
            field = "volume_resources" if fault == "volumes" else "ipc_resources"
            entries = deepcopy(getattr(intent, field))
            next(iter(entries.values()))["dispatch"] = "inflight"
            setattr(intent, field, entries)
        elif fault == "state":
            state = await db.get(EgressState, intent.egress_state_id)
            state.key_dispatch = "inflight"
        elif fault == "legacy":
            current = await db.get(SandboxSession, row.session_id)
            current.guest_deployment_uid = "untracked"
        else:
            intent.creation_fenced = True
    async with f.h.sessions.begin() as db:
        assert not await f.h.repository.mark_ready(
            db, row.sandbox_id, datetime.now(UTC), row.status_changed_at
        )
    assert (await row_for(f.h, row.session_id)).status == "creating"


@pytest.mark.parametrize(
    "fault",
    ["workspace", "ca-clone", "ipc-volume", "ipc-pod", "state-missing", "owner", "legacy-ipc"],
)
async def test_ready_rechecks_exact_current_dependency_bindings(creation, fault):
    f = creation
    row = await build(f)
    async with f.h.sessions.begin() as db:
        current = await db.get(SandboxSession, row.session_id)
        if fault == "workspace":
            current.pvc_uid = "foreign"
        elif fault == "ca-clone":
            current.ca_clones = {**current.ca_clones, "key": "foreign"}
        elif fault == "ipc-volume":
            current.ipc_pvc_uid = "foreign"
        elif fault == "ipc-pod":
            current.ipc_pod_uid = "foreign"
        elif fault == "legacy-ipc":
            current.ipc_deployment_uid = "foreign"
        elif fault == "owner":
            current.claimed_by = uuid4()
        else:
            await db.execute(delete(EgressState))
    async with f.h.sessions.begin() as db:
        assert not await f.h.repository.mark_ready(
            db, row.sandbox_id, datetime.now(UTC), row.status_changed_at
        )
    assert (await row_for(f.h, row.session_id)).status == "creating"


@pytest.mark.parametrize("fault", ["resume", "missing-service"])
async def test_no_legacy_fallback_for_configured_pair(creation, fault):
    f = creation
    if fault == "missing-service":
        f.h.service.pair_creation = None
    with pytest.raises(RuntimeError):
        await f.h.service.build(f.row, resume=fault == "resume")
    assert not f.remote.created and not f.h.kube.calls


@pytest.mark.parametrize(
    "fault", ["missing", "null", "extra", "mtu", "runtime", "subject", "size", "issuer"]
)
def test_runtime_inputs_are_required_and_strict(monkeypatch, manager_tls, fault):
    import json

    from ads_sandbox_manager.config import load_settings

    configure(monkeypatch, manager_tls)
    value = pair_inputs()
    if fault == "missing":
        monkeypatch.delenv("ADS_SANDBOX_MANAGER_PAIR_INPUTS")
    else:
        if fault == "null":
            value = None
        elif fault == "extra":
            value["private_key"] = "not-allowed"
        elif fault == "mtu":
            value["guest"]["transport_mtu"] = 1500
        elif fault == "runtime":
            value["guest"]["runtime_class"] = value["egress"]["runtime_class"]
        elif fault == "subject":
            value["egress"]["ipc_service_subject"] = "not-a-native-uuid"
        elif fault == "size":
            value["state_bytes"] = True
        else:
            value["egress"]["keycloak_issuer"] = "https://override.test"
        monkeypatch.setenv("ADS_SANDBOX_MANAGER_PAIR_INPUTS", json.dumps(value))
    with pytest.raises((ValueError, RuntimeError)):
        load_settings()
