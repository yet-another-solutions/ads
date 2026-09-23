# ruff: noqa: F811
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from uuid import UUID, uuid4

import pytest
from kubernetes.client.exceptions import ApiException
from sqlalchemy import select

from ads_sandbox_manager.ca_objects import CA_NAME, ca_pvc
from ads_sandbox_manager.config import CaSettings
from ads_sandbox_manager.lifecycle import IDLE, LifecycleService, Signal
from ads_sandbox_manager.lifecycle_store import CleanupWork, LifecycleRepository, sandbox_targets
from ads_sandbox_manager.objects import COMPONENT, JOB_UID
from ads_sandbox_manager.session_objects import (
    CA_CONSUMER,
    CA_CONSUMER_ROLE,
    CA_CONSUMERS,
    CA_SOURCE_UID,
    ca_consumer_name,
    guest_deployment,
    session_name,
)
from ads_sandbox_manager.sessions import SessionBindError
from ads_sandbox_manager.store import SandboxSession, SessionPVC
from test_lifecycle import FakeCleanup
from test_session_objects import object_settings  # noqa: F401
from test_sessions import row_for, sessions_harness  # noqa: F401

pytestmark = pytest.mark.anyio


def configure_ca(h):
    # These identity/lifecycle tests write to real PostgreSQL, not a timed fake.
    # Allow failure-state commits to finish without masking the expected rejection.
    h.settings = replace(
        h.settings,
        ca=CaSettings("registry.test/ca:v1", "signer", "extra"),
        control_seconds=10,
    )
    h.service.settings = h.settings
    attempt = uuid4()
    sources = {}
    for role in ("public", "private"):
        obj = ca_pvc(h.settings, role, str(attempt))
        obj["metadata"].update(uid=str(uuid4()), resourceVersion="1")
        obj["status"] = {"phase": "Bound", "capacity": {"storage": "300Mi"}}
        sources[role] = obj
    h.sources, h.attempt = sources, attempt
    h.service.ca = SimpleNamespace(clone_sources=AsyncMock(side_effect=lambda: deepcopy(h.sources)))
    return h


async def test_ca_intent_precedes_all_clones_guest_gets_only_ro_public(sessions_harness):
    h, sid = configure_ca(sessions_harness), uuid4()

    async def before(body):
        if body["metadata"]["labels"][COMPONENT] == CA_CONSUMER:
            row = await row_for(h, sid)
            assert row.ca_attempt == h.attempt
            assert row.ca_sources == {
                role: obj["metadata"]["uid"] for role, obj in h.sources.items()
            }
            assert not any(k[0] == "Deployment" for k in h.kube.objects)

    h.kube.before_create = before
    row = await h.service.provision(sid)
    assert set(row.ca_clones) == set(CA_CONSUMERS)
    assert row.status == "creating"
    for role, source_role in CA_CONSUMERS.items():
        obj = h.kube.objects[("PersistentVolumeClaim", ca_consumer_name(row.sandbox_id, role))]
        assert obj["metadata"]["uid"] == row.ca_clones[role]
        assert obj["spec"]["dataSource"]["name"] == f"{CA_NAME}-{source_role}"
        assert obj["spec"]["volumeMode"] == "Block"
        assert obj["spec"]["resources"]["requests"]["storage"] == str(300 * 1024**2)
        assert obj["metadata"]["labels"][CA_SOURCE_UID] == row.ca_sources[source_role]
        assert "ownerReferences" not in obj["metadata"]
    guest = h.kube.objects[("Deployment", session_name(row.sandbox_id))]
    pod = guest["spec"]["template"]["spec"]
    assert pod["volumes"][-1] == {
        "name": "ca-public",
        "persistentVolumeClaim": {
            "claimName": ca_consumer_name(row.sandbox_id, "guest"),
            "readOnly": True,
        },
    }
    assert pod["containers"][0]["env"][-1] == {"name": "ADS_CA_ATTEMPT", "value": str(h.attempt)}
    assert "secret" not in str(pod["volumes"]).lower()
    assert ca_consumer_name(row.sandbox_id, "key") not in str(guest)
    assert (await row_for(h, sid)).ca_clones == row.ca_clones


@pytest.mark.parametrize("mode", ["missing-service", "not-ready", "split-attempt"])
async def test_no_compute_without_safe_source_pair(sessions_harness, mode):
    h, sid = configure_ca(sessions_harness), uuid4()
    if mode == "missing-service":
        h.service.ca = None
    elif mode == "not-ready":
        h.service.ca.clone_sources = AsyncMock(return_value=None)
    else:
        h.sources["private"]["metadata"]["labels"][JOB_UID] = str(uuid4())
    with pytest.raises(SessionBindError):
        await h.service.provision(sid)
    row = await row_for(h, sid)
    assert row.status == "failed" and row.ca_attempt is None
    assert not any(k[0] == "Deployment" for k in h.kube.objects)


@pytest.mark.parametrize("mode", ["attempt", "source-uid", "lost-response"])
async def test_create_race_keeps_cleanup_intent_and_never_starts_compute(sessions_harness, mode):
    h, sid = configure_ca(sessions_harness), uuid4()

    async def after(body):
        if body["metadata"]["labels"][COMPONENT] != CA_CONSUMER:
            return
        if mode == "lost-response":
            raise TimeoutError()
        if mode == "source-uid":
            h.sources["public"]["metadata"]["uid"] = str(uuid4())
        else:
            for obj in h.sources.values():
                obj["metadata"]["labels"][JOB_UID] = str(uuid4())

    h.kube.after_create = after
    with pytest.raises((SessionBindError, TimeoutError)):
        await h.service.provision(sid)
    row = await row_for(h, sid)
    assert row.ca_attempt == h.attempt and row.status == "failed"
    targets = sandbox_targets(row, retain=False)
    for role in CA_CONSUMERS:
        assert any(t["name"] == ca_consumer_name(row.sandbox_id, role) for t in targets)
    assert all(not t["name"].startswith(CA_NAME) for t in targets)
    assert not any(k[0] == "Deployment" for k in h.kube.objects)


@pytest.mark.parametrize("field", ["source", "owner", "reference", "deleting", "role", "lost"])
async def test_foreign_clone_conflicts_fail_closed_without_deletion(sessions_harness, field):
    h, sid = configure_ca(sessions_harness), uuid4()

    async def conflict(body):
        if body["metadata"]["labels"][COMPONENT] != CA_CONSUMER:
            return
        obj = h.kube.put(body)
        if field == "source":
            obj["spec"]["dataSource"]["name"] = "foreign"
        elif field == "owner":
            obj["metadata"]["ownerReferences"] = [{"uid": "foreign"}]
        elif field == "reference":
            obj["spec"]["dataSourceRef"] = {**body["spec"]["dataSource"], "namespace": "foreign"}
        elif field == "deleting":
            obj["metadata"]["deletionTimestamp"] = "now"
        elif field == "role":
            obj["metadata"]["labels"][CA_CONSUMER_ROLE] = "key"
        else:
            obj["status"] = {"phase": "Lost"}
        raise ApiException(status=409)

    h.kube.before_create = conflict
    with pytest.raises(SessionBindError, match="CA clone"):
        await h.service.provision(sid)
    assert (await row_for(h, sid)).status == "failed"
    assert len(h.kube.objects) == 2  # workspace and untouched conflicting clone


async def test_matching_conflict_and_api_mirrored_reference_adopt_exact_uid(sessions_harness):
    h, sid = configure_ca(sessions_harness), uuid4()

    async def conflict(body):
        if body["metadata"]["labels"][COMPONENT] == CA_CONSUMER:
            obj = h.kube.put(body)
            obj["spec"]["dataSourceRef"] = deepcopy(body["spec"]["dataSource"])
            obj["spec"]["dataSourceRef"].pop("apiGroup")
            obj["spec"]["dataSource"].pop("apiGroup")
            obj["spec"]["resources"]["requests"]["storage"] = "300Mi"
            raise ApiException(status=409)

    h.kube.before_create = conflict
    row = await h.service.provision(sid)
    assert set(row.ca_clones) == set(CA_CONSUMERS)
    async with h.sessions.begin() as db:
        assert await h.repository.mark_ready(
            db, row.sandbox_id, datetime.now(UTC), row.status_changed_at
        )


@pytest.mark.parametrize("mode", ["missing", "replaced"])
async def test_clone_rechecked_before_guest_compute(sessions_harness, mode):
    h, sid = configure_ca(sessions_harness), uuid4()

    async def topics(sandbox):
        key = ("PersistentVolumeClaim", ca_consumer_name(sandbox, "guest"))
        if mode == "missing":
            del h.kube.objects[key]
        else:
            h.kube.objects[key]["metadata"]["uid"] = str(uuid4())

    h.topics.hook = topics
    with pytest.raises(SessionBindError):
        await h.service.provision(sid)
    assert not any(k[0] == "Deployment" for k in h.kube.objects)


async def test_ready_refuses_partial_ca_bind(sessions_harness):
    h = configure_ca(sessions_harness)
    row = await h.service.provision(uuid4())
    async with h.sessions.begin() as db:
        current = await db.get(SandboxSession, row.session_id)
        current.ca_clones = {"guest": row.ca_clones["guest"]}
    async with h.sessions.begin() as db:
        assert not await h.repository.mark_ready(
            db, row.sandbox_id, datetime.now(UTC), row.status_changed_at
        )


async def test_idle_removes_all_clones_after_release_retains_workspace_and_resume_reclones(
    sessions_harness,
):
    h = configure_ca(sessions_harness)
    row = await h.service.provision(uuid4())
    now = datetime.now(UTC)
    async with h.sessions.begin() as db:
        assert await h.repository.mark_ready(db, row.sandbox_id, now, row.status_changed_at)
        current = await db.get(SandboxSession, row.session_id)
        pvc = await db.get(SessionPVC, row.pvc_id)
        current.last_execution_at = pvc.last_execution = now - timedelta(hours=4)
    cleanup, repository = FakeCleanup(h.kube), LifecycleRepository()
    service = LifecycleService(
        h.settings,
        h.sessions,
        repository,
        cleanup,
        AsyncMock(),
        Mock(mint=Mock(return_value="subject")),
        Mock(mint=Mock(return_value=SimpleNamespace(access_token="token"))),
        AsyncMock(),
    )
    await service.admit(IDLE, Signal(row.session_id, row.sandbox_id))
    async with h.sessions.begin() as db:
        work = await db.scalar(select(CleanupWork).where(CleanupWork.session_id == row.session_id))
    await service.shutdown_ack(row.sandbox_id, work.state_changed)
    cleanup.release = False
    await service.execute(work.work_id)
    assert all(kind == "Deployment" for kind, _, _ in cleanup.deleted)
    cleanup.release, cleanup.reclaim = True, False
    await service.execute(work.work_id)
    assert (await row_for(h, row.session_id)).status == "shutting_down"
    cleanup.reclaim = True
    await service.execute(work.work_id)
    stopped = await row_for(h, row.session_id)
    assert stopped.status == "stopped" and stopped.ca_attempt is None and stopped.ca_clones is None
    assert set(h.kube.objects) == {("PersistentVolumeClaim", session_name(row.pvc_id))}
    resumed = await h.service.provision(row.session_id)
    assert resumed.pvc_uid == row.pvc_uid
    assert set(resumed.ca_clones) == set(CA_CONSUMERS)
    assert all(resumed.ca_clones[role] != row.ca_clones[role] for role in CA_CONSUMERS)


async def test_recovery_captures_missing_uid_clone_before_identity_rotation(sessions_harness):
    h, sid = configure_ca(sessions_harness), uuid4()

    async def lost(body):
        if body["metadata"]["labels"][COMPONENT] == CA_CONSUMER:
            raise TimeoutError()

    h.kube.after_create = lost
    with pytest.raises(TimeoutError):
        await h.service.provision(sid)
    old = await row_for(h, sid)
    async with h.sessions.begin() as db:
        assert await LifecycleRepository().recover(db, sid, old.sandbox_id, datetime.now(UTC), 60)
    current = await row_for(h, sid)
    assert current.sandbox_id != old.sandbox_id and current.ca_attempt is None
    async with h.sessions.begin() as db:
        work = await db.scalar(select(CleanupWork).where(CleanupWork.session_id == sid))
    for role in CA_CONSUMERS:
        assert any(
            t["name"] == ca_consumer_name(old.sandbox_id, role) and t["uid"] is None
            for t in work.targets
        )
    orphan = h.kube.objects[("PersistentVolumeClaim", ca_consumer_name(old.sandbox_id, "guest"))]
    signal = LifecycleService.object_signal(orphan)
    assert signal.session_id == sid and signal.sandbox_id == old.sandbox_id
    for obj in h.sources.values():
        assert LifecycleService.object_signal(obj) is None
    foreign = deepcopy(orphan)
    foreign["metadata"]["name"] = f"{CA_NAME}-public"
    assert LifecycleService.object_signal(foreign) is None
    foreign["metadata"]["name"] = ca_consumer_name(old.sandbox_id, "guest")
    foreign["kind"] = "Deployment"
    assert LifecycleService.object_signal(foreign) is None


async def test_production_guest_builder_requires_attempt(sessions_harness):
    h = configure_ca(sessions_harness)
    with pytest.raises(ValueError, match="CA attempt"):
        guest_deployment(h.settings, uuid4(), uuid4(), h.settings.golden_version, uuid4())
    assert isinstance(h.attempt, UUID)


async def test_committed_clone_missing_is_not_silently_recreated(sessions_harness):
    h = configure_ca(sessions_harness)
    row = await h.service.provision(uuid4())
    key = ("PersistentVolumeClaim", ca_consumer_name(row.sandbox_id, "key"))
    del h.kube.objects[key]
    creates = [c for c in h.kube.calls if c[0] == "create"]
    with pytest.raises(SessionBindError, match="committed CA clone missing"):
        await h.service.build(row, resume=False)
    assert creates == [c for c in h.kube.calls if c[0] == "create"]
    assert (await row_for(h, row.session_id)).status == "failed"


async def test_process_restart_reuses_exact_three_clone_bindings(sessions_harness):
    h = configure_ca(sessions_harness)
    row = await h.service.provision(uuid4())
    creates = [c for c in h.kube.calls if c[0] == "create"]
    # A restarted worker may continue only with the same durable claim.
    from ads_sandbox_manager.sessions import SessionProvisioner

    service = SessionProvisioner(
        h.settings,
        h.kube,
        h.golden,
        h.sessions,
        h.repository,
        h.topics,
        h.projects,
        h.service.ca,
    )
    resumed = await service.build(await row_for(h, row.session_id), resume=False)
    assert resumed.ca_attempt == row.ca_attempt and resumed.ca_clones == row.ca_clones
    assert creates == [c for c in h.kube.calls if c[0] == "create"]
