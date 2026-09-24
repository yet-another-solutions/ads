# ruff: noqa: F811
from __future__ import annotations

import asyncio
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from functools import partial
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from ads_sandbox_manager.ca_objects import ca_pvc
from ads_sandbox_manager.config import CaSettings
from ads_sandbox_manager.objects import JOB_UID, golden_pvc
from ads_sandbox_manager.pair_store import PairClaimLost, PairIntent
from ads_sandbox_manager.pair_volume_inputs import (
    VOLUME_ROLES,
    new_volume_resources,
    validate_volume_resources,
)
from ads_sandbox_manager.pair_volume_kube import PairVolumeAdapter
from ads_sandbox_manager.pair_volume_publication import PairVolumePublication
from ads_sandbox_manager.pair_volume_store import PairVolumeRepository
from ads_sandbox_manager.session_objects import ca_consumer_name, session_name
from ads_sandbox_manager.store import SandboxSession, SessionPVC
from test_kube_release import api  # noqa: F401
from test_pair_controls import controls  # noqa: F401
from test_pair_creator_fence import cleanup_claim
from test_pair_store import ledger, snapshot  # noqa: F401
from test_relay_custody_cleanup import saved
from test_session_objects import object_settings  # noqa: F401
from test_sessions import row_for, sessions_harness  # noqa: F401

pytestmark = pytest.mark.anyio


@pytest.fixture
async def publication(controls):
    f = controls
    settings = replace(f.service.settings, ca=CaSettings("registry.test/ca:v1", "signer", "extra"))
    f.h.settings = f.adapter.kube.settings = settings
    f.service.settings = settings
    f.intent = await f.service.prepare(f.row)
    f.golden_source = golden_pvc(settings, str(uuid4()))
    f.golden_source["metadata"].update(uid=str(uuid4()), resourceVersion="1")
    f.golden_source["status"] = {"phase": "Bound"}
    attempt = str(uuid4())
    f.ca_sources = {role: ca_pvc(settings, role, attempt) for role in ("public", "private")}
    for source in f.ca_sources.values():
        source["metadata"].update(uid=str(uuid4()), resourceVersion="1")
        source["status"] = {"phase": "Bound"}
    f.golden, f.ca = AsyncMock(), AsyncMock()
    f.golden.clone_source.return_value = f.golden_source
    f.ca.clone_sources.return_value = f.ca_sources
    kube = f.adapter.kube
    kube.core.read_namespaced_persistent_volume_claim.side_effect = partial(
        f.remote.read, "PersistentVolumeClaim"
    )
    kube.core.create_namespaced_persistent_volume_claim.side_effect = (
        lambda namespace, body, **kwargs: f.remote.create(namespace, body=body, **kwargs)
    )
    f.volumes = PairVolumeAdapter(kube, f.golden, f.ca)
    f.volumes_repo = PairVolumeRepository(f.repo)
    f.service = PairVolumePublication(settings, f.h.sessions, f.volumes_repo, f.volumes)
    f.remote.created.clear()
    f.remote.finished.clear()
    yield f
    f.remote.release.set()
    await f.service.drain()


async def prepare(f):
    return await f.service.prepare(f.row, f.intent.generation)


def name(f, role):
    return (
        session_name(f.row.pvc_id)
        if role == "workspace"
        else ca_consumer_name(f.row.sandbox_id, role)
    )


def resource(f, role):
    return f.remote.objects[("PersistentVolumeClaim", name(f, role))]


def hook_create(f, role, *, delayed=False, lost_reply=False):
    original = f.remote.create

    def create(namespace, body, **kwargs):
        if body["metadata"]["name"] == name(f, role):
            f.remote.finished.clear()
            f.remote.delay = delayed
            f.remote.lost_reply = lost_reply
        return original(namespace, body=body, **kwargs)

    f.adapter.kube.core.create_namespaced_persistent_volume_claim.side_effect = create


async def test_payload_committed_before_io_and_atomic_workspace_and_ca_bindings(publication):
    f, seen = publication, []
    original = f.volumes.create

    async def create(intent, role):
        async with asyncio.timeout(5), f.h.sessions.begin() as db:
            row = await db.get(SandboxSession, f.row.session_id, with_for_update=True)
            current = await f.repo.snapshot(db, intent.generation)
            entry = current.volume_resources[role]
            assert entry == intent.volume_resources[role]
            assert entry["dispatch"] == "inflight" and entry["uid"] is None
            assert entry["payload"]["pvc_id"] == str(row.pvc_id)
            if role != "workspace":
                assert str(row.ca_attempt) == entry["payload"]["sources"]["public"]["job_uid"]
                assert row.ca_sources == {
                    key: value["uid"] for key, value in entry["payload"]["sources"].items()
                }
            seen.append(role)
        return await original(intent, role)

    f.volumes.create = create
    first = await prepare(f)
    assert seen == list(VOLUME_ROLES)
    row = await row_for(f.h, f.row.session_id)
    async with f.h.sessions.begin() as db:
        pvc = await db.get(SessionPVC, row.pvc_id)
        assert pvc.uid == row.pvc_uid == resource(f, "workspace")["metadata"]["uid"]
        assert pvc.state == "attaching"
    assert row.ca_clones == {
        role: resource(f, role)["metadata"]["uid"] for role in ("guest", "egress", "key")
    }
    assert row.status == "creating" and not f.h.kube.calls
    assert all(
        entry["dispatch"] == "settled" and entry["uid"] for entry in first.volume_resources.values()
    )
    f.service = PairVolumePublication(
        f.h.settings, f.h.sessions, PairVolumeRepository(f.repo), f.volumes
    )
    assert (await prepare(f)).volume_resources == first.volume_resources
    assert len(f.remote.created) == 4


async def test_concurrent_creators_share_one_write_per_clone(publication):
    f = publication
    left, right = await asyncio.gather(prepare(f), prepare(f))
    assert left.volume_resources == right.volume_resources
    assert len(f.remote.created) == 4


@pytest.mark.parametrize("role", VOLUME_ROLES)
@pytest.mark.parametrize("fault", ["reply", "settlement", "binding"])
async def test_failed_write_or_commit_never_recreates_or_forges_settlement(
    publication, role, fault
):
    f = publication
    method = "settle" if fault == "settlement" else "bind"
    original = getattr(f.volumes_repo, method)

    async def fail(*args):
        result = await original(*args)
        member = args[2] if fault == "settlement" else args[4]
        if member == role:
            raise RuntimeError("commit failed")
        return result

    if fault == "reply":
        hook_create(f, role, lost_reply=True)
    else:
        setattr(f.volumes_repo, method, fail)
    with pytest.raises(RuntimeError):
        await prepare(f)
    before = (await snapshot(f, f.intent.generation)).volume_resources[role]
    assert before["uid"] is None
    assert before["dispatch"] == ("settled" if fault == "binding" else "inflight")
    setattr(f.volumes_repo, method, original)
    after = (await prepare(f)).volume_resources[role]
    assert after["payload"] == before["payload"] and after["dispatch"] == before["dispatch"]
    assert after["uid"] == resource(f, role)["metadata"]["uid"]
    assert len(f.remote.created) == 4


@pytest.mark.parametrize("role", VOLUME_ROLES)
@pytest.mark.parametrize("cancel_writer", [False, True])
async def test_cleanup_captures_late_clone_without_settlement_or_release(
    publication, role, cancel_writer
):
    f = publication
    hook_create(f, role, delayed=True)
    task = asyncio.create_task(prepare(f))
    try:
        assert await asyncio.to_thread(f.remote.started.wait, 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        operations = tuple(f.service._dispatches)
        assert len(operations) == 1
        if cancel_writer:
            operations[0].cancel()
            await asyncio.gather(*operations, return_exceptions=True)
        capture, work, claim = await cleanup_claim(f)
        await capture.capture(work, recovery=claim)
        first = await saved(f, work)
        assert first.pair_snapshot["volume_resources"][role]["uid"] is None
        f.remote.release.set()
        assert await asyncio.to_thread(f.remote.finished.wait, 5)
        await f.service.drain()
        await capture.capture(first, recovery=claim)
        final = await saved(f, work)
        assert (
            final.pair_snapshot["volume_resources"][role]["uid"]
            == resource(f, role)["metadata"]["uid"]
        )
        assert final.pair_snapshot["volume_resources"][role]["dispatch"] == "inflight"
        current = await snapshot(f, f.intent.generation)
        assert current.creation_fenced and current.volume_resources[role]["uid"] is None
        assert current.volume_resources[role]["dispatch"] == (
            "inflight" if cancel_writer else "settled"
        )
        async with f.h.sessions.begin() as db:
            assert not await capture.repository.complete(db, final, datetime.now(UTC))
        with pytest.raises(PairClaimLost):
            await prepare(f)
    finally:
        f.remote.release.set()
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize("role", VOLUME_ROLES)
@pytest.mark.parametrize(
    "fault", ["absent", "uid", "owner", "labels", "deleting", "source", "capacity"]
)
async def test_missing_replaced_or_incompatible_clone_never_repaired(publication, role, fault):
    f = publication
    before = await prepare(f)
    obj = resource(f, role)
    if fault == "absent":
        del f.remote.objects[("PersistentVolumeClaim", name(f, role))]
    elif fault == "uid":
        obj["metadata"]["uid"] = str(uuid4())
    elif fault == "owner":
        obj["metadata"]["ownerReferences"] = [{"uid": "foreign"}]
    elif fault == "labels":
        obj["metadata"]["labels"] = {}
    elif fault == "deleting":
        obj["metadata"]["deletionTimestamp"] = "now"
    elif fault == "source":
        obj["spec"]["dataSource"]["name"] = "foreign"
    else:
        obj["spec"]["resources"]["requests"]["storage"] = "999Gi"
    with pytest.raises(RuntimeError):
        await prepare(f)
    assert (await snapshot(f, f.intent.generation)).volume_resources == before.volume_resources
    assert len(f.remote.created) == 4


@pytest.mark.parametrize("role", ["workspace", "guest"])
@pytest.mark.parametrize("late", [False, True])
async def test_source_replacement_during_dispatch_cannot_bind(publication, role, late):
    f, original = publication, publication.volumes.create
    target = f.golden_source if role == "workspace" else f.ca_sources["private"]

    async def create(intent, member):
        if member == role and not late:
            target["metadata"]["uid"] = str(uuid4())
        return await original(intent, member)

    if late:
        remote = f.remote.create

        def create_remote(namespace, body, **kwargs):
            result = remote(namespace, body=body, **kwargs)
            if body["metadata"]["name"] == name(f, role):
                target["metadata"]["uid"] = str(uuid4())
            return result

        f.adapter.kube.core.create_namespaced_persistent_volume_claim.side_effect = create_remote
    f.volumes.create = create
    with pytest.raises(RuntimeError, match="sources changed"):
        await prepare(f)
    entry = (await snapshot(f, f.intent.generation)).volume_resources[role]
    assert entry["uid"] is None and entry["dispatch"] == "inflight"
    assert len(f.remote.created) == (0 if role == "workspace" else 1) + int(late)


@pytest.mark.parametrize(
    "fault", ["untracked", "disk-uid", "disk-state", "disk-scope", "missing", "ca-half", "control"]
)
async def test_untracked_or_changed_scope_blocks_dispatch(publication, fault):
    f = publication
    async with f.h.sessions.begin() as db:
        row = await db.get(SandboxSession, f.row.session_id)
        pvc = await db.get(SessionPVC, row.pvc_id)
        if fault == "untracked":
            row.pvc_uid = pvc.uid = "untracked"
        elif fault == "disk-uid":
            pvc.uid = "foreign"
        elif fault == "disk-state":
            pvc.state = "attached"
        elif fault == "disk-scope":
            pvc.sandbox_id = uuid4()
        elif fault == "missing":
            await db.delete(pvc)
        elif fault == "ca-half":
            row.ca_sources = {"public": "foreign"}
        else:
            intent = await db.get(PairIntent, f.intent.generation)
            intent.control_dispatch = {**intent.control_dispatch, "Service/egress": "inflight"}
    with pytest.raises(RuntimeError):
        await prepare(f)
    assert len(f.remote.created) == (1 if fault == "ca-half" else 0)


@pytest.mark.parametrize("fault", ["timestamp", "ca-anchor"])
async def test_restart_cannot_rewrite_committed_disk_transition_or_ca_anchor(publication, fault):
    f = publication
    before = await prepare(f)
    async with f.h.sessions.begin() as db:
        row = await db.get(SandboxSession, f.row.session_id)
        if fault == "timestamp":
            pvc = await db.get(SessionPVC, row.pvc_id)
            pvc.last_state_change += timedelta(microseconds=1)
        else:
            row.ca_attempt = row.ca_sources = row.ca_clones = None
    with pytest.raises(PairClaimLost):
        await prepare(f)
    assert (await snapshot(f, f.intent.generation)).volume_resources == before.volume_resources
    assert len(f.remote.created) == 4


async def test_clone_defaults_and_quantity_canonicalization(publication):
    f = publication
    before = await prepare(f)
    for role in VOLUME_ROLES:
        obj = resource(f, role)
        obj["spec"]["volumeName"] = "assigned-pv"
        obj["spec"]["dataSource"].pop("apiGroup")
        obj["spec"]["dataSourceRef"] = deepcopy(obj["spec"]["dataSource"])
        if role != "workspace":
            obj["spec"]["resources"]["requests"]["storage"] = "256Mi"
    assert (await prepare(f)).volume_resources == before.volume_resources
    assert len(f.remote.created) == 4


async def test_cleanup_keeps_known_uid_after_absence_without_source_reads(publication):
    f = publication
    before = await prepare(f)
    capture, work, claim = await cleanup_claim(f)
    f.golden.clone_source.side_effect = RuntimeError("must not read source")
    f.ca.clone_sources.side_effect = RuntimeError("must not read source")
    for role in VOLUME_ROLES:
        obj = resource(f, role)
        obj["metadata"]["deletionTimestamp"] = "now"
        obj["spec"] = {}
    await capture.capture(work, recovery=claim)
    first = await saved(f, work)
    assert first.pair_snapshot["volume_resources"] == before.volume_resources
    for role in VOLUME_ROLES:
        del f.remote.objects[("PersistentVolumeClaim", name(f, role))]
    await capture.capture(first, recovery=claim)
    final = await saved(f, work)
    assert final.pair_snapshot["volume_resources"] == before.volume_resources
    async with f.h.sessions.begin() as db:
        assert not await capture.repository.complete(db, final, datetime.now(UTC))


@pytest.mark.parametrize("fault", ["payload", "uid", "dispatch"])
async def test_cleanup_rejects_changed_clone_ownership(publication, fault):
    f = publication
    await prepare(f)
    capture, work, claim = await cleanup_claim(f)
    async with f.h.sessions.begin() as db:
        intent = await db.get(PairIntent, f.intent.generation)
        resources = deepcopy(intent.volume_resources)
        entry = resources["workspace"]
        if fault == "payload":
            entry["payload"]["sources"]["workspace"]["uid"] = str(uuid4())
        elif fault == "uid":
            entry["uid"] = str(uuid4())
        else:
            entry["dispatch"] = "inflight"
        intent.volume_resources = resources
    with pytest.raises(PairClaimLost, match="ownership changed"):
        await capture.capture(work, recovery=claim)
    assert (await saved(f, work)).pair_snapshot == work.pair_snapshot


@pytest.mark.parametrize("fault", ["status", "project", "pvc-transition"])
async def test_scope_change_after_io_cannot_bind_or_publish_next_clone(publication, fault):
    f, original = publication, publication.volumes.create

    async def create(intent, role):
        uid = await original(intent, role)
        async with f.h.sessions.begin() as db:
            row = await db.get(SandboxSession, f.row.session_id)
            if fault == "status":
                row.status = "failed"
            elif fault == "project":
                row.project_id = uuid4()
            else:
                pvc = await db.get(SessionPVC, row.pvc_id)
                pvc.last_state_change += timedelta(microseconds=1)
        return uid

    f.volumes.create = create
    with pytest.raises(PairClaimLost):
        await prepare(f)
    current = await snapshot(f, f.intent.generation)
    assert current.volume_resources["workspace"]["dispatch"] == "settled"
    assert current.volume_resources["workspace"]["uid"] is None
    assert len(f.remote.created) == 1


@pytest.mark.parametrize(
    "fault",
    [
        "unavailable",
        "name",
        "namespace",
        "deleting",
        "owner",
        "mode",
        "class",
        "access",
        "uid",
        "job",
        "size",
    ],
)
async def test_invalid_verified_source_fails_before_any_clone_reservation(publication, fault):
    f = publication
    obj = f.golden_source
    if fault == "unavailable":
        f.golden.clone_source.return_value = None
    elif fault in ("name", "namespace", "uid"):
        obj["metadata"][fault] = ""
    elif fault == "deleting":
        obj["metadata"]["deletionTimestamp"] = "now"
    elif fault == "owner":
        obj["metadata"]["ownerReferences"] = [{"uid": "foreign"}]
    elif fault == "job":
        obj["metadata"]["labels"][JOB_UID] = "invalid"
    elif fault == "size":
        obj["spec"]["resources"]["requests"]["storage"] = "0"
    elif fault == "mode":
        obj["spec"]["volumeMode"] = "Filesystem"
    elif fault == "class":
        obj["spec"]["storageClassName"] = "foreign"
    else:
        obj["spec"]["accessModes"] = ["ReadWriteMany"]
    with pytest.raises(RuntimeError, match="sources unavailable"):
        await prepare(f)
    assert (await snapshot(f, f.intent.generation)).volume_resources == new_volume_resources()
    assert not f.remote.created


@pytest.mark.parametrize("fault", ["different-job", "same-uid", "half"])
async def test_ca_pair_must_remain_one_complete_source_pair(publication, fault):
    f = publication
    if fault == "different-job":
        f.ca_sources["private"]["metadata"]["labels"][JOB_UID] = str(uuid4())
    elif fault == "same-uid":
        f.ca_sources["private"]["metadata"]["uid"] = f.ca_sources["public"]["metadata"]["uid"]
    else:
        del f.ca_sources["private"]
    with pytest.raises(RuntimeError):
        await prepare(f)
    current = await snapshot(f, f.intent.generation)
    assert current.volume_resources["workspace"]["uid"]
    assert all(
        current.volume_resources[role]["dispatch"] == "unissued"
        for role in ("guest", "egress", "key")
    )
    assert len(f.remote.created) == 1


@pytest.mark.parametrize("fault", ["extra", "missing", "uid", "dispatch", "payload", "unissued"])
def test_corrupt_clone_evidence_rejected(fault):
    value = new_volume_resources()
    if fault == "extra":
        value["extra"] = {}
    elif fault == "missing":
        del value["workspace"]
    elif fault == "uid":
        value["workspace"]["uid"] = "foreign"
    elif fault == "dispatch":
        value["workspace"]["dispatch"] = "finished"
    elif fault == "payload":
        value["workspace"] = {"uid": None, "dispatch": "inflight", "payload": {}}
    else:
        value["guest"]["payload"] = {}
    with pytest.raises(RuntimeError):
        validate_volume_resources(value)
