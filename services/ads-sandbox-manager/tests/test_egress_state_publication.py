# ruff: noqa: F811
from __future__ import annotations

import asyncio
import base64
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from threading import Event, Lock
from uuid import uuid4

import pytest
from kubernetes.client.exceptions import ApiException
from sqlalchemy import delete, select, update

from ads_sandbox_manager.egress_state_kube import (
    EgressStateAdapter,
    decode_key,
    identity,
    key_secret,
    state_volume,
)
from ads_sandbox_manager.egress_state_publication import EgressStatePublication
from ads_sandbox_manager.egress_state_store import EgressState, EgressStateRepository, WrappingKey
from ads_sandbox_manager.lifecycle_store import CleanupWork, LifecycleRepository
from ads_sandbox_manager.pair_store import PairClaimLost, PairIntent
from ads_sandbox_manager.store import SandboxSession
from test_egress_state_store import reserve, snapshot, state_store  # noqa: F401
from test_kube_release import api  # noqa: F401
from test_pair_store import ledger  # noqa: F401
from test_session_objects import object_settings  # noqa: F401
from test_sessions import sessions_harness  # noqa: F401

pytestmark = pytest.mark.anyio


class MemoryResources:
    def __init__(self, api):
        self.objects, self.created = {}, []
        self.lock = Lock()
        self.delay = self.lost_reply = None
        self.started, self.release, self.finished = Event(), Event(), Event()
        api.core.read_namespaced_secret.side_effect = self.read
        api.core.read_namespaced_persistent_volume_claim.side_effect = self.read
        api.core.create_namespaced_secret.side_effect = self.create
        api.core.create_namespaced_persistent_volume_claim.side_effect = self.create

    def read(self, name, namespace, **kwargs):
        with self.lock:
            if name not in self.objects:
                raise ApiException(status=404)
            assert self.objects[name]["metadata"]["namespace"] == namespace
            return deepcopy(self.objects[name])

    def create(self, namespace, body, **kwargs):
        name, role = (
            body["metadata"]["name"],
            body["metadata"]["labels"]["ads.io/egress-state-role"],
        )
        if self.delay == role:
            self.started.set()
            if not self.release.wait(timeout=10):
                raise TimeoutError("fixture release not signalled")
        with self.lock:
            if name in self.objects:
                raise ApiException(status=409)
            assert body["metadata"]["namespace"] == namespace
            self.objects[name] = deepcopy(body)
            self.objects[name]["metadata"].update(uid=str(uuid4()), resourceVersion="1")
            self.created.append(role)
            self.finished.set()
            if self.lost_reply == role:
                self.lost_reply = None
                raise TimeoutError("private exception body must not escape")
            return deepcopy(self.objects[name])


@pytest.fixture
def publication(state_store, api):
    h = state_store
    h.settings = replace(h.f.h.settings, control_seconds=10)
    api.settings = h.settings
    h.adapter = EgressStateAdapter(api)
    h.remote = MemoryResources(api)
    h.service = EgressStatePublication(h.settings, h.f.h.sessions, h.repo, h.adapter)
    yield h
    h.remote.release.set()


async def prepare(h):
    return await h.service.prepare(h.f.row, h.pair.generation, storage_bytes=1024**3)


async def test_publisher_commits_anchor_and_dispatch_before_each_api_write(publication):
    h, seen = publication, []
    original = h.adapter._create

    async def create(state, role, body):
        async with h.f.h.sessions.begin() as db:
            # This lock would deadlock if the creator still held its transaction.
            await db.get(SandboxSession, h.f.row.session_id, with_for_update=True)
            pair = await db.get(PairIntent, h.pair.generation)
            saved = await h.repo.snapshot(db, state.state_id)
            assert pair.egress_state_id == state.state_id
            assert getattr(saved, f"{role}_dispatch") == "inflight"
            assert getattr(saved, f"{role}_uid") is None
            if role == "volume":
                assert saved.key_dispatch == "settled" and saved.key_uid
            seen.append(role)
        return await original(state, role, body)

    h.adapter._create = create
    result = await prepare(h)
    assert seen == h.remote.created == ["key", "volume"]
    assert result.key_dispatch == result.volume_dispatch == "settled"
    assert result.key_uid and result.volume_uid
    assert result.key_uid != result.volume_uid
    assert set(h.remote.objects) == {
        identity(result, role)["metadata"]["name"] for role in ("key", "volume")
    }
    for obj in h.remote.objects.values():
        assert not obj["metadata"].get("ownerReferences")
    assert not h.f.h.kube.calls
    assert (await h.adapter.load_key(result)).fingerprint == result.key_fingerprint


async def test_restart_observes_only_original_resources_and_key(publication, monkeypatch):
    h = publication
    first = await prepare(h)

    def forbidden(*args):
        pytest.fail("reserved wrapping key regenerated")

    monkeypatch.setattr("ads_sandbox_manager.egress_state_store.secrets.token_bytes", forbidden)
    h.service = EgressStatePublication(
        h.settings,
        h.f.h.sessions,
        EgressStateRepository(h.f.repo),
        EgressStateAdapter(h.adapter.kube),
    )
    second = await prepare(h)
    assert (second.state_id, second.key_uid, second.volume_uid, second.key_fingerprint) == (
        first.state_id,
        first.key_uid,
        first.volume_uid,
        first.key_fingerprint,
    )
    assert h.remote.created == ["key", "volume"]


@pytest.mark.parametrize("role", ["key", "volume"])
async def test_lost_reply_never_settles_or_recreates_after_restart(publication, role):
    h = publication
    h.remote.lost_reply = role
    with pytest.raises(RuntimeError, match="create failed") as error:
        await prepare(h)
    assert "private exception" not in str(error.value)
    state, key = await reserve(h)
    assert key is None and getattr(state, f"{role}_dispatch") == "inflight"
    assert getattr(state, f"{role}_uid") is None
    if role == "key":
        with pytest.raises(RuntimeError, match="bound and settled"):
            await prepare(h)
    else:
        await prepare(h)
    state = await snapshot(h, state.state_id)
    assert getattr(state, f"{role}_dispatch") == "inflight"
    assert getattr(state, f"{role}_uid") is not None
    assert h.remote.created == (["key"] if role == "key" else ["key", "volume"])


@pytest.mark.parametrize("role", ["key", "volume"])
async def test_cancellation_preserves_late_original_writer_completion(publication, role):
    h = publication
    h.remote.delay = role
    task = asyncio.create_task(prepare(h))
    try:
        assert await asyncio.to_thread(h.remote.started.wait, 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        state, _ = await reserve(h)
        assert getattr(state, f"{role}_dispatch") == "inflight"
        h.remote.release.set()
        assert await asyncio.to_thread(h.remote.finished.wait, 5)
        await h.service.drain()
        state = await snapshot(h, state.state_id)
        assert getattr(state, f"{role}_dispatch") == "settled"
        assert getattr(state, f"{role}_uid") is None
        result = await prepare(h)
        assert result.key_uid and result.volume_uid
        assert h.remote.created == ["key", "volume"]
    finally:
        h.remote.release.set()
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)


async def test_fence_during_dispatch_records_completion_but_cannot_bind_or_advance(publication):
    h = publication
    h.remote.delay = "key"
    task = asyncio.create_task(prepare(h))
    try:
        assert await asyncio.to_thread(h.remote.started.wait, 5)
        state, _ = await reserve(h)
        async with h.f.h.sessions.begin() as db:
            pair = await db.get(PairIntent, h.pair.generation, with_for_update=True)
            pair.creation_fenced = True
        h.remote.release.set()
        with pytest.raises(PairClaimLost, match="fenced"):
            await task
        state = await snapshot(h, state.state_id)
        assert state.key_dispatch == "settled" and state.key_uid is None
        assert state.volume_dispatch == "unissued"
        assert h.remote.created == ["key"]
    finally:
        h.remote.release.set()
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize("role", ["key", "volume"])
async def test_missing_bound_resource_never_recreates(publication, role):
    h = publication
    state = await prepare(h)
    del h.remote.objects[identity(state, role)["metadata"]["name"]]
    with pytest.raises(RuntimeError, match="disappeared"):
        await prepare(h)
    assert h.remote.created == ["key", "volume"]
    assert getattr(await snapshot(h, state.state_id), f"{role}_uid")


async def test_missing_anchored_sql_record_never_regenerates(publication, monkeypatch):
    h = publication
    state = await prepare(h)
    async with h.f.h.sessions.begin() as db:
        await db.execute(delete(EgressState).where(EgressState.state_id == state.state_id))

    def forbidden(*args):
        pytest.fail("missing anchored reservation regenerated wrapping key")

    monkeypatch.setattr("ads_sandbox_manager.egress_state_store.secrets.token_bytes", forbidden)
    with pytest.raises(RuntimeError, match="disappeared"):
        await prepare(h)
    assert h.remote.created == ["key", "volume"]


async def test_changed_pair_anchor_blocks_existing_record_adoption(publication):
    h = publication
    state, _ = await reserve(h)
    async with h.f.h.sessions.begin() as db:
        await db.execute(
            update(PairIntent)
            .where(PairIntent.generation == h.pair.generation)
            .values(egress_state_id=uuid4())
        )
    with pytest.raises(RuntimeError, match="anchor changed"):
        await prepare(h)
    async with h.f.h.sessions.begin() as db:
        with pytest.raises(RuntimeError, match="anchor changed"):
            await h.repo.owned(db, h.f.row, h.f.owner, h.pair.generation, state.state_id)
    assert not h.remote.created


async def test_cleanup_keeps_original_anchor_and_fence_refuses_drift(publication):
    h = publication
    state = await prepare(h)
    lifecycle = LifecycleRepository()
    async with h.f.h.sessions.begin() as db:
        assert await lifecycle.recover(
            db, h.f.row.session_id, h.f.row.sandbox_id, datetime.now(UTC), 120
        )
        work = await db.scalar(
            select(CleanupWork).where(CleanupWork.session_id == h.f.row.session_id)
        )
        assert work.pair_snapshot["egress_state_id"] == str(state.state_id)
        lifecycle.cleanup_pair(work)
        await lifecycle.fence_pair_creators(db, work)
    with pytest.raises(PairClaimLost):
        await prepare(h)
    async with h.f.h.sessions.begin() as db:
        pair = await db.get(PairIntent, h.pair.generation)
        pair.egress_state_id = uuid4()
    with pytest.raises(PairClaimLost, match="cleanup anchor"):
        async with h.f.h.sessions.begin() as db:
            await lifecycle.fence_pair_creators(db, work)
    assert (await snapshot(h, state.state_id)).key_uid == state.key_uid


@pytest.mark.parametrize(
    "fault",
    [
        "uid",
        "name",
        "namespace",
        "labels",
        "owner",
        "deleting",
        "mutable",
        "type",
        "data",
        "fingerprint",
        "stringData",
        "version",
    ],
)
async def test_wrapping_custody_identity_and_contents_are_exact(publication, fault):
    h = publication
    state = await prepare(h)
    obj = h.remote.objects[identity(state, "key")["metadata"]["name"]]
    if fault in ("uid", "name"):
        obj["metadata"][fault] = "foreign"
    elif fault == "namespace":
        h.adapter.kube.settings = replace(h.settings, namespace="other")
    elif fault == "labels":
        obj["metadata"]["labels"] = {}
    elif fault == "owner":
        obj["metadata"]["ownerReferences"] = [{"uid": "controller"}]
    elif fault == "deleting":
        obj["metadata"]["deletionTimestamp"] = "now"
    elif fault == "mutable":
        obj["immutable"] = False
    elif fault == "type":
        obj["type"] = "kubernetes.io/tls"
    elif fault == "data":
        obj["data"] = {"unexpected": "secret"}
    elif fault == "fingerprint":
        obj["data"] = {"wrapping.key": base64.b64encode(b"x" * 32).decode()}
    elif fault == "stringData":
        obj["stringData"] = {"wrapping.key": "secret"}
    else:
        obj["metadata"]["resourceVersion"] = ""
    with pytest.raises((RuntimeError, ValueError)):
        await h.adapter.load_key(state)
    assert h.remote.created == ["key", "volume"]


@pytest.mark.parametrize(
    "fault",
    ["capacity", "mode", "class", "access", "clone", "selector", "limits", "uid", "custody"],
)
async def test_volume_cannot_gain_different_storage_or_custody(publication, fault):
    h = publication
    state = await prepare(h)
    obj = h.remote.objects[identity(state, "volume")["metadata"]["name"]]
    spec = obj["spec"]
    if fault == "capacity":
        spec["resources"]["requests"]["storage"] = "2Gi"
    elif fault == "mode":
        spec["volumeMode"] = "Filesystem"
    elif fault == "class":
        spec["storageClassName"] = "local-path"
    elif fault == "access":
        spec["accessModes"] = ["ReadWriteMany"]
    elif fault == "clone":
        spec["dataSource"] = {"kind": "PersistentVolumeClaim", "name": "other"}
    elif fault == "selector":
        spec["selector"] = {"matchLabels": {"disk": "other"}}
    elif fault == "limits":
        spec["resources"]["limits"] = {"storage": "2Gi"}
    elif fault == "uid":
        obj["metadata"]["uid"] = str(uuid4())
    else:
        obj["metadata"]["labels"]["ads.io/wrapping-custody-uid"] = str(uuid4())
    with pytest.raises(RuntimeError):
        await h.adapter.observe_volume(state)
    assert h.remote.created == ["key", "volume"]


async def test_api_quantity_canonicalization_and_assigned_pv_do_not_change_capacity(publication):
    h = publication
    state = await prepare(h)
    obj = h.remote.objects[identity(state, "volume")["metadata"]["name"]]
    obj["spec"]["resources"]["requests"]["storage"] = "1Gi"
    obj["spec"]["volumeName"] = "allocated-pv"
    assert await h.adapter.observe_volume(state) == state.volume_uid
    assert state_volume(state)["spec"]["resources"]["requests"]["storage"] == str(1024**3)


async def test_custody_disappearance_after_volume_read_is_not_publication_success(publication):
    h = publication
    state = await prepare(h)
    original = h.adapter._read

    async def read(saved, role):
        obj = await original(saved, role)
        if role == "volume":
            del h.remote.objects[identity(saved, "key")["metadata"]["name"]]
        return obj

    h.adapter._read = read
    with pytest.raises(RuntimeError, match="disappeared"):
        await h.adapter.observe_volume(state)


@pytest.mark.parametrize("data", [None, {}, {"wrapping.key": "!"}, {"wrapping.key": "AA=="}])
async def test_invalid_wrapping_encoding_is_redacted(data):
    with pytest.raises(ValueError, match="invalid persistent wrapping custody"):
        decode_key(data, "0" * 64)


async def test_mismatched_key_and_unknown_role_cannot_build_or_publish(publication):
    h = publication
    state, _ = await reserve(h)
    with pytest.raises(ValueError, match="reservation"):
        key_secret(state, WrappingKey(b"x" * 32))
    with pytest.raises(ValueError, match="unsupported"):
        identity(state, "guest")
    with pytest.raises(ValueError, match="settled"):
        state_volume(state)
    with pytest.raises(ValueError, match="recorded"):
        await h.adapter.load_key(state)
    with pytest.raises(ValueError, match="recorded"):
        await h.adapter.observe_volume(state)
    assert not h.remote.created


async def test_concurrent_callers_never_duplicate_either_resource(publication):
    h = publication
    results = await asyncio.gather(*(prepare(h) for _ in range(6)), return_exceptions=True)
    # An observer that races original custody settlement cannot authorize volume
    # dispatch. It may fail closed, then a fresh attempt observes settled evidence.
    for result in results:
        if isinstance(result, Exception):
            assert isinstance(result, RuntimeError) and "bound and settled" in str(result)
    final = await prepare(h)
    assert final.key_uid and final.volume_uid
    assert h.remote.created == ["key", "volume"]


async def test_reservation_deadline_cannot_publish_before_session_lock(publication):
    h = publication
    h.service = EgressStatePublication(
        replace(h.settings, control_seconds=0.05), h.f.h.sessions, h.repo, h.adapter
    )
    async with h.f.h.sessions.begin() as db:
        await db.get(SandboxSession, h.f.row.session_id, with_for_update=True)
        with pytest.raises(TimeoutError):
            await prepare(h)
    async with h.f.h.sessions.begin() as db:
        pair = await db.get(PairIntent, h.pair.generation)
        assert pair.egress_state_id is None
        assert not list(await db.scalars(select(EgressState)))
    assert not h.remote.created


async def test_absent_unobserved_custody_times_out_without_regeneration_or_dispatch(publication):
    h = publication
    state, key = await reserve(h)
    assert key is not None
    h.service = EgressStatePublication(
        replace(
            h.settings,
            session_objects=replace(h.settings.session_objects, create_seconds=0.2),
        ),
        h.f.h.sessions,
        h.repo,
        h.adapter,
    )
    with pytest.raises(TimeoutError):
        await prepare(h)
    saved = await snapshot(h, state.state_id)
    assert saved.key_fingerprint == key.fingerprint
    assert saved.key_dispatch == "inflight" and saved.key_uid is None
    assert saved.volume_dispatch == "unissued"
    assert not h.remote.created


@pytest.mark.parametrize("failure", ["settings", "adapter", "claim", "session-config"])
async def test_invalid_publication_configuration_never_commits_reservation(publication, failure):
    h = publication
    if failure == "settings":
        h.service.settings = replace(h.settings, namespace="changed")
    elif failure == "adapter":
        h.adapter.kube.settings = replace(h.settings, namespace="changed")
    elif failure == "claim":
        h.f.row.claimed_by = None
    else:
        h.service.settings = replace(h.settings, session_objects=None)
    with pytest.raises((RuntimeError, PairClaimLost)):
        await prepare(h)
    async with h.f.h.sessions.begin() as db:
        assert not list(await db.scalars(select(EgressState)))
    assert not h.remote.created


@pytest.mark.parametrize("status", [403, 500])
async def test_sdk_secret_error_bodies_never_escape(publication, status):
    h = publication
    h.adapter.kube.core.create_namespaced_secret.side_effect = ApiException(
        status=status, reason="sensitive-material"
    )
    with pytest.raises(RuntimeError, match="create failed") as error:
        await prepare(h)
    assert "sensitive-material" not in str(error.value)
    state, _ = await reserve(h)
    h.adapter.kube.core.read_namespaced_secret.side_effect = ApiException(
        status=status, reason="sensitive-material"
    )
    with pytest.raises(RuntimeError, match="read failed") as error:
        await h.adapter.observe_key(state)
    assert "sensitive-material" not in str(error.value)
    assert state.key_dispatch == "inflight"


async def test_already_exists_requires_the_exact_reserved_key_and_identity(publication):
    h = publication
    state, key = await reserve(h)
    assert key is not None
    body = key_secret(state, key)
    body["metadata"].update(uid=str(uuid4()), resourceVersion="1")
    h.remote.objects[body["metadata"]["name"]] = body
    assert await h.adapter.create_key(state, key) == body["metadata"]["uid"]
    body["data"]["wrapping.key"] = base64.b64encode(b"z" * 32).decode()
    with pytest.raises(ValueError, match="wrapping custody"):
        await h.adapter.create_key(state, key)
    assert not h.remote.created


async def test_success_response_without_observable_resource_does_not_settle(publication):
    h = publication
    h.adapter.kube.core.create_namespaced_secret.side_effect = lambda *args, **kwargs: {}
    with pytest.raises(RuntimeError, match="not observable"):
        await prepare(h)
    state, _ = await reserve(h)
    assert state.key_dispatch == "inflight" and state.key_uid is None


async def test_bound_or_settled_state_never_authorizes_adapter_create(publication):
    h = publication
    state = await prepare(h)
    key = await h.adapter.load_key(state)
    with pytest.raises(RuntimeError, match="original unbound"):
        await h.adapter.create_key(state, key)
    with pytest.raises(RuntimeError, match="original unbound"):
        await h.adapter.create_volume(state)
    assert h.remote.created == ["key", "volume"]
