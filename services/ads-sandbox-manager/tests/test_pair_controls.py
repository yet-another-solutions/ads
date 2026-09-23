# ruff: noqa: F811
from __future__ import annotations

import asyncio
from copy import deepcopy
from dataclasses import replace
from datetime import timedelta
from functools import partial
from threading import Event, Lock
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import pytest
from kubernetes.client.exceptions import ApiException
from sqlalchemy import delete, select

from ads_sandbox_manager.pair_controls import PairControlProvisioner
from ads_sandbox_manager.pair_kube import PairControlAdapter
from ads_sandbox_manager.pair_store import CONTROL_RESOURCES, PairClaimLost, PairIntent
from ads_sandbox_manager.store import SandboxSession
from test_kube_release import api  # noqa: F401
from test_pair_store import ledger, snapshot  # noqa: F401
from test_session_objects import object_settings  # noqa: F401
from test_sessions import row_for, sessions_harness  # noqa: F401

pytestmark = pytest.mark.anyio


class MemoryControlApi:
    """Only the remote SDK is fake; real adapter, transactions and serialization."""

    def __init__(self, adapter):
        self.objects, self.created = {}, []
        self.lock = Lock()
        self.lost_reply = False
        self.delay = False
        self.started, self.release, self.finished = Event(), Event(), Event()
        adapter.custom = Mock()
        adapter.networking = Mock()
        adapter.kube.core.read_namespaced_pod.side_effect = partial(self.read, "Pod")
        for kind, sdk, name, verb in (
            ("PodGroup", adapter.custom, "custom_object", "get"),
            ("Service", adapter.kube.core, "service", "read"),
            ("NetworkPolicy", adapter.networking, "network_policy", "read"),
        ):
            getattr(sdk, verb + "_namespaced_" + name).side_effect = partial(self.read, kind)
            getattr(sdk, "create_namespaced_" + name).side_effect = self.create

    def read(self, kind, *args, **kwargs):
        key = (kind, args[-1] if kind == "PodGroup" else args[0])
        with self.lock:
            if key not in self.objects:
                raise ApiException(status=404)
            return deepcopy(self.objects[key])

    def create(self, *args, body, **kwargs):
        if self.delay:
            self.started.set()
            if not self.release.wait(timeout=10):
                raise TimeoutError("fixture release not signalled")
        with self.lock:
            key = (body["kind"], body["metadata"]["name"])
            if key in self.objects:
                raise ApiException(status=409)
            obj = deepcopy(body)
            obj["metadata"].update(uid=str(uuid4()), resourceVersion="1")
            if body["kind"] == "Service":
                obj["spec"]["clusterIP"] = "10.2.3.4"
            self.objects[key] = obj
            self.created.append(key)
            self.finished.set()
            if self.lost_reply:
                self.lost_reply = False
                raise TimeoutError("lost response after successful creation")
            return deepcopy(obj)


class HookedAdapter(PairControlAdapter):
    before = None
    after = None

    async def ensure(self, pair, kind, role, uid=None):
        if self.before:
            await self.before(pair, kind, role, uid)
        result = await super().ensure(pair, kind, role, uid)
        if self.after:
            await self.after(pair, kind, role, result)
        return result


@pytest.fixture
def controls(ledger, api):
    f = ledger
    settings = replace(f.h.settings, control_seconds=10)
    api.settings = settings
    f.adapter = HookedAdapter(api)
    f.remote = MemoryControlApi(f.adapter)
    f.service = PairControlProvisioner(settings, f.h.sessions, f.repo, f.adapter)
    yield f
    f.remote.release.set()  # Never strand the deliberately late SDK thread.


async def intent_for(f):
    async with f.h.sessions.begin() as db:
        return await db.scalar(select(PairIntent).where(PairIntent.session_id == f.row.session_id))


async def test_real_adapter_pipeline_commits_intent_and_each_uid_before_next_api(controls):
    f = controls
    steps = []

    async def before(pair, kind, role, uid):
        # A fresh transaction can lock the session during external work: the
        # provisioner is not holding a database transaction across this callback.
        async with asyncio.timeout(5), f.h.sessions.begin() as db:
            current = await db.get(SandboxSession, pair.session_id, with_for_update=True)
            intent = await f.repo.snapshot(db, pair.generation)
            assert current.status == "creating"
            assert len(intent.control_uids) == 8
            assert sum(value is not None for value in intent.control_uids.values()) == len(steps)
            assert uid is None
        steps.append((kind, role))

    f.adapter.before = before
    result = await f.service.prepare(f.row)
    assert steps == list(CONTROL_RESOURCES)
    assert all(result.control_uids.values())
    assert (await row_for(f.h, f.row.session_id)).status == "creating"
    assert not f.h.kube.calls  # No compute, topics, health or ready publication.
    f.adapter.before = None
    again = await f.service.prepare(f.row)
    assert again.generation == result.generation
    assert again.control_uids == result.control_uids
    assert len(f.remote.created) == 8


async def test_concurrent_same_claim_preparations_are_idempotent(controls):
    f = controls
    left, right = await asyncio.gather(f.service.prepare(f.row), f.service.prepare(f.row))
    assert left.generation == right.generation
    assert left.control_uids == right.control_uids
    assert len(f.remote.created) == 8


async def test_lost_create_response_preserves_intent_and_retry_observes_same_uid(controls):
    f = controls
    f.remote.lost_reply = True
    with pytest.raises(TimeoutError):
        await f.service.prepare(f.row)
    old = await intent_for(f)
    assert len(f.remote.created) == 1
    assert all(uid is None for uid in old.control_uids.values())
    result = await f.service.prepare(f.row)
    assert result.generation == old.generation
    assert len(f.remote.created) == 8
    assert (
        result.control_uids["PodGroup/guest"]
        == next(iter(f.remote.objects.values()))["metadata"]["uid"]
    )


async def test_binding_transaction_rollback_is_recovered_without_duplicate_create(controls):
    f = controls
    original = f.repo.bind

    async def rollback(*args, **kwargs):
        await original(*args, **kwargs)
        raise RuntimeError("transaction failed before commit")

    f.repo.bind = rollback
    with pytest.raises(RuntimeError, match="transaction failed"):
        await f.service.prepare(f.row)
    old = await intent_for(f)
    assert all(uid is None for uid in old.control_uids.values())
    assert len(f.remote.created) == 1
    f.repo.bind = original
    result = await f.service.prepare(f.row)
    assert result.generation == old.generation and all(result.control_uids.values())
    assert len(f.remote.created) == 8


async def test_stale_create_completion_cannot_bind_or_advance_but_is_observable(controls):
    f = controls

    async def after(*args):
        async with f.h.sessions.begin() as db:
            current = await db.get(SandboxSession, f.row.session_id, with_for_update=True)
            current.status_changed_at += timedelta(microseconds=1)

    f.adapter.after = after
    with pytest.raises(PairClaimLost):
        await f.service.prepare(f.row)
    old = await intent_for(f)
    assert all(uid is None for uid in old.control_uids.values())
    assert len(f.remote.created) == 1
    assert await f.adapter.observe(old.binding(), "PodGroup", "guest")
    f.adapter.after = None
    with pytest.raises(PairClaimLost):
        await f.service.prepare(f.row)
    assert len(f.remote.created) == 1


async def test_cancelled_sdk_thread_can_finish_late_without_faking_retirement(controls):
    f = controls
    f.remote.delay = True
    task = asyncio.create_task(f.service.prepare(f.row))
    try:
        assert await asyncio.to_thread(f.remote.started.wait, 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        old = await intent_for(f)
        assert old is not None and all(uid is None for uid in old.control_uids.values())
        # An early absence does not prove the delayed create cannot still commit.
        assert await f.adapter.observe(old.binding(), "PodGroup", "guest") is None
    finally:
        f.remote.release.set()
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
    assert await asyncio.to_thread(f.remote.finished.wait, 5)
    assert await f.adapter.observe(old.binding(), "PodGroup", "guest")
    assert len(f.remote.created) == 1
    assert (await snapshot(f, old.generation)).control_uids["PodGroup/guest"] is None


async def test_missing_intent_mid_operation_never_allocates_new_generation(controls):
    f = controls

    async def after(pair, *args):
        async with f.h.sessions.begin() as db:
            await db.execute(delete(PairIntent).where(PairIntent.generation == pair.generation))

    f.adapter.after = after
    with pytest.raises(PairClaimLost, match="missing"):
        await f.service.prepare(f.row)
    assert await intent_for(f) is None
    assert len(f.remote.created) == 1


@pytest.mark.parametrize("mode", ["missing", "replacement", "foreign-generation"])
async def test_previously_bound_resources_never_recreate_or_adopt_replacements(controls, mode):
    f = controls
    before = await f.service.prepare(f.row)
    key = f.remote.created[0]
    if mode == "missing":
        del f.remote.objects[key]
    elif mode == "replacement":
        f.remote.objects[key]["metadata"]["uid"] = "replacement"
    else:
        f.remote.objects[key]["metadata"]["labels"]["ads.io/attachment-generation"] = str(uuid4())
    with pytest.raises(RuntimeError):
        await f.service.prepare(f.row)
    assert (await snapshot(f, before.generation)).control_uids == before.control_uids
    assert len(f.remote.created) == 8


@pytest.mark.parametrize("field", ["namespace", "golden_version"])
async def test_configuration_drift_fails_before_external_io(controls, field):
    f = controls
    original = await f.service.prepare(f.row)
    changed = replace(
        f.service.settings, **{field: "v0.0.11" if field == "golden_version" else "changed"}
    )
    f.service.settings = changed
    with pytest.raises(RuntimeError, match="configuration"):
        await f.service.prepare(f.row)
    f.adapter.kube.settings = changed
    with pytest.raises(RuntimeError, match="configuration"):
        await f.service.prepare(f.row)
    assert len(f.remote.created) == 8
    assert (await snapshot(f, original.generation)).control_uids == original.control_uids


async def test_permission_failure_is_not_success_or_empty_intent(controls):
    f = controls
    f.adapter.custom.get_namespaced_custom_object.side_effect = ApiException(status=403)
    with pytest.raises(ApiException):
        await f.service.prepare(f.row)
    assert not f.remote.created
    assert await intent_for(f) is not None


@pytest.mark.parametrize("missing", ["claim", "configuration"])
async def test_missing_preconditions_never_touch_kubernetes_or_database(controls, missing):
    f = controls
    if missing == "claim":
        f.row.claimed_by = None
    else:
        f.service.settings = replace(f.service.settings, session_objects=None)
    f.adapter.ensure = AsyncMock()
    with pytest.raises(PairClaimLost):
        await f.service.prepare(f.row)
    assert await intent_for(f) is None
    f.adapter.ensure.assert_not_called()
