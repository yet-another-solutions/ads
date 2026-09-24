# ruff: noqa: F811
from __future__ import annotations

import asyncio
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from functools import partial
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import pytest
from kubernetes.client.exceptions import ApiException

from ads_sandbox_manager.pair_resource_proof import resource_targets
from ads_sandbox_manager.pair_resource_teardown import PairResourceTeardown
from ads_sandbox_manager.pair_store import PairClaimLost, PairIntent
from ads_sandbox_manager.store import SandboxSession
from test_kube_release import api  # noqa: F401
from test_node_release_wire import node_report  # noqa: F401
from test_pair_block_storage import configure_block_storage, make_idle
from test_pair_cleanup_journal import journal  # noqa: F401
from test_pair_controls import controls  # noqa: F401
from test_pair_creation import creation  # noqa: F401
from test_pair_ipc_storage import configure_ipc_storage
from test_pair_ipc_storage import dispose as dispose_ipc
from test_pair_runtime_teardown import state, teardown  # noqa: F401
from test_pair_store import ledger, snapshot  # noqa: F401
from test_pair_volume_publication import publication as volume_publication  # noqa: F401
from test_session_objects import object_settings  # noqa: F401
from test_sessions import sessions_harness  # noqa: F401

pytestmark = pytest.mark.anyio


@pytest.fixture
async def resources(teardown, request):
    f = teardown
    if getattr(request, "param", None) == "idle":
        await make_idle(f)
    await configure_ipc_storage(f)
    f.reclaim_during_delete = True
    assert await dispose_ipc(f)
    await configure_block_storage(f)
    f.block_reclaim = True
    assert await f.block_stage.dispose(f.work, recovery=f.claim)
    f.resource_events, f.resource_hook, f.resource_lost = [], None, False

    def remove(kind, *args, body, **kwargs):
        name = args[-1] if kind == "PodGroup" else args[0]
        key = kind, name
        if key not in f.remote.objects:
            raise ApiException(status=404)
        obj = f.remote.objects[key]
        assert body["preconditions"] == {
            "uid": obj["metadata"]["uid"],
            "resourceVersion": obj["metadata"]["resourceVersion"],
        }
        f.resource_events.append(key)
        del f.remote.objects[key]
        if f.resource_lost:
            f.resource_lost = False
            raise TimeoutError("lost resource delete reply")
        return {}

    for kind, sdk, name in (
        ("PodGroup", f.adapter.custom, "custom_object"),
        ("Service", f.adapter.kube.core, "service"),
        ("NetworkPolicy", f.adapter.networking, "network_policy"),
        ("Secret", f.adapter.kube.core, "secret"),
    ):
        setattr(sdk, "delete_namespaced_" + name, Mock(side_effect=partial(remove, kind)))
    original_request = f.adapter._request

    async def guarded_request(operation, desired, body=None):
        if operation == "delete":
            saved = await state(f)
            assert saved["ipc_storage_reclaimed"] and len(saved["block_disposition"]) == 5
            if f.resource_hook:
                await f.resource_hook()
        return await original_request(operation, desired, body)

    f.adapter._request = guarded_request
    f.topic_disposal = AsyncMock()
    f.topic_disposal.remove.return_value = True
    f.resource_stage = PairResourceTeardown(f.runtime, f.adapter, f.topic_disposal)
    return f


async def dispose(f):
    return await f.resource_stage.dispose(f.work, recovery=f.claim)


async def test_exact_controls_secrets_and_topics_finish_but_do_not_erase_generation(resources):
    f = resources
    assert await dispose(f)
    saved = await state(f)
    assert saved["resource_disposition"] == resource_targets(saved)
    assert saved["topic_disposition"] == "deleted"
    assert len(f.resource_events) == 12
    f.topic_disposal.remove.assert_awaited_once_with(f.work.sandbox_id)
    assert not f.remote.objects
    events = list(f.resource_events)
    assert await dispose(f) and f.resource_events == events
    async with f.h.sessions.begin() as db:
        assert not await f.capture.repository.complete(db, f.work, datetime.now(UTC))
        assert await db.get(PairIntent, f.intent.generation) is not None


@pytest.mark.parametrize("resources", ["idle"], indirect=True)
async def test_idle_keeps_only_original_workspace_state_custody_and_topics(resources):
    f = resources
    before = deepcopy(f.remote.objects)
    assert await dispose(f)
    saved = await state(f)
    assert saved["topic_disposition"] == "retained"
    assert saved["resource_disposition"]["state-key"]["disposition"] == "retained"
    assert len(f.remote.objects) == 3
    assert all(before[key] == value for key, value in f.remote.objects.items())
    assert sorted(kind for kind, name in f.remote.objects) == [
        "PersistentVolumeClaim",
        "PersistentVolumeClaim",
        "Secret",
    ]
    f.topic_disposal.remove.assert_not_awaited()


async def test_lost_resource_delete_reply_retries_original_uid_and_keeps_receipts(resources):
    f = resources
    f.resource_lost = True
    with pytest.raises(TimeoutError):
        await dispose(f)
    assert await dispose(f)
    assert len(f.resource_events) == len(set(f.resource_events)) == 12
    assert (await state(f))["topic_disposition"] == "deleted"


async def test_replacement_secret_and_topic_failure_preserve_pending_obligations(resources):
    f = resources
    original = {}
    for key, value in f.remote.objects.items():
        if key[0] == "Secret":
            original[key] = value["metadata"]["uid"]
            value["metadata"]["uid"] = str(uuid4())
    with pytest.raises(RuntimeError, match="credential disposition"):
        await dispose(f)
    assert all(key in f.remote.objects for key in original)
    f.topic_disposal.remove.assert_not_awaited()
    for key, uid in original.items():
        f.remote.objects[key]["metadata"]["uid"] = uid
    f.topic_disposal.remove.return_value = False
    assert not await dispose(f)
    assert (await state(f))["topic_disposition"] is None
    f.topic_disposal.remove.return_value = True
    assert await dispose(f)
    assert (await state(f))["topic_disposition"] == "deleted"


@pytest.mark.parametrize("fault", ["claim", "cancel", "replacement", "storage-proof"])
async def test_resource_stage_never_bypasses_claim_or_original_release(resources, fault):
    f = resources
    before = deepcopy(f.remote.objects)
    if fault == "storage-proof":
        async with f.h.sessions.begin() as db:
            intent = await db.get(PairIntent, f.intent.generation)
            value = deepcopy(intent.cleanup_journal)
            value["ipc_storage_reclaimed"] = None
            intent.cleanup_journal = value
        assert not await dispose(f)
        assert f.remote.objects == before
    elif fault == "replacement":
        for obj in f.remote.objects.values():
            obj["metadata"]["uid"] = str(uuid4())
        with pytest.raises(RuntimeError):
            await dispose(f)
    else:

        async def hook():
            if fault == "cancel":
                raise asyncio.CancelledError
            async with f.h.sessions.begin() as db:
                row = await db.get(SandboxSession, f.claim.session_id)
                row.status_changed_at += timedelta(microseconds=1)

        f.resource_hook = hook
        with pytest.raises((PairClaimLost, asyncio.CancelledError)):
            await dispose(f)
    assert (await state(f))["topic_disposition"] is None
    f.topic_disposal.remove.assert_not_awaited()
