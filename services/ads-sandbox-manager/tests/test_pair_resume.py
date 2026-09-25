# ruff: noqa: F811
from __future__ import annotations

import asyncio
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select

from ads_sandbox_manager.egress_state_store import EgressState, state_snapshot
from ads_sandbox_manager.pair_store import PairClaimLost, PairIntent
from ads_sandbox_manager.pair_transfer import PairTransfer
from ads_sandbox_manager.store import SandboxSession
from test_kube_release import api  # noqa: F401
from test_node_release_wire import node_report  # noqa: F401
from test_pair_cleanup_journal import journal  # noqa: F401
from test_pair_controls import controls  # noqa: F401
from test_pair_creation import creation  # noqa: F401
from test_pair_resource_teardown import resources  # noqa: F401
from test_pair_runtime_teardown import teardown  # noqa: F401
from test_pair_store import ledger, snapshot  # noqa: F401
from test_pair_transfer import claim, stopped
from test_pair_volume_publication import publication as volume_publication  # noqa: F401
from test_session_objects import object_settings  # noqa: F401
from test_sessions import sessions_harness  # noqa: F401

pytestmark = pytest.mark.anyio


async def prepared(f):
    row = await stopped(f)
    for (kind, _), obj in f.remote.objects.items():
        if kind == "PersistentVolumeClaim":
            obj["status"] = {"phase": "Bound"}
    return row


@pytest.mark.parametrize("resources", ["idle"], indirect=True)
async def test_real_paired_builder_resumes_original_state_with_new_attachment(resources):
    f = resources
    row = await prepared(f)
    before = deepcopy(f.remote.objects)
    prior = f.work.pair_snapshot
    created = len(f.remote.created)
    topics = f.topics.prepare.await_count
    # A retained clone does not require its historical shared source to survive.
    f.golden.clone_source.side_effect = RuntimeError("retired golden source unavailable")
    current = await f.h.service.provision(row.session_id)
    assert current.status == "creating" and current.sandbox_id == row.sandbox_id
    async with f.h.sessions.begin() as db:
        new = await db.scalar(
            select(PairIntent).where(
                PairIntent.sandbox_id == row.sandbox_id,
                PairIntent.retired_at.is_(None),
            )
        )
        assert new.generation != f.intent.generation
        assert new.retained_from == f.intent.generation
        assert (await db.get(PairTransfer, new.generation)).validated_at is not None
        persistent = await db.get(EgressState, new.egress_state_id)
        assert state_snapshot(persistent) == prior["egress_state"]
        assert new.relay_custody["public_keys"] != prior["relay_custody"]["public_keys"]
        assert all(new.compute_uids[key] != value for key, value in prior["compute_uids"].items())
    assert all(f.remote.objects[key] == value for key, value in before.items())
    assert len(f.remote.created) - created == 20
    assert f.topics.prepare.await_count == topics
    count = len(f.remote.created)
    replay = await f.creator.build(current, resume=True)
    assert replay.ipc_pod_uid == current.ipc_pod_uid and len(f.remote.created) == count
    async with f.h.sessions.begin() as db:
        assert await f.h.repository.mark_ready(
            db,
            current.sandbox_id,
            datetime.now(UTC),
            current.status_changed_at,
        )
        assert (await db.get(SandboxSession, row.session_id)).status == "ready"


@pytest.mark.parametrize("resources", ["idle"], indirect=True)
@pytest.mark.parametrize(
    "fault", ["missing-workspace", "missing-state", "key", "pv", "foreign-pod", "claim", "cancel"]
)
async def test_retained_validation_blocks_reattachment_before_any_new_remote_write(
    resources, fault
):
    f = resources
    row = await prepared(f)
    current = await claim(f, row)
    before = len(f.remote.created)
    workspace = f.work.pair_snapshot["volume_resources"]["workspace"]["uid"]
    state_uid = f.work.pair_snapshot["egress_state"]["volume_uid"]
    if fault in ("missing-workspace", "missing-state"):
        uid = workspace if fault == "missing-workspace" else state_uid
        key = next(
            key for key, value in f.remote.objects.items() if value["metadata"]["uid"] == uid
        )
        del f.remote.objects[key]
    elif fault == "key":
        secret = next(value for (kind, _), value in f.remote.objects.items() if kind == "Secret")
        secret["data"]["wrapping.b64"] = "malformed"
    elif fault == "pv":
        original_pv = f.adapter.kube.core.read_persistent_volume.side_effect

        def replaced_pv(*args, **kwargs):
            value = deepcopy(original_pv(*args, **kwargs))
            value["metadata"]["uid"] = str(uuid4())
            return value

        f.adapter.kube.core.read_persistent_volume.side_effect = replaced_pv
    elif fault == "foreign-pod":
        name = next(
            key[1]
            for key, value in f.remote.objects.items()
            if value["metadata"]["uid"] == workspace
        )
        f.remote.objects[("Pod", "foreign")] = {
            "spec": {"volumes": [{"persistentVolumeClaim": {"claimName": name}}]},
        }
    else:
        original = f.creator.state.kube.observe_volume

        async def changed(*args):
            if fault == "cancel":
                raise asyncio.CancelledError
            result = await original(*args)
            async with f.h.sessions.begin() as db:
                item = await db.get(SandboxSession, row.session_id)
                item.status_changed_at += timedelta(microseconds=1)
            return result

        f.creator.state.kube.observe_volume = changed
    with pytest.raises((RuntimeError, ValueError, PairClaimLost, asyncio.CancelledError)):
        await f.creator.build(current, resume=True)
    assert len(f.remote.created) == before
    async with f.h.sessions.begin() as db:
        active = await db.scalar(
            select(PairIntent).where(
                PairIntent.sandbox_id == row.sandbox_id,
                PairIntent.retired_at.is_(None),
            )
        )
        assert active is not None
        assert (await db.get(PairTransfer, active.generation)).validated_at is None
        assert set(active.compute_dispatch.values()) == {"unissued"}
