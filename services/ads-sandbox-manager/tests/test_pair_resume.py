# ruff: noqa: F811
"""O2 retained resume: plain-column inheritance rebuilds the same state."""

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
from test_pair_controls import controls  # noqa: F401
from test_pair_creation import creation  # noqa: F401
from test_pair_store import ledger, snapshot  # noqa: F401
from test_pair_teardown_world import pair_world  # noqa: F401
from test_pair_transfer import claim
from test_pair_volume_publication import publication as volume_publication  # noqa: F401
from test_session_objects import object_settings  # noqa: F401
from test_sessions import sessions_harness  # noqa: F401

pytestmark = pytest.mark.anyio


async def prepared(f):
    # Full idle release: capture + uid-fenced teardown + finish_idle leaves the
    # retained workspace PVC as the only survivor, exactly the pre-resume world.
    await f.pair_service.execute(f.work.work_id)
    async with f.h.sessions.begin() as db:
        row = await db.get(SandboxSession, f.row.session_id)
    assert row.status == "stopped"
    for (kind, _), obj in f.remote.objects.items():
        if kind == "PersistentVolumeClaim":
            obj["status"] = {"phase": "Bound"}
    return row


async def test_real_paired_builder_resumes_original_state_with_new_attachment(pair_world):
    f = pair_world
    row = await prepared(f)
    before = deepcopy(f.remote.objects)
    prior = f.work.pair_snapshot
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
        # Retention carries identity, not the prior capture's release evidence:
        # the new attachment re-captures its own bound-PV identity, so compare
        # modulo the stored key on both sides.
        expected_state = dict(prior["egress_state"])
        expected_state.pop("volume_release", None)
        resumed_state = dict(state_snapshot(persistent))
        resumed_state.pop("volume_release", None)
        assert resumed_state == expected_state
        assert new.relay_custody["public_keys"] != prior["relay_custody"]["public_keys"]
        assert all(new.compute_uids[key] != value for key, value in prior["compute_uids"].items())
    assert all(f.remote.objects[key] == value for key, value in before.items())
    replay = await f.creator.build(current, resume=True)
    assert replay.ipc_pod_uid == current.ipc_pod_uid
    async with f.h.sessions.begin() as db:
        assert await f.h.repository.mark_ready(
            db,
            current.sandbox_id,
            datetime.now(UTC),
            current.status_changed_at,
        )
        assert (await db.get(SandboxSession, row.session_id)).status == "ready"


@pytest.mark.parametrize(
    "fault", ["missing-workspace", "missing-state", "key", "pv", "foreign-pod", "claim", "cancel"]
)
async def test_retained_validation_blocks_reattachment_before_any_new_remote_write(
    pair_world, fault
):
    f = pair_world
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
        # Plain-column world validates the workspace PVC identity by uid, not
        # the cluster PV claimRef; a replaced PV uid maps to a replaced claim.
        key = next(
            key for key, value in f.remote.objects.items() if value["metadata"]["uid"] == workspace
        )
        f.remote.objects[key]["metadata"]["uid"] = str(uuid4())
    elif fault == "foreign-pod":
        # The world equivalent of a foreign consumer: the original clone shows
        # foreign evidence (deletion timestamp) so it is no longer usable.
        name = next(
            key[1]
            for key, value in f.remote.objects.items()
            if value["metadata"]["uid"] == workspace
        )
        f.remote.objects[
            key := next(
                key
                for key, value in f.remote.objects.items()
                if key == ("PersistentVolumeClaim", name)
            )
        ]["metadata"]["deletionTimestamp"] = "2026-10-04T00:00:00Z"
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
