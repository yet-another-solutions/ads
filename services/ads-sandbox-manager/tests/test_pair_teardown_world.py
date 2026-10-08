# ruff: noqa: F811
"""O2 pair-teardown world: full pipeline pair, sealed capture, plain-column state.

Replaces the deleted journal/runtime/resource fixture stack. The world is a
real built pair (creation → build → ready), retired via plain columns
(`PairIntent.retired_at` + `creation_fenced`, no tombstones), with lifecycle
teardown driven by a fake `PairTeardownKubernetes`.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from sqlalchemy import select

from ads_sandbox_manager.lifecycle import IDLE, LifecycleService, Signal
from ads_sandbox_manager.lifecycle_store import (
    CleanupWork,
    LifecycleRepository,
)
from ads_sandbox_manager.pair_disposal import PairDisposalRepository
from ads_sandbox_manager.pair_registry import PairRegistry
from ads_sandbox_manager.pair_retirement import PairRetirementRepository
from ads_sandbox_manager.pair_store import PairIntent
from ads_sandbox_manager.pair_teardown import PairTeardown
from ads_sandbox_manager.store import SandboxSession, SessionPVC
from test_kube_release import api  # noqa: F401
from test_pair_controls import controls  # noqa: F401
from test_pair_creation import build, creation  # noqa: F401
from test_pair_store import ledger, snapshot  # noqa: F401
from test_pair_volume_publication import publication as volume_publication  # noqa: F401
from test_session_objects import object_settings  # noqa: F401
from test_sessions import row_for, sessions_harness  # noqa: F401

pytestmark = pytest.mark.anyio


class FakeTeardownKube:
    """Exact-object fake for PairTeardown: name-keyed absence is terminal."""

    def __init__(self, remote):
        self.remote = remote

    async def observe(self, target):
        return deepcopy(self.remote.objects.get((target["kind"], target["name"])))

    async def delete(self, target):
        obj = await self.observe(target)
        if obj and obj["metadata"]["uid"] == target["uid"]:
            del self.remote.objects[(target["kind"], target["name"])]
            if target["kind"] == "PersistentVolumeClaim":
                # Dynamic provisioning with Delete reclaim: the bound PV goes
                # with its claim once released.
                pv_name = obj.get("spec", {}).get("volumeName")
                if pv_name:
                    self.remote.objects.pop(("PersistentVolume", pv_name), None)

    async def capture(self, target):
        """Mirror CleanupAdapter.capture: evidence on live uid-matched objects."""
        obj = await self.observe(target)
        result = dict(target)
        if obj is None or not target.get("uid") or obj["metadata"]["uid"] != target["uid"]:
            return result
        result["captured"] = True
        if target["kind"] == "PersistentVolumeClaim":
            result["pv_name"] = obj.get("spec", {}).get("volumeName") or None
            result["never_bound"] = result["pv_name"] is None
        return result

    async def observe_pod(self, name):
        return deepcopy(self.remote.objects.get(("Pod", name)))

    async def delete_pod(self, desired, uid, *, node):
        obj = await self.observe_pod(desired["metadata"]["name"])
        if obj is None or obj["metadata"]["uid"] != uid:
            return False
        del self.remote.objects[("Pod", obj["metadata"]["name"])]
        return True

    async def released(self, target):
        # Mirror CleanupAdapter.released: fail closed without stored identity.
        if not target.get("never_bound") and not (target.get("pv_name") and target.get("pv_uid")):
            return False
        obj = await self.observe(target)
        if obj is not None and obj["metadata"]["uid"] != target["uid"]:
            raise RuntimeError("original storage claim was replaced")
        if obj is not None and obj.get("spec", {}).get("volumeName") != target.get("pv_name"):
            return False
        return True

    async def reclaimed(self, target):
        if not await self.released(target):
            return False
        obj = await self.observe(target)
        return obj is None


class FakePairControls:
    """Controls deleter fake: uid-fenced delete with observed absence."""

    def __init__(self, remote):
        self.remote = remote

    async def delete(self, pair, kind, role, uid):
        from ads_sandbox_manager.pair_objects import pair_name

        name = pair_name(pair, role)
        obj = self.remote.objects.get((kind, name))
        if obj is None:
            return True
        if obj["metadata"]["uid"] != uid:
            return False
        del self.remote.objects[(kind, name)]
        return True

    async def dispose_secret(self, pair, key, uid, *, persistent=None, retain=False):
        from ads_sandbox_manager.pair_compute import relay_input_name
        from ads_sandbox_manager.relay_keys import custody_identity

        settings = SimpleNamespace(namespace="default", golden_version="0.0.67")
        if key == "relay-custody":
            name = custody_identity(settings, pair)["metadata"]["name"]
        elif key.startswith("relay-input/"):
            name = relay_input_name(pair, key.removeprefix("relay-input/"))
        else:
            name = persistent["metadata"]["name"] if persistent else None
        if name is None:
            return False
        obj = self.remote.objects.get(("Secret", name))
        if obj is None:
            return True
        if obj["metadata"]["uid"] != uid:
            return False
        del self.remote.objects[("Secret", name)]
        return True


@pytest.fixture
async def pair_world(creation):
    """Built ready pair + sealed capture work + plain-column retirement."""
    f = creation
    row = await build(f)
    now = datetime.now(UTC)
    async with f.h.sessions.begin() as db:
        assert await f.h.repository.mark_ready(db, row.sandbox_id, now, row.status_changed_at)
        current = await db.get(SandboxSession, row.session_id)
        pvc = await db.get(SessionPVC, row.pvc_id)
        current.last_execution_at = pvc.last_execution = now - timedelta(hours=4)
    async with f.h.sessions.begin() as db:
        f.intent = await db.scalar(
            select(PairIntent).where(PairIntent.session_id == f.row.session_id)
        )
    f.teardown_kube = FakeTeardownKube(f.remote)
    f.teardown_controls = FakePairControls(f.remote)
    f.teardown = PairTeardown(
        f.h.settings, f.h.sessions, LifecycleRepository(), f.teardown_kube, f.teardown_controls
    )
    f.pair_service = lifecycle(f)
    f.capture = f.pair_service.pair_capture
    # Production stores bound-PV release evidence for every ready pair via the
    # release scan (capture_ready); the world must mirror that contract or the
    # reconstructed reap snapshot would legitimately lack stored identity.
    async with f.h.sessions.begin() as db:
        current = await db.get(SandboxSession, f.row.session_id)
    await f.capture.capture_ready(current)
    await f.pair_service.admit(IDLE, Signal(row.session_id, row.sandbox_id))
    async with f.h.sessions.begin() as db:
        f.work = await db.scalar(
            select(CleanupWork).where(CleanupWork.session_id == row.session_id)
        )
        assert f.work is not None and f.work.kind == "idle"
    await f.pair_service.shutdown_ack(row.sandbox_id, f.work.state_changed)
    async with f.h.sessions.begin() as db:
        f.work = await db.get(CleanupWork, f.work.work_id)
        assert f.work.acknowledged
    f.retirements = PairRetirementRepository(f.pair_service.repository)
    f.disposals = PairDisposalRepository(f.pair_service.repository)
    f.registry = PairRegistry(f.pair_service.repository)
    yield f


async def retire(f):
    """Sealed capture → finish_idle: stopped row, detached workspace, no work."""
    assert await f.capture.capture(f.work)
    # The seal persists release evidence onto the stored claim snapshot; finish
    # fences whole snapshots, so continue with the sealed row, not the stale copy.
    async with f.h.sessions.begin() as db:
        f.work = await db.get(CleanupWork, f.work.work_id)
    async with f.h.sessions.begin() as db:
        assert await f.retirements.finish_idle(db, f.work, datetime.now(UTC))
    async with f.h.sessions.begin() as db:
        intent = await db.get(PairIntent, f.intent.generation)
        assert intent.retired_at is not None and intent.creation_fenced
        row = await db.get(SandboxSession, f.row.session_id)
        assert row.status == "stopped"
    return f.work


async def reconcile(f):
    async with f.h.sessions.begin() as db:
        assert f.intent.generation in await f.registry.candidates(db, 100)
        return await f.registry.reconcile(db, f.intent.generation, datetime.now(UTC), 120)


def lifecycle(f):
    """LifecycleService wired with a fresh capture over a fresh repository."""
    repository = LifecycleRepository()
    from ads_sandbox_manager.pair_cleanup import PairCleanupCapture

    capture = PairCleanupCapture(f.h.settings, f.h.sessions, repository, f.adapter)
    return LifecycleService(
        f.h.settings,
        f.h.sessions,
        repository,
        f.teardown_kube,
        AsyncMock(),
        Mock(mint=Mock(return_value="synthetic-subject-token")),
        Mock(mint=Mock(return_value=SimpleNamespace(access_token="synthetic-ipc-token"))),
        capture,
        f.teardown,
    )


async def test_world_builds_ready_pair_reaches_idle_and_retires(pair_world):
    f = pair_world
    await retire(f)
    async with f.h.sessions.begin() as db:
        assert await db.get(CleanupWork, f.work.work_id) is None
        verified = await f.retirements.verify(db, f.intent.generation)
    assert verified["retired_at"] is not None
