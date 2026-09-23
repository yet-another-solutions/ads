# ruff: noqa: F811
from __future__ import annotations

import asyncio
from copy import deepcopy
from dataclasses import replace
from threading import Event, Lock
from uuid import uuid4

import pytest
from kubernetes.client.exceptions import ApiException
from sqlalchemy import inspect

from ads_sandbox_manager.pair_store import PairClaimLost, PairIntentRepository
from ads_sandbox_manager.relay_key_custody import RelayKeyCustody
from ads_sandbox_manager.relay_key_kube import RelayKeyAdapter
from ads_sandbox_manager.relay_keys import RelayKeys
from ads_sandbox_manager.store import SandboxSession
from test_kube_release import api  # noqa: F401
from test_pair_store import begin, ledger, snapshot  # noqa: F401
from test_session_objects import object_settings  # noqa: F401
from test_sessions import row_for, sessions_harness  # noqa: F401

pytestmark = pytest.mark.anyio


class MemorySecrets:
    def __init__(self, adapter):
        self.object = None
        self.created = 0
        self.lock = Lock()
        self.delay = self.lost_reply = False
        self.started, self.release, self.finished = Event(), Event(), Event()
        adapter.kube.core.read_namespaced_secret.side_effect = self.read
        adapter.kube.core.create_namespaced_secret.side_effect = self.create

    def read(self, name, namespace, **kwargs):
        with self.lock:
            if self.object is None:
                raise ApiException(status=404)
            return deepcopy(self.object)

    def create(self, namespace, body, **kwargs):
        if self.delay:
            self.started.set()
            if not self.release.wait(timeout=10):
                raise TimeoutError("fixture release not signalled")
        with self.lock:
            if self.object is not None:
                raise ApiException(status=409)
            self.object = deepcopy(body)
            self.object["metadata"].update(uid=str(uuid4()), resourceVersion="1")
            self.created += 1
            self.finished.set()
            if self.lost_reply:
                self.lost_reply = False
                raise TimeoutError("lost reply")
            return deepcopy(self.object)


@pytest.fixture
def custody(ledger, api):
    f = ledger
    # This fixture uses real PostgreSQL transactions, including eight competing
    # callers. The shared fake-I/O 100 ms budget is not a commit-latency contract.
    # Use the same bounded budget as the control orchestration DB fixture;
    # individual timeout tests override it explicitly below.
    f.h.settings = replace(f.h.settings, control_seconds=10)
    api.settings = f.h.settings
    f.adapter = RelayKeyAdapter(api)
    f.remote = MemorySecrets(f.adapter)
    f.service = RelayKeyCustody(f.h.settings, f.h.sessions, f.repo, f.adapter)
    yield f
    f.remote.release.set()


async def prepare(f):
    intent = await begin(f)
    return await f.service.prepare(f.row, intent.generation)


async def test_prepare_commits_public_pair_before_single_secret_create(custody):
    f = custody
    observed = []
    original = f.adapter.create

    async def create(pair, public_keys, keys):
        # A fresh transaction sees committed SQL and can lock the session
        # before entering the real adapter and its fake remote SDK.
        async with asyncio.timeout(5), f.h.sessions.begin() as db:
            await db.get(SandboxSession, f.row.session_id, with_for_update=True)
            stored = await f.repo.snapshot(db, pair.generation)
            observed.append(deepcopy(stored.relay_custody))
        return await original(pair, public_keys, keys)

    f.adapter.create = create
    result = await prepare(f)
    assert observed == [
        {
            "public_keys": result.relay_custody["public_keys"],
            "uid": None,
            "dispatch": "inflight",
        }
    ]
    assert result.relay_custody["dispatch"] == "settled"
    assert result.relay_custody["uid"] == f.remote.object["metadata"]["uid"]
    assert set(result.relay_custody["public_keys"]) == {"guest", "egress"}
    assert f.remote.created == 1


async def test_restart_loads_existing_secret_without_regeneration_or_create(custody):
    f = custody
    first = await prepare(f)
    f.repo = PairIntentRepository()
    f.service = RelayKeyCustody(f.h.settings, f.h.sessions, f.repo, RelayKeyAdapter(f.adapter.kube))
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(
            RelayKeys,
            "generate",
            classmethod(
                lambda cls: (_ for _ in ()).throw(AssertionError("restart must not generate"))
            ),
        )
        second = await f.service.prepare(f.row, first.generation)
    assert second.relay_custody == first.relay_custody
    assert f.remote.created == 1


async def test_concurrent_prepare_has_one_key_pair_and_one_create(custody):
    f = custody
    intent = await begin(f)
    results = await asyncio.gather(*(f.service.prepare(f.row, intent.generation) for _ in range(8)))
    assert {str(r.relay_custody) for r in results} == {str(results[0].relay_custody)}
    assert f.remote.created == 1
    assert len(results) == 8
    stored = await snapshot(f, intent.generation)
    assert stored.relay_custody["dispatch"] == "settled"
    assert stored.relay_custody["uid"] == f.remote.object["metadata"]["uid"]
    assert all(
        result.relay_custody["public_keys"] == stored.relay_custody["public_keys"]
        for result in results
    )


async def test_control_deadline_stops_blocked_reservation_before_key_publication(custody):
    f = custody
    intent = await begin(f)
    service = RelayKeyCustody(
        replace(f.h.settings, control_seconds=0.05), f.h.sessions, f.repo, f.adapter
    )
    # Deterministic lock contention, not a race against CI commit speed. The
    # configured transaction deadline must still cancel before any external I/O.
    async with f.h.sessions.begin() as db:
        await db.get(SandboxSession, f.row.session_id, with_for_update=True)
        with pytest.raises(TimeoutError):
            await service.prepare(f.row, intent.generation)
    assert (await snapshot(f, intent.generation)).relay_custody == {
        "public_keys": None,
        "uid": None,
        "dispatch": "unissued",
    }
    assert f.remote.object is None and f.remote.created == 0


async def test_lost_create_reply_remains_inflight_and_restart_observes_without_retry(custody):
    f = custody
    intent = await begin(f)
    f.remote.lost_reply = True
    with pytest.raises(RuntimeError, match="create failed"):
        await f.service.prepare(f.row, intent.generation)
    stored = await snapshot(f, intent.generation)
    assert stored.relay_custody["dispatch"] == "inflight"
    assert stored.relay_custody["uid"] is None
    assert f.remote.created == 1
    result = await RelayKeyCustody(
        f.h.settings, f.h.sessions, PairIntentRepository(), RelayKeyAdapter(f.adapter.kube)
    ).prepare(f.row, intent.generation)
    assert result.relay_custody["dispatch"] == "inflight"
    assert result.relay_custody["uid"] == f.remote.object["metadata"]["uid"]
    assert f.remote.created == 1


async def test_caller_cancellation_retains_original_operation_and_settlement(custody):
    f = custody
    intent = await begin(f)
    f.remote.delay = True
    task = asyncio.create_task(f.service.prepare(f.row, intent.generation))
    assert await asyncio.to_thread(f.remote.started.wait, 5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    stored = await snapshot(f, intent.generation)
    assert stored.relay_custody["dispatch"] == "inflight"
    f.remote.release.set()
    assert await asyncio.to_thread(f.remote.finished.wait, 5)
    await f.service.drain()
    stored = await snapshot(f, intent.generation)
    assert stored.relay_custody["dispatch"] == "settled"
    assert stored.relay_custody["uid"] is None  # Cancelled claimant cannot bind.
    assert f.remote.created == 1


async def test_claim_loss_or_fence_blocks_reservation_and_binding(custody):
    f = custody
    intent = await begin(f)
    async with f.h.sessions.begin() as db:
        row = await db.get(SandboxSession, f.row.session_id)
        row.claimed_by = uuid4()
    with pytest.raises(PairClaimLost):
        await f.service.prepare(f.row, intent.generation)
    assert (await snapshot(f, intent.generation)).relay_custody == {
        "public_keys": None,
        "uid": None,
        "dispatch": "unissued",
    }
    async with f.h.sessions.begin() as db:
        row = await db.get(SandboxSession, f.row.session_id)
        row.claimed_by = f.owner
        pair = await db.get(type(intent), intent.generation)
        pair.creation_fenced = True
    with pytest.raises(PairClaimLost, match="fenced"):
        await f.service.prepare(f.row, intent.generation)
    assert f.remote.created == 0


@pytest.mark.parametrize(
    "field,value",
    [
        ("dispatch", "expired"),
        ("dispatch", False),
        ("uid", False),
        ("uid", " "),
        ("public_keys", {}),
        ("public_keys", None),
    ],
)
async def test_corrupt_custody_evidence_fails_closed(custody, field, value):
    f = custody
    intent = await begin(f)
    intent.relay_custody = {
        "public_keys": RelayKeys.generate().public_keys(),
        "uid": None,
        "dispatch": "inflight",
        **{field: value},
    }
    with pytest.raises(RuntimeError, match="custody evidence"):
        f.repo._validate(intent)


async def test_repository_rollback_keeps_unissued_and_no_secret(custody):
    f = custody
    intent = await begin(f)
    keys = RelayKeys.generate()
    with pytest.raises(RuntimeError, match="rollback"):
        async with f.h.sessions.begin() as db:
            await f.repo.reserve_relay_keys(
                db, f.row, f.owner, intent.generation, keys.public_keys()
            )
            raise RuntimeError("rollback")
    assert (await snapshot(f, intent.generation)).relay_custody["dispatch"] == "unissued"
    assert f.remote.object is None


async def test_binding_and_settlement_are_immutable_separate_steps(custody):
    f = custody
    intent = await begin(f)
    keys = RelayKeys.generate()
    async with f.h.sessions.begin() as db:
        original, dispatched = await f.repo.reserve_relay_keys(
            db, f.row, f.owner, intent.generation, keys.public_keys()
        )
    assert dispatched
    async with f.h.sessions.begin() as db:
        await f.repo.bind_relay_keys(db, f.row, f.owner, intent.generation, "uid")
    assert (await snapshot(f, intent.generation)).relay_custody["dispatch"] == "inflight"
    async with f.h.sessions.begin() as db:
        await f.repo.settle_relay_keys(db, original)
        await f.repo.settle_relay_keys(db, original)
    with pytest.raises(RuntimeError, match="replacement"):
        async with f.h.sessions.begin() as db:
            await f.repo.bind_relay_keys(db, f.row, f.owner, intent.generation, "other")
    assert (await snapshot(f, intent.generation)).relay_custody == {
        "public_keys": keys.public_keys(),
        "uid": "uid",
        "dispatch": "settled",
    }


async def test_unreserved_custody_cannot_bind_or_settle(custody):
    f = custody
    intent = await begin(f)
    with pytest.raises(RuntimeError, match="never dispatched"):
        async with f.h.sessions.begin() as db:
            await f.repo.bind_relay_keys(db, f.row, f.owner, intent.generation, "uid")
    with pytest.raises(RuntimeError, match="never dispatched"):
        async with f.h.sessions.begin() as db:
            await f.repo.settle_relay_keys(db, intent)


async def test_abandoned_reservation_never_expires_or_regenerates_on_absence(custody):
    f = custody
    intent = await begin(f)
    public = RelayKeys.generate().public_keys()
    async with f.h.sessions.begin() as db:
        await f.repo.reserve_relay_keys(db, f.row, f.owner, intent.generation, public)
    # Simulated process death before dispatch: no private keys or remote object.
    settings = replace(
        f.h.settings, session_objects=replace(f.h.settings.session_objects, create_seconds=1)
    )
    service = RelayKeyCustody(settings, f.h.sessions, PairIntentRepository(), f.adapter)
    with pytest.raises(TimeoutError):
        await service.prepare(f.row, intent.generation)
    assert (await snapshot(f, intent.generation)).relay_custody == {
        "public_keys": public,
        "uid": None,
        "dispatch": "inflight",
    }
    assert f.remote.object is None and f.remote.created == 0


async def test_bound_custody_loss_blocks_restart_without_regeneration(custody):
    f = custody
    intent = await prepare(f)
    f.remote.object = None
    with pytest.raises(RuntimeError, match="disappeared"):
        await f.service.prepare(f.row, intent.generation)
    assert (await snapshot(f, intent.generation)).relay_custody == intent.relay_custody
    assert f.remote.created == 1


async def test_failed_settlement_does_not_authorize_binding_or_retry(custody):
    f = custody
    intent = await begin(f)
    original = f.repo.settle_relay_keys

    async def fail(*args):
        raise RuntimeError("settlement unavailable")

    f.repo.settle_relay_keys = fail
    with pytest.raises(RuntimeError, match="settlement unavailable"):
        await f.service.prepare(f.row, intent.generation)
    f.repo.settle_relay_keys = original
    stored = await snapshot(f, intent.generation)
    assert stored.relay_custody["dispatch"] == "inflight"
    assert stored.relay_custody["uid"] is None
    replay = await f.service.prepare(f.row, intent.generation)
    assert replay.relay_custody["dispatch"] == "inflight"
    assert f.remote.created == 1


@pytest.mark.parametrize("field", ["namespace", "public_keys"])
async def test_original_settlement_refuses_changed_identity(custody, field):
    f = custody
    intent = await begin(f)
    async with f.h.sessions.begin() as db:
        original, _ = await f.repo.reserve_relay_keys(
            db, f.row, f.owner, intent.generation, RelayKeys.generate().public_keys()
        )
    async with f.h.sessions.begin() as db:
        stored = await db.get(type(intent), intent.generation)
        if field == "namespace":
            stored.namespace = "changed"
        else:
            stored.relay_custody = {
                **stored.relay_custody,
                "public_keys": RelayKeys.generate().public_keys(),
            }
    with pytest.raises(PairClaimLost, match="identity changed"):
        async with f.h.sessions.begin() as db:
            await f.repo.settle_relay_keys(db, original)


async def test_fresh_schema_has_nonnullable_nonsecret_custody_ledger(custody):
    f = custody
    async with f.h.sessions() as db:
        connection = await db.connection()
        columns = await connection.run_sync(lambda c: inspect(c).get_columns("sandbox_pair_intent"))
    assert not next(c for c in columns if c["name"] == "relay_custody")["nullable"]
    assert not any("private" in c["name"] or "secret" in c["name"] for c in columns)
