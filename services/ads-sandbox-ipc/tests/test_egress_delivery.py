from __future__ import annotations

import asyncio
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

import pytest

from ads_commons.egress import (
    EgressApplied,
    EgressPing,
    ProjectEgressSettings,
    ProjectEgressSnapshot,
)
from ads_sandbox_ipc.egress import EgressDelivery, RevisionFloor, StaleRevision
from ads_sandbox_ipc.pid_store import PidStore


class Transport:
    def __init__(self):
        self.instance = uuid4()
        self.calls = []
        self.errors = []
        self.relays = True
        self.delay = None
        self.return_instance = None
        self.wrong_revision = False

    async def ping(self):
        return EgressPing(self.instance, True)

    async def relays_healthy(self):
        return self.relays

    async def apply(self, body):
        self.calls.append(body)
        instance = self.return_instance or self.instance
        if self.delay:
            await self.delay.wait()
        if self.errors:
            error = self.errors.pop(0)
            if error:
                raise error
        return EgressApplied(instance, body.snapshot.revision + int(self.wrong_revision))


def snapshot(revision=1):
    return ProjectEgressSnapshot(revision, ProjectEgressSettings(rules=()))


def setup(tmp_path):
    project = uuid4()
    transport = Transport()
    floor = RevisionFloor(tmp_path, project)
    return EgressDelivery(project, floor, transport, 0.1), transport


@pytest.mark.anyio
async def test_install_knowledge_and_restart_evidence_are_separate(tmp_path):
    delivery, transport = setup(tmp_path)
    delivery.floor.advance(8)
    await delivery.receive(delivery.project_id, snapshot(7))
    assert transport.calls == []
    assert not delivery.ever_installed.is_set()
    await delivery.receive(delivery.project_id, snapshot(8))
    assert delivery.ever_installed.is_set()
    assert delivery.installed.revision == 8
    restored = EgressDelivery(
        delivery.project_id, RevisionFloor(tmp_path, delivery.project_id), transport
    )
    assert restored.floor.revision == 8
    assert restored.installed is None
    assert not restored.ever_installed.is_set()
    raw = (tmp_path / "egress/revision.json").read_text()
    assert "token" not in raw and "settings" not in raw and "instance" not in raw


@pytest.mark.anyio
@pytest.mark.parametrize(
    "errors,latched",
    [
        ([RuntimeError(), None], False),
        ([RuntimeError(), RuntimeError()], True),
        ([StaleRevision()], False),
    ],
)
async def test_exactly_two_attempts_and_stale_exemption(tmp_path, errors, latched):
    delivery, transport = setup(tmp_path)
    transport.errors = errors.copy()
    await delivery.receive(delivery.project_id, snapshot())
    assert len(transport.calls) == len(errors)
    assert delivery.failed is latched
    if latched:
        transport.instance = uuid4()
        assert not await delivery.healthy()
        await delivery.receive(delivery.project_id, snapshot(2))
        assert len(transport.calls) == 2


@pytest.mark.anyio
async def test_unexpected_uuid_success_is_noop_not_failure(tmp_path):
    delivery, transport = setup(tmp_path)
    transport.return_instance = uuid4()
    await delivery.receive(delivery.project_id, snapshot())
    assert len(transport.calls) == 1
    assert delivery.installed is None
    assert not delivery.failed and not delivery.ever_installed.is_set()


@pytest.mark.anyio
async def test_changed_uuid_reapplies_in_background_without_revoking_admission(tmp_path):
    delivery, transport = setup(tmp_path)
    await delivery.receive(delivery.project_id, snapshot(2))
    transport.instance = uuid4()
    transport.delay = asyncio.Event()
    assert await delivery.healthy()
    assert delivery.installed is None
    assert delivery.ever_installed.is_set()
    await asyncio.sleep(0)
    assert await delivery.healthy()  # ping does not wait for the delivery lock
    transport.delay.set()
    await delivery._reapply
    assert delivery.installed.instance_id == transport.instance
    assert transport.calls[-1].snapshot.revision == 2
    await delivery.close()


@pytest.mark.anyio
async def test_second_restart_during_background_apply_is_not_lost(tmp_path):
    delivery, transport = setup(tmp_path)
    delivery.timeout_seconds = 5
    await delivery.receive(delivery.project_id, snapshot())
    transport.instance = uuid4()
    transport.delay = asyncio.Event()
    assert await delivery.healthy()
    await asyncio.sleep(0)
    assert len(transport.calls) == 2
    transport.instance = uuid4()
    assert await delivery.healthy()
    transport.delay.set()
    await delivery._reapply
    assert len(transport.calls) == 3
    assert delivery.installed.instance_id == transport.instance
    assert delivery.ever_installed.is_set()
    await delivery.close()


@pytest.mark.anyio
async def test_startup_observes_restart_after_unexpected_initial_apply(ipc, tmp_path):
    from ipc_support import eventually

    delivery, transport = setup(tmp_path / "floor")
    ipc.service.egress = delivery
    replacement = uuid4()
    transport.return_instance = replacement
    await delivery.receive(delivery.project_id, snapshot())
    assert delivery.installed is None and not delivery.ever_installed.is_set()
    transport.return_instance = None
    transport.instance = replacement
    async with ipc.running(boot=False):
        await eventually(lambda: ipc.service.kafka_ready)
        assert delivery.installed.instance_id == replacement
        assert len(transport.calls) == 2


@pytest.mark.anyio
async def test_late_response_after_new_observation_is_not_installation_evidence(tmp_path):
    delivery, transport = setup(tmp_path)
    transport.delay = asyncio.Event()
    task = asyncio.create_task(delivery.receive(delivery.project_id, snapshot()))
    await asyncio.sleep(0)
    transport.instance = uuid4()
    await delivery.healthy()
    transport.delay.set()
    await task
    # Background reapply can install only the current instance, never the delayed old one.
    if delivery.installed:
        assert delivery.installed.instance_id == transport.instance
    await delivery.close()


@pytest.mark.anyio
async def test_stale_on_new_instance_never_establishes_installation(tmp_path):
    delivery, transport = setup(tmp_path)
    transport.errors = [StaleRevision()]
    await delivery.receive(delivery.project_id, snapshot())
    assert delivery.installed is None and not delivery.ever_installed.is_set()
    await delivery.close()


@pytest.mark.anyio
async def test_foreign_project_and_shutdown_cannot_mutate_floor(tmp_path):
    delivery, transport = setup(tmp_path)
    await delivery.receive(uuid4(), snapshot(100))
    assert delivery.floor.revision == 0 and transport.calls == []
    await delivery.close()
    await delivery.receive(delivery.project_id, snapshot(100))
    assert delivery.floor.revision == 0 and transport.calls == []


@pytest.mark.anyio
async def test_old_health_reply_cannot_restore_old_instance(tmp_path):
    delivery, transport = setup(tmp_path)
    old, new = uuid4(), uuid4()
    blocked = asyncio.Event()
    calls = 0

    async def ping():
        nonlocal calls
        calls += 1
        if calls == 1:
            await blocked.wait()
            return EgressPing(old, True)
        return EgressPing(new, True)

    transport.ping = ping
    first = asyncio.create_task(delivery.healthy())
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    assert await delivery.healthy()
    assert delivery.instance == new
    blocked.set()
    assert await first
    assert delivery.instance == new
    await delivery.close()


@pytest.mark.anyio
async def test_bad_revision_result_latches_and_unhealthy_relay_is_not_hidden(tmp_path):
    delivery, transport = setup(tmp_path)
    transport.wrong_revision = True
    await delivery.receive(delivery.project_id, snapshot())
    assert delivery.failed and len(transport.calls) == 2
    other, peer = setup(tmp_path / "other")
    peer.relays = False
    assert not await other.healthy()


def test_revision_storage_corruption_and_binding_fail_closed(tmp_path: Path):
    project = uuid4()
    floor = RevisionFloor(tmp_path, project)
    floor.advance(3)
    with pytest.raises(ValueError, match="binding"):
        RevisionFloor(tmp_path, uuid4())
    floor.path.write_text('{"project_id":"bad","revision":0}')
    with pytest.raises(ValueError):
        RevisionFloor(tmp_path, project)


def test_pid_cleanup_does_not_remove_revision_floor(ipc):
    project = uuid4()
    floor = RevisionFloor(ipc.settings.pid_directory, project)
    floor.advance(9)
    PidStore(ipc.settings).clear()
    assert RevisionFloor(ipc.settings.pid_directory, project).revision == 9


@pytest.mark.anyio
async def test_initial_configuration_gates_execution_but_restart_does_not(ipc, tmp_path):
    from ads_commons.sandbox import SandboxPing
    from ipc_support import eventually

    delivery, transport = setup(tmp_path / "floor")
    ipc.service.egress = delivery
    async with ipc.running(boot=False):
        await eventually(lambda: ipc.kube.polls > 1)
        await ipc.send(ipc.request())
        assert not ipc.service.kafka_ready and ipc.service.current is None
        await delivery.receive(delivery.project_id, snapshot())
        await eventually(lambda: ipc.service.kafka_ready)
        transport.instance = uuid4()
        transport.delay = asyncio.Event()
        ping = SandboxPing(ipc.settings.sandbox_id, uuid4())
        await ipc.service.ping(ping, "manager-token")
        assert ipc.service.kafka_ready and ipc.publisher.messages[-1] == ping
        await ipc.send(ipc.request())
        assert ipc.service.current is not None
        transport.delay.set()


@pytest.mark.anyio
@pytest.mark.parametrize(
    "claims",
    [
        {"aud": "other"},
        {"iss": "https://other.test"},
        {"azp": "ads-sandbox-manager"},
        {"sub": str(uuid4())},
        {"exp": 1},
        {"sub": "bad-uuid"},
    ],
)
async def test_snapshot_verifies_audience_caller_native_subject_and_expiry(ipc, tmp_path, claims):
    from uuid import UUID

    import msgspec

    from ads_commons.egress import EGRESS_CONFIG_TOPIC, EgressConfigUpdate
    from ads_sandbox_ipc.config import EgressPair
    from ads_sandbox_ipc.controller import KafkaController
    from ipc_support import SUBJECT

    delivery, transport = setup(tmp_path / "floor")
    pair = EgressPair(
        delivery.project_id,
        "https://egress.test",
        ("https://local.test/health", "https://peer.test/health"),
        UUID(SUBJECT),
    )
    settings = replace(ipc.settings, egress=pair)
    ipc.service.egress = delivery
    controller = KafkaController(settings, ipc.keys.verifier, ipc.service)
    raw = msgspec.json.encode(EgressConfigUpdate(delivery.project_id, snapshot()))
    token = ipc.keys.token(**{"azp": "ads", **claims})
    await controller.on_message(EGRESS_CONFIG_TOPIC, raw, [("authorization", token.encode())])
    assert transport.calls == [] and delivery.floor.revision == 0
    valid = ipc.keys.token(azp="ads")
    await controller.on_message(EGRESS_CONFIG_TOPIC, raw, [("authorization", valid.encode())])
    assert len(transport.calls) == 1 and delivery.ever_installed.is_set()
    await delivery.close()
