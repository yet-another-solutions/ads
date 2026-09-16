from __future__ import annotations

import pytest

from ads_policy.audit import (
    AuditBacklogFull,
    BufferedAuditSink,
    CollectingAuditSink,
    record,
)
from ads_policy.build import BUILD_ENV, identity
from ads_policy.config import GovernanceSettings
from ads_policy.contract import AuditEvent, Capability, Effect, IsolationLevel
from ads_policy.service import PolicyService
from policy_helpers import decision_request, run_request

SETTINGS = GovernanceSettings()


class _FlakySink:
    def __init__(self) -> None:
        self.available = False
        self.received: list[AuditEvent] = []

    async def send(self, event: AuditEvent) -> None:
        if not self.available:
            raise ConnectionError("audit exchange unreachable")
        self.received.append(event)


def _event(capability: Capability, resource: str, weight: int) -> AuditEvent:
    return AuditEvent(
        run_id="run-1",
        subject="alice",
        capability=capability,
        resource=resource,
        effect=Effect.DENY,
        rule_id=capability.value,
        weight=weight,
        policy_hash="hash",
    )


@pytest.mark.anyio
async def test_an_event_carries_the_arguments(
    service: PolicyService, journal: CollectingAuditSink
) -> None:
    run = await service.start(run_request(IsolationLevel.VM))
    request = decision_request(run.id, Capability.SECRET_READ, "ads-client-secret")
    await service.decide(request)
    await service.flush_audit()
    event = journal.events()[-1]
    assert event.resource == "ads-client-secret"
    assert event.capability is Capability.SECRET_READ
    assert event.effect is Effect.DENY
    assert event.policy_hash == run.policy_hash


@pytest.mark.anyio
async def test_content_travels_only_when_opted_in(service: PolicyService) -> None:
    run = await service.start(run_request(IsolationLevel.VM))
    request = decision_request(run.id, Capability.FS_READ, "/workspace/src/app.py")
    decision = await service.decide(request)
    assert record(request, decision, content="the model said ...").content is None
    opted_in = record(request, decision, content="the model said ...", include_content=True)
    assert opted_in.content == "the model said ..."


def test_every_event_is_identifiable() -> None:
    """Redelivery must be recognisable, so two events are never the same event."""
    first = _event(Capability.SECRET_READ, "ads-client-secret", 5)
    second = _event(Capability.SECRET_READ, "ads-client-secret", 5)
    assert first.event_id != second.event_id
    assert len(first.event_id) == 32


@pytest.mark.anyio
async def test_a_decision_is_answered_before_it_is_published(service: PolicyService) -> None:
    run = await service.start(run_request(IsolationLevel.VM))
    request = decision_request(run.id, Capability.DB_QUERY, "select 1")
    decision = await service.decide(request)
    assert decision.effect is Effect.ALLOW
    assert await service.flush_audit() == 1


@pytest.mark.anyio
async def test_events_survive_an_unreachable_exchange() -> None:
    sink = _FlakySink()
    buffered = BufferedAuditSink(sink)
    events = [
        _event(Capability.SECRET_READ, "ads-client-secret", 5),
        _event(Capability.FS_READ, "/home/dev/other/.env", 3),
        _event(Capability.VCS_PUSH, "main", 5),
    ]
    for event in events:
        buffered.enqueue(event)
    assert await buffered.drain() == 0
    assert buffered.pending == tuple(events)
    sink.available = True
    assert await buffered.drain() == 3
    assert sink.received == events
    assert buffered.pending == ()
    assert await buffered.drain() == 0


@pytest.mark.anyio
async def test_an_exchange_that_fails_midway_keeps_the_rest() -> None:
    sink = _FlakySink()
    buffered = BufferedAuditSink(sink)
    sink.available = True
    buffered.enqueue(_event(Capability.SECRET_READ, "ads-client-secret", 5))
    await buffered.drain()
    sink.available = False
    buffered.enqueue(_event(Capability.VCS_PUSH, "main", 5))
    await buffered.drain()
    assert len(sink.received) == 1
    assert len(buffered.pending) == 1
    sink.available = True
    await buffered.drain()
    assert len(sink.received) == 2


def test_the_backlog_has_a_ceiling() -> None:
    buffered = BufferedAuditSink(_FlakySink(), GovernanceSettings(audit_backlog=2))
    buffered.enqueue(_event(Capability.SECRET_READ, "a", 5))
    buffered.enqueue(_event(Capability.SECRET_READ, "b", 5))
    with pytest.raises(AuditBacklogFull):
        buffered.enqueue(_event(Capability.SECRET_READ, "c", 5))


@pytest.mark.anyio
async def test_every_row_names_the_build_that_wrote_it() -> None:
    """The payload checks ship in the image, so the policy hash alone cannot say."""
    journal = CollectingAuditSink()
    buffered = BufferedAuditSink(journal, decided_by="ads-supervisor 0.2.0@1a2b3c4")
    buffered.enqueue(_event(Capability.SECRET_READ, "a", 5))
    await buffered.drain()
    assert journal.events()[-1].decided_by == "ads-supervisor 0.2.0@1a2b3c4"


def test_a_build_names_its_release(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(BUILD_ENV, "0.2.0@1a2b3c4")
    assert identity("ads-policy") == "ads-policy 0.2.0@1a2b3c4"


def test_a_build_without_a_release_says_it_is_a_developer_s(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Rather than pass itself off as whatever was released last."""
    monkeypatch.delenv(BUILD_ENV, raising=False)
    assert identity("ads-policy") == "ads-policy dev"


@pytest.mark.anyio
async def test_a_decision_that_cannot_be_journalled_is_refused(
    pdp_service_with_full_backlog: PolicyService,
) -> None:
    run = await pdp_service_with_full_backlog.start(run_request(IsolationLevel.VM))
    request = decision_request(run.id, Capability.DB_QUERY, "select 1")
    decision = await pdp_service_with_full_backlog.decide(request)
    assert decision.effect is Effect.DENY
    assert decision.rule_id == "audit.backlog"
    assert decision.enforced


@pytest.mark.anyio
async def test_a_denied_decision_still_produces_an_event(
    monkeypatch: pytest.MonkeyPatch, service: PolicyService, journal: CollectingAuditSink
) -> None:
    run = await service.start(run_request(IsolationLevel.VM))

    def explode(*args: object, **kwargs: object) -> None:
        raise RuntimeError("rule table is corrupt")

    monkeypatch.setattr("ads_policy.pdp.classify", explode)
    request = decision_request(run.id, Capability.DB_QUERY, "select 1")
    await service.decide(request)
    await service.flush_audit()
    assert journal.events()[-1].rule_id == "policy.error"
