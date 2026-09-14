from __future__ import annotations

import msgspec
import pytest

from ads_audit.budget import DEFAULT_REPEAT_MULTIPLIER, deny_budget
from ads_audit.repository import InMemoryAuditRepository
from ads_audit.service import AuditService
from ads_policy.contract import AuditEvent, Capability, Effect

pytestmark = pytest.mark.anyio


def _denied(
    capability: Capability, resource: str, weight: int, subject: str = "alice"
) -> AuditEvent:
    return AuditEvent(
        run_id="run-1",
        subject=subject,
        capability=capability,
        resource=resource,
        effect=Effect.DENY,
        rule_id=capability.value,
        weight=weight,
        policy_hash="hash",
    )


def test_distinct_denials_add_their_rule_weights() -> None:
    events = [
        _denied(Capability.SECRET_READ, "ads-client-secret", 5),
        _denied(Capability.FS_READ, "/home/dev/other/.env", 3),
    ]
    assert deny_budget(events) == 8


def test_retrying_a_denied_call_costs_a_multiple() -> None:
    once = [_denied(Capability.SECRET_READ, "ads-client-secret", 5)]
    twice = once * 2
    assert deny_budget(once) == 5
    assert deny_budget(twice) == 5 + 5 * DEFAULT_REPEAT_MULTIPLIER
    assert deny_budget(twice) > deny_budget(once) * 2


def test_allowed_calls_cost_nothing() -> None:
    allowed = AuditEvent(
        run_id="run-1",
        subject="alice",
        capability=Capability.DB_QUERY,
        resource="select 1",
        effect=Effect.ALLOW,
        rule_id="db.query.broker",
        weight=0,
        policy_hash="hash",
    )
    assert deny_budget([allowed]) == 0


async def test_the_budget_is_derived_from_the_journal(
    repository: InMemoryAuditRepository, service: AuditService
) -> None:
    assert await service.budget_for_run("run-1") == 0
    await repository.append(_denied(Capability.SECRET_READ, "ads-client-secret", 5))
    assert await service.budget_for_run("run-1") == 5
    assert await service.budget_for_run("run-2") == 0
    assert await service.budget_for_run("run-1") == await service.budget_for_run("run-1")


async def test_a_subject_budget_accumulates_across_runs(
    repository: InMemoryAuditRepository, service: AuditService
) -> None:
    for run_id in ("run-1", "run-2"):
        event = _denied(Capability.SECRET_READ, "ads-client-secret", 5)
        await repository.append(msgspec.structs.replace(event, run_id=run_id))
    assert await service.budget_for_subject("alice") > await service.budget_for_run("run-1")
    assert await service.budget_for_subject("bob") == 0


async def test_a_redelivered_event_is_counted_once(
    repository: InMemoryAuditRepository, service: AuditService
) -> None:
    event = _denied(Capability.SECRET_READ, "ads-client-secret", 5)
    await repository.append(event)
    await repository.append(event)
    assert len(repository.all()) == 1
    assert await service.budget_for_run("run-1") == 5


async def test_a_redelivery_keeps_the_time_the_decision_was_made() -> None:
    """The journal keys on it, so it must survive the trip and not be reassigned."""
    event = _denied(Capability.SECRET_READ, "ads-client-secret", 5)
    carried = msgspec.json.decode(msgspec.json.encode(event), type=AuditEvent)
    assert carried.recorded_at == event.recorded_at
    assert carried.event_id == event.event_id
