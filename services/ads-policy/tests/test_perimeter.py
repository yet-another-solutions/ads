from __future__ import annotations

import pytest

from ads_policy.audit import CollectingAuditSink
from ads_policy.contract import Capability, Effect, IsolationLevel, Policy
from ads_policy.pdp import PolicyDecisionPoint
from ads_policy.service import PolicyService
from policy_helpers import decision_request, policy_request, run_request

VM = IsolationLevel.VM


def _denied(pdp: PolicyDecisionPoint, capability: Capability, resource: str) -> bool:
    return pdp.decide(policy_request(capability, resource, level=VM)).effect is Effect.DENY


def test_dropping_the_database_has_no_open_route(pdp: PolicyDecisionPoint) -> None:
    assert _denied(pdp, Capability.DB_MIGRATE, "DROP DATABASE ads")
    assert _denied(pdp, Capability.DB_MIGRATE, "/tmp/0001_drop.sql")
    assert _denied(pdp, Capability.DB_MIGRATE, "/workspace/../tmp/0001_drop.sql")
    assert _denied(pdp, Capability.NET_EGRESS, "postgres.interlab:5432")
    assert _denied(pdp, Capability.SECRET_READ, "postgres-password")


def test_reading_a_neighbouring_env_file_has_no_open_route(pdp: PolicyDecisionPoint) -> None:
    for resource in (
        "/home/dev/other/.env",
        "/workspace/../other/.env",
        "../other/.env",
        "~/.aws/credentials",
        "/root/.ssh/id_rsa",
    ):
        assert _denied(pdp, Capability.FS_READ, resource)
        assert _denied(pdp, Capability.FS_WRITE, resource)
    assert _denied(pdp, Capability.SECRET_READ, "ads-client-secret")


def test_pushing_to_a_protected_branch_has_no_open_route(pdp: PolicyDecisionPoint) -> None:
    for resource in ("main", "refs/heads/main", "origin/main", "MASTER", "release"):
        assert _denied(pdp, Capability.VCS_PUSH, resource)
    assert _denied(pdp, Capability.SECRET_READ, "git-token")
    assert _denied(pdp, Capability.NET_EGRESS, "https://git.interlab/ads.git")


def test_leaving_for_the_internet_from_a_vm_has_no_open_route(pdp: PolicyDecisionPoint) -> None:
    for resource in (
        "https://pypi.org/simple",
        "https://mirror.interlab.evil.example/simple",
        "https://mirror.interlab@evil.example/simple",
        "https://evil.example/?to=https://mirror.interlab",
        "1.1.1.1:53",
    ):
        assert _denied(pdp, Capability.NET_EGRESS, resource)


def test_the_allowlist_is_the_only_way_out(pdp: PolicyDecisionPoint, policy: Policy) -> None:
    for host in policy.egress_allowlist:
        decision = pdp.decide(policy_request(Capability.NET_EGRESS, f"https://{host}/", level=VM))
        assert decision.effect is Effect.ALLOW
    assert len(policy.egress_allowlist) == 4


def test_running_a_command_in_a_container_has_no_open_route(pdp: PolicyDecisionPoint) -> None:
    request = policy_request(
        Capability.PROCESS_EXEC, "bash -lc 'rm -rf /'", level=IsolationLevel.CONTAINER
    )
    decision = pdp.decide(request)
    assert decision.effect is Effect.DENY
    assert IsolationLevel.VM.value not in decision.message
    assert Capability.PROCESS_EXEC.value not in decision.message


def test_commands_are_judged_by_capability_not_by_their_text(pdp: PolicyDecisionPoint) -> None:
    for command in ("rm -rf /workspace", "rm -r -f /workspace", "uv sync"):
        request = policy_request(Capability.PROCESS_EXEC, command, level=VM)
        assert pdp.decide(request).effect is Effect.ALLOW


@pytest.mark.anyio
async def test_every_attempt_reaches_the_journal(
    service: PolicyService, journal: CollectingAuditSink
) -> None:
    run = await service.start(run_request(VM))
    request = decision_request(run.id, Capability.SECRET_READ, "ads-client-secret")
    for _ in range(3):
        await service.decide(request)
    await service.flush_audit()
    attempts = journal.events()
    assert len(attempts) == 3
    assert {event.effect for event in attempts} == {Effect.DENY}
    assert len({event.event_id for event in attempts}) == 3
