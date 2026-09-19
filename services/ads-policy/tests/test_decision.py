from __future__ import annotations

import pytest

from ads_policy.config import DENIED_MESSAGE, PolicyDefaults
from ads_policy.contract import (
    Approval,
    Capability,
    Effect,
    IsolationLevel,
    Mode,
    Policy,
    PolicyDecision,
    Transform,
)
from ads_policy.pdp import PolicyDecisionPoint
from ads_policy.policy import org_policy
from policy_helpers import policy_request

DENIED = (
    (Capability.FS_READ, "/home/dev/other/.env", IsolationLevel.VM),
    (Capability.PROCESS_EXEC, "uv sync", IsolationLevel.CONTAINER),
    (Capability.NET_EGRESS, "https://pypi.org/simple", IsolationLevel.VM),
    (Capability.DB_MIGRATE, "/workspace/migrations/0001_init.sql", IsolationLevel.CONTAINER),
    (Capability.SECRET_READ, "ads-client-secret", IsolationLevel.VM),
    (Capability.VCS_PUSH, "main", IsolationLevel.VM),
)


def test_a_warning_rides_on_an_allow() -> None:
    decision = PolicyDecision(
        effect=Effect.ALLOW,
        rule_id="fs.write.workdir",
        reason="large diff",
        warnings=("touching 40 files",),
    )
    assert decision.permitted
    assert decision.warnings == ("touching 40 files",)


def test_escalation_is_a_deny_carrying_approval() -> None:
    decision = PolicyDecision(
        effect=Effect.DENY,
        rule_id="vcs.push.protected",
        reason="protected branch",
        approval=Approval(required_attribute="repo.admin", prompt="approve push to main?"),
    )
    assert decision.effect is Effect.DENY
    assert not decision.permitted
    assert decision.approval is not None


def test_transform_changes_the_action_not_the_verdict() -> None:
    decision = PolicyDecision(
        effect=Effect.TRANSFORM,
        rule_id="output.redact",
        reason="secret in tool output",
        transform=Transform(payload="[redacted]", redactions=("aws-access-key",)),
    )
    assert decision.permitted
    assert decision.transform is not None


def test_review_mode_records_a_deny_without_applying_it(policy: Policy) -> None:
    watching = org_policy(PolicyDefaults(mode=Mode.REVIEW))
    decision = PolicyDecisionPoint(watching).decide(
        policy_request(Capability.SECRET_READ, "ads-client-secret")
    )
    assert decision.effect is Effect.DENY
    assert decision.permitted
    assert not decision.enforced
    enforced = PolicyDecisionPoint(policy).decide(
        policy_request(Capability.SECRET_READ, "ads-client-secret")
    )
    assert not enforced.permitted
    assert enforced.enforced


def test_a_deny_says_only_what_is_permitted_instead(
    pdp: PolicyDecisionPoint, policy: Policy
) -> None:
    allowed_messages = {DENIED_MESSAGE}
    allowed_messages |= {f"use {rule.alternative}" for rule in policy.rules if rule.alternative}
    for capability, resource, level in DENIED:
        decision = pdp.decide(policy_request(capability, resource, level=level))
        assert decision.effect is Effect.DENY
        assert decision.message in allowed_messages
        for name in IsolationLevel:
            assert name.value not in decision.message


def test_a_deny_without_an_alternative_describes_nothing(pdp: PolicyDecisionPoint) -> None:
    decision = pdp.decide(
        policy_request(Capability.PROCESS_EXEC, "uv sync", level=IsolationLevel.CONTAINER)
    )
    assert decision.message == DENIED_MESSAGE
    assert Capability.PROCESS_EXEC.value not in decision.message


def test_the_reason_keeps_the_detail_the_agent_does_not_get(pdp: PolicyDecisionPoint) -> None:
    decision = pdp.decide(
        policy_request(Capability.PROCESS_EXEC, "uv sync", level=IsolationLevel.CONTAINER)
    )
    assert IsolationLevel.CONTAINER.value in decision.reason
    assert Capability.PROCESS_EXEC.value in decision.reason


def test_a_policy_error_denies(monkeypatch: pytest.MonkeyPatch, pdp: PolicyDecisionPoint) -> None:
    def explode(*args: object, **kwargs: object) -> None:
        raise RuntimeError("rule table is corrupt")

    monkeypatch.setattr("ads_policy.pdp.classify", explode)
    decision = pdp.decide(policy_request(Capability.FS_READ, "/workspace/src/app.py"))
    assert decision.effect is Effect.DENY
    assert decision.rule_id == "policy.error"
    assert decision.message == DENIED_MESSAGE


def test_a_policy_error_propagates_when_fail_closed_is_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def explode(*args: object, **kwargs: object) -> None:
        raise RuntimeError("rule table is corrupt")

    monkeypatch.setattr("ads_policy.pdp.classify", explode)
    lenient = PolicyDecisionPoint(org_policy(PolicyDefaults(deny_on_policy_error=False)))
    with pytest.raises(RuntimeError, match="corrupt"):
        lenient.decide(policy_request(Capability.FS_READ, "/workspace/src/app.py"))


def test_every_decision_carries_the_policy_version(pdp: PolicyDecisionPoint) -> None:
    allowed = pdp.decide(policy_request(Capability.FS_READ, "/workspace/src/app.py"))
    denied = pdp.decide(policy_request(Capability.SECRET_READ, "ads-client-secret"))
    assert allowed.policy_hash == pdp.policy_hash
    assert denied.policy_hash == pdp.policy_hash


def test_a_denied_decision_carries_the_rule_weight(pdp: PolicyDecisionPoint) -> None:
    denied = pdp.decide(policy_request(Capability.SECRET_READ, "ads-client-secret"))
    allowed = pdp.decide(policy_request(Capability.DB_QUERY, "select 1"))
    assert denied.weight == 5
    assert allowed.weight == 0
