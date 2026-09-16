from __future__ import annotations

import pytest

from ads_policy.config import GovernanceSettings
from ads_policy.contract import (
    Capability,
    CapabilityDef,
    Classifier,
    ClassifierKind,
    Effect,
    IsolationLevel,
    Mode,
    Policy,
    ResourceClass,
    Rule,
)
from ads_policy.pdp import PolicyDecisionPoint, classify
from ads_policy.policy import load_policy, org_policy
from policy_helpers import policy_request

SETTINGS = GovernanceSettings()
WORKDIR = SETTINGS.workdir


@pytest.mark.parametrize(
    ("capability", "resource", "expected"),
    [
        (Capability.FS_READ, f"{WORKDIR}/app.py", ResourceClass.WORKDIR),
        (Capability.FS_READ, "/etc/passwd", ResourceClass.OUTSIDE_WORKDIR),
        (Capability.FS_WRITE, f"{WORKDIR}/app.py", ResourceClass.WORKDIR),
        (Capability.PROCESS_EXEC, "uv sync", ResourceClass.ANY),
        (Capability.NET_EGRESS, "mirror.interlab", ResourceClass.ALLOWLIST),
        (Capability.NET_EGRESS, "https://github.com/x", ResourceClass.INTERNET),
        (Capability.DB_QUERY, "select 1", ResourceClass.BROKER),
        (Capability.DB_MIGRATE, f"{WORKDIR}/0001.sql", ResourceClass.TEMPORARY),
        (Capability.DB_MIGRATE, "DROP DATABASE ads", ResourceClass.OUTSIDE_WORKDIR),
        (Capability.DB_MIGRATE, "/tmp/0001.sql", ResourceClass.OUTSIDE_WORKDIR),
        (Capability.SECRET_READ, "ads-client-secret", ResourceClass.ANY),
        (Capability.VCS_PUSH, "refs/heads/main", ResourceClass.PROTECTED_BRANCH),
        (Capability.VCS_PUSH, "refs/heads/feature/x", ResourceClass.FEATURE_BRANCH),
    ],
)
def test_the_declared_classifiers_answer_what_the_matrix_expects(
    capability: Capability, resource: str, expected: ResourceClass
) -> None:
    """The built-in declarations have to classify exactly as the hand-written chain did."""
    policy = org_policy()
    assert classify(policy_request(capability, resource), policy) == expected


def test_a_capability_nothing_is_declared_for_falls_to_any() -> None:
    bare = load_policy({"capabilities": [], "rules": []})
    assert classify(policy_request(Capability.FS_READ, "/etc/passwd"), bare) == ResourceClass.ANY


def test_a_document_may_classify_a_capability_differently() -> None:
    """Reclassifying is a policy change: no new image, no new code."""
    document = {
        "capabilities": [
            {
                "capability": "fs.read",
                "classifier": {"kind": "literal", "match": "workdir"},
            }
        ],
        "rules": [
            {
                "id": "fs.read.workdir",
                "capability": "fs.read",
                "resourceClass": "workdir",
                "levels": ["local", "container", "vm"],
            }
        ],
    }
    pdp = PolicyDecisionPoint(load_policy(document))
    outside = pdp.decide(policy_request(Capability.FS_READ, "/etc/passwd"))
    assert outside.effect is Effect.ALLOW


def test_a_document_may_name_a_class_of_its_own() -> None:
    document = {
        "capabilities": [
            {
                "capability": "net.egress",
                "classifier": {"kind": "host", "match": "mirror", "otherwise": "elsewhere"},
            }
        ],
        "egressAllowlist": ["mirror.interlab"],
        "rules": [
            {
                "id": "net.egress.mirror",
                "capability": "net.egress",
                "resourceClass": "mirror",
                "levels": ["container"],
            },
            {
                "id": "net.egress.elsewhere",
                "capability": "net.egress",
                "resourceClass": "elsewhere",
            },
        ],
    }
    pdp = PolicyDecisionPoint(load_policy(document))
    allowed = pdp.decide(
        policy_request(Capability.NET_EGRESS, "mirror.interlab", level=IsolationLevel.CONTAINER)
    )
    denied = pdp.decide(
        policy_request(Capability.NET_EGRESS, "github.com", level=IsolationLevel.CONTAINER)
    )
    assert allowed.effect is Effect.ALLOW
    assert denied.effect is Effect.DENY
    assert denied.rule_id == "net.egress.elsewhere"


def test_a_rule_over_an_unreachable_class_is_refused_at_load() -> None:
    """Deny-by-default hides this mistake, so the document has to be rejected."""
    document = {
        "capabilities": [
            {
                "capability": "fs.read",
                "classifier": {"kind": "path", "match": "workdir", "otherwise": "outside-workdir"},
            }
        ],
        "rules": [
            {
                "id": "typo",
                "capability": "fs.read",
                "resourceClass": "workdirr",
                "levels": ["vm"],
            }
        ],
    }
    with pytest.raises(ValueError, match="never answers with"):
        load_policy(document)


def test_an_unreadable_classifier_is_refused_at_load() -> None:
    with pytest.raises(ValueError, match="unreadable capability"):
        load_policy(
            {"capabilities": [{"capability": "fs.read", "classifier": {"kind": "telepathy"}}]}
        )


def test_the_hash_follows_the_classifier(policy: Policy) -> None:
    """Two policies with the same rules can still decide differently."""
    reclassified = Policy(
        schema_version=policy.schema_version,
        version=policy.version,
        mode=policy.mode,
        deny_on_policy_error=policy.deny_on_policy_error,
        rules=policy.rules,
        egress_allowlist=policy.egress_allowlist,
        protected_branches=policy.protected_branches,
        capabilities=(
            CapabilityDef(
                Capability.FS_READ,
                Classifier(ClassifierKind.LITERAL, ResourceClass.WORKDIR),
            ),
        ),
    )
    assert reclassified.digest() != policy.digest()


def test_a_classifier_the_code_does_not_know_is_a_policy_error() -> None:
    """deny_on_policy_error turns it into a refusal rather than a crash."""
    policy = Policy(
        schema_version="ads.governance/v1",
        version="broken",
        mode=Mode.ENFORCE,
        deny_on_policy_error=True,
        rules=(Rule("fs.read.any", Capability.FS_READ, ResourceClass.ANY, frozenset()),),
        egress_allowlist=(),
        protected_branches=(),
        capabilities=(
            CapabilityDef(
                Capability.FS_READ,
                Classifier("no-such-kind", ResourceClass.WORKDIR),  # type: ignore[arg-type]
            ),
        ),
    )
    decision = PolicyDecisionPoint(policy).decide(policy_request(Capability.FS_READ, "/x"))
    assert decision.effect is Effect.DENY
    assert decision.rule_id == "policy.error"
