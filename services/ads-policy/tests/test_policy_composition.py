from __future__ import annotations

from pathlib import Path

import pytest

from ads_policy.config import GovernanceSettings
from ads_policy.contract import (
    Capability,
    Effect,
    IsolationLevel,
    Mode,
    Policy,
    Rule,
    Scope,
)
from ads_policy.pdp import PolicyDecisionPoint
from ads_policy.policy import compose, load_policy, org_policy, read_policy_document
from ads_policy.run import attributes_from_roles
from policy_helpers import policy_request


def _dev_policy(*rules: Rule, **overrides: object) -> Policy:
    values: dict[str, object] = {
        "schema_version": "ads.governance/v1",
        "version": "dev-1",
        "mode": Mode.ENFORCE,
        "deny_on_policy_error": True,
        "rules": rules,
        "egress_allowlist": (),
        "protected_branches": (),
    }
    values.update(overrides)
    return Policy(**values)  # type: ignore[arg-type]


def test_dev_policy_is_optional(policy: Policy) -> None:
    assert compose(policy, None) is policy


def test_dev_policy_narrows_a_rule(policy: Policy) -> None:
    dev = _dev_policy(Rule("process.exec", Capability.PROCESS_EXEC, Scope.ANY, frozenset()))
    pdp = PolicyDecisionPoint(compose(policy, dev))
    request = policy_request(Capability.PROCESS_EXEC, "uv sync", level=IsolationLevel.LOCAL)
    assert pdp.decide(request).effect is Effect.DENY


def test_dev_policy_cannot_widen_a_rule(policy: Policy) -> None:
    dev = _dev_policy(
        Rule("secret.read", Capability.SECRET_READ, Scope.ANY, frozenset(IsolationLevel))
    )
    pdp = PolicyDecisionPoint(compose(policy, dev))
    request = policy_request(Capability.SECRET_READ, "ads-client-secret")
    assert pdp.decide(request).effect is Effect.DENY


def test_dev_policy_cannot_add_a_row_the_org_policy_does_not_have(policy: Policy) -> None:
    dev = _dev_policy(
        Rule("fs.read.anywhere", Capability.FS_READ, Scope.ANY, frozenset(IsolationLevel))
    )
    composed = compose(policy, dev)
    assert composed.rule_for(Capability.FS_READ, Scope.ANY) is None


def test_dev_policy_narrows_the_egress_allowlist(policy: Policy) -> None:
    dev = _dev_policy(egress_allowlist=("mirror.interlab", "evil.example"))
    composed = compose(policy, dev)
    assert composed.egress_allowlist == ("mirror.interlab",)


def test_an_omitted_allowlist_means_not_narrowed(policy: Policy) -> None:
    composed = compose(policy, _dev_policy())
    assert composed.egress_allowlist == policy.egress_allowlist


def test_dev_policy_only_adds_protected_branches(policy: Policy) -> None:
    composed = compose(policy, _dev_policy(protected_branches=("staging",)))
    assert set(policy.protected_branches) < set(composed.protected_branches)
    assert "staging" in composed.protected_branches


def test_enforcement_survives_composition(policy: Policy) -> None:
    review = _dev_policy(mode=Mode.REVIEW)
    assert compose(policy, review).mode is Mode.ENFORCE
    lenient_org = org_policy(GovernanceSettings(mode=Mode.REVIEW, deny_on_policy_error=False))
    assert compose(lenient_org, _dev_policy()).mode is Mode.ENFORCE
    assert compose(lenient_org, _dev_policy(mode=Mode.REVIEW)).mode is Mode.REVIEW
    assert compose(lenient_org, _dev_policy()).deny_on_policy_error is True


def test_weights_and_attribute_requirements_never_loosen(policy: Policy) -> None:
    dev = _dev_policy(
        Rule(
            "vcs.push.feature",
            Capability.VCS_PUSH,
            Scope.FEATURE_BRANCH,
            frozenset(IsolationLevel),
            weight=1,
            requires=(("agent", "true"),),
        )
    )
    rule = compose(policy, dev).rule_for(Capability.VCS_PUSH, Scope.FEATURE_BRANCH)
    assert rule is not None
    assert rule.weight == 2
    assert ("repo.write", "true") in rule.requires
    assert ("agent", "true") in rule.requires


def test_hash_is_computed_over_the_content_not_the_label() -> None:
    document = {
        "hash": "0" * 64,
        "version": "org-1",
        "rules": [{"id": "secret.read", "capability": "secret.read", "scope": "any"}],
    }
    honest = dict(document)
    del honest["hash"]
    assert load_policy(document).digest() == load_policy(honest).digest()
    assert load_policy(document).digest() != document["hash"]


def test_hash_ignores_rule_order_and_follows_rule_content(policy: Policy) -> None:
    reordered = Policy(
        schema_version=policy.schema_version,
        version=policy.version,
        mode=policy.mode,
        deny_on_policy_error=policy.deny_on_policy_error,
        rules=tuple(reversed(policy.rules)),
        egress_allowlist=policy.egress_allowlist,
        protected_branches=policy.protected_branches,
    )
    assert reordered.digest() == policy.digest()
    widened = compose(
        policy,
        _dev_policy(Rule("process.exec", Capability.PROCESS_EXEC, Scope.ANY, frozenset())),
    )
    assert widened.digest() != policy.digest()


def test_an_unreadable_rule_is_rejected_at_load() -> None:
    with pytest.raises(ValueError, match="unreadable rule"):
        load_policy({"rules": [{"id": "nope", "capability": "db.write", "scope": "any"}]})
    with pytest.raises(ValueError, match="unreadable rule"):
        load_policy({"rules": [{"id": "nope", "scope": "any"}]})


def test_an_unknown_level_in_a_document_is_dropped() -> None:
    loaded = load_policy(
        {
            "rules": [
                {
                    "id": "process.exec",
                    "capability": "process.exec",
                    "scope": "any",
                    "levels": ["vm", "bare-metal"],
                }
            ]
        }
    )
    rule = loaded.rule_for(Capability.PROCESS_EXEC, Scope.ANY)
    assert rule is not None
    assert rule.levels == {IsolationLevel.VM}


def test_policy_is_written_over_attributes_not_role_names(policy: Policy) -> None:
    settings = GovernanceSettings()
    rendered = repr(policy)
    for role in settings.write_roles | settings.agent_roles:
        assert role not in rendered
    for roles in (("developer",), ("maintainer", "viewer")):
        assert attributes_from_roles(roles)["repo.write"] == "true"
    assert attributes_from_roles(("viewer",))["repo.write"] == "false"


def test_missing_attributes_deny_the_capability(pdp: PolicyDecisionPoint) -> None:
    request = policy_request(
        Capability.VCS_PUSH,
        "feature/governance",
        level=IsolationLevel.VM,
        attributes={"repo.write": "false"},
    )
    decision = pdp.decide(request)
    assert decision.effect is Effect.DENY
    assert decision.rule_id == "vcs.push.feature"


def test_the_delivered_policy_is_read_from_the_mounted_directory(tmp_path: Path) -> None:
    settings = GovernanceSettings(policy_dir=tmp_path)
    assert read_policy_document(settings) is None
    (tmp_path / "policy.yaml").write_text(
        """
        version: org-2
        rules:
          - id: process.exec
            capability: process.exec
            scope: any
            levels: [vm]
        """
    )
    document = read_policy_document(settings)
    assert document is not None
    loaded = load_policy(document, settings)
    assert loaded.version == "org-2"
    rule = loaded.rule_for(Capability.PROCESS_EXEC, Scope.ANY)
    assert rule is not None
    assert rule.levels == {IsolationLevel.VM}
