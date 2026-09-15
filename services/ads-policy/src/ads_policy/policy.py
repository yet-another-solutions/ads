from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from typing import Any

import msgspec

from ads_policy.config import GovernanceSettings
from ads_policy.contract import Capability, IsolationLevel, Mode, Policy, Rule, Scope
from ads_policy.pdp import PolicyDecisionPoint


def org_policy(settings: GovernanceSettings | None = None) -> Policy:
    """The organisation policy assembled from the configured matrix."""
    config = settings or GovernanceSettings()
    return Policy(
        schema_version=config.schema_version,
        version=config.policy_version,
        mode=config.mode,
        deny_on_policy_error=config.deny_on_policy_error,
        rules=config.rules,
        egress_allowlist=config.egress_allowlist,
        protected_branches=config.protected_branches,
        default_weight=config.default_weight,
    )


def read_policy_document(
    settings: GovernanceSettings | None = None,
) -> dict[str, Any] | None:
    """Read the delivered policy. The source sits behind this call and may change.

    YAML because a policy is read and edited by people. The ConfigMap is mounted as
    a directory, never through ``subPath``, so the file changes under a running pod.
    """
    config = settings or GovernanceSettings()
    document = config.policy_dir / config.policy_document_name
    if not document.is_file():
        return None
    return msgspec.yaml.decode(document.read_bytes(), type=dict[str, Any])


def load_policy(document: Mapping[str, Any], settings: GovernanceSettings | None = None) -> Policy:
    """Parse a policy document, ignoring any hash the document claims about itself."""
    config = settings or GovernanceSettings()
    rules = tuple(_load_rule(raw) for raw in document.get("rules", ()))
    return Policy(
        schema_version=str(document.get("schemaVersion", config.schema_version)),
        version=str(document.get("version", config.policy_version)),
        mode=Mode(str(document.get("mode", config.mode.value))),
        deny_on_policy_error=bool(document.get("denyOnPolicyError", config.deny_on_policy_error)),
        rules=rules,
        egress_allowlist=tuple(str(host) for host in document.get("egressAllowlist", ())),
        protected_branches=tuple(str(name) for name in document.get("protectedBranches", ())),
        default_weight=int(document.get("defaultWeight", config.default_weight)),
    )


def _load_rule(raw: Mapping[str, Any]) -> Rule:
    try:
        capability = Capability(str(raw["capability"]))
        scope = Scope(str(raw["scope"]))
    except (KeyError, ValueError) as exc:
        raise ValueError(f"unreadable rule {raw.get('id')!r}") from exc
    levels = frozenset(
        IsolationLevel(str(level)) for level in raw.get("levels", ()) if _known_level(level)
    )
    requires = tuple(sorted((str(k), str(v)) for k, v in dict(raw.get("requires", {})).items()))
    return Rule(
        id=str(raw.get("id", f"{capability.value}.{scope.value}")),
        capability=capability,
        scope=scope,
        levels=levels,
        weight=int(raw.get("weight", 1)),
        alternative=str(raw.get("alternative", "")),
        requires=requires,
    )


def _known_level(level: object) -> bool:
    return str(level) in {item.value for item in IsolationLevel}


def reload_policy(
    pdp: PolicyDecisionPoint, settings: GovernanceSettings | None = None
) -> str | None:
    """Publish the delivered document if it says something new. Returns the new hash.

    Nothing is published until the document parses, so a broken edit raises and
    leaves the running version in place rather than disarming the policy. The
    caller decides what to say about it; runs pinned to an older version are
    unaffected either way.
    """
    config = settings or GovernanceSettings()
    document = read_policy_document(config)
    if document is None:
        return None
    candidate = load_policy(document, config)
    if candidate.digest() == pdp.policy_hash:
        return None
    return pdp.reload(candidate)


def compose(org: Policy, dev: Policy | None = None) -> Policy:
    """Compose the two sources: the dev policy may only narrow, never widen.

    A section the dev policy omits means "not narrowed", so a local policy that
    only tightens one rule does not have to restate the rest.
    """
    if dev is None:
        return org
    narrowing = {rule.key(): rule for rule in dev.rules}
    allowed = {host.lower() for host in dev.egress_allowlist}
    return Policy(
        schema_version=org.schema_version,
        version=f"{org.version}+{dev.version}",
        mode=Mode.REVIEW if org.mode is Mode.REVIEW and dev.mode is Mode.REVIEW else Mode.ENFORCE,
        deny_on_policy_error=org.deny_on_policy_error or dev.deny_on_policy_error,
        rules=tuple(_narrow(rule, narrowing.get(rule.key())) for rule in org.rules),
        egress_allowlist=(
            tuple(host for host in org.egress_allowlist if host.lower() in allowed)
            if dev.egress_allowlist
            else org.egress_allowlist
        ),
        protected_branches=tuple(sorted(set(org.protected_branches) | set(dev.protected_branches))),
        default_weight=max(org.default_weight, dev.default_weight),
    )


def _narrow(rule: Rule, dev_rule: Rule | None) -> Rule:
    if dev_rule is None:
        return rule
    return replace(
        rule,
        levels=rule.levels & dev_rule.levels,
        weight=max(rule.weight, dev_rule.weight),
        requires=tuple(sorted(set(rule.requires) | set(dev_rule.requires))),
    )
