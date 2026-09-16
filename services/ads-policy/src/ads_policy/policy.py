from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from typing import Any

import msgspec

from ads_policy.config import GovernanceSettings
from ads_policy.contract import (
    DEFAULT_REQUEST,
    DEFAULT_RESPONSE,
    Binding,
    Capability,
    CapabilityDef,
    CheckKind,
    Classifier,
    ClassifierKind,
    Interception,
    IsolationLevel,
    Mode,
    Policy,
    ResourceClass,
    Rule,
    Side,
    Switch,
)
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
        capabilities=config.capabilities,
        bindings=config.bindings,
        default_weight=config.default_weight,
        interception=Interception(request=DEFAULT_REQUEST, response=DEFAULT_RESPONSE),
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
    # A missing section means "keep the built-in classifiers"; an empty one means the
    # document declares none, and then everything classifies as `any`.
    declared = document.get("capabilities")
    capabilities = (
        config.capabilities
        if declared is None
        else tuple(_load_capability(raw) for raw in declared)
    )
    bound = document.get("bindings")
    bindings = config.bindings if bound is None else tuple(_load_binding(raw) for raw in bound)
    _check_reachable(rules, capabilities)
    return Policy(
        schema_version=str(document.get("schemaVersion", config.schema_version)),
        version=str(document.get("version", config.policy_version)),
        mode=Mode(str(document.get("mode", config.mode.value))),
        deny_on_policy_error=bool(document.get("denyOnPolicyError", config.deny_on_policy_error)),
        rules=rules,
        egress_allowlist=tuple(str(host) for host in document.get("egressAllowlist", ())),
        protected_branches=tuple(str(name) for name in document.get("protectedBranches", ())),
        capabilities=capabilities,
        bindings=bindings,
        default_weight=int(document.get("defaultWeight", config.default_weight)),
        interception=_load_interception(document.get("interception"), "interception"),
    )


def _load_interception(raw: object, where: str) -> Interception:
    """A missing section, or a missing side, is left unstated.

    Unstated is never off: it resolves to the level above, and at the top to the
    default, which is enforced. Turning a side off has to be written down.
    """
    if raw is None:
        return Interception()
    if not isinstance(raw, Mapping):
        raise ValueError(f"{where} must be a mapping of request and response")
    return Interception(
        request=_load_side(raw.get("request"), f"{where}.request", DEFAULT_REQUEST),
        response=_load_side(raw.get("response"), f"{where}.response", DEFAULT_RESPONSE),
    )


def _load_side(raw: object, where: str, default: Side) -> Side | None:
    """``{on, checks}``, either optional. Missing checks are that side's usual ones."""
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        raise ValueError(f"{where} must be a mapping of on and checks")
    try:
        on = Switch(str(raw.get("on", Switch.ENFORCE.value)))
    except ValueError as exc:
        raise ValueError(f"{where}.on must be one of {[s.value for s in Switch]}") from exc
    if "checks" not in raw:
        return Side(checks=default.checks, on=on)
    try:
        checks = frozenset(CheckKind(str(check)) for check in raw["checks"])
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"{where}.checks must be a list of {[c.value for c in CheckKind]}"
        ) from exc
    # Only the checks this side can run. An outbound injection check would be read as
    # protection and do nothing: what goes out is ours, there is no one to inject it.
    unsupported = checks - default.checks
    if unsupported:
        raise ValueError(f"{where} cannot check {sorted(c.value for c in unsupported)}")
    return Side(checks=checks, on=on)


def _load_binding(raw: Mapping[str, Any]) -> Binding:
    try:
        binding = Binding(
            source=str(raw["source"]),
            tool=str(raw["tool"]),
            capability=Capability(str(raw["capability"])),
            argument=str(raw.get("argument", "")),
            value=str(raw.get("value", "")),
        )
    except (KeyError, ValueError) as exc:
        raise ValueError(f"unreadable binding {raw.get('tool')!r}") from exc
    if bool(binding.argument) == bool(binding.value):
        raise ValueError(
            f"binding {binding.tool!r} needs exactly one of argument or value:"
            " the resource is either carried by the call or fixed by the binding"
        )
    return binding


def _load_capability(raw: Mapping[str, Any]) -> CapabilityDef:
    try:
        capability = Capability(str(raw["capability"]))
        spec = dict(raw["classifier"])
        kind = ClassifierKind(str(spec["kind"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"unreadable capability {raw.get('capability')!r}") from exc
    return CapabilityDef(
        capability=capability,
        classifier=Classifier(
            kind=kind,
            match=str(spec["match"]),
            otherwise=str(spec.get("otherwise", "")),
            value=str(spec.get("value", "")),
        ),
    )


def _check_reachable(rules: tuple[Rule, ...], capabilities: tuple[CapabilityDef, ...]) -> None:
    """A rule over a class no classifier answers with is dead, and silently so.

    In a deny-by-default matrix a typo does not fail loudly: the rule simply never
    matches and the capability is refused where the author meant to permit it. So the
    document is rejected instead.
    """
    answers: dict[Capability, frozenset[str]] = {
        definition.capability: definition.classifier.classes() for definition in capabilities
    }
    for rule in rules:
        reachable = answers.get(rule.capability, frozenset({ResourceClass.ANY}))
        if rule.resource_class not in reachable:
            raise ValueError(
                f"rule {rule.id!r} is written over {rule.resource_class!r}, which the"
                f" classifier for {rule.capability.value} never answers with"
                f" ({sorted(reachable)})"
            )


def _load_rule(raw: Mapping[str, Any]) -> Rule:
    try:
        capability = Capability(str(raw["capability"]))
        # Any word will do here: whether a classifier can produce it is checked once
        # the capabilities are known, and that check names the mistake properly.
        resource_class = str(raw["resourceClass"])
    except KeyError as exc:
        raise ValueError(f"unreadable rule {raw.get('id')!r}") from exc
    except ValueError as exc:
        raise ValueError(f"unreadable rule {raw.get('id')!r}") from exc
    levels = frozenset(
        IsolationLevel(str(level)) for level in raw.get("levels", ()) if _known_level(level)
    )
    requires = tuple(sorted((str(k), str(v)) for k, v in dict(raw.get("requires", {})).items()))
    rule_id = str(raw.get("id", f"{capability.value}.{resource_class}"))
    return Rule(
        id=rule_id,
        capability=capability,
        resource_class=resource_class,
        levels=levels,
        weight=int(raw.get("weight", 1)),
        alternative=str(raw.get("alternative", "")),
        requires=requires,
        inspect=_load_interception(raw.get("inspect"), f"rule {rule_id!r} inspect"),
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
        rules=tuple(_narrow(org, rule, dev, narrowing.get(rule.key())) for rule in org.rules),
        egress_allowlist=(
            tuple(host for host in org.egress_allowlist if host.lower() in allowed)
            if dev.egress_allowlist
            else org.egress_allowlist
        ),
        protected_branches=tuple(sorted(set(org.protected_branches) | set(dev.protected_branches))),
        # Neither classification nor binding is a permission, and a dev policy does not
        # get to change either: rebinding `bash` to `fs.read` would widen everything
        # without touching a single rule.
        capabilities=org.capabilities,
        bindings=org.bindings,
        default_weight=max(org.default_weight, dev.default_weight),
        # Narrowing again: a dev policy may add checks and switch a side up, never
        # remove or switch down. A side it does not mention it leaves alone.
        interception=org.interception.stricter(dev.interception),
    )


def _narrow(org: Policy, rule: Rule, dev: Policy, dev_rule: Rule | None) -> Rule:
    """Every row is read at least as strictly as either policy would read it.

    The reading is resolved on both sides before it is combined: a dev policy that
    tightens its top level has to reach an org row that states its own, or the row
    would quietly stay as loose as the org wrote it.
    """
    theirs = dev.inspection_for(dev_rule)
    inspect = (
        org.inspection_for(rule).stricter(theirs) if theirs != Interception() else rule.inspect
    )
    if dev_rule is None:
        return replace(rule, inspect=inspect)
    return replace(
        rule,
        levels=rule.levels & dev_rule.levels,
        weight=max(rule.weight, dev_rule.weight),
        requires=tuple(sorted(set(rule.requires) | set(dev_rule.requires))),
        inspect=inspect,
    )
