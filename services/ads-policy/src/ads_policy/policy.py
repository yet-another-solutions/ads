from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import Any

import msgspec

from ads_policy.config import PolicyDefaults
from ads_policy.contract import (
    DEFAULT_PROMPT,
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


def org_policy(settings: PolicyDefaults | None = None) -> Policy:
    config = settings or PolicyDefaults()
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
        interception=Interception(
            request=DEFAULT_REQUEST, response=DEFAULT_RESPONSE, prompt=DEFAULT_PROMPT
        ),
    )


def read_policy_document(document: Path) -> dict[str, Any] | None:
    if not document.is_file():
        return None
    return msgspec.yaml.decode(document.read_bytes(), type=dict[str, Any])


def load_policy(document: Mapping[str, Any], settings: PolicyDefaults | None = None) -> Policy:
    config = settings or PolicyDefaults()
    rules = tuple(_load_rule(raw) for raw in document.get("rules", ()))
    declared_capabilities = document.get("capabilities")
    capabilities = (
        config.capabilities
        if declared_capabilities is None
        else tuple(_load_capability(raw) for raw in declared_capabilities)
    )
    declared_bindings = document.get("bindings")
    bindings = (
        config.bindings
        if declared_bindings is None
        else tuple(_load_binding(raw) for raw in declared_bindings)
    )
    _reject_rules_no_classifier_can_reach(rules, capabilities)
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
        unchecked_sources=_load_unchecked_sources(document.get("sources")),
    )


def _load_unchecked_sources(raw: object) -> frozenset[str]:
    if raw is None:
        return frozenset()
    if not isinstance(raw, Mapping):
        raise ValueError("sources must be a mapping of source to its checks")
    return frozenset(
        str(source) for source, spec in raw.items() if _checks_are_off(spec, f"sources[{source!r}]")
    )


def _checks_are_off(raw: object, where: str) -> bool:
    if not isinstance(raw, Mapping) or "checks" not in raw:
        raise ValueError(f"{where} must state checks: enforce or off")
    value = Switch.OFF.value if raw["checks"] is False else str(raw["checks"])
    if value not in (Switch.ENFORCE.value, Switch.OFF.value):
        raise ValueError(f"{where}.checks must be enforce or off")
    return value == Switch.OFF.value


def _load_interception(raw: object, where: str) -> Interception:
    if raw is None:
        return Interception()
    if not isinstance(raw, Mapping):
        raise ValueError(f"{where} must be a mapping of prompt, request and response")
    return Interception(
        request=_load_side(raw.get("request"), f"{where}.request", DEFAULT_REQUEST),
        response=_load_side(raw.get("response"), f"{where}.response", DEFAULT_RESPONSE),
        prompt=_load_side(raw.get("prompt"), f"{where}.prompt", DEFAULT_PROMPT),
    )


# YAML 1.1 reads a bare `on` as true: PyYAML hands the key over as True, and helm, rendering
# the chart's values into the ConfigMap, as the string "true". A bare `off` arrives as False.
_SWITCH_KEYS: tuple[object, ...] = ("on", True, "true")


def _switch_of(raw: Mapping[Any, Any], where: str) -> Switch:
    given = [key for key in _SWITCH_KEYS if key in raw]
    if len(given) > 1:
        raise ValueError(f"{where}.on is given more than once")
    value = raw[given[0]] if given else Switch.ENFORCE.value
    if value is False:
        value = Switch.OFF.value
    try:
        return Switch(str(value))
    except ValueError as exc:
        raise ValueError(f"{where}.on must be one of {[s.value for s in Switch]}") from exc


def _load_side(raw: object, where: str, default: Side) -> Side | None:
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        raise ValueError(f"{where} must be a mapping of on and checks")
    on = _switch_of(raw, where)
    checks = _load_checks(raw["checks"], f"{where}.checks") if "checks" in raw else default.checks
    checks_this_side_cannot_run = checks - default.checks
    if checks_this_side_cannot_run:
        raise ValueError(
            f"{where} cannot check {sorted(c.value for c in checks_this_side_cannot_run)}"
        )
    review = (
        _load_checks(raw["review"], f"{where}.review")
        if "review" in raw
        else default.review & checks
    )
    reviewed_but_not_run = review - checks
    if reviewed_but_not_run:
        raise ValueError(
            f"{where}.review names checks the side does not run: "
            f"{sorted(c.value for c in reviewed_but_not_run)}"
        )
    return Side(checks=checks, on=on, review=review)


def _load_checks(raw: object, where: str) -> frozenset[CheckKind]:
    if not isinstance(raw, list):
        raise ValueError(f"{where} must be a list of {[c.value for c in CheckKind]}")
    try:
        return frozenset(CheckKind(str(check)) for check in raw)
    except ValueError as exc:
        raise ValueError(f"{where} must be a list of {[c.value for c in CheckKind]}") from exc


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


def _reject_rules_no_classifier_can_reach(
    rules: tuple[Rule, ...], capabilities: tuple[CapabilityDef, ...]
) -> None:
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
        resource_class_checked_later = str(raw["resourceClass"])
    except KeyError as exc:
        raise ValueError(f"unreadable rule {raw.get('id')!r}") from exc
    except ValueError as exc:
        raise ValueError(f"unreadable rule {raw.get('id')!r}") from exc
    levels = frozenset(
        IsolationLevel(str(level)) for level in raw.get("levels", ()) if _known_level(level)
    )
    requires = tuple(sorted((str(k), str(v)) for k, v in dict(raw.get("requires", {})).items()))
    rule_id = str(raw.get("id", f"{capability.value}.{resource_class_checked_later}"))
    return Rule(
        id=rule_id,
        capability=capability,
        resource_class=resource_class_checked_later,
        levels=levels,
        weight=int(raw.get("weight", 1)),
        alternative=str(raw.get("alternative", "")),
        requires=requires,
        inspect=_load_interception(raw.get("inspect"), f"rule {rule_id!r} inspect"),
    )


def _known_level(level: object) -> bool:
    return str(level) in {item.value for item in IsolationLevel}


def reload_policy(
    pdp: PolicyDecisionPoint, path: Path, settings: PolicyDefaults | None = None
) -> str | None:
    document = read_policy_document(path)
    if document is None:
        return None
    candidate = load_policy(document, settings)
    if candidate.digest() == pdp.policy_hash:
        return None
    return pdp.reload(candidate)


def compose(org: Policy, dev: Policy | None = None) -> Policy:
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
        capabilities=org.capabilities,
        bindings=org.bindings,
        default_weight=max(org.default_weight, dev.default_weight),
        interception=org.interception.stricter(dev.interception),
        unchecked_sources=org.unchecked_sources,
    )


def _narrow(org: Policy, rule: Rule, dev: Policy, dev_rule: Rule | None) -> Rule:
    dev_reading = dev.inspection_for(dev_rule)
    dev_states_nothing = dev_reading == Interception()
    inspect = rule.inspect if dev_states_nothing else org.inspection_for(rule).stricter(dev_reading)
    if dev_rule is None:
        return replace(rule, inspect=inspect)
    return replace(
        rule,
        levels=rule.levels & dev_rule.levels,
        weight=max(rule.weight, dev_rule.weight),
        requires=tuple(sorted(set(rule.requires) | set(dev_rule.requires))),
        inspect=inspect,
    )
