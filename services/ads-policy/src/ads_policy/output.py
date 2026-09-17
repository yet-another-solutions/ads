from __future__ import annotations

from collections.abc import Sequence

from ads_policy.config import GovernanceSettings
from ads_policy.contract import (
    CheckKind,
    Effect,
    InterceptionPoint,
    PolicyDecision,
    Transform,
)
from ads_policy.secrets import find_secrets, redact

ALL_CHECKS = frozenset(CheckKind)


def inspect_payload(
    text: str,
    point: InterceptionPoint,
    settings: GovernanceSettings | None = None,
    checks: frozenset[CheckKind] = ALL_CHECKS,
) -> PolicyDecision:
    config = settings or GovernanceSettings()
    findings = find_secrets(text) if CheckKind.SECRETS in checks else ()
    rules = tuple(sorted({finding.rule_id for finding in findings}))
    if point is InterceptionPoint.REQUEST:
        if findings:
            return PolicyDecision(
                effect=Effect.DENY,
                rule_id="payload.leak",
                reason=f"outbound payload carries {list(rules)}",
                message=config.denied_message,
                weight=config.leak_weight,
                point=point,
            )
        return PolicyDecision(
            effect=Effect.ALLOW,
            rule_id="payload.outbound",
            reason="no credential matched",
            point=point,
        )
    warnings = _injection_marker_warnings(text, config) if CheckKind.INJECTION in checks else ()
    if findings:
        return PolicyDecision(
            effect=Effect.TRANSFORM,
            rule_id="payload.redact",
            reason=f"redacted {list(rules)}",
            warnings=warnings,
            transform=Transform(payload=redact(text, findings), redactions=rules),
            point=point,
        )
    return PolicyDecision(
        effect=Effect.ALLOW,
        rule_id="payload.inbound",
        reason="no credential matched",
        warnings=warnings,
        point=point,
    )


def inspect_texts(
    texts: Sequence[str],
    settings: GovernanceSettings | None = None,
    checks: frozenset[CheckKind] = ALL_CHECKS,
) -> tuple[PolicyDecision, tuple[str, ...]]:
    per_text_decisions = [
        inspect_payload(text, InterceptionPoint.RESPONSE, settings, checks) for text in texts
    ]
    cleaned = tuple(
        decision.transform.payload if decision.transform else text
        for decision, text in zip(per_text_decisions, texts, strict=True)
    )
    redactions = tuple(
        sorted(
            {
                rule
                for decision in per_text_decisions
                if decision.transform
                for rule in decision.transform.redactions
            }
        )
    )
    warnings = tuple(
        dict.fromkeys(warning for decision in per_text_decisions for warning in decision.warnings)
    )
    if redactions:
        return PolicyDecision(
            effect=Effect.TRANSFORM,
            rule_id="payload.redact",
            reason=f"redacted {list(redactions)}",
            warnings=warnings,
            transform=Transform(payload="\n".join(cleaned), redactions=redactions),
            point=InterceptionPoint.RESPONSE,
        ), cleaned
    return PolicyDecision(
        effect=Effect.ALLOW,
        rule_id="payload.inbound",
        reason="no credential matched",
        warnings=warnings,
        point=InterceptionPoint.RESPONSE,
    ), cleaned


def _injection_marker_warnings(text: str, config: GovernanceSettings) -> tuple[str, ...]:
    lowered = text.lower()
    return tuple(
        f"possible injected instruction: {marker}"
        for marker in config.injection_markers
        if marker in lowered
    )
