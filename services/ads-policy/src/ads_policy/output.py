from __future__ import annotations

from collections.abc import Sequence

from ads_policy.config import PayloadInspection
from ads_policy.contract import (
    CheckKind,
    Effect,
    InterceptionPoint,
    PolicyDecision,
    Transform,
)
from ads_policy.secrets import find_secrets, redact

ALL_CHECKS = frozenset(CheckKind)
PROMPT_INJECTION_RULE = "payload.injection"
SCANNER_UNAVAILABLE_RULE = "payload.injection.unchecked"


def inspect_payload(
    text: str,
    point: InterceptionPoint,
    settings: PayloadInspection | None = None,
    checks: frozenset[CheckKind] = ALL_CHECKS,
) -> PolicyDecision:
    config = settings or PayloadInspection()
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
    if findings:
        return PolicyDecision(
            effect=Effect.TRANSFORM,
            rule_id="payload.redact",
            reason=f"redacted {list(rules)}",
            transform=Transform(payload=redact(text, findings), redactions=rules),
            point=point,
        )
    return PolicyDecision(
        effect=Effect.ALLOW,
        rule_id="payload.inbound",
        reason="no credential matched",
        point=point,
    )


def inspect_texts(
    texts: Sequence[str],
    settings: PayloadInspection | None = None,
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
    if redactions:
        return PolicyDecision(
            effect=Effect.TRANSFORM,
            rule_id="payload.redact",
            reason=f"redacted {list(redactions)}",
            transform=Transform(payload="\n".join(cleaned), redactions=redactions),
            point=InterceptionPoint.RESPONSE,
        ), cleaned
    return PolicyDecision(
        effect=Effect.ALLOW,
        rule_id="payload.inbound",
        reason="no credential matched",
        point=InterceptionPoint.RESPONSE,
    ), cleaned


def prompt_injection_found(
    score: float, settings: PayloadInspection | None = None
) -> PolicyDecision:
    config = settings or PayloadInspection()
    return PolicyDecision(
        effect=Effect.DENY,
        rule_id=PROMPT_INJECTION_RULE,
        reason=f"the injection scanner scored the result {score:.3f}",
        message=config.denied_message,
        weight=config.injection_weight,
        point=InterceptionPoint.RESPONSE,
    )


def prompt_injection_unchecked(
    reason: str, settings: PayloadInspection | None = None
) -> PolicyDecision:
    config = settings or PayloadInspection()
    return PolicyDecision(
        effect=Effect.DENY,
        rule_id=SCANNER_UNAVAILABLE_RULE,
        reason=f"the injection scanner could not read the result: {reason}",
        message=config.denied_message,
        point=InterceptionPoint.RESPONSE,
    )
