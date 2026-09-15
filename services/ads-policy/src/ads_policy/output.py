from __future__ import annotations

from ads_policy.config import GovernanceSettings
from ads_policy.contract import Effect, InterceptionPoint, PolicyDecision, Transform
from ads_policy.secrets import find_secrets, redact


def inspect_payload(
    text: str, point: InterceptionPoint, settings: GovernanceSettings | None = None
) -> PolicyDecision:
    """Second interception point: a legal call can still carry a dangerous payload.

    Outbound a secret is a leak and the call is refused, because a request with the
    secret cut out would return nonsense and hide the attempt. Inbound the same secret
    is redacted and passed on, which is what transform exists for. Injected
    instructions are only looked for inbound — we write what goes out — and they stay
    a warning, never a verdict.
    """
    config = settings or GovernanceSettings()
    findings = find_secrets(text)
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
    warnings = _injection_warnings(text, config)
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


def _injection_warnings(text: str, config: GovernanceSettings) -> tuple[str, ...]:
    """Substring markers, and weak: they miss case, encoding and other languages.

    A trained classifier belongs here; until then this is a signal that something
    should be looked at, never a reason to refuse.
    """
    lowered = text.lower()
    return tuple(
        f"possible injected instruction: {marker}"
        for marker in config.injection_markers
        if marker in lowered
    )
