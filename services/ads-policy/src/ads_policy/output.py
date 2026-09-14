from __future__ import annotations

import re

from ads_policy.config import GovernanceSettings
from ads_policy.contract import Effect, PolicyDecision, Transform


def inspect_tool_output(text: str, settings: GovernanceSettings | None = None) -> PolicyDecision:
    """Second interception point: a legal call can still return a dangerous result.

    Secrets are redacted, which is what transform exists for. Injected
    instructions are heuristic and reported as a warning, never as a verdict.
    """
    config = settings or GovernanceSettings()
    payload, redactions = _redact(text, config)
    warnings = _injection_warnings(text, config)
    if redactions:
        return PolicyDecision(
            effect=Effect.TRANSFORM,
            rule_id="output.redact",
            reason=f"redacted {list(redactions)}",
            warnings=warnings,
            transform=Transform(payload=payload, redactions=redactions),
        )
    return PolicyDecision(
        effect=Effect.ALLOW,
        rule_id="output.inspect",
        reason="no secret pattern matched",
        warnings=warnings,
    )


def _redact(text: str, config: GovernanceSettings) -> tuple[str, tuple[str, ...]]:
    payload = text
    fired: list[str] = []
    for name, pattern in config.secret_patterns:
        payload, count = re.subn(pattern, f"[redacted:{name}]", payload)
        if count:
            fired.append(name)
    return payload, tuple(fired)


def _injection_warnings(text: str, config: GovernanceSettings) -> tuple[str, ...]:
    lowered = text.lower()
    return tuple(
        f"possible injected instruction: {marker}"
        for marker in config.injection_markers
        if marker in lowered
    )
