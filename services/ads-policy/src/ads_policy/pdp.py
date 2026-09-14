from __future__ import annotations

from collections import OrderedDict

from ads_policy.config import GovernanceSettings
from ads_policy.contract import (
    Capability,
    Effect,
    Mode,
    Policy,
    PolicyDecision,
    PolicyRequest,
    Rule,
    Run,
    RunState,
    Scope,
)
from ads_policy.normalize import branch_name, egress_host, is_migration_file, within_workdir


def classify(
    request: PolicyRequest, policy: Policy, settings: GovernanceSettings | None = None
) -> Scope:
    """Turn the raw resource into the matrix qualifier."""
    config = settings or GovernanceSettings()
    workdir = request.context.workdir
    capability = request.capability
    if capability in (Capability.FS_READ, Capability.FS_WRITE):
        inside = within_workdir(request.resource, workdir)
        return Scope.WORKDIR if inside else Scope.OUTSIDE_WORKDIR
    if capability is Capability.NET_EGRESS:
        allowlist = {host.lower() for host in policy.egress_allowlist}
        return Scope.ALLOWLIST if egress_host(request.resource) in allowlist else Scope.INTERNET
    if capability is Capability.DB_QUERY:
        return Scope.BROKER
    if capability is Capability.DB_MIGRATE:
        migration = is_migration_file(request.resource, workdir, config)
        return Scope.TEMPORARY if migration else Scope.OUTSIDE_WORKDIR
    if capability is Capability.VCS_PUSH:
        protected = {name.lower() for name in policy.protected_branches}
        target = branch_name(request.resource, config)
        return Scope.PROTECTED_BRANCH if target in protected else Scope.FEATURE_BRANCH
    return Scope.ANY


class PolicyDecisionPoint:
    """The only source of decisions. Keeps every version a live run may be pinned to."""

    def __init__(self, policy: Policy, settings: GovernanceSettings | None = None) -> None:
        self._settings = settings or GovernanceSettings()
        self._versions: OrderedDict[str, Policy] = OrderedDict()
        self._current = self._remember(policy)

    @property
    def policy(self) -> Policy:
        return self._versions[self._current]

    @property
    def policy_hash(self) -> str:
        return self._current

    def reload(self, policy: Policy) -> str:
        """Publish a new version without disturbing runs pinned to an older one."""
        self._current = self._remember(policy)
        return self._current

    def decide(self, request: PolicyRequest) -> PolicyDecision:
        return self._evaluate(self.policy, self._current, request)

    def decide_for_run(self, run: Run, request: PolicyRequest) -> PolicyDecision:
        """Evaluate against the version pinned at the start of the run."""
        if run.state is not RunState.RUNNING:
            return self._refuse("run.state", f"run {run.id} is {run.state.value}", run.policy_hash)
        policy = self._versions.get(run.policy_hash)
        if policy is None:
            return self._refuse("policy.missing", "pinned policy is gone", run.policy_hash)
        return self._evaluate(policy, run.policy_hash, request)

    def _remember(self, policy: Policy) -> str:
        """Keep the recent versions runs may still be pinned to, and no more.

        A run outlives its policy by at most its own lifetime, so the oldest versions
        are eventually unreachable; a run pinned past the horizon is refused rather
        than decided under a version nobody can produce.
        """
        digest = policy.digest()
        self._versions[digest] = policy
        self._versions.move_to_end(digest)
        while len(self._versions) > self._settings.policy_versions_kept:
            self._versions.popitem(last=False)
        return digest

    def _evaluate(self, policy: Policy, policy_hash: str, request: PolicyRequest) -> PolicyDecision:
        try:
            scope = classify(request, policy, self._settings)
        except Exception as exc:
            if not policy.deny_on_policy_error:
                raise
            return self._deny(
                policy,
                policy_hash,
                rule_id="policy.error",
                reason=f"policy error: {exc}",
                weight=policy.default_weight,
            )
        rule = policy.rule_for(request.capability, scope)
        if rule is None:
            return self._deny(
                policy,
                policy_hash,
                rule_id="policy.default-deny",
                reason=f"no rule for {request.capability.value} in {scope.value}",
                weight=policy.default_weight,
            )
        if not rule.satisfied_by(request.attributes):
            return self._deny(
                policy,
                policy_hash,
                rule_id=rule.id,
                reason=f"attributes {list(rule.requires)} not satisfied",
                weight=rule.weight,
                rule=rule,
            )
        if not rule.allows(request.isolation_level):
            return self._deny(
                policy,
                policy_hash,
                rule_id=rule.id,
                reason=(
                    f"{request.capability.value} in {scope.value} "
                    f"is not allowed at {request.isolation_level.value}"
                ),
                weight=rule.weight,
                rule=rule,
            )
        return PolicyDecision(
            effect=Effect.ALLOW,
            rule_id=rule.id,
            reason=f"{request.capability.value} in {scope.value}",
            policy_hash=policy_hash,
            mode=policy.mode,
        )

    def _deny(
        self,
        policy: Policy,
        policy_hash: str,
        *,
        rule_id: str,
        reason: str,
        weight: int,
        rule: Rule | None = None,
    ) -> PolicyDecision:
        alternative = rule.alternative if rule is not None else ""
        return PolicyDecision(
            effect=Effect.DENY,
            rule_id=rule_id,
            reason=reason,
            message=f"use {alternative}" if alternative else self._settings.denied_message,
            weight=weight,
            policy_hash=policy_hash,
            mode=policy.mode,
        )

    def _refuse(self, rule_id: str, reason: str, policy_hash: str) -> PolicyDecision:
        """Lifecycle refusal. Applies whatever mode the policy runs in."""
        return PolicyDecision(
            effect=Effect.DENY,
            rule_id=rule_id,
            reason=reason,
            message=self._settings.denied_message,
            policy_hash=policy_hash,
            mode=Mode.ENFORCE,
        )
