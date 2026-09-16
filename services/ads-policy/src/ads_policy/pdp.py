from __future__ import annotations

from collections import OrderedDict

from ads_policy.config import GovernanceSettings
from ads_policy.contract import (
    Capability,
    Classifier,
    ClassifierKind,
    Effect,
    Mode,
    Policy,
    PolicyDecision,
    PolicyRequest,
    ResourceClass,
    Rule,
    Run,
    RunState,
    ToolCallRequest,
)
from ads_policy.normalize import branch_name, egress_host, within_workdir


class Unbound(ValueError):
    """The call does not resolve to a capability, so there is nothing to decide.

    Two ways to get here, and both are refusals rather than guesses: no binding names
    this tool, or the binding names an argument the call did not carry.
    """

    def __init__(self, rule_id: str, detail: str) -> None:
        super().__init__(detail)
        self.rule_id = rule_id


def resolve(call: ToolCallRequest, policy: Policy) -> tuple[Capability, str]:
    """Turn one agent's tool call into the capability and resource it amounts to."""
    binding = policy.binding_for(call.source, call.tool)
    if binding is None:
        raise Unbound("binding.missing", f"nothing binds {call.tool!r} from {call.source!r}")
    resource = binding.resource(call.arguments)
    if resource is None:
        raise Unbound(
            "binding.resource",
            f"{call.tool!r} carries no {binding.argument!r} to act on",
        )
    return binding.capability, resource


def classify(
    request: PolicyRequest, policy: Policy, settings: GovernanceSettings | None = None
) -> str:
    """Turn the raw resource into the class the matrix is written over.

    Which classifier a capability uses comes from the policy; what each classifier
    means is here. A capability the policy declares nothing for classifies as ``any``
    and so only matches a rule written over ``any`` — which, absent one, is a denial.
    """
    config = settings or GovernanceSettings()
    classifier = policy.classifier_for(request.capability)
    if classifier is None:
        return ResourceClass.ANY
    if classifier.kind is ClassifierKind.LITERAL:
        return classifier.match
    return (
        classifier.match
        if _matches(classifier, request, policy, config)
        else (classifier.otherwise or ResourceClass.ANY)
    )


def _matches(
    classifier: Classifier,
    request: PolicyRequest,
    policy: Policy,
    config: GovernanceSettings,
) -> bool:
    resource = request.resource
    workdir = request.context.workdir
    if classifier.kind is ClassifierKind.PATH:
        return within_workdir(resource, workdir)
    if classifier.kind is ClassifierKind.SUFFIX:
        return resource.strip().endswith(classifier.value) and within_workdir(resource, workdir)
    if classifier.kind is ClassifierKind.HOST:
        return egress_host(resource) in {host.lower() for host in policy.egress_allowlist}
    if classifier.kind is ClassifierKind.BRANCH:
        return branch_name(resource, config) in {name.lower() for name in policy.protected_branches}
    raise ValueError(f"no such classifier: {classifier.kind}")


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

    def policy_of(self, run: Run) -> Policy | None:
        """The version this run was pinned to, or nothing if it has aged out."""
        return self._versions.get(run.policy_hash)

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
            resource_class = classify(request, policy, self._settings)
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
        rule = policy.rule_for(request.capability, resource_class)
        if rule is None:
            return self._deny(
                policy,
                policy_hash,
                rule_id="policy.default-deny",
                reason=f"no rule for {request.capability.value} in {resource_class}",
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
                    f"{request.capability.value} in {resource_class} "
                    f"is not allowed at {request.isolation_level.value}"
                ),
                weight=rule.weight,
                rule=rule,
            )
        return PolicyDecision(
            effect=Effect.ALLOW,
            rule_id=rule.id,
            reason=f"{request.capability.value} in {resource_class}",
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
