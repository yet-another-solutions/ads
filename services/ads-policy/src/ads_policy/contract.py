from __future__ import annotations

import hashlib
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

import msgspec


class Capability(StrEnum):
    """Normalised capability, never a tool name of the agent."""

    FS_READ = "fs.read"
    FS_WRITE = "fs.write"
    PROCESS_EXEC = "process.exec"
    NET_EGRESS = "net.egress"
    DB_QUERY = "db.query"
    DB_MIGRATE = "db.migrate"
    SECRET_READ = "secret.read"
    VCS_PUSH = "vcs.push"


class Scope(StrEnum):
    """Resource qualifier the PDP derives from the resource, never a caller claim."""

    ANY = "any"
    WORKDIR = "workdir"
    OUTSIDE_WORKDIR = "outside-workdir"
    ALLOWLIST = "allowlist"
    INTERNET = "internet"
    BROKER = "broker"
    TEMPORARY = "temporary"
    FEATURE_BRANCH = "feature-branch"
    PROTECTED_BRANCH = "protected-branch"


class IsolationLevel(StrEnum):
    """Where a run executes. Assigned by the server, never self-declared."""

    LOCAL = "local"
    CONTAINER = "container"
    VM = "vm"


class Placement(StrEnum):
    """Which kind of executor opened the run, which decides how its level is found.

    A cluster placement is derived from where the pod landed. A workstation has no
    nodes to read, so the supervisor states it and is trusted to, because a developer
    machine is the one place the agent has no more rights than the developer already.
    """

    CLUSTER = "cluster"
    WORKSTATION = "workstation"


class Effect(StrEnum):
    """Decision outcome. Escalation is a deny carrying approval, not a third value."""

    ALLOW = "allow"
    DENY = "deny"
    TRANSFORM = "transform"


class Mode(StrEnum):
    """Whether decisions are applied or only recorded."""

    ENFORCE = "enforce"
    REVIEW = "review"


class RunState(StrEnum):
    RUNNING = "running"
    FINISHED = "finished"
    REVOKED = "revoked"


@dataclass(frozen=True, slots=True)
class Rule:
    """One row of the capability matrix. Empty ``levels`` is an explicit deny."""

    id: str
    capability: Capability
    scope: Scope
    levels: frozenset[IsolationLevel] = frozenset()
    weight: int = 1
    alternative: str = ""
    requires: tuple[tuple[str, str], ...] = ()

    def key(self) -> tuple[Capability, Scope]:
        return (self.capability, self.scope)

    def allows(self, level: IsolationLevel) -> bool:
        return level in self.levels

    def satisfied_by(self, attributes: Mapping[str, str]) -> bool:
        return all(attributes.get(name) == value for name, value in self.requires)


@dataclass(frozen=True, slots=True)
class Policy:
    """A policy version. Anything without a rule is denied."""

    schema_version: str
    version: str
    mode: Mode
    deny_on_policy_error: bool
    rules: tuple[Rule, ...]
    egress_allowlist: tuple[str, ...]
    protected_branches: tuple[str, ...]
    default_weight: int = 1

    def rule_for(self, capability: Capability, scope: Scope) -> Rule | None:
        for rule in self.rules:
            if rule.key() == (capability, scope):
                return rule
        return None

    def digest(self) -> str:
        """Hash of the content actually applied, independent of rule order."""
        return hashlib.sha256(msgspec.json.encode(self._canonical())).hexdigest()

    def _canonical(self) -> list[Any]:
        rules = sorted(
            [
                rule.id,
                rule.capability.value,
                rule.scope.value,
                sorted(level.value for level in rule.levels),
                rule.weight,
                rule.alternative,
                sorted([name, value] for name, value in rule.requires),
            ]
            for rule in self.rules
        )
        return [
            self.schema_version,
            self.version,
            self.mode.value,
            self.deny_on_policy_error,
            rules,
            sorted(host.lower() for host in self.egress_allowlist),
            sorted(branch.lower() for branch in self.protected_branches),
            self.default_weight,
        ]


class Approval(msgspec.Struct, frozen=True):
    """Escalation to a human. The contract exists, the queue behind it does not yet."""

    required_attribute: str
    prompt: str


class Transform(msgspec.Struct, frozen=True):
    """Replacement payload for the only outcome that changes the action, not the verdict."""

    payload: str
    redactions: tuple[str, ...] = ()


class RunContext(msgspec.Struct, frozen=True):
    """What the PDP is told explicitly, next to the opaque attributes."""

    project: str
    repo: str
    env: str
    workdir: str


class PolicyRequest(msgspec.Struct, frozen=True):
    """Isolation level is an attribute here, next to capability and resource."""

    subject: str
    capability: Capability
    resource: str
    isolation_level: IsolationLevel
    context: RunContext
    attributes: dict[str, str] = msgspec.field(default_factory=dict)


class PolicyDecision(msgspec.Struct, frozen=True):
    """``reason`` goes to the audit, ``message`` is all the agent gets to see."""

    effect: Effect
    rule_id: str
    reason: str
    message: str = ""
    warnings: tuple[str, ...] = ()
    approval: Approval | None = None
    transform: Transform | None = None
    weight: int = 0
    policy_hash: str = ""
    mode: Mode = Mode.ENFORCE

    @property
    def enforced(self) -> bool:
        return self.mode is Mode.ENFORCE

    @property
    def permitted(self) -> bool:
        """What a PEP acts on: in review mode a deny is recorded, never applied."""
        return self.effect is not Effect.DENY or self.mode is Mode.REVIEW


class Run(msgspec.Struct, frozen=True):
    """One agent run. The policy version is pinned at start, the state is revocable."""

    id: str
    subject: str
    context: RunContext
    isolation_level: IsolationLevel
    policy_hash: str
    state: RunState = RunState.RUNNING


class AuditEvent(msgspec.Struct, frozen=True):
    """A decision with its arguments. Content is carried only when opted in.

    ``event_id`` and ``recorded_at`` together make a redelivery from the broker
    harmless. Both are fixed when the decision is made, not when the row lands, so
    the journal recognises an event it already holds and a retry does not inflate
    the budget.
    """

    run_id: str
    subject: str
    capability: Capability
    resource: str
    effect: Effect
    rule_id: str
    weight: int
    policy_hash: str
    content: str | None = None
    event_id: str = msgspec.field(default_factory=lambda: uuid.uuid4().hex)
    recorded_at: datetime = msgspec.field(default_factory=lambda: datetime.now(UTC))


class RunRequest(msgspec.Struct, frozen=True):
    """What a controller sends to open a run. The level is derived, never taken."""

    subject: str
    project: str
    repo: str
    env: str
    workdir: str
    placement: Placement = Placement.CLUSTER
    runtime_class_name: str | None = None
    node_labels: dict[str, str] = msgspec.field(default_factory=dict)


class DecisionRequest(msgspec.Struct, frozen=True):
    """What a PEP asks about. Subject and resource are its own, the rest is the run."""

    run_id: str
    subject: str
    capability: Capability
    resource: str
    attributes: dict[str, str] = msgspec.field(default_factory=dict)
