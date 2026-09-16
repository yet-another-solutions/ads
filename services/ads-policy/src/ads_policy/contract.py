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


class ResourceClass(StrEnum):
    """What kind of thing the resource is, derived by the PDP and never claimed.

    Not who is asking and not what they may do — a property of the object acted on.
    It is the third axis of the matrix, and it is what keeps ``fs.read`` one
    capability instead of two: the same call against the workdir and against
    somewhere else classifies differently.

    These are the classes the built-in capabilities produce, named so the code can
    read. A resource class is a plain string everywhere: a policy document may
    declare a capability whose classifier answers with a word that is not here.
    """

    ANY = "any"
    WORKDIR = "workdir"
    OUTSIDE_WORKDIR = "outside-workdir"
    ALLOWLIST = "allowlist"
    INTERNET = "internet"
    BROKER = "broker"
    TEMPORARY = "temporary"
    FEATURE_BRANCH = "feature-branch"
    PROTECTED_BRANCH = "protected-branch"


class ClassifierKind(StrEnum):
    """How a capability turns a raw resource into a resource class.

    Which kind applies to which capability is data, and lives in the policy document.
    The kinds themselves are code, because each is a piece of normalisation rather
    than a preference — and because a rule may only be written over a class some
    classifier can actually produce.
    """

    #: Is the path inside the run workdir?
    PATH = "path"
    #: Is it a file with this suffix, inside the workdir?
    SUFFIX = "suffix"
    #: Is the host on the policy's egress allowlist?
    HOST = "host"
    #: Is the branch one of the policy's protected branches?
    BRANCH = "branch"
    #: The resource says nothing; the answer is always the same.
    LITERAL = "literal"


@dataclass(frozen=True, slots=True)
class Classifier:
    """A classifier and the two classes it chooses between."""

    kind: ClassifierKind
    match: str
    otherwise: str = ""
    value: str = ""

    def classes(self) -> frozenset[str]:
        """Everything this classifier can answer, so a rule can be checked against it."""
        return frozenset({self.match} | ({self.otherwise} if self.otherwise else set()))


@dataclass(frozen=True, slots=True)
class CapabilityDef:
    """A capability and how the resource it names becomes a class."""

    capability: Capability
    classifier: Classifier


@dataclass(frozen=True, slots=True)
class Binding:
    """What one agent's tool means in our vocabulary.

    This is the only place a foreign tool name appears: the matrix stays written over
    capabilities, so updating an agent or attaching an MCP server changes bindings and
    leaves the rules alone.

    We write these, never the agent and never the MCP server. A server describing its
    own tool is self-declaration, and a decision may not rest on it.

    The resource comes either from a named argument or from a constant. A search takes
    a query, and a query is not an object of access — the thing being reached is the
    provider, so that binding carries the provider as ``value``.
    """

    source: str
    tool: str
    capability: Capability
    argument: str = ""
    value: str = ""

    def resource(self, arguments: Mapping[str, str]) -> str | None:
        """None when the call does not carry what the binding says it should."""
        if self.value:
            return self.value
        found = arguments.get(self.argument)
        return found if found else None


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


class InterceptionPoint(StrEnum):
    """Where a decision was taken, so the journal can tell a boundary from a signal.

    One tool call can produce two of these — the matrix permitted it and the payload
    check refused it — and they mean different things. ``call`` is deterministic and
    is the only one that guarantees anything; the other two read a payload with
    heuristics. They are also not symmetric: a secret on its way out is a leak and is
    refused, the same secret on its way back is redacted and passed on.
    """

    CALL = "call"
    REQUEST = "request"
    RESPONSE = "response"


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
    resource_class: str
    levels: frozenset[IsolationLevel] = frozenset()
    weight: int = 1
    alternative: str = ""
    requires: tuple[tuple[str, str], ...] = ()

    def key(self) -> tuple[Capability, str]:
        return (self.capability, str(self.resource_class))

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
    capabilities: tuple[CapabilityDef, ...] = ()
    bindings: tuple[Binding, ...] = ()
    default_weight: int = 1

    def binding_for(self, source: str, tool: str) -> Binding | None:
        for binding in self.bindings:
            if binding.source == source and binding.tool == tool:
                return binding
        return None

    def rule_for(self, capability: Capability, resource_class: str) -> Rule | None:
        for rule in self.rules:
            if rule.key() == (capability, str(resource_class)):
                return rule
        return None

    def classifier_for(self, capability: Capability) -> Classifier | None:
        for definition in self.capabilities:
            if definition.capability is capability:
                return definition.classifier
        return None

    def digest(self) -> str:
        """Hash of the content actually applied, independent of rule order."""
        return hashlib.sha256(msgspec.json.encode(self._canonical())).hexdigest()

    def _canonical(self) -> list[Any]:
        rules = sorted(
            [
                rule.id,
                rule.capability.value,
                str(rule.resource_class),
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
            # Two policies with the same rules but different classifiers decide
            # differently, so the hash has to tell them apart.
            sorted(
                [
                    definition.capability.value,
                    str(definition.classifier.kind),
                    definition.classifier.match,
                    definition.classifier.otherwise,
                    definition.classifier.value,
                ]
                for definition in self.capabilities
            ),
            # A binding decides what a call even is, so it belongs in the hash for the
            # same reason a rule does.
            sorted(
                [
                    binding.source,
                    binding.tool,
                    binding.capability.value,
                    binding.argument,
                    binding.value,
                ]
                for binding in self.bindings
            ),
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
    point: InterceptionPoint = InterceptionPoint.CALL
    #: What the call was recognised as, so a PEP that asked by tool name can say so
    #: in its own journal. Absent when nothing bound it.
    capability: Capability | None = None
    resource: str = ""

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
    #: Absent when the call never resolved to one — an unbound tool is still a row.
    capability: Capability | None
    resource: str
    effect: Effect
    rule_id: str
    weight: int
    policy_hash: str
    content: str | None = None
    point: InterceptionPoint = InterceptionPoint.CALL
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
    """What a PEP asks about when it already knows the capability.

    Our own code does: ``@require_permission(Capability.FS_READ)`` names it outright.
    An agent's tool call does not, and asks with :class:`ToolCallRequest` instead.
    """

    run_id: str
    subject: str
    capability: Capability
    resource: str
    attributes: dict[str, str] = msgspec.field(default_factory=dict)


class ToolCallRequest(msgspec.Struct, frozen=True):
    """A tool call in the agent's own words, for the PDP to recognise.

    The PEP does not translate it. Bindings are policy, pinned to the run along with
    the rules, and a PEP holding its own copy would decide under a version nobody
    recorded.
    """

    run_id: str
    subject: str
    source: str
    tool: str
    arguments: dict[str, str] = msgspec.field(default_factory=dict)
    attributes: dict[str, str] = msgspec.field(default_factory=dict)
