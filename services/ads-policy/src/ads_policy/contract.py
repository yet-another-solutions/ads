from __future__ import annotations

import hashlib
import uuid
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Any

import msgspec

MAX_CONVERSATION_LENGTH = 64
UNCHECKED_SOURCE_RULE = "source.unchecked"

ConversationId = Annotated[
    str, msgspec.Meta(max_length=MAX_CONVERSATION_LENGTH, pattern=r"^[A-Za-z0-9._:-]*$")
]


def as_text(value: Any) -> str:
    """A tool argument as the policy reads it: a resource is a string, whatever it arrived as."""
    if isinstance(value, str):
        return value
    return msgspec.json.encode(value).decode("utf-8")


def _one_each[K, V](pairs: Iterable[tuple[K, V]]) -> dict[K, V]:
    table: dict[K, V] = {}
    for key, value in pairs:
        if key in table:
            raise ValueError(f"the policy says two different things about {key}")
        table[key] = value
    return table


def string_values(node: Any) -> Iterator[str]:
    """Every string anywhere in a decoded JSON value, for the checks that read text."""
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for value in node.values():
            yield from string_values(value)
    elif isinstance(node, list):
        for value in node:
            yield from string_values(value)


class Capability(StrEnum):
    FS_READ = "fs.read"
    FS_WRITE = "fs.write"
    PROCESS_EXEC = "process.exec"
    NET_EGRESS = "net.egress"
    DB_QUERY = "db.query"
    DB_MIGRATE = "db.migrate"
    SECRET_READ = "secret.read"
    VCS_PUSH = "vcs.push"


class ResourceClass(StrEnum):
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
    PATH = "path"
    SUFFIX = "suffix"
    HOST = "host"
    BRANCH = "branch"
    LITERAL = "literal"


@dataclass(frozen=True, slots=True)
class Classifier:
    kind: ClassifierKind
    match: str
    otherwise: str = ""
    value: str = ""

    def classes(self) -> frozenset[str]:
        return frozenset({self.match} | ({self.otherwise} if self.otherwise else set()))


@dataclass(frozen=True, slots=True)
class CapabilityDef:
    capability: Capability
    classifier: Classifier


@dataclass(frozen=True, slots=True)
class Binding:
    source: str
    tool: str
    capability: Capability
    argument: str = ""
    value: str = ""

    def resource(self, arguments: Mapping[str, Any]) -> str | None:
        if self.value:
            return self.value
        found = arguments.get(self.argument)
        return as_text(found) if found else None


class IsolationLevel(StrEnum):
    LOCAL = "local"
    CONTAINER = "container"
    VM = "vm"


class Placement(StrEnum):
    CLUSTER = "cluster"
    WORKSTATION = "workstation"


class Effect(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    TRANSFORM = "transform"


class InterceptionPoint(StrEnum):
    CALL = "call"
    PROMPT = "prompt"
    REQUEST = "request"
    RESPONSE = "response"


class Mode(StrEnum):
    ENFORCE = "enforce"
    REVIEW = "review"


class Switch(StrEnum):
    OFF = "off"
    REVIEW = "review"
    ENFORCE = "enforce"

    def stricter(self, other: Switch) -> Switch:
        from_least_to_most_strict = list(Switch)
        if from_least_to_most_strict.index(self) >= from_least_to_most_strict.index(other):
            return self
        return other


class CheckKind(StrEnum):
    SECRETS = "secrets"
    INJECTION = "injection"


class Side(msgspec.Struct, frozen=True):
    checks: frozenset[CheckKind]
    on: Switch = Switch.ENFORCE
    review: frozenset[CheckKind] = frozenset()

    def switch_for(self, check: CheckKind) -> Switch:
        if check not in self.checks:
            return Switch.OFF
        if check in self.review:
            return Switch.REVIEW if self.on is Switch.ENFORCE else self.on
        return self.on

    def stricter(self, other: Side) -> Side:
        checks = self.checks | other.checks
        reviewed_by_both = self.review & other.review
        reviewed_where_only_one_asks = (self.review - other.checks) | (other.review - self.checks)
        return Side(
            checks=checks,
            on=self.on.stricter(other.on),
            review=reviewed_by_both | reviewed_where_only_one_asks,
        )


DEFAULT_REQUEST = Side(checks=frozenset({CheckKind.SECRETS}))
DEFAULT_RESPONSE = Side(
    checks=frozenset({CheckKind.SECRETS, CheckKind.INJECTION}),
    review=frozenset({CheckKind.INJECTION}),
)
DEFAULT_PROMPT = Side(
    checks=frozenset({CheckKind.SECRETS, CheckKind.INJECTION}),
    review=frozenset({CheckKind.INJECTION}),
)


class Interception(msgspec.Struct, frozen=True):
    request: Side | None = None
    response: Side | None = None
    prompt: Side | None = None

    def filled_from(self, fallback: Interception) -> Interception:
        return Interception(
            request=self.request or fallback.request,
            response=self.response or fallback.response,
            prompt=self.prompt or fallback.prompt,
        )

    def stricter(self, other: Interception) -> Interception:
        return Interception(
            request=_stricter_of_stated(self.request, other.request),
            response=_stricter_of_stated(self.response, other.response),
            prompt=_stricter_of_stated(self.prompt, other.prompt),
        )

    def side(self, point: InterceptionPoint) -> Side:
        if point is InterceptionPoint.REQUEST:
            return self.request or DEFAULT_REQUEST
        if point is InterceptionPoint.RESPONSE:
            return self.response or DEFAULT_RESPONSE
        if point is InterceptionPoint.PROMPT:
            return self.prompt or DEFAULT_PROMPT
        raise ValueError(f"{point.value} is not a payload side")

    def canonical(self) -> list[Any]:
        return [
            _canonical_side(self.request),
            _canonical_side(self.response),
            _canonical_side(self.prompt),
        ]


def _stricter_of_stated(one: Side | None, other: Side | None) -> Side | None:
    if one is None or other is None:
        return one or other
    return one.stricter(other)


def _canonical_side(side: Side | None) -> list[Any] | None:
    if side is None:
        return None
    return [
        side.on.value,
        sorted(check.value for check in side.checks),
        sorted(check.value for check in side.review),
    ]


class RunState(StrEnum):
    RUNNING = "running"
    FINISHED = "finished"
    REVOKED = "revoked"


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    capability: Capability
    resource_class: str
    levels: frozenset[IsolationLevel] = frozenset()
    weight: int = 1
    alternative: str = ""
    requires: tuple[tuple[str, str], ...] = ()
    inspect: Interception = Interception()

    def key(self) -> tuple[Capability, str]:
        return (self.capability, str(self.resource_class))

    def allows(self, level: IsolationLevel) -> bool:
        return level in self.levels

    def satisfied_by(self, attributes: Mapping[str, str]) -> bool:
        return all(attributes.get(name) == value for name, value in self.requires)


class SourceChecks(msgspec.Struct, frozen=True):
    source: str
    checks: Switch


@dataclass(frozen=True, slots=True)
class Policy:
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
    interception: Interception = Interception()
    unchecked_sources: frozenset[str] = frozenset()
    _binding_by_tool: dict[tuple[str, str], Binding] = dataclass_field(
        init=False, repr=False, compare=False
    )
    _rule_by_key: dict[tuple[Capability, str], Rule] = dataclass_field(
        init=False, repr=False, compare=False
    )
    _classifier_by_capability: dict[Capability, Classifier] = dataclass_field(
        init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "_binding_by_tool",
            _one_each(((binding.source, binding.tool), binding) for binding in self.bindings),
        )
        object.__setattr__(
            self, "_rule_by_key", _one_each((rule.key(), rule) for rule in self.rules)
        )
        object.__setattr__(
            self,
            "_classifier_by_capability",
            _one_each(
                (definition.capability, definition.classifier) for definition in self.capabilities
            ),
        )

    def binding_for(self, source: str, tool: str) -> Binding | None:
        return self._binding_by_tool.get((source, tool))

    def is_unchecked(self, source: str) -> bool:
        return source in self.unchecked_sources

    def source_checks(self) -> tuple[SourceChecks, ...]:
        named = {binding.source for binding in self.bindings} | self.unchecked_sources
        return tuple(
            SourceChecks(source, Switch.OFF if self.is_unchecked(source) else Switch.ENFORCE)
            for source in sorted(named)
        )

    def rule_for(self, capability: Capability, resource_class: str) -> Rule | None:
        return self._rule_by_key.get((capability, str(resource_class)))

    def inspection_for(self, rule: Rule | None) -> Interception:
        if rule is None:
            return self.interception
        return rule.inspect.filled_from(self.interception)

    def classifier_for(self, capability: Capability) -> Classifier | None:
        return self._classifier_by_capability.get(capability)

    def digest(self) -> str:
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
                rule.inspect.canonical(),
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
            self.interception.canonical(),
            *self._unchecked_sources_only_when_any(),
        ]

    def _unchecked_sources_only_when_any(self) -> list[list[str]]:
        return [sorted(self.unchecked_sources)] if self.unchecked_sources else []


class Approval(msgspec.Struct, frozen=True):
    required_attribute: str
    prompt: str


class Transform(msgspec.Struct, frozen=True):
    payload: str
    redactions: tuple[str, ...] = ()


class RunContext(msgspec.Struct, frozen=True):
    project: str
    repo: str
    env: str
    workdir: str


class PolicyRequest(msgspec.Struct, frozen=True):
    subject: str
    capability: Capability
    resource: str
    isolation_level: IsolationLevel
    context: RunContext
    attributes: dict[str, str] = msgspec.field(default_factory=dict)


class PolicyDecision(msgspec.Struct, frozen=True):
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
    capability: Capability | None = None
    resource: str = ""
    interception: Interception = msgspec.field(default_factory=Interception)

    @property
    def enforced(self) -> bool:
        return self.mode is Mode.ENFORCE

    @property
    def permitted(self) -> bool:
        return self.effect is not Effect.DENY or self.mode is Mode.REVIEW


class Site(msgspec.Struct, frozen=True):
    placement: Placement
    runtime_class_name: str | None = None
    node_labels: dict[str, str] = msgspec.field(default_factory=dict)


class Run(msgspec.Struct, frozen=True):
    id: str
    subject: str
    context: RunContext
    isolation_level: IsolationLevel | None
    policy_hash: str
    state: RunState = RunState.RUNNING
    holder: str = ""
    conversation: str = ""


class AuditEvent(msgspec.Struct, frozen=True):
    run_id: str
    subject: str
    capability: Capability | None
    resource: str
    effect: Effect
    rule_id: str
    weight: int
    policy_hash: str
    content: str | None = None
    point: InterceptionPoint = InterceptionPoint.CALL
    decided_by: str = ""
    conversation: str = ""
    source: str = ""
    tool: str = ""
    event_id: str = msgspec.field(default_factory=lambda: uuid.uuid4().hex)
    recorded_at: datetime = msgspec.field(default_factory=lambda: datetime.now(UTC))


class RunRequest(msgspec.Struct, frozen=True):
    subject: str
    project: str
    repo: str
    env: str
    workdir: str
    placement: Placement | None = Placement.CLUSTER
    runtime_class_name: str | None = None
    node_labels: dict[str, str] = msgspec.field(default_factory=dict)
    holder: str = ""
    conversation: ConversationId = ""


class ConversationBlockRequest(msgspec.Struct, frozen=True):
    budget: int
    by: str


class DecisionRequest(msgspec.Struct, frozen=True):
    run_id: str
    subject: str
    capability: Capability
    resource: str
    attributes: dict[str, str] = msgspec.field(default_factory=dict)
    site: Site | None = None
    source: str = ""
    tool: str = ""


class PromptRequest(msgspec.Struct, frozen=True):
    run_id: str
    subject: str


class ToolCallRequest(msgspec.Struct, frozen=True):
    run_id: str
    subject: str
    source: str
    tool: str
    arguments: dict[str, Any] = msgspec.field(default_factory=dict)
    attributes: dict[str, str] = msgspec.field(default_factory=dict)
    site: Site | None = None
