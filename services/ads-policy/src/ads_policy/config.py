from __future__ import annotations

import os
import ssl
from dataclasses import dataclass, field
from pathlib import Path

from ads_policy.contract import (
    Binding,
    Capability,
    CapabilityDef,
    Classifier,
    ClassifierKind,
    IsolationLevel,
    Mode,
    ResourceClass,
    Rule,
)

ALL_LEVELS = frozenset(IsolationLevel)
LOCAL_ONLY = frozenset({IsolationLevel.LOCAL})
EXEC_LEVELS = frozenset({IsolationLevel.LOCAL, IsolationLevel.VM})
VM_ONLY = frozenset({IsolationLevel.VM})

DEFAULT_RULES: tuple[Rule, ...] = (
    Rule("fs.read.workdir", Capability.FS_READ, ResourceClass.WORKDIR, ALL_LEVELS),
    Rule("fs.write.workdir", Capability.FS_WRITE, ResourceClass.WORKDIR, ALL_LEVELS),
    Rule("fs.read.outside", Capability.FS_READ, ResourceClass.OUTSIDE_WORKDIR, weight=3),
    Rule("fs.write.outside", Capability.FS_WRITE, ResourceClass.OUTSIDE_WORKDIR, weight=3),
    Rule("process.exec", Capability.PROCESS_EXEC, ResourceClass.ANY, EXEC_LEVELS, weight=2),
    Rule(
        "net.egress.internet", Capability.NET_EGRESS, ResourceClass.INTERNET, LOCAL_ONLY, weight=2
    ),
    Rule("net.egress.allowlist", Capability.NET_EGRESS, ResourceClass.ALLOWLIST, ALL_LEVELS),
    Rule("db.query.broker", Capability.DB_QUERY, ResourceClass.BROKER, ALL_LEVELS),
    Rule(
        "db.migrate.temporary",
        Capability.DB_MIGRATE,
        ResourceClass.TEMPORARY,
        VM_ONLY,
        weight=2,
        alternative="db.query",
    ),
    Rule(
        "db.migrate.outside",
        Capability.DB_MIGRATE,
        ResourceClass.OUTSIDE_WORKDIR,
        weight=4,
        alternative="db.query",
    ),
    Rule("secret.read", Capability.SECRET_READ, ResourceClass.ANY, weight=5),
    Rule(
        "vcs.push.feature",
        Capability.VCS_PUSH,
        ResourceClass.FEATURE_BRANCH,
        EXEC_LEVELS,
        weight=2,
        requires=(("repo.write", "true"),),
    ),
    Rule(
        "vcs.push.protected",
        Capability.VCS_PUSH,
        ResourceClass.PROTECTED_BRANCH,
        weight=5,
        alternative="vcs.push to a feature branch",
    ),
)

#: How each capability's resource becomes a class. Data, so a delivered policy can
#: reclassify without a new image; the kinds behind them stay code.
DEFAULT_CAPABILITIES: tuple[CapabilityDef, ...] = (
    CapabilityDef(
        Capability.FS_READ,
        Classifier(ClassifierKind.PATH, ResourceClass.WORKDIR, ResourceClass.OUTSIDE_WORKDIR),
    ),
    CapabilityDef(
        Capability.FS_WRITE,
        Classifier(ClassifierKind.PATH, ResourceClass.WORKDIR, ResourceClass.OUTSIDE_WORKDIR),
    ),
    CapabilityDef(
        Capability.PROCESS_EXEC,
        Classifier(ClassifierKind.LITERAL, ResourceClass.ANY),
    ),
    CapabilityDef(
        Capability.NET_EGRESS,
        Classifier(ClassifierKind.HOST, ResourceClass.ALLOWLIST, ResourceClass.INTERNET),
    ),
    CapabilityDef(
        Capability.DB_QUERY,
        Classifier(ClassifierKind.LITERAL, ResourceClass.BROKER),
    ),
    CapabilityDef(
        Capability.DB_MIGRATE,
        Classifier(
            ClassifierKind.SUFFIX,
            ResourceClass.TEMPORARY,
            ResourceClass.OUTSIDE_WORKDIR,
            value=".sql",
        ),
    ),
    CapabilityDef(
        Capability.SECRET_READ,
        Classifier(ClassifierKind.LITERAL, ResourceClass.ANY),
    ),
    CapabilityDef(
        Capability.VCS_PUSH,
        Classifier(
            ClassifierKind.BRANCH, ResourceClass.PROTECTED_BRANCH, ResourceClass.FEATURE_BRANCH
        ),
    ),
)

#: The only place a foreign tool name appears. Expect to replace this per deployment:
#: agents rename and add tools, and that is precisely why it is data and why it is
#: separate from the rules. A tool absent here is refused, which is the safe default
#: and also the reason an agent upgrade wants a look at this list.
DEFAULT_BINDINGS: tuple[Binding, ...] = (
    Binding("opencode", "bash", Capability.PROCESS_EXEC, argument="command"),
    Binding("opencode", "read", Capability.FS_READ, argument="filePath"),
    Binding("opencode", "write", Capability.FS_WRITE, argument="filePath"),
    Binding("opencode", "edit", Capability.FS_WRITE, argument="filePath"),
    Binding("opencode", "grep", Capability.FS_READ, argument="path"),
    Binding("opencode", "glob", Capability.FS_READ, argument="path"),
    Binding("opencode", "list", Capability.FS_READ, argument="path"),
    Binding("opencode", "webfetch", Capability.NET_EGRESS, argument="url"),
    # A query is not an object of access; what the call reaches is the provider.
    Binding("opencode", "websearch", Capability.NET_EGRESS, value="search-proxy.interlab"),
)

DEFAULT_EGRESS_ALLOWLIST = (
    "mirror.interlab",
    "llm-gateway.interlab",
    "tool-broker.interlab",
    "git-proxy.interlab",
)

DEFAULT_PROTECTED_BRANCHES = ("main", "master", "release")

DEFAULT_INJECTION_MARKERS = (
    "ignore previous instructions",
    "ignore all previous",
    "disregard the above",
    "you are now",
    "system prompt",
)


@dataclass(frozen=True, slots=True)
class GovernanceSettings:
    """Every tunable of the governance layer. Modules read them, never redefine them."""

    workdir: str = "/workspace"
    policy_dir: Path = Path("/policy")
    policy_document_name: str = "policy.yaml"
    schema_version: str = "ads.governance/v1"
    policy_version: str = "org-1"
    mode: Mode = Mode.ENFORCE
    deny_on_policy_error: bool = True
    default_weight: int = 1
    leak_weight: int = 5
    deny_repeat_multiplier: int = 3
    run_ttl_seconds: int = 3600
    audit_backlog: int = 10000
    policy_versions_kept: int = 32
    denied_message: str = "this action is not available"
    application_node_label: str = "ads.io/application-node"
    sandbox_node_label: str = "ads.io/sandbox-node"
    node_label_value: str = "true"
    vm_runtime_class: str = "kata-clh"
    kata_runtime_classes: frozenset[str] = frozenset({"kata-clh", "kata-qemu"})
    sandbox_available: bool = True
    egress_allowlist: tuple[str, ...] = DEFAULT_EGRESS_ALLOWLIST
    protected_branches: tuple[str, ...] = DEFAULT_PROTECTED_BRANCHES
    ref_prefixes: tuple[str, ...] = ("refs/heads/", "refs/remotes/")
    remote_names: frozenset[str] = frozenset({"origin", "upstream"})
    write_roles: frozenset[str] = frozenset({"developer", "maintainer"})
    agent_roles: frozenset[str] = frozenset({"agent"})
    rules: tuple[Rule, ...] = DEFAULT_RULES
    capabilities: tuple[CapabilityDef, ...] = DEFAULT_CAPABILITIES
    bindings: tuple[Binding, ...] = DEFAULT_BINDINGS
    injection_markers: tuple[str, ...] = DEFAULT_INJECTION_MARKERS


def _list(name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    return tuple(item.strip() for item in raw.split(",") if item.strip())


def _flag(name: str, default: bool) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on"}


def _seconds(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be a whole number of seconds") from exc
    if value <= 0:
        raise RuntimeError(f"{name} must be greater than zero")
    return value


def load_governance_settings() -> GovernanceSettings:
    """Deployment-specific values from the environment, the rest from the defaults above."""
    raw_mode = os.environ.get("ADS_POLICY_MODE", Mode.ENFORCE.value).strip()
    try:
        mode = Mode(raw_mode)
    except ValueError as exc:
        raise RuntimeError(f"ADS_POLICY_MODE must be one of {[m.value for m in Mode]}") from exc
    return GovernanceSettings(
        workdir=os.environ.get("ADS_RUN_WORKDIR", "/workspace").rstrip("/") or "/",
        policy_dir=Path(os.environ.get("ADS_POLICY_DIR", "/policy")),
        mode=mode,
        deny_on_policy_error=_flag("ADS_POLICY_DENY_ON_ERROR", True),
        sandbox_available=_flag("ADS_SANDBOX_AVAILABLE", True),
        run_ttl_seconds=_seconds("ADS_RUN_TTL_SECONDS", 3600),
        egress_allowlist=_list("ADS_EGRESS_ALLOWLIST", DEFAULT_EGRESS_ALLOWLIST),
        protected_branches=_list("ADS_PROTECTED_BRANCHES", DEFAULT_PROTECTED_BRANCHES),
    )


@dataclass(frozen=True, slots=True)
class Settings:
    """How the policy service itself runs."""

    api_token: str
    tls_cert_path: Path
    tls_key_path: Path
    redis_url: str = ""
    amqp_url: str = ""
    audit_flush_seconds: float = 1.0
    policy_reload_seconds: float = 10.0
    tls_ca_bundle: Path | None = None
    bind_host: str = "0.0.0.0"
    port: int = 8080
    governance: GovernanceSettings = field(default_factory=GovernanceSettings)


def _env(name: str, default: str | None = None) -> str:
    value = os.environ.get(name, default)
    if value is None:
        raise RuntimeError(f"{name} is required")
    return value


def _existing_file(name: str, raw: str) -> Path:
    path = Path(raw)
    if not path.is_file():
        raise RuntimeError(f"{name} must exist")
    return path


def load_tls_context(settings: Settings) -> ssl.SSLContext:
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(settings.tls_cert_path), str(settings.tls_key_path))
    except ssl.SSLError as exc:
        raise RuntimeError("ADS policy TLS certificate and key could not be loaded") from exc
    if settings.tls_ca_bundle is not None:
        try:
            ssl.create_default_context(cafile=str(settings.tls_ca_bundle))
        except ssl.SSLError as exc:
            raise RuntimeError("ADS_TLS_CA_BUNDLE could not be loaded") from exc
    return context


def load_settings() -> Settings:
    cert_path = _existing_file("ADS_TLS_CERT_PATH", _env("ADS_TLS_CERT_PATH").strip())
    key_path = _existing_file("ADS_TLS_KEY_PATH", _env("ADS_TLS_KEY_PATH").strip())
    ca_raw = os.environ.get("ADS_TLS_CA_BUNDLE", "").strip()
    api_token = _env("ADS_POLICY_API_TOKEN")
    if len(api_token.strip()) < 16:
        raise RuntimeError("ADS_POLICY_API_TOKEN must be at least 16 characters")
    redis_url = _env("ADS_REDIS_URL").strip()
    if not redis_url:
        raise RuntimeError("ADS_REDIS_URL is required")
    amqp_url = _env("ADS_AMQP_URL").strip()
    if not amqp_url:
        raise RuntimeError("ADS_AMQP_URL is required")
    settings = Settings(
        api_token=api_token,
        tls_cert_path=cert_path,
        tls_key_path=key_path,
        redis_url=redis_url,
        amqp_url=amqp_url,
        tls_ca_bundle=_existing_file("ADS_TLS_CA_BUNDLE", ca_raw) if ca_raw else None,
        bind_host=_env("ADS_BIND_HOST", "0.0.0.0"),
        port=int(_env("ADS_PORT", "8080")),
        policy_reload_seconds=_seconds("ADS_POLICY_RELOAD_SECONDS", 10),
        governance=load_governance_settings(),
    )
    load_tls_context(settings)
    return settings
