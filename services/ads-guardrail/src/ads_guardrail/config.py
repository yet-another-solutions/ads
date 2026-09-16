from __future__ import annotations

import os
import re
import ssl
from dataclasses import dataclass
from pathlib import Path

import msgspec

from ads_guardrail.contract import Application

SHA256 = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True, slots=True)
class Settings:
    """Every tunable of the guardrail. Modules read them, never redefine them."""

    api_token: str
    tls_cert_path: Path
    tls_key_path: Path
    policy_url: str = ""
    policy_api_token: str = ""
    amqp_url: str = ""
    attributes: dict[str, str] | None = None
    tls_ca_bundle: Path | None = None
    bind_host: str = "0.0.0.0"
    port: int = 8080
    audit_flush_seconds: float = 1.0
    #: The MCP servers this stands in front of, by name. An agent reaches one at
    #: ``/mcp/<name>`` instead of its real address, which is the whole installation: one
    #: URL per server in its config, and nothing in its code. The name is also what
    #: bindings call the server, as ``mcp:<name>`` — two servers may both offer `search`.
    mcp_servers: dict[str, str] | None = None
    mcp_timeout_seconds: float = 60.0
    #: Where a caller may name its run. A proxied call is matched to its run by the
    #: credentials it carries; this is only needed when the same credentials hold
    #: several runs at once, and the named run must still be one of theirs.
    run_header: str = "x-ads-run"
    #: Applications that call with their own key. Their runs are opened here.
    applications: tuple[Application, ...] = ()
    #: Who a person's token must be issued for. Empty means no person's token is
    #: accepted at all: without it any token of theirs — issued to some other
    #: application entirely — would act in their runs.
    mcp_audience: str = ""
    keycloak_well_known_url: str = ""
    keycloak_issuer: str = ""


def _env(name: str, default: str | None = None) -> str:
    value = os.environ.get(name, default)
    if value is None:
        raise RuntimeError(f"{name} is required")
    return value


def _required(name: str) -> str:
    value = _env(name).strip()
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def _existing_file(name: str, raw: str) -> Path:
    path = Path(raw)
    if not path.is_file():
        raise RuntimeError(f"{name} must exist")
    return path


def _pairs(name: str) -> dict[str, str]:
    """``key=value,key=value`` — how a controller hands over what it read off the pod."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return {}
    pairs: dict[str, str] = {}
    for item in raw.split(","):
        key, _, value = item.partition("=")
        if key.strip():
            pairs[key.strip()] = value.strip()
    return pairs


def _mcp_servers() -> dict[str, str]:
    """``name=url,name=url``. A name becomes a path segment, so it has to be one."""
    servers = {name: url.rstrip("/") for name, url in _pairs("ADS_MCP_SERVERS").items()}
    for name, url in servers.items():
        if not name.replace("-", "").replace("_", "").isalnum():
            raise RuntimeError(f"ADS_MCP_SERVERS: {name!r} is not usable as a path segment")
        if not url.startswith(("http://", "https://")):
            raise RuntimeError(f"ADS_MCP_SERVERS: {name!r} needs an http(s) URL")
    return servers


def _applications() -> tuple[Application, ...]:
    """A JSON list. Each key fingerprint names one application, and only one."""
    raw = os.environ.get("ADS_APPLICATIONS", "").strip()
    if not raw:
        return ()
    try:
        applications = msgspec.json.decode(raw, type=tuple[Application, ...])
    except msgspec.DecodeError as exc:
        raise RuntimeError(f"ADS_APPLICATIONS is unreadable: {exc}") from exc
    seen: set[str] = set()
    for application in applications:
        if not application.name.strip():
            raise RuntimeError("ADS_APPLICATIONS: an application needs a name")
        if not SHA256.fullmatch(application.key_sha256):
            raise RuntimeError(
                f"ADS_APPLICATIONS: {application.name!r} needs key_sha256 as 64 lowercase hex"
            )
        if application.key_sha256 in seen:
            raise RuntimeError(f"ADS_APPLICATIONS: {application.name!r} reuses another's key")
        seen.add(application.key_sha256)
    return applications


def load_tls_context(settings: Settings) -> ssl.SSLContext:
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(settings.tls_cert_path), str(settings.tls_key_path))
    except ssl.SSLError as exc:
        raise RuntimeError("ADS guardrail TLS certificate and key could not be loaded") from exc
    if settings.tls_ca_bundle is not None:
        try:
            ssl.create_default_context(cafile=str(settings.tls_ca_bundle))
        except ssl.SSLError as exc:
            raise RuntimeError("ADS_TLS_CA_BUNDLE could not be loaded") from exc
    return context


def load_settings() -> Settings:
    cert_path = _existing_file("ADS_TLS_CERT_PATH", _required("ADS_TLS_CERT_PATH"))
    key_path = _existing_file("ADS_TLS_KEY_PATH", _required("ADS_TLS_KEY_PATH"))
    ca_raw = os.environ.get("ADS_TLS_CA_BUNDLE", "").strip()
    api_token = _required("ADS_GUARDRAIL_API_TOKEN")
    if len(api_token) < 16:
        raise RuntimeError("ADS_GUARDRAIL_API_TOKEN must be at least 16 characters")
    settings = Settings(
        api_token=api_token,
        tls_cert_path=cert_path,
        tls_key_path=key_path,
        policy_url=_required("ADS_POLICY_URL").rstrip("/"),
        policy_api_token=_required("ADS_POLICY_API_TOKEN"),
        amqp_url=_required("ADS_AMQP_URL"),
        attributes=_pairs("ADS_ATTRIBUTES"),
        tls_ca_bundle=_existing_file("ADS_TLS_CA_BUNDLE", ca_raw) if ca_raw else None,
        bind_host=_env("ADS_BIND_HOST", "0.0.0.0"),
        port=int(_env("ADS_PORT", "8080")),
        mcp_servers=_mcp_servers(),
        mcp_timeout_seconds=float(_env("ADS_MCP_TIMEOUT_SECONDS", "60")),
        run_header=_env("ADS_RUN_HEADER", "x-ads-run").lower(),
        applications=_applications(),
        mcp_audience=_env("ADS_MCP_AUDIENCE", "").strip(),
        keycloak_well_known_url=_env("ADS_KEYCLOAK_WELL_KNOWN_URL", "").strip(),
        keycloak_issuer=_env("ADS_KEYCLOAK_ISSUER", "").strip(),
    )
    if settings.mcp_audience and not (
        settings.keycloak_well_known_url and settings.keycloak_issuer
    ):
        raise RuntimeError(
            "ADS_MCP_AUDIENCE needs ADS_KEYCLOAK_WELL_KNOWN_URL and ADS_KEYCLOAK_ISSUER:"
            " a person's token cannot be checked without them"
        )
    load_tls_context(settings)
    return settings
