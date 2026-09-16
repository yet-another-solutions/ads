from __future__ import annotations

import os
import ssl
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Settings:
    """Every tunable of the supervisor. Modules read them, never redefine them."""

    api_token: str
    tls_cert_path: Path
    tls_key_path: Path
    subject: str
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
    #: Where the run id rides. A long-lived worker serves many runs, so the call has
    #: to say which one it belongs to; without it there is nothing to charge a budget
    #: against and nothing to revoke.
    run_header: str = "x-ads-run"


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


def load_tls_context(settings: Settings) -> ssl.SSLContext:
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(settings.tls_cert_path), str(settings.tls_key_path))
    except ssl.SSLError as exc:
        raise RuntimeError("ADS supervisor TLS certificate and key could not be loaded") from exc
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
    api_token = _required("ADS_SUPERVISOR_API_TOKEN")
    if len(api_token) < 16:
        raise RuntimeError("ADS_SUPERVISOR_API_TOKEN must be at least 16 characters")
    settings = Settings(
        api_token=api_token,
        tls_cert_path=cert_path,
        tls_key_path=key_path,
        subject=_required("ADS_SUBJECT"),
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
    )
    load_tls_context(settings)
    return settings
