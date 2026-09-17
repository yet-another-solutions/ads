from __future__ import annotations

import os
import re
import ssl
from dataclasses import dataclass
from pathlib import Path

import msgspec

from ads_guardrail.contract import Application, McpServer

SHA256_HEX = re.compile(r"[0-9a-f]{64}")
PATH_SEGMENT = re.compile(r"[A-Za-z0-9_-]+")


@dataclass(frozen=True, slots=True)
class Settings:
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
    mcp_servers: tuple[McpServer, ...] = ()
    mcp_timeout_seconds: float = 60.0
    run_header: str = "x-ads-run"
    applications: tuple[Application, ...] = ()
    person_token_audience: str = ""
    keycloak_well_known_url: str = ""
    keycloak_issuer: str = ""
    injection_scanner_url: str = ""
    injection_scanner_api_token: str = ""
    injection_scanner_timeout_seconds: float = 30.0


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


def _key_value_pairs(name: str) -> dict[str, str]:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return {}
    pairs: dict[str, str] = {}
    for item in raw.split(","):
        key, _, value = item.partition("=")
        if key.strip():
            pairs[key.strip()] = value.strip()
    return pairs


def _json_list[T](name: str, item_type: type[T]) -> tuple[T, ...]:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return ()
    try:
        return msgspec.json.decode(raw, type=tuple[item_type, ...])  # type: ignore[valid-type]
    except msgspec.DecodeError as exc:
        raise RuntimeError(f"{name} is unreadable: {exc}") from exc


def _mcp_servers() -> tuple[McpServer, ...]:
    servers = _json_list("ADS_MCP_SERVERS", McpServer)
    names: set[str] = set()
    checked: list[McpServer] = []
    for server in servers:
        if not PATH_SEGMENT.fullmatch(server.name):
            raise RuntimeError(f"ADS_MCP_SERVERS: {server.name!r} is not usable as a path segment")
        if not server.url.startswith(("http://", "https://")):
            raise RuntimeError(f"ADS_MCP_SERVERS: {server.name!r} needs an http(s) URL")
        if server.name in names:
            raise RuntimeError(f"ADS_MCP_SERVERS: {server.name!r} is listed twice")
        names.add(server.name)
        checked.append(msgspec.structs.replace(server, url=server.url.rstrip("/")))
    return tuple(checked)


def _applications() -> tuple[Application, ...]:
    applications = _json_list("ADS_APPLICATIONS", Application)
    fingerprints: set[str] = set()
    for application in applications:
        if not application.name.strip():
            raise RuntimeError("ADS_APPLICATIONS: an application needs a name")
        if not SHA256_HEX.fullmatch(application.key_sha256):
            raise RuntimeError(
                f"ADS_APPLICATIONS: {application.name!r} needs key_sha256 as 64 lowercase hex"
            )
        if application.key_sha256 in fingerprints:
            raise RuntimeError(f"ADS_APPLICATIONS: {application.name!r} reuses another's key")
        fingerprints.add(application.key_sha256)
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
        attributes=_key_value_pairs("ADS_ATTRIBUTES"),
        tls_ca_bundle=_existing_file("ADS_TLS_CA_BUNDLE", ca_raw) if ca_raw else None,
        bind_host=_env("ADS_BIND_HOST", "0.0.0.0"),
        port=int(_env("ADS_PORT", "8080")),
        mcp_servers=_mcp_servers(),
        mcp_timeout_seconds=float(_env("ADS_MCP_TIMEOUT_SECONDS", "60")),
        run_header=_env("ADS_RUN_HEADER", "x-ads-run").lower(),
        applications=_applications(),
        person_token_audience=_env("ADS_MCP_AUDIENCE", "").strip(),
        keycloak_well_known_url=_env("ADS_KEYCLOAK_WELL_KNOWN_URL", "").strip(),
        keycloak_issuer=_env("ADS_KEYCLOAK_ISSUER", "").strip(),
        injection_scanner_url=_env("ADS_INJECTION_SCANNER_URL", "").strip().rstrip("/"),
        injection_scanner_api_token=_env("ADS_INJECTION_SCANNER_API_TOKEN", "").strip(),
        injection_scanner_timeout_seconds=float(
            _env("ADS_INJECTION_SCANNER_TIMEOUT_SECONDS", "30")
        ),
    )
    if bool(settings.injection_scanner_url) != bool(settings.injection_scanner_api_token):
        raise RuntimeError(
            "ADS_INJECTION_SCANNER_URL and ADS_INJECTION_SCANNER_API_TOKEN go together"
        )
    if settings.person_token_audience and not (
        settings.keycloak_well_known_url and settings.keycloak_issuer
    ):
        raise RuntimeError(
            "ADS_MCP_AUDIENCE needs ADS_KEYCLOAK_WELL_KNOWN_URL and ADS_KEYCLOAK_ISSUER"
        )
    load_tls_context(settings)
    return settings
