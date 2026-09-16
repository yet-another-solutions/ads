from __future__ import annotations

import asyncio
import json
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import cast

import httpx2
import pytest

from ads.config import Settings
from ads.oidc import OidcClient
from ads_commons_beans import JwtVerifier
from tests.certs import issue_tls, openssl_available

pytestmark = pytest.mark.skipif(not openssl_available(), reason="openssl required")


class _UnusedVerifier:
    def decode(self, token: str, *, nonce: str | None = None) -> None:
        raise AssertionError("metadata tests must not decode tokens")


def _oidc_client(settings: Settings) -> OidcClient:
    return OidcClient(settings, cast(JwtVerifier, _UnusedVerifier()))


def _settings(*, cert: Path, key: Path, ca: Path, well_known: str) -> Settings:
    return Settings(
        keycloak_well_known_url=well_known,
        keycloak_issuer="https://kc/realms/ads",
        keycloak_client_id="ads",
        keycloak_client_secret="secret",
        keycloak_audience="ads",
        keycloak_role="user",
        session_secret="test-session-secret-32b!",
        public_base_url="https://ads.example",
        tls_cert_path=cert,
        tls_key_path=key,
        tls_ca_bundle=ca,
        bind_host="127.0.0.1",
        port=8080,
    )


def _serve_https(cert: Path, key: Path, body: bytes) -> tuple[HTTPServer, str]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            return

    httpd = HTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert), str(key))
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    host, port = httpd.server_address
    return httpd, f"https://{host}:{port}/realms/ads/.well-known/openid-configuration"


def test_oidc_accepts_configured_ca_bundle(tmp_path: Path) -> None:
    ca_crt, server_crt, server_key = issue_tls(tmp_path)
    payload = json.dumps(
        {
            "issuer": "https://kc/realms/ads",
            "authorization_endpoint": "https://kc/auth",
            "token_endpoint": "https://kc/token",
            "jwks_uri": "https://kc/jwks",
        }
    ).encode()
    httpd, url = _serve_https(server_crt, server_key, payload)
    try:
        settings = _settings(cert=server_crt, key=server_key, ca=ca_crt, well_known=url)
        metadata = asyncio.run(_oidc_client(settings).metadata())
        assert metadata["jwks_uri"] == "https://kc/jwks"
    finally:
        httpd.shutdown()


def test_oidc_rejects_unknown_ca_bundle(tmp_path: Path) -> None:
    trusted = tmp_path / "trusted"
    other = tmp_path / "other"
    trusted.mkdir()
    other.mkdir()
    trusted_ca, _, _ = issue_tls(trusted)
    _, other_cert, other_key = issue_tls(other)
    payload = b'{"issuer":"https://kc/realms/ads"}'
    httpd, url = _serve_https(other_cert, other_key, payload)
    try:
        settings = _settings(cert=other_cert, key=other_key, ca=trusted_ca, well_known=url)
        with pytest.raises(httpx2.HTTPError):
            asyncio.run(_oidc_client(settings).metadata())
    finally:
        httpd.shutdown()
