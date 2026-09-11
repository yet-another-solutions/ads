from __future__ import annotations

import pytest

from ads.config import Settings


def test_session_secret_must_be_at_least_16_bytes(tmp_path) -> None:
    settings = Settings(
        keycloak_well_known_url="http://keycloak.test/realms/ads/.well-known/openid-configuration",
        keycloak_issuer="http://keycloak.test/realms/ads",
        keycloak_client_id="ads",
        keycloak_client_secret="test-secret",
        keycloak_audience="ads",
        keycloak_role="user",
        session_secret="short",
        public_base_url="http://testserver",
        data_dir=tmp_path / "data",
        tls_enabled=False,
        tls_cert_path=None,
        tls_key_path=None,
        bind_host="127.0.0.1",
        port=8080,
    )
    with pytest.raises(RuntimeError, match="16 bytes"):
        settings.session_secret_bytes()
