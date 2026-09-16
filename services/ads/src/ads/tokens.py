"""Standard Token Exchange V2 access for ads. Tokens stay in memory, never persisted."""

from __future__ import annotations

import ssl
from typing import Protocol

from ads.config import Settings
from ads_commons.security import SecurityContext


class TokenMinter(Protocol):
    """Exchange for an audience. ``subject_token`` overrides the bound holder token."""

    def exchange(self, audience: str, subject_token: str | None = None) -> str: ...

    def mint(self, audience: str, subject_token: str | None = None) -> SecurityContext: ...


class TokenAuthenticator(Protocol):
    def authenticate(self, token: str, *, audience: str | None = None) -> SecurityContext: ...


def ssl_context_for(settings: Settings) -> ssl.SSLContext | None:
    if settings.tls_ca_bundle is None:
        return None
    return ssl.create_default_context(cafile=str(settings.tls_ca_bundle))
