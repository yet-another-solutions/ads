from __future__ import annotations

import json
import ssl
from typing import Protocol
from urllib.request import urlopen

from ads_commons.security.context import SecurityContext


class InvalidAccessToken(Exception):
    """JWT failed resource-server verification."""

    def __init__(self, detail: str = "invalid token") -> None:
        super().__init__(detail)
        self.detail = detail


class AccessTokenVerifier(Protocol):
    def authenticate(self, token: str, *, audience: str | None = None) -> SecurityContext: ...


def jwks_uri_from_well_known(url: str, ssl_context: ssl.SSLContext | None = None) -> str:
    try:
        with urlopen(url, context=ssl_context, timeout=10) as response:
            payload = json.loads(response.read())
    except (OSError, ValueError, TypeError) as exc:
        raise InvalidAccessToken("openid configuration could not be loaded") from exc
    if not isinstance(payload, dict):
        raise InvalidAccessToken("openid configuration is not an object")
    jwks_uri = payload.get("jwks_uri")
    if not isinstance(jwks_uri, str) or not jwks_uri.strip():
        raise InvalidAccessToken("openid configuration missing jwks_uri")
    return jwks_uri
