from __future__ import annotations

import json
import ssl
from urllib.request import urlopen


class TokenExchangeError(Exception):
    """Standard Token Exchange V2 failed."""

    def __init__(self, detail: str = "token exchange failed") -> None:
        super().__init__(detail)
        self.detail = detail


def token_endpoint_from_well_known(url: str, ssl_context: ssl.SSLContext | None = None) -> str:
    try:
        with urlopen(url, context=ssl_context, timeout=10) as response:
            payload = json.loads(response.read())
    except (OSError, ValueError, TypeError) as exc:
        raise TokenExchangeError("openid configuration could not be loaded") from exc
    if not isinstance(payload, dict):
        raise TokenExchangeError("openid configuration is not an object")
    token_endpoint = payload.get("token_endpoint")
    if not isinstance(token_endpoint, str) or not token_endpoint.strip():
        raise TokenExchangeError("openid configuration missing token_endpoint")
    return token_endpoint
