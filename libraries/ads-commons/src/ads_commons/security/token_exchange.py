from __future__ import annotations

import json
import ssl
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from ads_commons.security.context import SecurityContext
from ads_commons.security.holder import AuthenticationRequired, SecurityContextHolder
from ads_commons.security.jwt import InvalidAccessToken, JwtVerifier

GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"
SUBJECT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"
REQUESTED_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"


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


class TokenExchange:
    """Mint a fresh Standard Token Exchange V2 token. No cache. Does not store tokens."""

    def __init__(
        self,
        *,
        token_endpoint: str,
        client_id: str,
        client_secret: str,
        verifier: JwtVerifier,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        self._token_endpoint = token_endpoint
        self._client_id = client_id
        self._client_secret = client_secret
        self._verifier = verifier
        self._ssl_context = ssl_context

    def exchange(self, audience: str) -> str:
        if not audience.strip():
            raise TokenExchangeError("audience is required")
        subject_token = SecurityContextHolder.require().access_token
        if not subject_token or not subject_token.strip():
            raise AuthenticationRequired("access token required")
        body = urlencode(
            {
                "grant_type": GRANT_TYPE,
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "subject_token": subject_token,
                "subject_token_type": SUBJECT_TOKEN_TYPE,
                "requested_token_type": REQUESTED_TOKEN_TYPE,
                "audience": audience,
            }
        ).encode()
        request = Request(self._token_endpoint, data=body, method="POST")
        request.add_header("Content-Type", "application/x-www-form-urlencoded")
        request.add_header("Accept", "application/json")
        try:
            with urlopen(request, context=self._ssl_context, timeout=10) as response:
                payload: Any = json.loads(response.read())
        except (HTTPError, URLError, TimeoutError, OSError, ValueError, TypeError) as exc:
            raise TokenExchangeError("token exchange failed") from exc
        token = payload.get("access_token") if isinstance(payload, dict) else None
        if not isinstance(token, str) or not token.strip():
            raise TokenExchangeError("token exchange returned no access_token")
        return token

    def mint(self, audience: str) -> SecurityContext:
        """Exchange, then wrap the new JWT. Claims come from that token, not the inbound context."""
        token = self.exchange(audience)
        try:
            return self._verifier.authenticate(token, audience=audience)
        except InvalidAccessToken as exc:
            raise TokenExchangeError("exchanged token is invalid") from exc
