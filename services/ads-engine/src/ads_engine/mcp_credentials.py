"""Run-local MCP identity. Only the watcher rotates; request paths only read."""

from __future__ import annotations

import asyncio
import math
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

import httpx2

from ads_commons.security import (
    SecurityContext,
    SecurityContextHolder,
    identity_from_claims,
    security_context_from_identity,
)
from ads_commons_beans import JwtVerifier, TokenExchangeSettings
from ads_engine.config import Settings

MCP_AUDIENCE = "ads-sandbox-mcp"
ENGINE_CLIENT = "ads-engine"


class ExecutionFailed(Exception):
    """Safe processing error; never retry an executor run or expose remote errors."""


@dataclass(frozen=True, slots=True)
class TokenPair:
    context: SecurityContext = field(repr=False)
    refresh_token: str = field(repr=False)
    expires_at: float
    refresh_expires_in: float


class RunCredentials:
    def __init__(self, pair: TokenPair, timeout: float) -> None:
        self._pair: TokenPair | None = pair
        self._timeout = timeout
        self._closed = False

    def current(self) -> TokenPair:
        pair = self._pair
        if self._closed or pair is None:
            raise ExecutionFailed("MCP credentials closed")
        if pair.expires_at - time.time() <= self._timeout:
            raise ExecutionFailed("MCP access token has insufficient validity")
        if not pair.context.has_role("user"):
            raise ExecutionFailed("MCP permission denied")
        return pair

    def replace(self, pair: TokenPair) -> None:
        if self._closed:
            raise ExecutionFailed("MCP credentials closed")
        # No await: readers observe the entire old or entire new immutable pair.
        self._pair = pair

    def close(self) -> None:
        self._closed = True
        self._pair = None


class McpCredentials:
    """Application-scoped factory; never retains a user's pair."""

    def __init__(
        self, settings: Settings, exchange: TokenExchangeSettings, verifier: JwtVerifier
    ) -> None:
        self._settings = settings
        self._exchange = exchange
        self._verifier = verifier
        # Behind a guardrail the credential is addressed to it: it exchanges the token for
        # the sandbox, which Keycloak allows only to a client within the token's audience.
        self._audience = settings.guardrail.audience if settings.guardrail else MCP_AUDIENCE
        if not exchange.token_endpoint.startswith("https://"):
            raise ValueError("MCP token endpoint must use HTTPS")

    @asynccontextmanager
    async def open(self, inbound_token: str) -> AsyncIterator[RunCredentials]:
        subject = SecurityContextHolder.require().subject
        async with httpx2.AsyncClient(
            verify=self._exchange.ssl_context or True,
            timeout=min(10.0, self._settings.mcp_timeout_seconds),
            follow_redirects=False,
        ) as client:
            pair = await self._request(
                client,
                {
                    "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                    "subject_token": inbound_token,
                    "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                    "requested_token_type": "urn:ietf:params:oauth:token-type:refresh_token",
                    "audience": self._audience,
                },
                subject,
            )
            credentials = RunCredentials(pair, self._settings.mcp_timeout_seconds)
            try:
                async with asyncio.TaskGroup() as tasks:
                    watcher = tasks.create_task(self._watch(client, credentials, subject))
                    try:
                        yield credentials
                    finally:
                        credentials.close()
                        watcher.cancel()
            finally:
                credentials.close()

    async def _watch(
        self, client: httpx2.AsyncClient, credentials: RunCredentials, subject: str
    ) -> None:
        while True:
            pair = credentials.current()
            await asyncio.sleep(
                max(0, pair.expires_at - time.time() - 2 * self._settings.mcp_timeout_seconds)
            )
            replacement = await self._request(
                client,
                {"grant_type": "refresh_token", "refresh_token": pair.refresh_token},
                subject,
            )
            credentials.replace(replacement)

    async def _request(
        self, client: httpx2.AsyncClient, grant: dict[str, str], subject: str
    ) -> TokenPair:
        started = time.time()
        try:
            response = await client.post(
                self._exchange.token_endpoint,
                data={
                    **grant,
                    "client_id": ENGINE_CLIENT,
                    "client_secret": self._exchange.client_secret,
                },
            )
            response.raise_for_status()
            payload = response.json()
            return await asyncio.to_thread(self._validate, payload, subject, started)
        except Exception:
            # Identity-provider response bodies/exceptions may contain credentials.
            raise ExecutionFailed("MCP credential mint or refresh failed") from None

    def _validate(self, payload: Any, subject: str, started: float) -> TokenPair:
        if not isinstance(payload, dict) or str(payload.get("token_type", "")).lower() != "bearer":
            raise ValueError("invalid token pair")
        access, refresh = payload.get("access_token"), payload.get("refresh_token")
        if not isinstance(access, str) or not access.strip():
            raise ValueError("missing access token")
        if not isinstance(refresh, str) or not refresh.strip():
            raise ValueError("missing refresh token")
        expires_in = _duration(payload.get("expires_in"))
        refresh_expires_in = _duration(payload.get("refresh_expires_in"))
        claims = self._verifier.verified_claims(access, audience=self._audience)
        audience = claims["aud"]
        if audience != self._audience and audience != [self._audience]:
            raise ValueError("MCP audience widened")
        if claims.get("sub") != subject or claims.get("azp") != ENGINE_CLIENT:
            raise ValueError("MCP identity changed")
        # Defense in depth against mutable realm mappings, not a replacement for
        # tight Keycloak scopes. v1 authorizes only the scoped realm user role.
        roles = claims.get("realm_access", {}).get("roles", [])
        if not isinstance(roles, list) or set(roles) - {"user"} or claims.get("resource_access"):
            raise ValueError("MCP roles widened")
        context = security_context_from_identity(
            identity_from_claims(claims, self._audience)
        ).with_access_token(access)
        expires_at = min(float(claims["exp"]), started + expires_in)
        if expires_at - time.time() <= 2 * self._settings.mcp_timeout_seconds:
            # Fail closed rather than spin on a server issuing unusably short tokens.
            raise ValueError("MCP token lifetime must exceed twice the MCP timeout")
        if not context.has_role("user"):
            raise ValueError("MCP permission revoked")
        return TokenPair(context, refresh, expires_at, refresh_expires_in)


def _duration(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (float, int)):
        raise ValueError("invalid token expiry")
    if not math.isfinite(value) or value <= 0:
        raise ValueError("invalid token expiry")
    return float(value)
