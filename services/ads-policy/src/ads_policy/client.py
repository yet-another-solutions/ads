from __future__ import annotations

import ssl
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import httpx2
import msgspec

from ads_policy.contract import (
    DecisionRequest,
    Effect,
    Mode,
    PolicyDecision,
    Run,
    RunRequest,
)

UNREACHABLE = "policy.unreachable"
UNCONFIGURED = "policy service is not configured"


class PolicyClient(Protocol):
    """How a PEP reaches the policy service."""

    def start_run(self, request: RunRequest) -> Run: ...

    def revoke_run(self, run_id: str) -> Run: ...

    def decide(self, request: DecisionRequest) -> PolicyDecision: ...


def unreachable(reason: str, message: str) -> PolicyDecision:
    """A decision that could not be obtained is a denial."""
    return PolicyDecision(
        effect=Effect.DENY,
        rule_id=UNREACHABLE,
        reason=reason,
        message=message,
        mode=Mode.ENFORCE,
    )


class HttpPolicyClient:
    """The policy service over TLS. Any failure to reach it denies."""

    def __init__(
        self,
        base_url: str,
        api_token: str,
        *,
        denied_message: str,
        verify: ssl.SSLContext | bool = True,
        timeout: float = 5.0,
        transport: httpx2.BaseTransport | None = None,
    ) -> None:
        self._denied_message = denied_message
        self._client = httpx2.Client(
            base_url=base_url.rstrip("/"),
            headers={"authorization": f"Bearer {api_token}"},
            verify=verify,
            timeout=timeout,
            transport=transport,
        )

    def start_run(self, request: RunRequest) -> Run:
        return msgspec.convert(self._post("/policy/runs", request), type=Run)

    def revoke_run(self, run_id: str) -> Run:
        return msgspec.convert(self._post(f"/policy/runs/{run_id}/revoke", None), type=Run)

    def decide(self, request: DecisionRequest) -> PolicyDecision:
        try:
            payload = self._post("/policy/decide", request)
        except (httpx2.HTTPError, ValueError) as exc:
            return unreachable(f"policy service: {exc}", self._denied_message)
        try:
            return msgspec.convert(payload, type=PolicyDecision)
        except (msgspec.ValidationError, TypeError) as exc:
            return unreachable(f"unreadable decision: {exc}", self._denied_message)

    def close(self) -> None:
        self._client.close()

    def _post(self, path: str, body: msgspec.Struct | None) -> Any:
        content = msgspec.json.encode(body) if body is not None else b"{}"
        response = self._client.post(
            path, content=content, headers={"content-type": "application/json"}
        )
        response.raise_for_status()
        return response.json()


@dataclass(frozen=True, slots=True, eq=False)
class UnconfiguredPolicyClient:
    """Stands in when no policy service address is set. Every decision is a denial."""

    denied_message: str

    def start_run(self, request: RunRequest) -> Run:
        raise RuntimeError(UNCONFIGURED)

    def revoke_run(self, run_id: str) -> Run:
        raise RuntimeError(UNCONFIGURED)

    def decide(self, request: DecisionRequest) -> PolicyDecision:
        return unreachable(UNCONFIGURED, self.denied_message)


def build_policy_client(
    base_url: str,
    api_token: str,
    *,
    denied_message: str,
    ca_bundle: Path | None = None,
) -> PolicyClient:
    """The policy service when an address is configured, a denial otherwise."""
    if not base_url or not api_token:
        return UnconfiguredPolicyClient(denied_message)
    verify: ssl.SSLContext | bool = True
    if ca_bundle is not None:
        verify = ssl.create_default_context(cafile=str(ca_bundle))
    return HttpPolicyClient(base_url, api_token, denied_message=denied_message, verify=verify)
