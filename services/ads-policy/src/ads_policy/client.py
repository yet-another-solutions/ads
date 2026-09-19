from __future__ import annotations

import ssl
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import quote

import httpx2
import msgspec

from ads_policy.contract import (
    ConversationBlockRequest,
    DecisionRequest,
    Effect,
    Mode,
    PolicyDecision,
    PromptRequest,
    Run,
    RunRequest,
    ToolCallRequest,
)

UNREACHABLE = "policy.unreachable"
UNCONFIGURED = "policy service is not configured"


class PolicyUnavailable(ConnectionError):
    pass


class PolicyClient(Protocol):
    def start_run(self, request: RunRequest) -> Run: ...

    def run(self, run_id: str) -> Run | None: ...

    def runs_held(self, holder: str) -> list[Run]: ...

    def revoke_run(self, run_id: str) -> Run: ...

    def finish_run(self, run_id: str) -> Run | None: ...

    def decide(self, request: DecisionRequest) -> PolicyDecision: ...

    def decide_call(self, call: ToolCallRequest) -> PolicyDecision: ...

    def decide_prompt(self, prompt: PromptRequest) -> PolicyDecision: ...


def unreachable(reason: str, message: str) -> PolicyDecision:
    return PolicyDecision(
        effect=Effect.DENY,
        rule_id=UNREACHABLE,
        reason=reason,
        message=message,
        mode=Mode.ENFORCE,
    )


class HttpPolicyClient:
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

    def run(self, run_id: str) -> Run | None:
        return self._run_or_none_if_unknown("GET", f"/policy/runs/{run_id}")

    def runs_held(self, holder: str) -> list[Run]:
        try:
            response = self._client.get("/policy/runs", params={"holder": holder})
            response.raise_for_status()
            return msgspec.convert(response.json(), type=list[Run])
        except (httpx2.HTTPError, ValueError, msgspec.ValidationError) as exc:
            raise PolicyUnavailable(f"policy service: {exc}") from exc

    def revoke_run(self, run_id: str) -> Run:
        return msgspec.convert(self._post(f"/policy/runs/{run_id}/revoke", None), type=Run)

    def finish_run(self, run_id: str) -> Run | None:
        return self._run_or_none_if_unknown("POST", f"/policy/runs/{run_id}/finish")

    def block_conversation(self, conversation: str, budget: int, by: str) -> None:
        try:
            response = self._client.post(
                f"/policy/conversations/{quote(conversation, safe='')}/revoke",
                content=msgspec.json.encode(ConversationBlockRequest(budget=budget, by=by)),
                headers={"content-type": "application/json"},
            )
            response.raise_for_status()
        except httpx2.HTTPError as exc:
            raise PolicyUnavailable(f"policy service: {exc}") from exc

    def lift_conversation_block(self, conversation: str) -> None:
        try:
            response = self._client.delete(
                f"/policy/conversations/{quote(conversation, safe='')}/revoke"
            )
            response.raise_for_status()
        except httpx2.HTTPError as exc:
            raise PolicyUnavailable(f"policy service: {exc}") from exc

    def _run_or_none_if_unknown(self, method: str, path: str) -> Run | None:
        try:
            response = self._client.request(
                method,
                path,
                content=b"{}" if method == "POST" else None,
                headers={"content-type": "application/json"},
            )
            if response.status_code == 404:
                return None
            response.raise_for_status()
            return msgspec.convert(response.json(), type=Run)
        except (httpx2.HTTPError, ValueError, msgspec.ValidationError) as exc:
            raise PolicyUnavailable(f"policy service: {exc}") from exc

    def decide(self, request: DecisionRequest) -> PolicyDecision:
        return self._ask("/policy/decide", request)

    def decide_call(self, call: ToolCallRequest) -> PolicyDecision:
        return self._ask("/policy/calls", call)

    def decide_prompt(self, prompt: PromptRequest) -> PolicyDecision:
        return self._ask("/policy/prompts", prompt)

    def _ask(self, path: str, body: msgspec.Struct) -> PolicyDecision:
        try:
            payload = self._post(path, body)
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
    denied_message: str

    def start_run(self, request: RunRequest) -> Run:
        raise RuntimeError(UNCONFIGURED)

    def run(self, run_id: str) -> Run | None:
        raise PolicyUnavailable(UNCONFIGURED)

    def runs_held(self, holder: str) -> list[Run]:
        raise PolicyUnavailable(UNCONFIGURED)

    def revoke_run(self, run_id: str) -> Run:
        raise RuntimeError(UNCONFIGURED)

    def finish_run(self, run_id: str) -> Run | None:
        raise PolicyUnavailable(UNCONFIGURED)

    def decide(self, request: DecisionRequest) -> PolicyDecision:
        return unreachable(UNCONFIGURED, self.denied_message)

    def decide_call(self, call: ToolCallRequest) -> PolicyDecision:
        return unreachable(UNCONFIGURED, self.denied_message)

    def decide_prompt(self, prompt: PromptRequest) -> PolicyDecision:
        return unreachable(UNCONFIGURED, self.denied_message)


def build_policy_client(
    base_url: str,
    api_token: str,
    *,
    denied_message: str,
    ca_bundle: Path | None = None,
) -> PolicyClient:
    if not base_url or not api_token:
        return UnconfiguredPolicyClient(denied_message)
    verify: ssl.SSLContext | bool = True
    if ca_bundle is not None:
        verify = ssl.create_default_context(cafile=str(ca_bundle))
    return HttpPolicyClient(base_url, api_token, denied_message=denied_message, verify=verify)
