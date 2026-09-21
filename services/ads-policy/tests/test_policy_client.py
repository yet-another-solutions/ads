from __future__ import annotations

import httpx2
import msgspec
import pytest

from ads_policy.client import HttpPolicyClient, PolicyUnavailable, build_policy_client
from ads_policy.config import DENIED_MESSAGE, ResourceNaming
from ads_policy.contract import (
    Capability,
    DecisionRequest,
    Effect,
    IsolationLevel,
    Mode,
    PolicyDecision,
    Run,
    RunContext,
    SourceChecks,
    Switch,
)
from policy_helpers import run_request

SETTINGS = ResourceNaming()
TOKEN = "policy-api-token-32-bytes-long"
URL = "https://ads-policy.interlab:8081"
REQUEST = DecisionRequest(
    run_id="run-1",
    subject="alice",
    capability=Capability.FS_READ,
    resource=f"{SETTINGS.workdir}/src/app.py",
)


def _client(handler: object) -> HttpPolicyClient:
    return HttpPolicyClient(
        URL,
        TOKEN,
        denied_message=DENIED_MESSAGE,
        transport=httpx2.MockTransport(handler),  # type: ignore[arg-type]
    )


def _json(payload: object, status: int = 200) -> httpx2.Response:
    return httpx2.Response(status, content=msgspec.json.encode(payload))


def test_the_sources_come_back_with_their_checks() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        assert request.url.path == "/policy/sources"
        return _json([{"source": "mcp:jira", "checks": "off"}])

    assert _client(handler).sources() == [SourceChecks("mcp:jira", Switch.OFF)]


def test_unreadable_sources_mean_the_policy_service_is_unavailable() -> None:
    with pytest.raises(PolicyUnavailable):
        _client(lambda request: _json({"not": "a list"})).sources()


def test_a_decision_round_trips() -> None:
    seen: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(request)
        return _json(
            PolicyDecision(
                effect=Effect.ALLOW,
                rule_id="fs.read.workdir",
                reason="fs.read in workdir",
                policy_hash="deadbeef",
            )
        )

    decision = _client(handler).decide(REQUEST)
    assert decision.effect is Effect.ALLOW
    assert decision.permitted
    assert decision.policy_hash == "deadbeef"
    assert seen[0].url.path == "/policy/decide"
    assert seen[0].headers["authorization"] == f"Bearer {TOKEN}"
    assert msgspec.json.decode(seen[0].content)["run_id"] == "run-1"


def test_a_review_mode_decision_keeps_its_mode() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        del request
        return _json(
            PolicyDecision(
                effect=Effect.DENY,
                rule_id="secret.read",
                reason="denied",
                mode=Mode.REVIEW,
            )
        )

    decision = _client(handler).decide(REQUEST)
    assert decision.effect is Effect.DENY
    assert decision.permitted
    assert not decision.enforced


def test_an_unreachable_service_denies() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        raise httpx2.ConnectError("no route to host", request=request)

    decision = _client(handler).decide(REQUEST)
    assert decision.effect is Effect.DENY
    assert decision.enforced
    assert decision.rule_id == "policy.unreachable"
    assert decision.message == DENIED_MESSAGE


def test_a_failing_service_denies() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        del request
        return httpx2.Response(500, content=b"boom")

    assert _client(handler).decide(REQUEST).rule_id == "policy.unreachable"


def test_an_unreadable_answer_denies() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        del request
        return _json({"effect": "maybe"})

    assert _client(handler).decide(REQUEST).rule_id == "policy.unreachable"


def test_a_run_round_trips() -> None:
    run = Run(
        id="run-1",
        subject="alice",
        context=RunContext(project="ads", repo="ads", env="dev", workdir=SETTINGS.workdir),
        isolation_level=IsolationLevel.VM,
        policy_hash="deadbeef",
    )

    def handler(request: httpx2.Request) -> httpx2.Response:
        del request
        return _json(run)

    client = _client(handler)
    assert client.start_run(run_request(IsolationLevel.VM)) == run
    assert client.revoke_run("run-1") == run
    client.close()


def test_no_configured_address_denies() -> None:
    client = build_policy_client("", "", denied_message=DENIED_MESSAGE)
    decision = client.decide(REQUEST)
    assert decision.effect is Effect.DENY
    assert decision.enforced
    assert decision.message == DENIED_MESSAGE
    with pytest.raises(RuntimeError, match="not configured"):
        client.start_run(run_request(IsolationLevel.VM))


def test_a_configured_address_is_reached_over_https() -> None:
    client = build_policy_client(URL, TOKEN, denied_message=DENIED_MESSAGE)
    assert isinstance(client, HttpPolicyClient)
