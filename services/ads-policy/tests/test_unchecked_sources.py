from __future__ import annotations

from dataclasses import replace

import msgspec
import pytest

from ads_policy.audit import CollectingAuditSink
from ads_policy.contract import (
    Capability,
    Effect,
    InterceptionPoint,
    IsolationLevel,
    Policy,
    SourceChecks,
    Switch,
    ToolCallRequest,
)
from ads_policy.policy import compose, load_policy, org_policy
from ads_policy.service import PolicyService
from policy_helpers import run_request

UNCHECKED = "mcp:jira"
CHAT = "3f2b6c1e-0000-4000-8000-000000000001"


@pytest.fixture
def policy() -> Policy:
    return replace(org_policy(), unchecked_sources=frozenset({UNCHECKED, "mcp:sandbox"}))


def _call(run_id: str, source: str, tool: str, **arguments: str) -> ToolCallRequest:
    return ToolCallRequest(
        run_id=run_id, subject="alice", source=source, tool=tool, arguments=dict(arguments)
    )


def test_a_source_whose_checks_are_off_is_unchecked() -> None:
    loaded = load_policy(
        {"sources": {UNCHECKED: {"checks": "off"}, "mcp:git": {"checks": "enforce"}}}
    )
    assert loaded.is_unchecked(UNCHECKED)
    assert not loaded.is_unchecked("mcp:git")
    assert not loaded.is_unchecked("mcp:other")


def test_a_bare_yaml_off_reads_as_off() -> None:
    document = msgspec.yaml.decode(b"sources:\n  mcp:jira: {checks: off}\n", type=dict[str, object])
    assert load_policy(document).is_unchecked(UNCHECKED)


def test_checks_are_either_enforced_or_off() -> None:
    with pytest.raises(ValueError, match="enforce or off"):
        load_policy({"sources": {UNCHECKED: {"checks": "review"}}})


def test_an_unchecked_source_is_listed_even_without_bindings() -> None:
    loaded = load_policy({"sources": {UNCHECKED: {"checks": "off"}}})
    assert SourceChecks(UNCHECKED, Switch.OFF) in loaded.source_checks()
    assert SourceChecks("mcp:sandbox", Switch.ENFORCE) in loaded.source_checks()


def test_a_document_without_sources_checks_everything() -> None:
    assert load_policy({}).unchecked_sources == frozenset()


def test_switching_a_source_off_is_a_new_policy() -> None:
    assert load_policy({"sources": {UNCHECKED: {"checks": "off"}}}).digest() != (
        load_policy({}).digest()
    )


def test_a_developer_policy_cannot_change_which_sources_are_unchecked() -> None:
    org = load_policy({"sources": {UNCHECKED: {"checks": "off"}}})
    dev = load_policy({"sources": {"mcp:git": {"checks": "off"}}})
    assert compose(org, dev).unchecked_sources == frozenset({UNCHECKED})


@pytest.mark.anyio
async def test_an_unbound_tool_of_an_unchecked_source_is_allowed_and_journalled(
    service: PolicyService, journal: CollectingAuditSink
) -> None:
    run = await service.start(run_request(IsolationLevel.VM))
    decision = await service.decide_call(_call(run.id, UNCHECKED, "create_issue", title="x"))
    assert decision.effect is Effect.ALLOW
    assert decision.rule_id == "source.unchecked"
    assert decision.weight == 0
    for side in (InterceptionPoint.REQUEST, InterceptionPoint.RESPONSE):
        assert decision.interception.side(side).on is Switch.OFF
    await service.flush_audit()
    [event] = journal.events()
    assert event.effect is Effect.ALLOW
    assert event.rule_id == "source.unchecked"
    assert event.weight == 0
    assert event.capability is None
    assert event.resource == f"{UNCHECKED}/create_issue"
    assert (event.source, event.tool) == (UNCHECKED, "create_issue")


@pytest.mark.anyio
async def test_a_bound_tool_of_an_unchecked_source_is_journalled_with_what_it_does(
    service: PolicyService, journal: CollectingAuditSink
) -> None:
    run = await service.start(run_request(IsolationLevel.LOCAL))
    decision = await service.decide_call(_call(run.id, "mcp:sandbox", "exec_shell", command="ls"))
    assert decision.effect is Effect.ALLOW
    assert (decision.capability, decision.resource) == (Capability.PROCESS_EXEC, "ls")
    await service.flush_audit()
    [event] = journal.events()
    assert (event.capability, event.resource) == (Capability.PROCESS_EXEC, "ls")
    assert (event.source, event.tool) == ("mcp:sandbox", "exec_shell")


@pytest.mark.anyio
async def test_a_blocked_conversation_is_refused_even_on_an_unchecked_source(
    service: PolicyService,
) -> None:
    run = await service.start(
        msgspec.structs.replace(run_request(IsolationLevel.VM), conversation=CHAT)
    )
    await service.block_conversation(CHAT, budget=31, by="ads-audit")
    decision = await service.decide_call(_call(run.id, UNCHECKED, "create_issue"))
    assert decision.effect is Effect.DENY
    assert decision.rule_id == "conversation.revoked"


@pytest.mark.anyio
async def test_a_revoked_run_is_refused_even_on_an_unchecked_source(
    service: PolicyService,
) -> None:
    run = await service.start(run_request(IsolationLevel.VM))
    await service.revoke(run.id)
    decision = await service.decide_call(_call(run.id, UNCHECKED, "create_issue"))
    assert decision.rule_id == "run.state"


@pytest.mark.anyio
async def test_someone_elses_run_is_refused_even_on_an_unchecked_source(
    service: PolicyService,
) -> None:
    run = await service.start(run_request(IsolationLevel.VM, subject="bob"))
    decision = await service.decide_call(_call(run.id, UNCHECKED, "create_issue"))
    assert decision.rule_id == "run.subject"


@pytest.mark.anyio
async def test_a_checked_source_journals_where_the_call_went(
    service: PolicyService, journal: CollectingAuditSink
) -> None:
    run = await service.start(run_request(IsolationLevel.LOCAL))
    await service.decide_call(_call(run.id, "opencode", "read", filePath="/workspace/README.md"))
    await service.flush_audit()
    [event] = journal.events()
    assert (event.source, event.tool) == ("opencode", "read")
