from __future__ import annotations

from typing import Any

import pytest

from ads_policy.contract import Capability, Policy, ToolCallRequest
from ads_policy.pdp import Unbound, resolve
from ads_policy.policy import load_policy, org_policy


def _call(
    tool: str, arguments: dict[str, Any] | None = None, source: str = "opencode"
) -> ToolCallRequest:
    return ToolCallRequest(
        run_id="run-1",
        subject="alice",
        source=source,
        tool=tool,
        arguments=arguments or {},
    )


@pytest.mark.parametrize(
    ("tool", "arguments", "capability", "resource"),
    [
        ("bash", {"command": "uv sync"}, Capability.PROCESS_EXEC, "uv sync"),
        ("read", {"filePath": "/workspace/app.py"}, Capability.FS_READ, "/workspace/app.py"),
        ("write", {"filePath": "/workspace/app.py"}, Capability.FS_WRITE, "/workspace/app.py"),
        (
            "webfetch",
            {"url": "https://mirror.interlab/x"},
            Capability.NET_EGRESS,
            "https://mirror.interlab/x",
        ),
    ],
)
def test_a_bound_tool_resolves_to_what_it_amounts_to(
    tool: str, arguments: dict[str, str], capability: Capability, resource: str
) -> None:
    assert resolve(_call(tool, arguments), org_policy()) == (capability, resource)


def test_an_argument_that_is_not_a_string_becomes_one() -> None:
    capability, resource = resolve(_call("bash", {"command": ["uv", "sync"]}), org_policy())
    assert capability is Capability.PROCESS_EXEC
    assert resource == '["uv","sync"]'


def test_a_nested_argument_arrives_whole_rather_than_flattened_on_the_way_in() -> None:
    call = _call("read", {"filePath": {"path": "/workspace/app.py"}})
    assert call.arguments["filePath"] == {"path": "/workspace/app.py"}
    _, resource = resolve(call, org_policy())
    assert resource == '{"path":"/workspace/app.py"}'


def test_a_search_resolves_to_the_provider_not_the_query() -> None:
    capability, resource = resolve(_call("websearch", {"query": "litestar guards"}), org_policy())
    assert capability is Capability.NET_EGRESS
    assert resource == "search-proxy.interlab"


def test_an_unbound_tool_does_not_resolve() -> None:
    with pytest.raises(Unbound) as raised:
        resolve(_call("telepathy", {"thought": "x"}), org_policy())
    assert raised.value.rule_id == "binding.missing"


def test_a_tool_from_another_source_does_not_resolve() -> None:
    with pytest.raises(Unbound) as raised:
        resolve(_call("read", {"filePath": "/x"}, source="mcp:jira"), org_policy())
    assert raised.value.rule_id == "binding.missing"


def test_a_call_without_the_argument_it_acts_on_does_not_resolve() -> None:
    with pytest.raises(Unbound) as raised:
        resolve(_call("read", {"somethingElse": "/x"}), org_policy())
    assert raised.value.rule_id == "binding.resource"


def test_an_empty_argument_is_no_argument() -> None:
    with pytest.raises(Unbound):
        resolve(_call("read", {"filePath": ""}), org_policy())


def test_a_document_binds_a_tool_of_its_own() -> None:
    policy = load_policy(
        {
            "bindings": [
                {
                    "source": "mcp:jira",
                    "tool": "create_issue",
                    "capability": "net.egress",
                    "value": "jira.interlab",
                }
            ],
            "rules": [],
        }
    )
    assert resolve(_call("create_issue", source="mcp:jira"), policy) == (
        Capability.NET_EGRESS,
        "jira.interlab",
    )


def test_a_document_that_declares_bindings_replaces_the_built_in_ones() -> None:
    policy = load_policy({"bindings": [], "rules": []})
    with pytest.raises(Unbound):
        resolve(_call("bash", {"command": "uv sync"}), policy)


def test_one_tool_cannot_be_bound_twice() -> None:
    twice = {"source": "opencode", "tool": "read", "capability": "fs.read", "argument": "filePath"}
    with pytest.raises(ValueError, match="two different things"):
        load_policy({"bindings": [twice, {**twice, "capability": "fs.write"}], "rules": []})


def test_one_row_of_the_matrix_cannot_be_written_twice() -> None:
    row = {"id": "process.exec", "capability": "process.exec", "resourceClass": "any"}
    with pytest.raises(ValueError, match="two different things"):
        load_policy({"rules": [row, {**row, "id": "process.exec.again", "levels": ["vm"]}]})


def test_a_binding_needs_exactly_one_source_of_the_resource() -> None:
    for binding in (
        {"source": "opencode", "tool": "read", "capability": "fs.read"},
        {
            "source": "opencode",
            "tool": "read",
            "capability": "fs.read",
            "argument": "filePath",
            "value": "/fixed",
        },
    ):
        with pytest.raises(ValueError, match="exactly one of argument or value"):
            load_policy({"bindings": [binding], "rules": []})


def test_an_unreadable_binding_is_refused_at_load() -> None:
    with pytest.raises(ValueError, match="unreadable binding"):
        load_policy(
            {
                "bindings": [
                    {"source": "opencode", "tool": "x", "capability": "telepathy", "value": "y"}
                ]
            }
        )


def test_the_hash_follows_the_bindings(policy: Policy) -> None:
    rebound = load_policy(
        {
            "bindings": [
                {
                    "source": "opencode",
                    "tool": "bash",
                    "capability": "fs.read",
                    "argument": "command",
                }
            ],
            "rules": [],
        }
    )
    assert rebound.digest() != policy.digest()
