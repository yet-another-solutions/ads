from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import msgspec

from ads_policy.contract import Binding, Capability
from ads_policy.policy import load_policy, org_policy

EXAMPLE = Path(__file__).resolve().parents[3] / "charts" / "ads" / "policy.example.yaml"
PROBE_SITES = ("probe-vm", "probe-container")


def _example() -> dict[str, Any]:
    return msgspec.yaml.decode(EXAMPLE.read_bytes(), type=dict[str, Any])


def _probe_bindings(bindings: tuple[Binding, ...]) -> tuple[Binding, ...]:
    return tuple(binding for binding in bindings if binding.source.startswith("mcp:probe-"))


def test_the_example_is_the_built_in_policy_plus_the_probe_bindings() -> None:
    example = load_policy(_example())
    built_in = org_policy()
    without_probe = replace(
        example,
        bindings=tuple(b for b in example.bindings if b not in _probe_bindings(example.bindings)),
    )
    assert without_probe.digest() == built_in.digest()


def test_every_probe_site_binds_the_same_tools() -> None:
    probe = _probe_bindings(load_policy(_example()).bindings)
    tools_by_site = {
        site: {(b.tool, b.capability) for b in probe if b.source == f"mcp:{site}"}
        for site in PROBE_SITES
    }
    assert tools_by_site["probe-vm"] == tools_by_site["probe-container"]
    assert ("run", Capability.PROCESS_EXEC) in tools_by_site["probe-vm"]


def test_the_probe_tool_meant_to_be_refused_is_not_bound() -> None:
    probe = _probe_bindings(load_policy(_example()).bindings)
    assert all(binding.tool != "unbound" for binding in probe)
