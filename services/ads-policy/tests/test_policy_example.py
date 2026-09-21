from __future__ import annotations

from pathlib import Path
from typing import Any

import msgspec

from ads_policy.policy import load_policy, org_policy

EXAMPLE = Path(__file__).resolve().parents[3] / "charts" / "ads" / "policy.example.yaml"


def _example() -> dict[str, Any]:
    return msgspec.yaml.decode(EXAMPLE.read_bytes(), type=dict[str, Any])


def test_the_example_is_the_built_in_policy() -> None:
    assert load_policy(_example()).digest() == org_policy().digest()
