from __future__ import annotations

import ast
from pathlib import Path


def test_preferences_src_does_not_import_ads_or_ads_engine() -> None:
    root = Path(__file__).resolve().parents[1] / "src"
    forbidden = ("ads_engine", "ads.")
    for path in root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name != "ads"
                    assert alias.name != "ads_engine"
                    assert not alias.name.startswith("ads.")
                    assert not alias.name.startswith("ads_engine.")
            elif isinstance(node, ast.ImportFrom) and node.module:
                module = node.module
                assert module != "ads"
                assert module != "ads_engine"
                assert not module.startswith("ads.")
                assert not module.startswith("ads_engine.")
    del forbidden
