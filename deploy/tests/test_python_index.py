"""Keep workspace dependency resolution independent of the test lab."""

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_workspace_uses_one_public_default_index():
    config = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert config["tool"]["uv"]["index"] == [
        {"name": "pypi", "url": "https://pypi.org/simple", "default": True}
    ]
    assert all("index" not in source for source in config["tool"]["uv"]["sources"].values())


def test_build_entry_points_inherit_the_workspace_index():
    paths = [
        ROOT / "noxfile.py",
        ROOT / "README.md",
        *sorted((ROOT / ".github/workflows").glob("*.yml")),
        *sorted((ROOT / "services").glob("*/Containerfile*")),
    ]
    for path in paths:
        text = path.read_text()
        # Helm render assertions may contain inert lab URLs; package proxies may not.
        assert ".interlab/repository/" not in text, path
        assert "UV_DEFAULT_INDEX" not in text, path
        assert "UV_INDEX_URL" not in text, path
