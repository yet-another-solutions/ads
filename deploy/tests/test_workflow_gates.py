"""Publishing must allow the same complete Python gate as pull-request CI."""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def test_publish_python_gate_matches_ci_budget_and_sessions():
    jobs = []
    for name in ("ci", "publish"):
        workflow = yaml.safe_load((ROOT / ".github/workflows" / f"{name}.yml").read_text())
        jobs.append(workflow["jobs"]["python"])
    ci, publish = jobs
    assert publish["timeout-minutes"] == ci["timeout-minutes"] == 60
    for job in jobs:
        nox = next(step for step in job["steps"] if step.get("name") == "Nox")
        assert "uv run --group dev nox -s lint deps typecheck test package" in nox["run"]
