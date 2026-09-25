from __future__ import annotations

import json
import stat
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parents[2]
CLI = ROOT / "deploy" / "reset" / "cli.py"


def run(directory, *args):
    return subprocess.run(
        [sys.executable, str(CLI), "--directory", str(directory), *args],
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )


def test_cli_import_encrypts_external_inputs_without_echoing_secrets(tmp_path):
    directory = tmp_path / "private"
    initialized = run(directory, "initialize-store")
    assert initialized.returncode == 0 and json.loads(initialized.stdout) == {"initialized": True}
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert stat.S_IMODE((directory / "key").stat().st_mode) == 0o600
    value = tmp_path / "input.json"
    value.write_text(json.dumps({"not-a-valid-config": "synthetic-secret-never-output"}))
    value.chmod(0o600)
    imported = run(directory, "import", "--record", "configuration", "--input", str(value))
    assert imported.returncode == 0
    assert b"synthetic-secret-never-output" not in (directory / "configuration").read_bytes()
    blocked = run(directory, "run")
    assert blocked.returncode == 1 and json.loads(blocked.stdout)["blocked"]
    assert (
        "synthetic-secret-never-output"
        not in imported.stdout + imported.stderr + blocked.stdout + blocked.stderr
    )
    assert not (directory / "checkpoint").exists()
    assert run(directory, "initialize-store").returncode == 1  # Never rotate the existing key.


def test_cli_rejects_unprotected_plaintext_input_before_import(tmp_path):
    directory = tmp_path / "private"
    assert run(directory, "initialize-store").returncode == 0
    value = tmp_path / "unsafe.json"
    value.write_text('{"token":"synthetic-private"}')
    value.chmod(0o644)
    rejected = run(directory, "import", "--record", "owner-auth", "--input", str(value))
    assert rejected.returncode == 1
    assert "synthetic-private" not in rejected.stdout + rejected.stderr
    assert not (directory / "owner-auth").exists()
