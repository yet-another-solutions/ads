"""Stream named canonical secret files to an SSH command, never into argv/logs."""

import argparse
import json
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--credentials", type=Path, required=True)
    parser.add_argument("--names", nargs="+", required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if any(Path(name).name != name or name in (".", "..") for name in args.names):
        parser.error("Credential names must be plain filenames without the .md suffix")
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("An SSH command after -- is required")
    payload = {
        name: (args.credentials / (name + ".md")).read_text().strip() for name in args.names
    }
    return subprocess.run(command, input=json.dumps(payload).encode()).returncode


if __name__ == "__main__":
    raise SystemExit(main())
