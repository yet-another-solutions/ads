"""Operator entry point. No operation is executed merely by importing this module."""

from __future__ import annotations

import argparse
import json
import logging
import os
import stat
from pathlib import Path

from coordinator import ResetCoordinator
from database import Database, Target
from preferences import PreferencesModels
from protected import MAX_BYTES, PreservationError, ProtectedStore
from workloads import Workloads

ROOT = Path(__file__).resolve().parents[2]


def private_json(path: Path):
    resolved = path.absolute()
    if resolved != resolved.resolve() or resolved.is_relative_to(ROOT):
        raise PreservationError("import input must be a protected external file")
    fd = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        meta = os.fstat(fd)
        if (
            not stat.S_ISREG(meta.st_mode)
            or meta.st_uid != os.geteuid()
            or stat.S_IMODE(meta.st_mode) != 0o600
            or meta.st_nlink != 1
            or not 0 < meta.st_size <= MAX_BYTES
        ):
            raise PreservationError("import input requires a bounded private owned file")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            return json.load(stream)
    finally:
        os.close(fd)


def initialize(directory: Path):
    resolved = directory.absolute()
    if resolved != resolved.resolve() or resolved.is_relative_to(ROOT):
        raise PreservationError("recovery destination must be external")
    resolved.mkdir(mode=0o700, parents=False, exist_ok=False)
    fd = os.open(resolved / "key", os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, os.urandom(32))
        os.fsync(fd)
    finally:
        os.close(fd)
    directory_fd = os.open(resolved, os.O_DIRECTORY | os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("initialize-store")
    imp = commands.add_parser("import")
    imp.add_argument("--record", choices=("configuration", "owner-auth"), required=True)
    imp.add_argument("--input", type=Path, required=True)
    run = commands.add_parser("run")
    run.add_argument("--new-cycle", action="store_true")
    commands.add_parser("status")
    args = parser.parse_args()
    logging.disable(logging.CRITICAL)  # Never let SDK debug logs expose backups or bearer values.
    if args.command == "initialize-store":
        initialize(args.directory)
        return {"initialized": True}
    store = ProtectedStore(args.directory, source_root=ROOT)
    databases, workloads, api = [], None, None
    try:
        if args.command == "import":
            with store.lock():
                store.write(args.record, private_json(args.input))
            return {"imported": args.record}
        if args.command == "status":
            with store.lock():
                return ResetCoordinator.evidence(store.read("checkpoint"))
        configured = store.read("configuration")
        if set(configured) != {"targets", "namespace", "context", "workloads", "ca_bundle"}:
            raise PreservationError("explicit reset configuration required")
        databases = [Database(Target(**target), ROOT) for target in configured["targets"]]
        if len({db.target.database for db in databases}) != len(databases):
            raise PreservationError("duplicate database reset targets")
        workloads = Workloads(
            configured["namespace"],
            configured["context"],
            configured["workloads"],
        )
        api = PreferencesModels(store, configured["ca_bundle"])
        return ResetCoordinator(store, databases, workloads, api).run(new_cycle=args.new_cycle)
    finally:
        if api is not None:
            api.close()
        if workloads is not None:
            workloads.close()
        for db in databases:
            db.close()
        store.close()


if __name__ == "__main__":
    try:
        print(json.dumps(main(), sort_keys=True))
    except (Exception, KeyboardInterrupt) as exc:
        # Exception text/tracebacks may contain SQL, HTTP or input data. The
        # encrypted checkpoint retains progress; resumption is never automatic.
        print(
            json.dumps(
                {
                    "ok": False,
                    "blocked": True,
                    "details_withheld": True,
                    "reason": str(exc)
                    if isinstance(exc, PreservationError)
                    else "reset operation interrupted",
                }
            )
        )
        raise SystemExit(1) from None
