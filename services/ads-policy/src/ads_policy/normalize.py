from __future__ import annotations

import posixpath
from urllib.parse import urlsplit

from ads_policy.config import GovernanceSettings


def within_workdir(resource: str, workdir: str) -> bool:
    candidate = resource.strip()
    if not candidate or candidate.startswith("~") or "\x00" in candidate:
        return False
    root = posixpath.normpath(workdir)
    if not candidate.startswith("/"):
        candidate = posixpath.join(root, candidate)
    resolved = posixpath.normpath(candidate)
    return resolved == root or resolved.startswith(root.rstrip("/") + "/")


def egress_host(resource: str) -> str:
    raw = resource.strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "//" + raw
    return (urlsplit(raw).hostname or "").lower()


def branch_name(resource: str, settings: GovernanceSettings | None = None) -> str:
    config = settings or GovernanceSettings()
    name = resource.strip()
    for prefix in config.ref_prefixes:
        if name.startswith(prefix):
            name = name[len(prefix) :]
    head, _, tail = name.partition("/")
    if tail and head in config.remote_names:
        name = tail
    return name.lower()
