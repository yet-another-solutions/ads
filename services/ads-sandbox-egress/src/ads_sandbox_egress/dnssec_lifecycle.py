"""Durable zone overlap plans; never a resolver cache or an upstream trust source."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass

import dns.name

from ads_sandbox_egress.dnssec_identity import DNSSECIdentities, SigningIdentity
from ads_sandbox_egress.identity_store import StateUnavailable


@dataclass(frozen=True)
class ZonePlan:
    prefix: str
    previous: str | None
    current: tuple[str, ...]
    retiring: dict[str, float]
    overlap: tuple[SigningIdentity, ...]
    now: float


class DNSSECLifecycle:
    def __init__(self, identities: DNSSECIdentities) -> None:
        self.identities, self.store = identities, identities.store

    def plan(
        self, zone: dns.name.Name, current: tuple[SigningIdentity, ...], *, now: float
    ) -> ZonePlan:
        if not math.isfinite(now) or now <= 0 or not current:
            raise ValueError("bounded zone lifecycle input required")
        wire = zone.canonicalize().to_wire()
        assert wire is not None
        prefix = "dns-zone/" + hashlib.sha256(wire).hexdigest() + "/"
        names = tuple(sorted(identity.name for identity in current))
        head = self.store.publication_head(prefix)
        old: dict[str, float] = {}
        if head is not None:
            try:
                data = json.loads(head[1])
                if set(data) != {"current", "retiring", "clock"} or now < data["clock"]:
                    raise ValueError("lifecycle clock rollback")
                old = dict(data["retiring"])
                old = {
                    name: end
                    for name, end in old.items()
                    if self.store.key_stage(name) != "retired"
                }
                for name in data["current"]:
                    if name not in names and name not in old:
                        # Freeze overlap at the last PRE-transition dependency,
                        # never extend it on each response signed by an old key.
                        old[name] = max(now, self.store.dependency_horizon(name))
                old = {name: end for name, end in old.items() if name not in names}
                if any(not math.isfinite(end) or end <= 0 for end in old.values()):
                    raise ValueError("invalid lifecycle interval")
            except (ValueError, TypeError, KeyError):
                raise StateUnavailable("invalid DNSSEC lifecycle journal") from None
        if len(names) + len(old) > 64:
            raise StateUnavailable("DNSSEC zone overlap capacity")
        overlap = tuple(
            self.identities.recover(name) for name, end in sorted(old.items()) if end >= now
        )
        if any(identity.zone != zone for identity in (*current, *overlap)):
            raise StateUnavailable("DNSSEC overlap crossed zone boundary")
        return ZonePlan(prefix, head[0] if head else None, names, old, overlap, now)

    def commit(self, plan: ZonePlan) -> None:
        head = self.store.publication_head(plan.prefix)
        if (head[0] if head else None) != plan.previous:
            raise StateUnavailable("DNSSEC zone changed before publication")
        retained = dict(plan.retiring)
        for name, end in tuple(retained.items()):
            if end < plan.now and self.store.dependency_horizon(name) < plan.now:
                # Commit the removal before erasing its private key. A crash
                # leaves an unused key, not an unrecoverable journal dependency.
                del retained[name]
        content = json.dumps(
            dict(current=plan.current, retiring=retained, clock=plan.now),
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        dependencies = (*plan.current, *(i.name for i in plan.overlap))
        generation = int(plan.previous.rsplit("/", 1)[1]) + 1 if plan.previous else 1
        self.store.commit_publication(
            plan.prefix + f"{generation:020d}", content, dependencies, plan.now + 1
        )
        for name in plan.retiring:
            stage = self.store.key_stage(name)
            if stage == "active":
                self.store.advance(name, "active", "retiring")
            if name not in retained:
                self.store.retire(name, now=plan.now)
        self.store.prune_publications(plan.prefix, now=plan.now)

    def collect(self, *, now: float) -> None:
        if not math.isfinite(now) or now <= 0:
            raise ValueError("bounded lifecycle clock required")
        for name in self.store.key_names("dnssec"):
            head = self.store.publication_head("dns-zone/" + name.split("/")[1] + "/")
            if head is None:
                continue
            data = json.loads(head[1])
            if name in data["current"] or data["retiring"].get(name, now) >= now:
                continue
            if (
                self.store.key_stage(name) == "retiring"
                and self.store.dependency_horizon(name) < now
            ):
                self.store.retire(name, now=now)
        self.store.prune_publications("dns-generation/", now=now)
