"""Sandbox-scoped ECH publication and retirement, independent of DNSSEC trust.

No origin ECH is forwarded. The DNS view owner rewrites only inspected records,
checks the complete synthetic DNSSEC outcome, and commits its generation with
the returned key dependency before serving it. A live context is installed
before this owner exposes any configuration. Existing TLS sessions own their
old context; rotation does not terminate authorized traffic.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass

import dns.rdtypes.svcbbase
import dns.rrset

from ads_sandbox_egress.identity_store import IdentityStore, StateUnavailable
from ads_sandbox_egress.policy import canonical_host
from ads_sandbox_egress.tls import ECHKey, TLSContext, TLSLibrary

_PREFIX = "ech-head/"


@dataclass(frozen=True, slots=True)
class ECHPublication:
    records: dns.rrset.RRset
    dependency: str | None
    retain_until: float


class ECHLifecycle:
    def __init__(
        self,
        store: IdentityStore,
        library: TLSLibrary,
        *,
        public_name: str,
        handshake_window: float,
        now: float,
        initialize: bool = False,
    ) -> None:
        if not math.isfinite(handshake_window) or not 0 < handshake_window <= 300:
            raise ValueError("explicit bounded ECH handshake window required")
        self.store, self.library = store, library
        self.public_name = canonical_host(public_name)
        self.handshake_window = handshake_window
        self._context: TLSContext | None = None
        self._generation = 0
        self._current = ""
        self._names: tuple[str, ...] = ()
        self._clock = 0.0
        self._time(now)
        head = store.publication_head(_PREFIX)
        if initialize:
            if head is not None or store.key_names("ech"):
                raise StateUnavailable("ECH initialization over retained publication")
            self.rotate(now=now)
        else:
            if head is None:
                raise StateUnavailable("required ECH publication missing")
            self._recover(head, now=now)

    def _time(self, now: float) -> None:
        if not math.isfinite(now) or now <= 0 or now < self._clock:
            raise StateUnavailable("ECH publication clock moved backwards")
        self._clock = now

    def _recover(self, head: tuple[str, bytes, float], *, now: float) -> None:
        try:
            value = json.loads(head[1])
            if (
                set(value) != {"generation", "public_name", "current", "names", "created_at"}
                or type(value["generation"]) is not int
                or not 1 <= value["generation"] <= 2**63 - 1
                or head[0] != _PREFIX + f"{value['generation']:020d}"
                or value["public_name"] != self.public_name
                or not isinstance(value["names"], list)
                or not 1 <= len(value["names"]) <= 64
                or any(not isinstance(name, str) for name in value["names"])
                or len(set(value["names"])) != len(value["names"])
                or value["current"] not in value["names"]
                or not math.isfinite(value["created_at"])
                or not 0 < value["created_at"] <= now
            ):
                raise StateUnavailable("ECH retained publication mismatch")
            names = tuple(value["names"])
            keys = tuple(ECHKey.recover(self.store, name) for name in names)
            if len({key.config_id for key in keys}) != len(keys):
                raise StateUnavailable("ambiguous retained ECH configuration IDs")
            context = TLSContext(self.library, keys)
        except StateUnavailable:
            raise
        except Exception:
            raise StateUnavailable("invalid retained ECH publication") from None
        self._context = context
        self._generation = value["generation"]
        self._names, self._current = names, value["current"]
        # A crash after durable publication but before these stage advances
        # cannot regenerate a key or lose its previously published config.
        try:
            for name in names:
                stage = self.store.key(name)[3]
                if stage == "published":
                    self.store.advance(name, stage, "active")
                if name != self._current and self.store.key(name)[3] == "active":
                    self.store.advance(name, "active", "retiring")
        except BaseException:
            self.close()
            raise

    @property
    def context(self) -> TLSContext:
        if self._context is None:
            raise StateUnavailable("ECH context unavailable")
        return self._context

    @property
    def configuration(self) -> bytes:
        _ = self.context  # Retained key without installed support is not publishable.
        return ECHKey.recover(self.store, self._current).configuration

    def _commit_head(
        self, names: tuple[str, ...], current: str, *, now: float, context: TLSContext
    ) -> None:
        generation = self._generation + 1
        if generation > 2**63 - 1:
            raise StateUnavailable("ECH journal exhausted")
        content = json.dumps(
            dict(
                generation=generation,
                public_name=self.public_name,
                current=current,
                names=names,
                created_at=now,
            ),
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        self.store.commit_publication(
            _PREFIX + f"{generation:020d}", content, names, now + self.handshake_window
        )
        previous = self._context
        self._context = context
        self._generation, self._names, self._current = generation, names, current
        if previous is not None:
            previous.close()

    def rotate(self, *, now: float) -> None:
        """Explicit rotation, never an automatic missing-state recovery path."""
        self._time(now)
        if len(self._names) >= 64:
            raise StateUnavailable("ECH live key capacity")
        occupied = {ECHKey.recover(self.store, name).config_id for name in self._names}
        for _ in range(16):
            key = self.library.generate_ech(self.public_name)
            if key.config_id not in occupied:
                break
        else:
            raise StateUnavailable("ECH configuration ID allocation exhausted")
        name = "ech/" + hashlib.sha256(key.configuration).hexdigest()
        key.prepare(self.store, name)
        # Build before advancing/exposing anything. Failed install leaves only
        # an unused encrypted prepared key; never a served unretained config.
        context = TLSContext(
            self.library,
            (*tuple(ECHKey.recover(self.store, old) for old in self._names), key),
        )
        try:
            self.store.advance(name, "prepared", "published")
            previous = self._current
            self._commit_head((*self._names, name), name, now=now, context=context)
        except BaseException:
            context.close()
            raise
        self.store.advance(name, "published", "active")
        if previous and self.store.key(previous)[3] == "active":
            self.store.advance(previous, "active", "retiring")

    def rewrite(self, original: dns.rrset.RRset, *, now: float) -> ECHPublication:
        """Replace only ServiceMode ECH, preserving every other SvcParam.

        AliasMode parameters have no endpoint semantics and stay byte-exact.
        This method is not DNS authorization, signing, or final publication.
        """
        self._time(now)
        if not 0 <= original.ttl <= 2**31 - 1 or not 1 <= len(original) <= 128:
            raise ValueError("bounded service RRset required")
        result = dns.rrset.RRset(original.name, original.rdclass, original.rdtype, original.covers)
        changed = False
        for record in original:
            if not isinstance(record, dns.rdtypes.svcbbase.SVCBBase):
                raise ValueError("service RRset required")
            params = dict(record.params)
            if record.priority and dns.rdtypes.svcbbase.ParamKey.ECH in params:
                params[dns.rdtypes.svcbbase.ParamKey.ECH] = dns.rdtypes.svcbbase.ECHParam(  # type: ignore[no-untyped-call]
                    self.configuration
                )
                record = record.replace(params=params)
                changed = True
            result.add(record, original.ttl)
        return ECHPublication(
            result,
            self._current if changed else None,
            now + original.ttl + self.handshake_window,
        )

    def collect(self, *, now: float) -> None:
        """Remove only keys past every committed DNS/configuration dependency."""
        self._time(now)
        retired = tuple(
            name
            for name in self._names
            if name != self._current and self.store.dependency_horizon(name) < now
        )
        if not retired:
            return
        keep = tuple(name for name in self._names if name not in retired)
        context = TLSContext(self.library, tuple(ECHKey.recover(self.store, name) for name in keep))
        try:
            self._commit_head(keep, self._current, now=now, context=context)
        except BaseException:
            context.close()
            raise
        for name in retired:
            if self.store.key(name)[3] == "active":
                self.store.advance(name, "active", "retiring")
            self.store.retire(name, now=now)
        self.store.prune_publications(_PREFIX, now=now)

    def close(self) -> None:
        if self._context is not None:
            self._context.close()
            self._context = None
