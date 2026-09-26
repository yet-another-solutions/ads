"""Initial-only root publication and strict authenticated recovery."""

from __future__ import annotations

import json

from ads_sandbox_egress.dnssec_identity import DNSSECIdentities, SigningIdentity
from ads_sandbox_egress.identity_store import IdentityStore, StateUnavailable

_NAME = "root-anchor/v1"


def root_identity(store: IdentityStore, *, initial: bool) -> SigningIdentity:
    identities = DNSSECIdentities(store)
    if initial:
        if store.publication_head("root-anchor/") is not None:
            raise StateUnavailable("root initialization over retained anchor")
        root = identities.initialize_root()
        store.advance(root.name, "prepared", "published")
        value = json.dumps(
            {"fingerprint": root.fingerprint, "dnskey": str(root.dnskey)},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        # No automatic root rotation or retirement. Publication is bound to
        # the authenticated custody inventory independently of the key row.
        store.commit_publication(_NAME, value, (root.name,), float(2**53))
        store.advance(root.name, "published", "active")
    head = store.publication_head("root-anchor/")
    if head is None or head[0] != _NAME:
        raise StateUnavailable("required root publication missing")
    try:
        value = json.loads(head[1])
        if set(value) != {"fingerprint", "dnskey"}:
            raise ValueError
        root = identities.root(expected_fingerprint=value["fingerprint"])
        if value["dnskey"] != str(root.dnskey) or root.stage not in ("published", "active"):
            raise ValueError
        if root.stage == "published":
            store.advance(root.name, "published", "active")
        return identities.root(expected_fingerprint=root.fingerprint)
    except (ValueError, TypeError, KeyError):
        raise StateUnavailable("invalid authenticated root publication") from None
