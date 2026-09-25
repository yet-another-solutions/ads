"""Authenticated NSEC/NSEC3 proof relationships, never cache-derived absence.

The supplied zone keys must already be authenticated against upstream anchors.
Signature checks here establish RRset integrity, not that external trust.
References: RFC 4035 5.3.4/5.4; RFC 5155 8 and 9.2.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from typing import Literal

import dns.dnssec
import dns.name
import dns.rdatatype
import dns.rdtypes.ANY.NSEC
import dns.rdtypes.ANY.NSEC3
import dns.rrset

from ads_sandbox_egress.dnssec_validation import CryptoBudget, SignatureCheck, check_signatures
from ads_sandbox_egress.policy import RequestDenied

NSEC = dns.rdtypes.ANY.NSEC.NSEC
NSEC3 = dns.rdtypes.ANY.NSEC3.NSEC3
Kind = Literal["nodata", "nxdomain", "wildcard", "wildcard_nodata", "unsigned_delegation"]


@dataclass(frozen=True, slots=True)
class DenialProof:
    valid: bool
    opt_out: bool
    # A structurally valid Opt-Out proof does not permit AD authentication.
    # Nor does a valid parent no-DS proof authenticate the child's answer.
    checks: tuple[SignatureCheck, ...]
    closest_encloser: dns.name.Name | None = None
    limitation: str | None = None


def has_type(record: NSEC | NSEC3, kind: dns.rdatatype.RdataType) -> bool:
    window, offset = divmod(int(kind), 256)
    octet, bit = divmod(offset, 8)
    return any(
        number == window and len(bitmap) > octet and bitmap[octet] & (0x80 >> bit) != 0
        for number, bitmap in record.windows
    )


def _authoritative(record: NSEC | NSEC3) -> bool:
    return not has_type(record, dns.rdatatype.DNAME) and not (
        has_type(record, dns.rdatatype.NS) and not has_type(record, dns.rdatatype.SOA)
    )


def _nodata(record: NSEC | NSEC3, kind: dns.rdatatype.RdataType) -> bool:
    if kind == dns.rdatatype.ANY:
        # ANY is a question meta-type, never a bitmap assertion. Only an
        # authenticated empty non-terminal can establish an empty RRset set.
        return not record.windows
    return (
        not has_type(record, kind)
        and not has_type(record, dns.rdatatype.CNAME)
        and (
            kind == dns.rdatatype.DS
            or not (has_type(record, dns.rdatatype.NS) and not has_type(record, dns.rdatatype.SOA))
        )
        # A child's SOA cannot deny its parent-side DS.
        and not (kind == dns.rdatatype.DS and has_type(record, dns.rdatatype.SOA))
    )


def _delegation(record: NSEC | NSEC3) -> bool:
    return (
        has_type(record, dns.rdatatype.NS)
        and not has_type(record, dns.rdatatype.DS)
        and not has_type(record, dns.rdatatype.SOA)
        and not has_type(record, dns.rdatatype.CNAME)
        and not has_type(record, dns.rdatatype.DNAME)
    )


def _ancestors(name: dns.name.Name, zone: dns.name.Name) -> list[dns.name.Name]:
    names = []
    while name.is_subdomain(zone):
        names.append(name)
        if name == zone:
            break
        name = name.parent()
    return names


def validate_denial(
    qname: dns.name.Name,
    qtype: dns.rdatatype.RdataType,
    kind: Kind,
    evidence: tuple[tuple[dns.rrset.RRset, dns.rrset.RRset | None], ...],
    trusted_keys: dns.rrset.RRset,
    *,
    now: float,
    budget: CryptoBudget,
    wildcard: dns.name.Name | None = None,
) -> DenialProof:
    """Validate one required proof, not the whole response or DNS resolution.

    For a wildcard positive answer, `wildcard` must come from an already
    verified answer RRSIG's label count, never untrusted answer text.
    """
    zone = trusted_keys.name
    if (
        not qname.is_absolute()
        or not qname.is_subdomain(zone)
        or kind not in ("nodata", "nxdomain", "wildcard", "wildcard_nodata", "unsigned_delegation")
        or len(evidence) > 64
        or kind == "unsigned_delegation"
        and (qtype != dns.rdatatype.DS or qname == zone)
    ):
        raise RequestDenied("dnssec_denial_scope_or_limit")
    checks = []
    nsec: dict[dns.name.Name, NSEC] = {}
    nsec3: dict[bytes, NSEC3] = {}
    parameters: tuple[int, bytes] | None = None
    malformed = False
    for rrset, signatures in evidence:
        if rrset.rdtype not in (dns.rdatatype.NSEC, dns.rdatatype.NSEC3):
            raise RequestDenied("dnssec_denial_record_type")
        checked = check_signatures(rrset, signatures, trusted_keys, now=now, budget=budget)
        checks.append(checked)
        if not any(not sig.wildcard for sig in checked.verified):
            continue
        if len(rrset) != 1:
            malformed = True
            continue
        record = next(iter(rrset))
        if isinstance(record, NSEC):
            if not record.next.is_subdomain(zone) or rrset.name in nsec:
                malformed = True
                continue
            nsec[rrset.name] = record
        elif isinstance(record, NSEC3):
            if record.algorithm != 1 or record.flags not in (0, 1):
                continue  # RFC 5155 8.1/8.2: ignored, not trusted absence.
            try:
                label = rrset.name.labels[0].upper()
                if len(label) != 32 or rrset.name.parent() != zone or len(record.next) != 20:
                    raise ValueError
                owner = base64.b32hexdecode(label)
            except (ValueError, binascii.Error):
                malformed = True
                continue
            config = (record.iterations, record.salt)
            if parameters is not None and config != parameters or owner in nsec3:
                malformed = True
                continue
            parameters = config
            nsec3[owner] = record

    def result(
        valid: bool,
        *,
        opt_out: bool = False,
        closest: dns.name.Name | None = None,
        limitation: str | None = None,
    ) -> DenialProof:
        return DenialProof(valid, opt_out, tuple(checks), closest, limitation)

    if malformed or nsec and nsec3:
        return result(False, limitation="inconsistent_denial_evidence")
    if not nsec and not nsec3:
        return result(False, limitation="no_verified_denial_evidence")
    ancestors = _ancestors(qname, zone)
    hashes: dict[dns.name.Name, bytes] = {}

    def hashed(name: dns.name.Name) -> bytes:
        if name not in hashes:
            assert parameters is not None
            iterations, salt = parameters
            # Charge BEFORE hashing. An attacker cannot force 65536 rounds
            # per label and only be timed out after blocking the event loop.
            budget.consume(iterations + 1)
            text = dns.dnssec.nsec3_hash(name, salt, iterations, 1)
            hashes[name] = base64.b32hexdecode(text)
        return hashes[name]

    def exact(name: dns.name.Name) -> NSEC | NSEC3 | None:
        return nsec.get(name) if nsec else nsec3.get(hashed(name))

    def covers(name: dns.name.Name) -> NSEC | NSEC3 | None:
        if nsec:
            for owner, item in nsec.items():
                if name == owner or name == item.next:
                    continue
                if name.is_subdomain(owner) and name != owner and not _authoritative(item):
                    continue
                if (
                    owner < name < item.next
                    or owner > item.next
                    and (name > owner or name < item.next)
                    or owner == item.next == zone
                ):
                    return item
        else:
            target = hashed(name)
            for owner_hash, item3 in nsec3.items():
                if target == owner_hash or target == item3.next:
                    continue
                if (
                    owner_hash < target < item3.next
                    or owner_hash > item3.next
                    and (target > owner_hash or target < item3.next)
                    or owner_hash == item3.next
                ):
                    return item3
        return None

    matching = exact(qname)
    if kind in ("nodata", "unsigned_delegation") and matching is not None:
        valid = _delegation(matching) if kind == "unsigned_delegation" else _nodata(matching, qtype)
        return result(valid)
    if matching is not None:
        return result(False)  # QNAME exists: no NXDOMAIN/wildcard expansion.
    closest: dns.name.Name | None
    if kind == "wildcard":
        if (
            wildcard is None
            or wildcard.labels[0] != b"*"
            or not wildcard.is_subdomain(zone)
            or qname == wildcard
            or not qname.is_subdomain(wildcard.parent())
        ):
            return result(False, limitation="verified_wildcard_scope_required")
        closest = wildcard.parent()
    elif nsec:
        # NSEC endpoints authenticate existing names, including ENT ancestors.
        # A row missing from our local store never establishes nonexistence.
        existing = (*nsec.keys(), *(record.next for record in nsec.values()))
        closest = next(
            (
                name
                for name in ancestors
                if any(endpoint.is_subdomain(name) for endpoint in existing)
            ),
            None,
        )
        if closest == qname:
            # An empty non-terminal exists but has no RRsets of its own.
            return result(kind == "nodata" and covers(qname) is not None, closest=closest)
    else:
        closest = next((name for name in ancestors if exact(name) is not None), None)
    if closest is None or closest == qname:
        return result(False, limitation="closest_encloser_missing")
    closest_record = exact(closest)
    if closest_record is not None and not _authoritative(closest_record):
        return result(False)
    next_closer = dns.name.Name(qname.labels[-len(closest.labels) - 1 :])
    covering = covers(next_closer)
    if covering is None:
        return result(False, limitation="next_closer_proof_missing")
    opt_out = isinstance(covering, NSEC3) and bool(covering.flags & 1)
    if kind == "wildcard":
        return result(True, opt_out=opt_out, closest=closest)
    if kind == "unsigned_delegation" or kind == "nodata" and qtype == dns.rdatatype.DS:
        # Nonmatching NSEC3 must be an Opt-Out closest-encloser proof.
        return result(bool(nsec3) and opt_out, opt_out=opt_out, closest=closest)
    star = dns.name.Name((b"*",) + closest.labels)
    if kind == "nxdomain":
        return result(covers(star) is not None, opt_out=opt_out, closest=closest)
    if kind == "wildcard_nodata":
        wildcard_record = exact(star)
        return result(
            wildcard_record is not None and _nodata(wildcard_record, qtype),
            opt_out=opt_out,
            closest=closest,
        )
    return result(False)
