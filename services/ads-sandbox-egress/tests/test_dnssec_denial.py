"""Signed, complete fixture-zone proofs; no inference from cached names."""

import asyncio
import base64
import copy
import shutil
import time

import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype
import dns.rrset
import pytest

from ads_sandbox_egress.dnssec_denial import has_type, validate_denial
from ads_sandbox_egress.dnssec_validation import CryptoBudget
from ads_sandbox_egress.policy import RequestDenied
from test_dns_transport import transport
from test_dnssec_validation import NOW, ZONE, corrupt, material, signature


class Zone:
    def __init__(self, family, *, iterations=0, opt_out=False, changes=None, now=NOW):
        self.family = family
        self.now = now
        self.private, key = material()
        self.keys = dns.rrset.from_rdata(ZONE, 60, key)
        self.names = {
            "example.": "SOA NS DNSKEY",
            "www.example.": "A",
            "child.example.": "NS",
            "*.wild.example.": "A",
            "wild.example.": "",
            "leaf.example.": "",
            "tip.leaf.example.": "TXT",
        }
        if changes:
            self.names.update(changes)
        self.proofs = []
        self.by_name = {}
        items = {}
        for name, types in self.names.items():
            if opt_out and name == "child.example.":
                continue
            if family == "NSEC" and not types:
                continue  # Empty non-terminals have no NSEC of their own.
            owner = dns.name.from_text(name)
            if family == "NSEC3":
                label = dns.dnssec.nsec3_hash(owner, b"", iterations, 1)
                owner = dns.name.from_text(label + ".example.")
            items[owner] = (name, types)
        owners = sorted(items)
        for index, owner in enumerate(owners):
            next_name = owners[(index + 1) % len(owners)]
            name, types = items[owner]
            if family == "NSEC":
                rrset = dns.rrset.from_text(
                    owner, 60, "IN", "NSEC", next_name.to_text() + " NSEC RRSIG " + types
                )
            else:
                rrset = dns.rrset.from_text(
                    owner,
                    60,
                    "IN",
                    "NSEC3",
                    f"1 {int(opt_out)} {iterations} - {next_name.labels[0].decode()} "
                    + ("RRSIG " if types else "")
                    + types,
                )
            sig = signature(rrset, self.private, key, now - 60, now + 600)
            proof = (rrset, dns.rrset.from_rdata(owner, 60, sig))
            self.proofs.append(proof)
            self.by_name[name] = proof

    def validate(self, name, kind, qtype="AAAA", *, proofs=None, wildcard=None, budget=None):
        return validate_denial(
            dns.name.from_text(name),
            dns.rdatatype.from_text(qtype),
            kind,
            tuple(self.proofs if proofs is None else proofs),
            self.keys,
            now=self.now,
            budget=budget or CryptoBudget(),
            wildcard=dns.name.from_text(wildcard) if wildcard else None,
        )

    def resign(self, rrset):
        return rrset, dns.rrset.from_rdata(
            rrset.name,
            60,
            signature(rrset, self.private, next(iter(self.keys)), self.now - 60, self.now + 600),
        )


@pytest.mark.parametrize("family", ["NSEC", "NSEC3"])
@pytest.mark.parametrize(
    "name,kind,qtype,expected",
    [
        ("www.example.", "nodata", "AAAA", True),
        ("www.example.", "nodata", "A", False),
        ("www.example.", "nodata", "ANY", False),
        ("missing.example.", "nxdomain", "A", True),
        ("www.example.", "nxdomain", "A", False),
        ("leaf.example.", "nxdomain", "A", False),
        ("leaf.example.", "nodata", "AAAA", True),
        ("leaf.example.", "nodata", "ANY", True),
        ("child.example.", "unsigned_delegation", "DS", True),
        ("www.example.", "unsigned_delegation", "DS", False),
        ("child.example.", "nodata", "A", False),
        ("example.", "nodata", "DS", False),
        ("x.wild.example.", "wildcard_nodata", "AAAA", True),
        ("x.wild.example.", "wildcard_nodata", "A", False),
        ("x.wild.example.", "nxdomain", "A", False),
    ],
)
def test_actual_signed_zone_negative_proof_matrix(family, name, kind, qtype, expected):
    result = Zone(family).validate(name, kind, qtype)
    assert result.valid is expected
    assert not result.opt_out


@pytest.mark.parametrize("family", ["NSEC", "NSEC3"])
def test_signed_wildcard_positive_requires_correct_nonexistence_proof(family):
    zone = Zone(family)
    result = zone.validate("x.wild.example.", "wildcard", "A", wildcard="*.wild.example.")
    assert result.valid and result.closest_encloser == dns.name.from_text("wild.example.")
    assert not zone.validate("www.example.", "wildcard", "A", wildcard="*.example.").valid
    assert not zone.validate("x.wild.example.", "wildcard", "A", wildcard="*.other.").valid
    assert not zone.validate("x.wild.example.", "wildcard", "A").valid


@pytest.mark.parametrize("family", ["NSEC", "NSEC3"])
@pytest.mark.parametrize("types", ["NS DS", "SOA NS", "CNAME", "DNAME", "A"])
def test_unsigned_delegation_cannot_be_invented_from_wrong_type_bitmap(family, types):
    zone = Zone(family, changes={"child.example.": types})
    assert not zone.validate("child.example.", "unsigned_delegation", "DS").valid


@pytest.mark.parametrize("family", ["NSEC", "NSEC3"])
@pytest.mark.parametrize("types", ["CNAME", "DNAME", "NS"])
def test_nodata_cannot_hide_alias_or_cross_delegation(family, types):
    zone = Zone(family, changes={"www.example.": types})
    # DNAME redirects descendants, not this exact owner.
    assert zone.validate("www.example.", "nodata", "AAAA").valid is (types == "DNAME")
    # CNAME redirects only its owner, unlike DNAME. Descendant nonexistence
    # can be authenticated; NS without SOA and DNAME remain forbidden cuts.
    assert zone.validate("x.www.example.", "nxdomain", "A").valid is (types == "CNAME")


@pytest.mark.parametrize("family", ["NSEC", "NSEC3"])
def test_invalid_signature_and_missing_proof_never_establish_absence(family):
    zone = Zone(family)
    proof, sigs = zone.by_name["www.example."]
    broken = (proof, dns.rrset.from_rdata(proof.name, 60, corrupt(next(iter(sigs)))))
    assert not zone.validate("www.example.", "nodata", proofs=[broken]).valid
    assert not zone.validate("www.example.", "nodata", proofs=[]).valid
    assert not zone.validate("www.example.", "nodata", proofs=[(proof, None)]).valid


def test_nsec3_opt_out_no_ds_is_not_authenticated_child_answer():
    zone = Zone("NSEC3", opt_out=True)
    result = zone.validate("child.example.", "unsigned_delegation", "DS")
    assert result.valid and result.opt_out
    ordinary = Zone("NSEC3")
    # Removing the child's exact proof does not widen any covering interval.
    reduced = [pair for pair in ordinary.proofs if pair is not ordinary.by_name["child.example."]]
    assert not ordinary.validate(
        "child.example.", "unsigned_delegation", "DS", proofs=reduced
    ).valid


def test_nsec3_opt_out_closest_encloser_retains_no_ad_marker():
    result = Zone("NSEC3", opt_out=True).validate("missing.example.", "nxdomain", "A")
    assert result.valid and result.opt_out


@pytest.mark.parametrize("change", ["unknown_hash", "unknown_flags", "salt", "iterations"])
def test_nsec3_unknown_or_inconsistent_parameters_never_become_success(change):
    zone = Zone("NSEC3")
    mutated = []
    for index, (rrset, _) in enumerate(zone.proofs):
        item = next(iter(rrset))
        if change == "unknown_hash":
            item = item.replace(algorithm=2)
        elif change == "unknown_flags":
            item = item.replace(flags=2)
        elif index == 0:
            item = item.replace(salt=b"a") if change == "salt" else item.replace(iterations=1)
        mutated.append(zone.resign(dns.rrset.from_rdata(rrset.name, 60, item)))
    assert not zone.validate("missing.example.", "nxdomain", proofs=mutated).valid


def test_nsec3_hash_work_is_charged_before_processing_hostile_iterations():
    zone = Zone("NSEC3")
    altered = []
    for rrset, _ in zone.proofs:
        item = next(iter(rrset)).replace(iterations=65535)
        altered.append(zone.resign(dns.rrset.from_rdata(rrset.name, 60, item)))
    with pytest.raises(RequestDenied, match="crypto_budget"):
        zone.validate("missing.example.", "nxdomain", proofs=altered)


def test_nsec_cross_zone_next_endpoint_cannot_establish_nonexistence():
    zone = Zone("NSEC")
    rrset, _ = zone.by_name["example."]
    item = next(iter(rrset)).replace(next=dns.name.from_text("other."))
    assert not zone.validate(
        "missing.example.",
        "nxdomain",
        proofs=[zone.resign(dns.rrset.from_rdata(rrset.name, 60, item))],
    ).valid


@pytest.mark.parametrize("family", ["NSEC", "NSEC3"])
def test_one_proof_cannot_mix_authenticated_rrset_generations(family):
    zone = Zone(family)
    duplicate = copy.deepcopy(zone.proofs[0])
    assert not zone.validate("missing.example.", "nxdomain", proofs=[*zone.proofs, duplicate]).valid


def test_type_bitmap_across_windows():
    rrset = dns.rrset.from_text(
        "example.", 60, "IN", "NSEC", "next.example. A NS TYPE257 TYPE65280"
    )
    item = next(iter(rrset))
    for kind in (1, 2, 257, 65280):
        assert has_type(item, dns.rdatatype.RdataType(kind))
    for kind in (5, 256, 258, 65535):
        assert not has_type(item, dns.rdatatype.RdataType(kind))


@pytest.mark.parametrize("family", ["NSEC", "NSEC3", "optout"])
@pytest.mark.parametrize(
    "case", ["nodata", "nodata_dname", "nxdomain", "wildcard", "unsigned", "corrupt"]
)
def test_independent_delv_authenticates_denial_and_unsigned_boundary(tmp_path, family, case):
    if shutil.which("delv") is None:
        pytest.skip("independent BIND delv unavailable")
    now = int(time.time())
    zone = Zone(
        "NSEC3" if family == "optout" else family,
        now=now,
        opt_out=family == "optout",
        changes={"www.example.": "DNAME"} if case == "nodata_dname" else None,
    )
    root_secret, root_key = material(flags=257)
    root_keys = dns.rrset.from_rdata(dns.name.root, 60, root_key)
    root_sig = signature(root_keys, root_secret, root_key, now - 60, now + 600, dns.name.root)
    ds = dns.rrset.from_rdata(ZONE, 60, dns.dnssec.make_ds(ZONE, next(iter(zone.keys)), 2))
    ds_sig = signature(ds, root_secret, root_key, now - 60, now + 600, dns.name.root)
    soa = dns.rrset.from_text(
        ZONE, 60, "IN", "SOA", "ns.example. hostmaster.example. 1 60 60 3600 60"
    )
    base = {
        (dns.name.root, dns.rdatatype.DNSKEY): (
            root_keys,
            dns.rrset.from_rdata(dns.name.root, 60, root_sig),
        ),
        (ZONE, dns.rdatatype.DNSKEY): zone.resign(zone.keys),
        (ZONE, dns.rdatatype.DS): (ds, dns.rrset.from_rdata(ZONE, 60, ds_sig)),
    }
    if case in ("nodata", "nodata_dname"):
        qname, qtype, kind = "www.example.", "AAAA", "nodata"
    elif case == "wildcard":
        qname, qtype, kind = "x.wild.example.", "A", "wildcard"
    elif case == "unsigned":
        qname, qtype, kind = "a.child.example.", "A", "unsigned_delegation"
    else:
        qname, qtype, kind = "missing.example.", "A", "nxdomain"
    proofs = zone.proofs
    if case == "corrupt":
        proofs = [
            (rrset, dns.rrset.from_rdata(rrset.name, 60, corrupt(next(iter(sigs)))))
            for rrset, sigs in proofs
        ]
    checked = zone.validate(
        "child.example." if case == "unsigned" else qname,
        kind,
        "DS" if case == "unsigned" else qtype,
        proofs=proofs,
        wildcard="*.wild.example." if case == "wildcard" else None,
    )
    assert checked.valid is (case != "corrupt")
    calls = []

    class View:
        async def answer(self, query, *, deadline):
            question = query.question[0]
            calls.append((question.name.to_text(), str(question.rdtype)))
            response = dns.message.make_response(query)
            response.flags |= dns.flags.RA
            response.flags &= ~dns.flags.AD
            identity = question.name, question.rdtype
            if identity in base:
                response.answer.extend(base[identity])
                return response
            if case == "unsigned" and question.rdtype == dns.rdatatype.A:
                response.answer.append(dns.rrset.from_text(qname, 60, "IN", "A", "1.1.1.1"))
                return response
            if case == "wildcard" and question.rdtype == dns.rdatatype.A:
                rrset = dns.rrset.from_text("*.wild.example.", 60, "IN", "A", "1.1.1.1")
                rrset, sigs = zone.resign(rrset)
                rrset.name = sigs.name = question.name
                response.answer.extend((rrset, sigs))
            else:
                response.authority.extend(zone.resign(soa))
                if case in ("nxdomain", "corrupt"):
                    response.set_rcode(dns.rcode.NXDOMAIN)
            for pair in proofs:
                response.authority.extend(pair)
            return response

    anchor = tmp_path / "upstream.anchor"
    anchor.write_text(
        'trust-anchors { "." static-key 257 3 15 "'
        + base64.b64encode(root_key.key).decode()
        + '"; };\n'
    )

    async def run():
        service = transport(View())
        host, port = await service.start("127.0.0.1", 0)
        process = None
        try:
            process = await asyncio.create_subprocess_exec(
                "delv",
                "@" + host,
                "-p",
                str(port),
                "-a",
                str(anchor),
                qname,
                qtype,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            out, err = await asyncio.wait_for(process.communicate(), 5)
            result = out + err
            if case == "corrupt":
                assert b"resolution failed" in result, (result, calls)
                assert b"fully validated" not in result
            elif case == "nxdomain" and checked.opt_out:
                # Delv's negative-proof display says "fully validated" here.
                # It is NOT a wire AD-bit proof. Preserve ADS's explicit marker;
                # final response assembly must still clear AD per RFC 5155 9.2.
                assert b"negative response" in result and b"NXDOMAIN" in result, (result, calls)
                assert checked.valid and checked.opt_out
            elif case == "unsigned" or checked.opt_out:
                assert b"unsigned answer" in result, (result, calls)
                if case in ("unsigned", "wildcard"):
                    assert b"1.1.1.1" in result
                assert b"fully validated" not in result
            else:
                assert b"fully validated" in result, (result, calls)
        finally:
            if process is not None and process.returncode is None:
                process.kill()
                await process.communicate()
            await service.close()
        assert not service._tasks and service._accepted == 0

    asyncio.run(run())
