import asyncio
import base64
import copy
import shutil
import time

import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.rrset
import pytest

from ads_sandbox_egress.dnssec_identity import DNSSECIdentities, DNSSECUnrepresentable
from ads_sandbox_egress.dnssec_transform import DNSSECTransformer
from ads_sandbox_egress.dnssec_validation import CryptoBudget
from ads_sandbox_egress.policy import RequestDenied
from ads_sandbox_egress.resolution import ResolutionJob
from test_dns_transport import transport
from test_dnssec_validation import NOW, ZONE, corrupt, material, records, signature
from test_identity_store import custody as custody
from test_identity_store import open_store


@pytest.fixture
def transformer(custody):
    store = open_store(custody, create=True)
    try:
        yield DNSSECTransformer(
            DNSSECIdentities(store), ResolutionJob(time.monotonic() + 30), CryptoBudget()
        )
    finally:
        store.close()


@pytest.mark.parametrize("algorithm", [8, 10, 13, 14, 15, 16])
@pytest.mark.parametrize("defect", ["valid", "expired", "future", "invalid", "expired_invalid"])
def test_actual_signatures_preserve_valid_and_combined_defects(transformer, algorithm, defect):
    private, key = material(algorithm)
    original = records()
    changed = records("www.example.", "A", "8.8.8.8")
    keys = transformer.keys(dns.rrset.from_rdata(ZONE, 60, key))
    sig = signature(
        original,
        private,
        key,
        inception=NOW + 60 if defect == "future" else NOW - 600,
        expiration=NOW - 1 if defect.startswith("expired") else NOW + 600,
    )
    if "invalid" in defect:
        sig = corrupt(sig)
    result = transformer.signatures(
        original, changed, dns.rrset.from_rdata(original.name, 35, sig), keys, now=NOW
    )
    assert result.before.valid == result.after.valid == (defect == "valid")
    assert {v.defect for v in result.before.failures} == {v.defect for v in result.after.failures}
    assert result.signatures.ttl == 35
    replacement = next(iter(result.signatures))
    assert replacement.inception == sig.inception and replacement.expiration == sig.expiration
    assert replacement.original_ttl == sig.original_ttl
    assert replacement.algorithm == sig.algorithm
    assert replacement.signature != sig.signature
    assert changed[0].address == "8.8.8.8" and original[0].address == "1.1.1.1"


def test_successful_alternative_is_not_erased_by_bad_signature(transformer):
    private, key = material()
    original = records()
    bad = corrupt(signature(original, private, key, expiration=NOW + 300))
    good = signature(original, private, key)
    keys = transformer.keys(dns.rrset.from_rdata(ZONE, 60, key))
    result = transformer.signatures(
        original, original, dns.rrset.from_rdata(original.name, 60, bad, good), keys, now=NOW
    )
    assert result.after.valid and len(result.after.verified) == 1
    assert [v.defect for v in result.after.failures] == ["signature_invalid"]


@pytest.mark.parametrize("flags,protocol", [(1, 3), (256, 2), (1, 2)])
@pytest.mark.parametrize("invalid", [False, True])
def test_key_eligibility_defects_are_not_repaired(transformer, flags, protocol, invalid):
    private, key = material(flags=flags, protocol=protocol)
    original = records()
    keys = transformer.keys(dns.rrset.from_rdata(ZONE, 60, key))
    sig = signature(original, private, key)
    if invalid:
        sig = corrupt(sig)
    result = transformer.signatures(
        original,
        original,
        dns.rrset.from_rdata(original.name, 60, sig),
        keys,
        now=NOW,
    )
    assert not result.after.valid
    assert keys.synthetic[0].flags == flags and keys.synthetic[0].protocol == protocol
    assert {v.defect for v in result.after.failures} == {v.defect for v in result.before.failures}
    assert ("signature_invalid" in {v.defect for v in result.after.failures}) == invalid


def test_missing_signature_stays_missing(transformer):
    _, key = material()
    original = records()
    keys = transformer.keys(dns.rrset.from_rdata(ZONE, 60, key))
    result = transformer.signatures(original, original, None, keys, now=NOW)
    assert result.signatures is None and not result.after.valid
    assert [v.defect for v in result.after.failures] == ["signature_missing"]


@pytest.mark.parametrize("digest", [1, 2, 4])
@pytest.mark.parametrize("mismatch", [False, True])
def test_delegation_uses_mapped_full_key_and_preserves_mismatch(transformer, digest, mismatch):
    _, key = material()
    keys = transformer.keys(dns.rrset.from_rdata(ZONE, 60, key))
    ds = dns.dnssec.make_ds(ZONE, key, digest, validating=True)
    if mismatch:
        ds = ds.replace(digest=bytes((ds.digest[0] ^ 1,)) + ds.digest[1:])
    original = dns.rrset.from_rdata(ZONE, 30, ds)
    result = transformer.delegation(original, keys)
    assert bool(result.after.matched) != mismatch
    assert result.records.ttl == 30 and result.records != original
    assert result.records[0].digest_type == digest
    assert result.records[0].key_tag == dns.dnssec.key_id(keys.synthetic[0])
    assert [v.defect for v in result.before.failures] == [v.defect for v in result.after.failures]


def test_wildcard_expansion_retains_signature_labels_and_original_ttl(transformer):
    private, key = material()
    wildcard = records("*.example.")
    sig = signature(wildcard, private, key)
    expanded = copy.deepcopy(wildcard)
    expanded.name = dns.name.from_text("deep.www.example.")
    changed = records("deep.www.example.", "A", "8.8.8.8")
    changed.ttl = 20
    keys = transformer.keys(dns.rrset.from_rdata(ZONE, 60, key))
    result = transformer.signatures(
        expanded, changed, dns.rrset.from_rdata(expanded.name, 15, sig), keys, now=NOW
    )
    assert result.after.valid and result.after.verified[0].wildcard
    assert result.signatures[0].labels == sig.labels == 1
    assert result.signatures[0].original_ttl == 60 and changed.ttl == 20


@pytest.mark.parametrize("case", ["missing", "unsupported", "interval", "scope"])
def test_nonrepresentable_signature_is_explicit_not_repaired(transformer, case):
    private, key = material()
    original = records()
    keys = transformer.keys(dns.rrset.from_rdata(ZONE, 60, key))
    sig = signature(original, private, key)
    if case == "missing":
        sig = sig.replace(key_tag=(sig.key_tag + 1) % 65536)
    elif case == "unsupported":
        sig = sig.replace(algorithm=253)
    elif case == "interval":
        sig = sig.replace(inception=NOW + 50, expiration=NOW)
    else:
        sig = sig.replace(signer=dns.name.from_text("other."))
    if case == "missing":
        result = transformer.signatures(
            original, original, dns.rrset.from_rdata(original.name, 60, sig), keys, now=NOW
        )
        assert not result.before.valid and not result.after.valid
        assert [f.defect for f in result.before.failures] == ["dnskey_missing"]
        assert [f.defect for f in result.after.failures] == ["dnskey_missing"]
        assert result.signatures[0].signature == sig.signature
    else:
        with pytest.raises(DNSSECUnrepresentable):
            transformer.signatures(
                original, original, dns.rrset.from_rdata(original.name, 60, sig), keys, now=NOW
            )


def test_budget_and_deadline_do_not_become_synthesis_fallback(transformer):
    _, key = material()
    original = dns.rrset.from_rdata(ZONE, 60, key)
    transformer.budget.remaining = 0
    with pytest.raises(RequestDenied, match="crypto_budget"):
        transformer.keys(original)
    transformer.job.deadline = time.monotonic() - 1
    with pytest.raises(RequestDenied, match="deadline"):
        transformer.keys(original)


@pytest.mark.parametrize("family", ["NSEC", "NSEC3"])
@pytest.mark.parametrize(
    "kind,name,qtype,wildcard",
    [
        ("nodata", "www.example.", "AAAA", None),
        ("nxdomain", "missing.example.", "A", None),
        ("wildcard", "a.wild.example.", "A", "*.wild.example."),
        ("wildcard_nodata", "a.wild.example.", "AAAA", None),
        ("unsigned_delegation", "child.example.", "DS", None),
    ],
)
@pytest.mark.parametrize("defect", ["none", "missing", "corrupt"])
def test_denial_substitution_preserves_acquired_structure_and_result(
    transformer, family, kind, name, qtype, wildcard, defect
):
    from test_dnssec_denial import Zone

    zone = Zone(family)
    mapping = transformer.keys(zone.keys)
    proofs = zone.proofs
    if defect == "missing":
        proofs = []
    elif defect == "corrupt":
        proofs = [
            (records, dns.rrset.from_rdata(records.name, 60, corrupt(next(iter(sigs)))))
            for records, sigs in proofs
        ]
    result = transformer.denial(
        dns.name.from_text(name),
        dns.rdatatype.from_text(qtype),
        kind,
        tuple(proofs),
        mapping,
        now=zone.now,
        wildcard=dns.name.from_text(wildcard) if wildcard else None,
    )
    assert result.before.valid == result.after.valid == (defect == "none")
    assert result.before.opt_out == result.after.opt_out
    assert len(result.evidence) == len(proofs)
    for (old, old_sigs), (changed, changed_sigs) in zip(proofs, result.evidence, strict=True):
        assert old == changed and old.ttl == changed.ttl
        assert changed_sigs != old_sigs


def test_opt_out_denial_does_not_gain_secure_answer_status(transformer):
    from test_dnssec_denial import Zone

    zone = Zone("NSEC3", opt_out=True)
    mapping = transformer.keys(zone.keys)
    result = transformer.denial(
        dns.name.from_text("child.example."),
        dns.rdatatype.DS,
        "unsigned_delegation",
        tuple(zone.proofs),
        mapping,
        now=zone.now,
    )
    assert result.before.valid and result.after.valid
    assert result.before.opt_out and result.after.opt_out


@pytest.mark.parametrize(
    "case", ["secure", "expired", "future", "invalid", "ds_mismatch", "alternative"]
)
def test_independent_delv_checks_transformed_keys_delegation_and_answer(
    transformer, tmp_path, case
):
    if shutil.which("delv") is None:
        pytest.skip("independent BIND delv unavailable")
    now = int(time.time())
    root_private, root_key = material(flags=257)
    child_private, child_key = material(flags=257)
    root_original = dns.rrset.from_rdata(dns.name.root, 60, root_key)
    child_original = dns.rrset.from_rdata(ZONE, 60, child_key)
    root = transformer.keys(root_original)
    child = transformer.keys(child_original)
    ds = dns.dnssec.make_ds(ZONE, child_key, 2)
    if case == "ds_mismatch":
        ds = ds.replace(digest=bytes((ds.digest[0] ^ 1,)) + ds.digest[1:])
    original_ds = dns.rrset.from_rdata(ZONE, 60, ds)
    transformed_ds = transformer.delegation(original_ds, child).records
    answer = records()
    changed = records("www.example.", "A", "8.8.8.8")

    def signed(original, changed, private, key, mapping, *, broken=False):
        sig = dns.dnssec.sign(
            original,
            private,
            mapping.original.name,
            key,
            inception=now + 60 if broken and case == "future" else now - 600,
            expiration=now - 1 if broken and case == "expired" else now + 600,
        )
        all_signatures = [corrupt(sig) if broken and case in ("invalid", "alternative") else sig]
        if broken and case == "alternative":
            all_signatures.append(sig)
        result = transformer.signatures(
            original,
            changed,
            dns.rrset.from_rdata(original.name, 60, *all_signatures),
            mapping,
            now=now,
        )
        return changed, result.signatures

    data = {
        (dns.name.root, dns.rdatatype.DNSKEY): signed(
            root_original, root.synthetic, root_private, root_key, root
        ),
        (ZONE, dns.rdatatype.DNSKEY): signed(
            child_original, child.synthetic, child_private, child_key, child
        ),
        (ZONE, dns.rdatatype.DS): signed(original_ds, transformed_ds, root_private, root_key, root),
        (answer.name, answer.rdtype): signed(
            answer, changed, child_private, child_key, child, broken=True
        ),
    }

    # External transport fixture: the actual transformer supplies every RRset.
    # No claim that this fixture is the production DNS view/publication owner.
    class View:
        async def answer(self, query, *, deadline):
            q = query.question[0]
            response = dns.message.make_response(query)
            response.flags |= dns.flags.RA
            response.flags &= ~dns.flags.AD
            response.answer.extend(data[(q.name, q.rdtype)])
            return response

    anchor = tmp_path / "transformed.anchor"
    anchor.write_text(
        'trust-anchors { "." static-key 257 3 15 "'
        + base64.b64encode(root.synthetic[0].key).decode()
        + '"; };\n'
    )

    async def run():
        server = transport(View())
        host, port = await server.start("127.0.0.1", 0)
        process = None
        try:
            process = await asyncio.create_subprocess_exec(
                "delv",
                "@" + host,
                "-p",
                str(port),
                "-a",
                str(anchor),
                "www.example.",
                "A",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            output, error = await asyncio.wait_for(process.communicate(), 5)
            combined = output + error
            if case in ("secure", "alternative"):
                assert b"fully validated" in combined, combined
                assert b"8.8.8.8" in combined and b"1.1.1.1" not in combined
            else:
                assert b"resolution failed" in combined, combined
                assert b"fully validated" not in combined, combined
        finally:
            if process is not None and process.returncode is None:
                process.kill()
                await process.communicate()
            await server.close()

    asyncio.run(run())


@pytest.mark.parametrize("family", ["NSEC", "NSEC3"])
@pytest.mark.parametrize("kind", ["nodata", "nxdomain"])
@pytest.mark.parametrize("broken", [False, True])
def test_independent_delv_checks_transformed_negative_proofs(
    transformer, tmp_path, family, kind, broken
):
    from test_dnssec_denial import Zone

    if shutil.which("delv") is None:
        pytest.skip("independent BIND delv unavailable")
    now = int(time.time())
    zone = Zone(family, now=now)
    mapping = transformer.keys(zone.keys)
    key_sigs = dns.rrset.from_rdata(
        ZONE, 60, signature(zone.keys, zone.private, zone.keys[0], now - 60, now + 600)
    )
    mapped_sigs = transformer.signatures(
        zone.keys, mapping.synthetic, key_sigs, mapping, now=now
    ).signatures
    proofs = tuple(
        (records, dns.rrset.from_rdata(records.name, 60, corrupt(sigs[0]) if broken else sigs[0]))
        for records, sigs in zone.proofs
    )
    name = dns.name.from_text("www.example." if kind == "nodata" else "missing.example.")
    qtype = dns.rdatatype.AAAA if kind == "nodata" else dns.rdatatype.A
    converted = transformer.denial(name, qtype, kind, proofs, mapping, now=now)
    soa, soa_sigs = zone.resign(
        dns.rrset.from_text(ZONE, 60, "IN", "SOA", "ns.example. admin.example. 1 60 60 60 60")
    )
    changed_soa_sigs = transformer.signatures(soa, soa, soa_sigs, mapping, now=now).signatures

    class View:
        async def answer(self, query, *, deadline):
            response = dns.message.make_response(query)
            response.flags |= dns.flags.RA
            response.flags &= ~dns.flags.AD
            q = query.question[0]
            if q.name == ZONE and q.rdtype == dns.rdatatype.DNSKEY:
                response.answer.extend((mapping.synthetic, mapped_sigs))
            else:
                response.set_rcode(dns.rcode.NXDOMAIN if kind == "nxdomain" else 0)
                response.authority.extend((soa, changed_soa_sigs))
                for records, sigs in converted.evidence:
                    response.authority.extend((records, sigs))
            return response

    anchor = tmp_path / "negative.anchor"
    anchor.write_text(
        'trust-anchors { "example." static-key 256 3 15 "'
        + base64.b64encode(mapping.synthetic[0].key).decode()
        + '"; };\n'
    )

    async def run():
        server = transport(View())
        host, port = await server.start("127.0.0.1", 0)
        process = None
        try:
            process = await asyncio.create_subprocess_exec(
                "delv",
                "@" + host,
                "-p",
                str(port),
                "-a",
                str(anchor),
                "+root=example.",
                str(name),
                dns.rdatatype.to_text(qtype),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            output, error = await asyncio.wait_for(process.communicate(), 5)
            combined = output + error
            if broken:
                assert b"resolution failed" in combined, combined
                assert b"fully validated" not in combined, combined
            else:
                assert b"fully validated" in combined, combined
                assert b"negative" in combined, combined
        finally:
            if process is not None and process.returncode is None:
                process.kill()
                await process.communicate()
            await server.close()

    asyncio.run(run())
