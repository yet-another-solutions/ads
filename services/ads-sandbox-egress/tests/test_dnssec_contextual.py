import asyncio
import time

import dns.dnssec
import dns.message
import dns.name
import dns.rdatatype
import dns.rrset
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from ads_sandbox_egress.dnssec_chain import PositiveChains
from ads_sandbox_egress.dnssec_validation import CryptoBudget
from ads_sandbox_egress.resolution import ResolutionJob
from test_dns_transport import transport
from test_dnssec_chain import CHILD, PARENT, ROOT, PublicDNS
from test_dnssec_denial import Zone
from test_dnssec_transform import transformer as transformer
from test_dnssec_validation import NOW, ZONE, corrupt, material, records, signature
from test_identity_store import custody as custody
from test_resolution import resolver


@pytest.mark.parametrize("case", ["complete", "bare", "wrong-soa", "bad-ds", "bad-parent"])
def test_missing_dnskeys_need_complete_response_and_authenticated_parent_expectation(case):
    fixture = PublicDNS()
    fixture.data[CHILD, dns.rdatatype.DNSKEY] = ()
    if case in ("bad-ds", "bad-parent"):
        name, kind = (
            (CHILD, dns.rdatatype.DS) if case == "bad-ds" else (PARENT, dns.rdatatype.DNSKEY)
        )
        rrset, sigs = fixture.data[name, kind]
        fixture.data[name, kind] = (
            rrset,
            dns.rrset.from_rdata(name, 60, corrupt(next(iter(sigs)))),
        )

    class View:
        async def answer(self, query, *, deadline):
            response = await fixture.answer(query, deadline=deadline)
            if query.question[0].name == CHILD and query.question[0].rdtype == dns.rdatatype.DNSKEY:
                if case != "bare":
                    response.authority.append(
                        dns.rrset.from_text(
                            PARENT if case == "wrong-soa" else CHILD,
                            60,
                            "IN",
                            "SOA",
                            "ns.example. hostmaster.example. 1 60 60 60 60",
                        )
                    )
            return response

    async def run():
        service = transport(View())
        _, port = await service.start("127.0.0.1", 0)
        try:
            chains = PositiveChains(resolver(upstream_port=port), {ROOT: fixture.keys[ROOT]})
            auth = await chains.authenticate(
                CHILD,
                ResolutionJob(time.monotonic() + 5),
                budget=CryptoBudget(),
            )
            assert auth.trusted_keys is None
            missing = [
                failure
                for checked in auth.delegations
                for failure in checked.failures
                if failure.defect == "dnskey_missing"
            ]
            assert bool(missing) is (case == "complete")
            assert auth.state == ("indeterminate" if case in ("bare", "wrong-soa") else "bogus")
            if case == "complete":
                assert auth.limitation == "authenticated_delegation_missing_dnskey"
        finally:
            await service.close()

    asyncio.run(run())


def test_signed_descendant_cannot_promote_authenticated_unsigned_cut():
    fixture = PublicDNS()
    parent = Zone("NSEC", now=fixture.now)
    fixture.keys[PARENT], fixture.private[PARENT] = parent.keys, parent.private
    fixture.data[PARENT, dns.rdatatype.DNSKEY] = parent.resign(parent.keys)
    fixture.data[PARENT, dns.rdatatype.DS] = fixture.signed(
        dns.rrset.from_rdata(
            PARENT,
            60,
            dns.dnssec.make_ds(PARENT, next(iter(parent.keys)), 2),
        ),
        ROOT,
    )
    island = dns.name.from_text("child.example.")
    descendant = dns.name.from_text("nested.child.example.")
    for name in (island, descendant):
        private, key = material(flags=257)
        fixture.private[name] = private
        fixture.keys[name] = dns.rrset.from_rdata(name, 60, key)
        fixture.data[name, dns.rdatatype.DNSKEY] = fixture.signed(fixture.keys[name], name)
    fixture.data[descendant, dns.rdatatype.DS] = fixture.signed(
        dns.rrset.from_rdata(
            descendant,
            60,
            dns.dnssec.make_ds(descendant, next(iter(fixture.keys[descendant])), 2),
        ),
        island,
    )

    class View:
        async def answer(self, query, *, deadline):
            response = await fixture.answer(query, deadline=deadline)
            if query.question[0].name == island and query.question[0].rdtype == dns.rdatatype.DS:
                for pair in parent.proofs:
                    response.authority.extend(pair)
            return response

    async def run():
        service = transport(View())
        _, port = await service.start("127.0.0.1", 0)
        try:
            chains = PositiveChains(resolver(upstream_port=port), {ROOT: fixture.keys[ROOT]})
            auth = await chains.authenticate(
                descendant,
                ResolutionJob(time.monotonic() + 5),
                budget=CryptoBudget(),
            )
            assert auth.state == "insecure" and auth.trusted_keys is None
            assert auth.limitation == "signed_island_below_unsigned_cut"
            assert any(proof.valid for proof in auth.denials)
        finally:
            await service.close()

    asyncio.run(run())


@pytest.mark.parametrize("case", ["signature", "expired-signature", "ds"])
def test_missing_key_substitution_does_not_create_synthetic_matching_tag(
    transformer, case, monkeypatch
):
    # Fixed test-only material makes the deliberately different short tags
    # deterministic. Production key generation is never overridden outside
    # this test.
    private = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    key = dns.dnssec.make_dnskey(private.public_key(), 15, flags=256)
    monkeypatch.setattr(
        "ads_sandbox_egress.dnssec_identity._generate",
        lambda algorithm: ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64))),
    )
    mapping = transformer.keys(dns.rrset.from_rdata(ZONE, 60, key))
    synthetic_tag = dns.dnssec.key_id(mapping.synthetic[0])
    assert synthetic_tag != dns.dnssec.key_id(key)
    original = records()
    if case == "ds":
        ds = dns.dnssec.make_ds(ZONE, key, 2).replace(key_tag=synthetic_tag)
        result = transformer.delegation(dns.rrset.from_rdata(ZONE, 60, ds), mapping)
        assert not result.before.matched and not result.after.matched
        assert [f.defect for f in result.after.failures] == ["dnskey_missing"]
        assert result.records[0].digest == ds.digest
        assert result.records[0].key_tag != synthetic_tag
    else:
        sig = signature(
            original,
            private,
            key,
            expiration=NOW - 1 if case == "expired-signature" else NOW + 60,
        ).replace(key_tag=synthetic_tag)
        result = transformer.signatures(
            original,
            records("www.example.", "A", "8.8.8.8"),
            dns.rrset.from_rdata(original.name, 60, sig),
            mapping,
            now=NOW,
        )
        assert not result.before.valid and not result.after.valid
        assert {f.defect for f in result.after.failures} == {
            f.defect for f in result.before.failures
        }
        assert "dnskey_missing" in {f.defect for f in result.after.failures}
        assert result.signatures[0].signature == sig.signature
        assert result.signatures[0].key_tag != synthetic_tag
