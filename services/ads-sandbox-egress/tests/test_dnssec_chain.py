import asyncio
import copy
import time

import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype
import dns.rrset
import pytest

from ads_sandbox_egress.dnssec_chain import PositiveChains
from ads_sandbox_egress.dnssec_validation import CryptoBudget, check_signatures
from ads_sandbox_egress.policy import RequestDenied
from ads_sandbox_egress.resolution import ResolutionJob, ResolutionLimits
from test_dns_transport import transport
from test_dnssec_validation import corrupt, material, signature
from test_resolution import resolver

ROOT = dns.name.root
PARENT = dns.name.from_text("example.")
CHILD = dns.name.from_text("nested.example.")
HOST = dns.name.from_text("www.nested.example.")


class PublicDNS:
    """Explicit external DNS fixture; acquisition, gates and verification are real."""

    def __init__(self):
        self.now = int(time.time())
        self.calls = []
        self.keys = {}
        self.private = {}
        self.data = {}
        for zone in (ROOT, PARENT, CHILD):
            private, key = material(flags=257)
            self.private[zone] = private
            self.keys[zone] = dns.rrset.from_rdata(zone, 60, key)
            self.data[zone, dns.rdatatype.DNSKEY] = self.signed(self.keys[zone], zone)
        for zone, parent in ((PARENT, ROOT), (CHILD, PARENT)):
            ds = dns.dnssec.make_ds(zone, next(iter(self.keys[zone])), 2)
            self.data[zone, dns.rdatatype.DS] = self.signed(
                dns.rrset.from_rdata(zone, 60, ds), parent
            )
        self.a = dns.rrset.from_text(HOST, 60, "IN", "A", "1.1.1.1")
        self.answer_records, self.answer_sigs = self.signed(self.a, CHILD)

    def signed(self, rrset, zone):
        sig = signature(
            rrset,
            self.private[zone],
            next(iter(self.keys[zone])),
            self.now - 600,
            self.now + 600,
            zone,
        )
        return rrset, dns.rrset.from_rdata(rrset.name, 60, sig)

    async def answer(self, query, *, deadline):
        question = query.question[0]
        assert query.flags & dns.flags.CD and query.ednsflags & dns.flags.DO
        self.calls.append((question.name, question.rdtype))
        response = dns.message.make_response(query)
        # AD is deliberately untrustworthy in this fixture. ADS must inspect
        # the original records and signatures even if upstream claims success.
        response.flags |= dns.flags.AD | dns.flags.RA
        response.answer.extend(self.data.get((question.name, question.rdtype), ()))
        return response


@pytest.mark.parametrize(
    "case,expected",
    [
        ("good", "secure"),
        ("valid_alternative", "secure"),
        ("ds_anchor", "secure"),
        ("wrong_anchor", "bogus"),
        ("root_bad_sig", "bogus"),
        ("parent_bad_sig", "bogus"),
        ("child_bad_sig", "bogus"),
        ("child_missing_sig", "bogus"),
        ("bad_ds_sig", "bogus"),
        ("ds_mismatch", "bogus"),
        ("unsupported_only_ds", "insecure"),
        ("mixed_supported_bad_ds", "bogus"),
        ("supported_bad_plus_unknown_sig", "bogus"),
        ("missing_keys", "indeterminate"),
        ("missing_ds", "indeterminate"),
        ("missing_ds_sig", "indeterminate"),
        ("unsupported_anchor", "indeterminate"),
        ("self_signed_ds", "indeterminate"),
        ("servfail", "indeterminate"),
        ("duplicate_keys", "indeterminate"),
        ("wildcard_ds", "indeterminate"),
        ("wildcard_dnskey", "indeterminate"),
    ],
)
def test_real_acquisition_follows_observed_positive_chain_and_preserves_failures(case, expected):
    fixture = PublicDNS()
    anchor = copy.deepcopy(fixture.keys[ROOT])
    if case == "wrong_anchor":
        anchor = dns.rrset.from_rdata(ROOT, 60, material()[1])
    elif case in ("ds_anchor", "unsupported_anchor"):
        ds = dns.dnssec.make_ds(ROOT, next(iter(anchor)), 2)
        if case == "unsupported_anchor":
            ds = ds.replace(algorithm=253)
        anchor = dns.rrset.from_rdata(ROOT, 60, ds)
    elif case in ("root_bad_sig", "parent_bad_sig", "child_bad_sig"):
        zone = ROOT if case == "root_bad_sig" else PARENT if case == "parent_bad_sig" else CHILD
        rrset, sigs = fixture.data[zone, dns.rdatatype.DNSKEY]
        fixture.data[zone, dns.rdatatype.DNSKEY] = (
            rrset,
            dns.rrset.from_rdata(zone, 60, corrupt(next(iter(sigs)))),
        )
    elif case == "valid_alternative":
        rrset, sigs = fixture.data[CHILD, dns.rdatatype.DNSKEY]
        good = next(iter(sigs))
        fixture.data[CHILD, dns.rdatatype.DNSKEY] = (
            rrset,
            dns.rrset.from_rdata(CHILD, 60, corrupt(good), good),
        )
    elif case == "supported_bad_plus_unknown_sig":
        rrset, sigs = fixture.data[CHILD, dns.rdatatype.DNSKEY]
        sig = next(iter(sigs))
        fixture.data[CHILD, dns.rdatatype.DNSKEY] = (
            rrset,
            dns.rrset.from_rdata(CHILD, 60, corrupt(sig), sig.replace(algorithm=253)),
        )
    elif case in ("ds_mismatch", "unsupported_only_ds", "mixed_supported_bad_ds"):
        ds = next(iter(fixture.data[CHILD, dns.rdatatype.DS][0]))
        values = (
            (ds.replace(algorithm=253),)
            if case == "unsupported_only_ds"
            else (ds.replace(digest=b"x" * 32), ds.replace(algorithm=253))
            if case == "mixed_supported_bad_ds"
            else (ds.replace(digest=b"x" * 32),)
        )
        fixture.data[CHILD, dns.rdatatype.DS] = fixture.signed(
            dns.rrset.from_rdata(CHILD, 60, *values), PARENT
        )
    elif case == "bad_ds_sig":
        rrset, sigs = fixture.data[CHILD, dns.rdatatype.DS]
        fixture.data[CHILD, dns.rdatatype.DS] = (
            rrset,
            dns.rrset.from_rdata(CHILD, 60, corrupt(next(iter(sigs)))),
        )
    elif case == "self_signed_ds":
        rrset = fixture.data[CHILD, dns.rdatatype.DS][0]
        fixture.data[CHILD, dns.rdatatype.DS] = fixture.signed(rrset, CHILD)
    elif case in ("wildcard_ds", "wildcard_dnskey"):
        kind = dns.rdatatype.DS if case == "wildcard_ds" else dns.rdatatype.DNSKEY
        rrset = fixture.data[CHILD, kind][0]
        wildcard = copy.deepcopy(rrset)
        wildcard.name = dns.name.from_text("*.example.")
        _, sigs = fixture.signed(wildcard, PARENT if kind == dns.rdatatype.DS else CHILD)
        sigs.name = CHILD
        fixture.data[CHILD, kind] = (rrset, sigs)
    elif case in ("missing_keys", "child_missing_sig", "missing_ds", "missing_ds_sig"):
        kind = (
            dns.rdatatype.DNSKEY
            if case in ("missing_keys", "child_missing_sig")
            else dns.rdatatype.DS
        )
        fixture.data[CHILD, kind] = (
            () if case in ("missing_keys", "missing_ds") else fixture.data[CHILD, kind][:1]
        )

    class Responses:
        async def answer(self, query, *, deadline):
            response = await fixture.answer(query, deadline=deadline)
            if query.question[0].name == CHILD:
                if case == "servfail":
                    response.set_rcode(dns.rcode.SERVFAIL)
                    response.answer.clear()
            return response

    async def run():
        service = transport(Responses())
        _, port = await service.start("127.0.0.1", 0)
        try:
            owner = PositiveChains(resolver(upstream_port=port), {ROOT: anchor})
            if case == "duplicate_keys":
                # Named acquisition boundary supplies contradictory split
                # RRsets; the production exact-evidence gate must not pick one.
                async def ambiguous(name, kind, job):
                    response = dns.message.make_response(dns.message.make_query(name, kind))
                    response.answer.extend(fixture.data[name, kind])
                    response.answer.append(copy.deepcopy(fixture.data[name, kind][0]))
                    return response

                owner.resolver.exchange = ambiguous
            auth = await owner.authenticate(
                CHILD, ResolutionJob(time.monotonic() + 5), budget=CryptoBudget()
            )
            assert auth.state == expected
            assert (auth.trusted_keys is not None) is (expected == "secure")
            if case != "duplicate_keys":
                assert all(message.flags & dns.flags.AD for message in auth.messages)
            if expected == "secure":
                assert auth.trusted_keys == fixture.keys[CHILD]
                checked = check_signatures(
                    fixture.a,
                    fixture.answer_sigs,
                    auth.trusted_keys,
                    now=time.time(),
                    budget=CryptoBudget(),
                )
                assert checked.valid
            if case == "good":
                assert fixture.calls == [
                    (CHILD, dns.rdatatype.DNSKEY),
                    (CHILD, dns.rdatatype.DS),
                    (PARENT, dns.rdatatype.DNSKEY),
                    (PARENT, dns.rdatatype.DS),
                    (ROOT, dns.rdatatype.DNSKEY),
                ]
                first = list(fixture.calls)
                again = await owner.authenticate(
                    CHILD, ResolutionJob(time.monotonic() + 5), budget=CryptoBudget()
                )
                assert again.state == "secure" and fixture.calls == first + first
        finally:
            await service.close()
        assert not service._tasks and service._accepted == 0

    asyncio.run(run())


@pytest.mark.parametrize("limit", ["queries", "crypto", "private"])
def test_chain_retains_original_budgets_and_all_section_address_denial(limit):
    fixture = PublicDNS()

    class BadAdditional:
        async def answer(self, query, *, deadline):
            response = await fixture.answer(query, deadline=deadline)
            response.additional.append(dns.rrset.from_text("unrelated.", 60, "IN", "A", "10.0.0.1"))
            return response

    async def run():
        service = transport(BadAdditional() if limit == "private" else fixture)
        _, port = await service.start("127.0.0.1", 0)
        try:
            owner = PositiveChains(
                resolver(
                    upstream_port=port,
                    limits=ResolutionLimits(subqueries=1 if limit == "queries" else 64),
                ),
                {ROOT: fixture.keys[ROOT]},
            )
            with pytest.raises(RequestDenied):
                await owner.authenticate(
                    CHILD,
                    ResolutionJob(time.monotonic() + 5),
                    budget=CryptoBudget(0 if limit == "crypto" else 128),
                )
        finally:
            await service.close()

    asyncio.run(run())


def test_upstream_anchor_is_explicit_copied_and_never_an_implicit_synthetic_root():
    fixture = PublicDNS()
    with pytest.raises(ValueError, match="explicit"):
        PositiveChains(resolver(), {})
    with pytest.raises(ValueError, match="scope"):
        PositiveChains(resolver(), {PARENT: fixture.keys[ROOT]})
    original = fixture.keys[ROOT]
    owner = PositiveChains(resolver(), {ROOT: original})
    original.clear()
    assert owner._anchors[ROOT]


def test_expired_original_job_cannot_return_authenticated_success(monkeypatch):
    fixture = PublicDNS()
    instance = resolver()

    async def external(name, kind, job):
        query = dns.message.make_query(name, kind, want_dnssec=True)
        query.flags |= dns.flags.CD
        return await fixture.answer(query, deadline=job.deadline)

    monkeypatch.setattr(instance, "exchange", external)

    async def run():
        owner = PositiveChains(instance, {ROOT: fixture.keys[ROOT]})
        with pytest.raises(RequestDenied, match="dns_resolution_deadline"):
            await owner.authenticate(
                ROOT, ResolutionJob(time.monotonic() - 1), budget=CryptoBudget()
            )

    asyncio.run(run())


def test_chain_expansion_limit_is_silent_denial_not_dnssec_diagnostic():
    fixture = PublicDNS()

    async def run():
        owner = PositiveChains(resolver(), {ROOT: fixture.keys[ROOT]})
        with pytest.raises(RequestDenied, match="chain_depth_or_cycle"):
            await owner._zone(
                CHILD, ResolutionJob(time.monotonic() + 5), CryptoBudget(), {}, frozenset((CHILD,))
            )

    asyncio.run(run())
