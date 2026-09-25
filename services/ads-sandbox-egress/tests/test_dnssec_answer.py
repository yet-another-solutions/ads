import asyncio
import base64
import copy
import shutil
import time

import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype
import dns.rrset
import pytest

from ads_sandbox_egress.dnssec_answer import AnswerAuthentication
from ads_sandbox_egress.dnssec_chain import PositiveChains
from ads_sandbox_egress.dnssec_validation import CryptoBudget
from ads_sandbox_egress.policy import RequestDenied
from ads_sandbox_egress.resolution import ResolutionJob, ResolutionLimits
from test_dns_transport import transport
from test_dnssec_chain import CHILD, HOST, ROOT, PublicDNS
from test_dnssec_denial import Zone
from test_dnssec_validation import corrupt, material, signature
from test_resolution import resolver


def response(name, kind, records=()):
    message = dns.message.make_response(dns.message.make_query(name, kind, want_dnssec=True))
    message.answer.extend(records)
    message.flags |= dns.flags.AD
    return message


def classify(message, fixture, anchors=None, *, budget=128, limits=None, deadline=None):
    async def run():
        service = transport(fixture)
        _, port = await service.start("127.0.0.1", 0)
        try:
            owner = AnswerAuthentication(
                PositiveChains(
                    resolver(upstream_port=port, limits=limits),
                    anchors or {ROOT: fixture.keys[ROOT]},
                )
            )
            result = await owner.classify(
                message,
                ResolutionJob(time.monotonic() + 5 if deadline is None else deadline),
                budget=CryptoBudget(budget),
            )
            return result
        finally:
            await service.close()
            assert not service._tasks and not service._writers

    return asyncio.run(run())


@pytest.mark.parametrize(
    "case,state",
    [
        ("good", "secure"),
        ("bad", "bogus"),
        ("expired", "bogus"),
        ("future", "bogus"),
        ("alternative", "secure"),
        ("missing", "indeterminate"),
        ("unsupported", "indeterminate"),
        ("wrong_zone", "indeterminate"),
        ("bad_chain", "bogus"),
        ("unrelated", "indeterminate"),
        ("servfail", "indeterminate"),
        ("no_ad", "secure"),
    ],
)
def test_positive_answer_status_is_locally_verified_not_ad(case, state):
    fixture = PublicDNS()
    sig = next(iter(fixture.answer_sigs))
    sigs = fixture.answer_sigs
    if case == "bad":
        sigs = dns.rrset.from_rdata(HOST, 60, corrupt(sig))
    elif case == "expired":
        sigs = dns.rrset.from_rdata(HOST, 60, sig.replace(expiration=fixture.now - 1))
    elif case == "future":
        sigs = dns.rrset.from_rdata(HOST, 60, sig.replace(inception=fixture.now + 1))
    elif case == "alternative":
        sigs = dns.rrset.from_rdata(HOST, 60, corrupt(sig), sig)
    elif case == "unsupported":
        sigs = dns.rrset.from_rdata(HOST, 60, sig.replace(algorithm=253))
    elif case == "wrong_zone":
        sigs = dns.rrset.from_rdata(HOST, 60, sig.replace(signer=dns.name.from_text("unrelated.")))
    elif case == "bad_chain":
        keys, key_sigs = fixture.data[CHILD, dns.rdatatype.DNSKEY]
        fixture.data[CHILD, dns.rdatatype.DNSKEY] = (
            keys,
            dns.rrset.from_rdata(CHILD, 60, corrupt(next(iter(key_sigs)))),
        )
    message = response(HOST, "A", (fixture.a,) if case == "missing" else (fixture.a, sigs))
    if case == "unrelated":
        message.question = dns.message.make_query("another.example.", "A").question
    if case == "servfail":
        message.set_rcode(dns.rcode.SERVFAIL)
    if case == "no_ad":
        message.flags &= ~dns.flags.AD
    original = copy.deepcopy(message)
    result = classify(message, fixture)
    assert result.state == state
    assert result.resolution_failure is (case == "servfail")
    assert message == original and message.flags == original.flags
    if case == "alternative":
        assert result.records[0].checks[0].valid
        assert result.records[0].checks[0].failures


class ZoneDNS:
    """External zone fixture; real sockets, acquisition and crypto on ADS side."""

    def __init__(self, family, *, optout=False):
        self.zone = Zone(family, opt_out=optout, now=int(time.time()))
        self.keys = {self.zone.keys.name: self.zone.keys}
        self.soa = dns.rrset.from_text(
            "example.", 60, "IN", "SOA", "ns.example. hostmaster.example. 1 60 60 60 60"
        )
        self.calls = 0

    async def answer(self, query, *, deadline):
        self.calls += 1
        message = dns.message.make_response(query)
        if query.question[0].name == self.zone.keys.name:
            message.answer.extend(self.zone.resign(self.zone.keys))
        return message

    def negative(self, name, *, nx=False, qtype="AAAA"):
        message = response(name, qtype)
        if nx:
            message.set_rcode(dns.rcode.NXDOMAIN)
        message.authority.extend(self.zone.resign(self.soa))
        for pair in self.zone.proofs:
            message.authority.extend(pair)
        return message


@pytest.mark.parametrize("family", ["NSEC", "NSEC3"])
@pytest.mark.parametrize(
    "case,name,nx,state",
    [
        ("good", "www.example.", False, "secure"),
        ("empty", "leaf.example.", False, "secure"),
        ("nx", "absent.example.", True, "secure"),
        ("wild_nodata", "new.wild.example.", False, "secure"),
        ("missing_proof", "www.example.", False, "bogus"),
        ("bad_proof", "www.example.", False, "bogus"),
        ("wrong_type", "www.example.", False, "bogus"),
        ("missing_soa", "www.example.", False, "indeterminate"),
        ("bad_soa", "www.example.", False, "bogus"),
        ("wrong_zone", "outside.", False, "indeterminate"),
    ],
)
def test_negative_answers_require_authenticated_zone_and_proof(family, case, name, nx, state):
    fixture = ZoneDNS(family)
    message = fixture.negative(name, nx=nx, qtype="A" if case == "wrong_type" else "AAAA")
    if case == "missing_proof":
        message.authority = message.authority[:2]
    if case == "missing_soa":
        message.authority = message.authority[2:]
    if case in ("bad_soa", "bad_proof"):
        for i, item in enumerate(message.authority):
            if item.rdtype == dns.rdatatype.RRSIG and (
                (item.covers == dns.rdatatype.SOA) is (case == "bad_soa")
            ):
                message.authority[i] = dns.rrset.from_rdata(
                    item.name, 60, corrupt(next(iter(item)))
                )
    result = classify(message, fixture, fixture.keys)
    assert result.state == state
    if state == "secure":
        assert result.denials[-1].valid
    assert not result.resolution_failure


@pytest.mark.parametrize("family,optout", [("NSEC", False), ("NSEC3", False), ("NSEC3", True)])
@pytest.mark.parametrize("missing", [False, True])
def test_positive_wildcard_requires_next_closer_proof(family, optout, missing):
    fixture = ZoneDNS(family, optout=optout)
    wildcard = dns.rrset.from_text("*.wild.example.", 60, "IN", "A", "1.1.1.1")
    rrset, sigs = fixture.zone.resign(wildcard)
    rrset, sigs = copy.deepcopy(rrset), copy.deepcopy(sigs)
    rrset.name = sigs.name = dns.name.from_text("new.wild.example.")
    message = response(rrset.name, "A", (rrset, sigs))
    if not missing:
        for pair in fixture.zone.proofs:
            message.authority.extend(pair)
    result = classify(message, fixture, fixture.keys)
    assert result.state == ("bogus" if missing else "insecure" if optout else "secure")
    assert not result.records[0].denials[0].valid if missing else result.records[0].denials[0].valid


@pytest.mark.parametrize("case", ["good", "bad", "missing", "signed_bad"])
def test_dname_synthesis_inherits_only_matching_authenticated_dname(case):
    fixture = PublicDNS()
    dname = dns.rrset.from_text("old.nested.example.", 60, "IN", "DNAME", "new.nested.example.")
    cname = dns.rrset.from_text(
        "www.old.nested.example.",
        60,
        "IN",
        "CNAME",
        "wrong.nested.example." if case == "bad" else "www.new.nested.example.",
    )
    terminal = dns.rrset.from_text(
        "wrong.nested.example." if case == "bad" else "www.new.nested.example.",
        60,
        "IN",
        "A",
        "1.1.1.1",
    )
    message = response(
        cname.name, "A", (*fixture.signed(dname, CHILD), *fixture.signed(terminal, CHILD))
    )
    if case != "missing":
        message.answer.append(cname)
    if case == "signed_bad":
        _, signatures = fixture.signed(cname, CHILD)
        message.answer.append(dns.rrset.from_rdata(cname.name, 60, corrupt(next(iter(signatures)))))
    result = classify(message, fixture)
    assert result.state == (
        "secure" if case == "good" else "indeterminate" if case == "missing" else "bogus"
    )
    if case == "good":
        synthesized = [r for r in result.records if r.synthesized_from]
        assert len(synthesized) == 1 and synthesized[0].synthesized_from == dname.name


def test_signed_alias_with_terminal_nxdomain_checks_both_alias_and_denial():
    fixture = ZoneDNS("NSEC3")
    cname = dns.rrset.from_text("alias.example.", 60, "IN", "CNAME", "absent.example.")
    message = fixture.negative(cname.name, nx=True, qtype="A")
    message.answer.extend(fixture.zone.resign(cname))
    result = classify(message, fixture, fixture.keys)
    assert result.state == "secure" and result.denials[-1].valid
    message.answer[1] = dns.rrset.from_rdata(cname.name, 60, corrupt(next(iter(message.answer[1]))))
    assert classify(message, fixture, fixture.keys).state == "bogus"


@pytest.mark.parametrize("case", ["private", "budget", "queries", "deadline", "duplicates", "loop"])
def test_classifier_keeps_denial_limits_and_all_section_gates(case):
    fixture = PublicDNS()
    message = response(HOST, "A", (fixture.a, fixture.answer_sigs))
    if case == "private":
        message.additional.append(dns.rrset.from_text("unrelated.", 60, "IN", "A", "10.0.0.1"))
    if case == "duplicates":
        message.answer.append(copy.deepcopy(fixture.a))
    if case == "loop":
        message.answer = [dns.rrset.from_text(HOST, 60, "IN", "CNAME", HOST.to_text())]
    with pytest.raises(RequestDenied):
        classify(
            message,
            fixture,
            budget=0 if case == "budget" else 128,
            limits=ResolutionLimits(subqueries=1) if case == "queries" else None,
            deadline=time.monotonic() - 1 if case == "deadline" else None,
        )


@pytest.mark.parametrize("family", ["NSEC", "NSEC3"])
@pytest.mark.parametrize(
    "case", ["unsigned", "island", "missing_proof", "specific_anchor", "no_soa"]
)
def test_unsigned_descendant_needs_parent_delegation_not_just_unsigned_soa(family, case):
    fixture = ZoneDNS(family)
    child = dns.name.from_text("child.example.")
    host = dns.name.from_text("www.child.example.")
    child_secret, child_key = material()
    child_keys = dns.rrset.from_rdata(child, 60, child_key)
    child_soa = dns.rrset.from_text(
        child, 60, "IN", "SOA", "ns.child.example. admin.child.example. 1 60 60 60 60"
    )
    a = dns.rrset.from_text(host, 60, "IN", "A", "1.1.1.1")
    message = response(host, "A", (a,))

    class View:
        async def answer(self, query, *, deadline):
            question = query.question[0]
            if question.name == fixture.zone.keys.name:
                return await fixture.answer(query, deadline=deadline)
            result = dns.message.make_response(query)
            if question.rdtype == dns.rdatatype.SOA and case != "no_soa":
                result.authority.append(child_soa)
            if question.name == child and question.rdtype == dns.rdatatype.DS:
                if case != "missing_proof":
                    for pair in fixture.zone.proofs:
                        result.authority.extend(pair)
            if question.name == child and question.rdtype == dns.rdatatype.DNSKEY:
                if case == "island":
                    result.answer.extend(
                        (
                            child_keys,
                            dns.rrset.from_rdata(
                                child,
                                60,
                                signature(
                                    child_keys,
                                    child_secret,
                                    child_key,
                                    fixture.zone.now - 60,
                                    fixture.zone.now + 600,
                                    child,
                                ),
                            ),
                        )
                    )
            return result

    if case == "island":
        message.answer.append(
            dns.rrset.from_rdata(
                host,
                60,
                signature(
                    a, child_secret, child_key, fixture.zone.now - 60, fixture.zone.now + 600, child
                ),
            )
        )
    anchors = dict(fixture.keys)
    if case == "specific_anchor":
        anchors[host] = dns.rrset.from_rdata(host, 60, material()[1])
    result = classify(message, View(), anchors)
    assert result.state == ("insecure" if case in ("unsigned", "island") else "indeterminate")
    if case == "unsigned":
        assert result.discovery_messages
        assert any(zone.state == "insecure" and zone.denials[-1].valid for zone in result.zones)


def test_missing_required_signature_at_authenticated_apex_is_bogus():
    fixture = ZoneDNS("NSEC")
    message = response("example.", "SOA", (fixture.soa,))

    class View:
        async def answer(self, query, *, deadline):
            if query.question[0].rdtype == dns.rdatatype.SOA:
                result = dns.message.make_response(query)
                result.answer.extend(fixture.zone.resign(fixture.soa))
                return result
            return await fixture.answer(query, deadline=deadline)

    result = classify(message, View(), fixture.keys)
    assert result.state == "bogus"
    assert result.records[0].checks[0].failures[0].defect == "signature_missing"


@pytest.mark.parametrize("family", ["NSEC", "NSEC3"])
@pytest.mark.parametrize("case", ["noncut", "unsigned_cut", "missing_proof", "missing_signatures"])
def test_signing_expectation_walk_uses_authenticated_cut_proofs(family, case):
    fixture = ZoneDNS(family)
    name = "www.child.example." if case == "unsigned_cut" else "www.example."
    a = dns.rrset.from_text(name, 60, "IN", "A", "1.1.1.1")
    message = response(name, "A", (a,))

    class View:
        async def answer(self, query, *, deadline):
            question = query.question[0]
            if question.rdtype == dns.rdatatype.DNSKEY:
                return await fixture.answer(query, deadline=deadline)
            result = dns.message.make_response(query)
            if question.rdtype == dns.rdatatype.SOA:
                # A signed ancestor SOA does not rule out an unsigned cut.
                result.authority.extend(fixture.zone.resign(fixture.soa))
            elif question.rdtype == dns.rdatatype.DS and case != "missing_proof":
                for records, signatures in fixture.zone.proofs:
                    result.authority.append(records)
                    if case != "missing_signatures":
                        result.authority.append(signatures)
            return result

    result = classify(message, View(), fixture.keys)
    assert result.state == (
        "bogus" if case == "noncut" else "insecure" if case == "unsigned_cut" else "indeterminate"
    )
    if case == "noncut":
        assert result.records[0].checks[0].failures[0].defect == "signature_missing"
        assert result.denials[-1].valid
    if case == "unsigned_cut":
        assert result.denials[-1].valid


@pytest.mark.parametrize(
    "case", ["query", "truncated", "multi_question", "any_conflict", "nxdomain"]
)
def test_protocol_conflicts_cannot_be_authenticated(case):
    fixture = PublicDNS()
    message = response(
        HOST, "ANY" if case == "any_conflict" else "A", (fixture.a, fixture.answer_sigs)
    )
    if case == "query":
        message.flags &= ~dns.flags.QR
    if case == "truncated":
        message.flags |= dns.flags.TC
    if case == "multi_question":
        message.question.append(dns.rrset.from_text("other.", 0, "IN", "A"))
    if case == "any_conflict":
        message.answer.extend(
            fixture.signed(dns.rrset.from_text(HOST, 60, "IN", "CNAME", "other.example."), CHILD)
        )
    if case == "nxdomain":
        message.set_rcode(dns.rcode.NXDOMAIN)
    with pytest.raises(RequestDenied):
        classify(message, fixture)


def test_closest_configured_anchor_prevents_signed_parent_downgrade():
    fixture = PublicDNS()
    a = dns.rrset.from_text("host.nested.example.", 60, "IN", "A", "1.1.1.1")
    message = response(a.name, "A", fixture.signed(a, ROOT))
    # A public root signature cannot bypass an independently pinned child.
    anchors = {ROOT: fixture.keys[ROOT], CHILD: fixture.keys[CHILD]}
    assert classify(message, fixture, anchors).state == "indeterminate"


def test_explicit_cname_query_keeps_required_dname_synthesis():
    fixture = PublicDNS()
    dname = dns.rrset.from_text("old.nested.example.", 60, "IN", "DNAME", "new.nested.example.")
    cname = dns.rrset.from_text(
        "host.old.nested.example.", 60, "IN", "CNAME", "host.new.nested.example."
    )
    message = response(cname.name, "CNAME", (*fixture.signed(dname, CHILD), cname))
    assert classify(message, fixture).state == "secure"
    wrong = dns.rrset.from_text(cname.name, 60, "IN", "CNAME", "wrong.nested.example.")
    message.answer = [*fixture.signed(dname, CHILD), *fixture.signed(wrong, CHILD)]
    assert classify(message, fixture).state == "bogus"


@pytest.mark.parametrize("case", ["good", "bad", "expired", "future", "alternative"])
def test_independent_delv_matches_complete_positive_answer_classification(tmp_path, case):
    if shutil.which("delv") is None:
        pytest.skip("independent BIND delv unavailable")
    fixture = PublicDNS()
    original = next(iter(fixture.answer_sigs))
    selected = original
    if case == "bad":
        selected = corrupt(original)
    if case in ("expired", "future"):
        start, end = (
            (fixture.now - 120, fixture.now - 60)
            if case == "expired"
            else (fixture.now + 60, fixture.now + 120)
        )
        selected = signature(
            fixture.a, fixture.private[CHILD], next(iter(fixture.keys[CHILD])), start, end, CHILD
        )
    sigs = dns.rrset.from_rdata(
        HOST, 60, *((corrupt(original), original) if case == "alternative" else (selected,))
    )
    fixture.data[HOST, dns.rdatatype.A] = (fixture.a, sigs)
    message = response(HOST, "A", (fixture.a, sigs))
    anchor = tmp_path / "upstream.anchor"
    anchor.write_text(
        'trust-anchors { "." static-key 257 3 15 "'
        + base64.b64encode(next(iter(fixture.keys[ROOT])).key).decode()
        + '"; };\n'
    )

    class View:
        async def answer(self, query, *, deadline):
            # Unlike the ADS-only upstream fixture, an independent validator
            # controls its own CD query flag. Never give it a trusted AD bit.
            result = dns.message.make_response(query)
            result.flags |= dns.flags.RA
            result.flags &= ~dns.flags.AD
            question = query.question[0]
            result.answer.extend(fixture.data.get((question.name, question.rdtype), ()))
            return result

    async def run():
        server = transport(View())
        host, port = await server.start("127.0.0.1", 0)
        process = None
        try:
            owner = AnswerAuthentication(
                PositiveChains(resolver(upstream_port=port), {ROOT: fixture.keys[ROOT]})
            )
            classified = await owner.classify(
                message, ResolutionJob(time.monotonic() + 5), budget=CryptoBudget()
            )
            process = await asyncio.create_subprocess_exec(
                "delv",
                "@" + host,
                "-p",
                str(port),
                "-a",
                str(anchor),
                HOST.to_text(),
                "A",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            out, err = await asyncio.wait_for(process.communicate(), 5)
            expected = case in ("good", "alternative")
            assert (classified.state == "secure") is expected
            assert (b"fully validated" in out + err) is expected, out + err
            if not expected:
                assert classified.state == "bogus"
                assert b"resolution failed" in out + err
        finally:
            if process is not None and process.returncode is None:
                process.kill()
                await process.communicate()
            await server.close()

    asyncio.run(run())
