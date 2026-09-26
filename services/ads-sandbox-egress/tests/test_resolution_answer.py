import asyncio
import copy
import time
from dataclasses import replace

import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype
import dns.rrset
import pytest

from ads_sandbox_egress.dnssec_answer import AnswerAuthentication
from ads_sandbox_egress.dnssec_chain import PositiveChains
from ads_sandbox_egress.dnssec_identity import DNSSECUnrepresentable
from ads_sandbox_egress.dnssec_validation import CryptoBudget
from ads_sandbox_egress.resolution import ResolutionJob
from ads_sandbox_egress.resolution_answer import assemble
from test_dns_transport import transport
from test_dnssec_chain import CHILD, HOST, ROOT, PublicDNS
from test_resolution import resolver


@pytest.mark.parametrize("alias", ["cname", "dname", "explicit_cname"])
@pytest.mark.parametrize("defect", ["secure", "bad_terminal", "servfail", "nxdomain"])
def test_real_acquisition_assembles_alias_before_classification(alias, defect):
    fixture = PublicDNS()
    target = dns.name.from_text("target.nested.example.")
    owner = HOST
    if alias in ("dname", "explicit_cname"):
        owner = dns.name.from_text("www.alias.nested.example.")
        target = dns.name.from_text("www.target.nested.example.")
        first = fixture.signed(
            dns.rrset.from_text(
                "alias.nested.example.", 20, "IN", "DNAME", "target.nested.example."
            ),
            CHILD,
        )
        # Deliberately absent synthesized CNAME: ADS must create the exact
        # protocol-required record without inventing a separate signature.
    else:
        first = fixture.signed(dns.rrset.from_text(owner, 20, "IN", "CNAME", str(target)), CHILD)
    kind = dns.rdatatype.CNAME if alias == "explicit_cname" else dns.rdatatype.A
    fixture.data[owner, kind] = first
    a = dns.rrset.from_text(target, 60, "IN", "A", "1.1.1.1")
    a_set, sigs = fixture.signed(a, CHILD)
    if defect == "bad_terminal":
        from test_dnssec_validation import corrupt

        sigs = dns.rrset.from_rdata(target, 60, corrupt(next(iter(sigs))))
    fixture.data[target, dns.rdatatype.A] = a_set, sigs

    class View:
        async def answer(self, query, *, deadline):
            result = await fixture.answer(query, deadline=deadline)
            q = query.question[0]
            if q.name == target and defect in ("servfail", "nxdomain"):
                result.answer.clear()
                result.set_rcode(dns.rcode.SERVFAIL if defect == "servfail" else dns.rcode.NXDOMAIN)
                if defect == "nxdomain":
                    soa = dns.rrset.from_text(
                        CHILD, 30, "IN", "SOA", f"ns.{CHILD} admin.{CHILD} 1 60 60 60 60"
                    )
                    result.authority.extend(fixture.signed(soa, CHILD))
                    proof = dns.rrset.from_text(
                        CHILD, 30, "IN", "NSEC", f"z.{CHILD} SOA NS RRSIG NSEC DNSKEY"
                    )
                    result.authority.extend(fixture.signed(proof, CHILD))
            result.additional.append(dns.rrset.from_text("unrelated.", 0, "IN", "A", "8.8.8.8"))
            return result

    async def run():
        server = transport(View())
        _, port = await server.start("127.0.0.1", 0)
        upstream = resolver(upstream_port=port)
        job = ResolutionJob(time.monotonic() + 10)
        try:
            acquired = await upstream.acquire(owner.to_text(), kind, job=job)
            combined = assemble(acquired, deadline=job.deadline)
            assert not combined.additional and not combined.flags & dns.flags.AD
            assert all(rrset.name.to_text() != "unrelated." for rrset in combined.answer)
            if alias == "explicit_cname":
                assert any(rrset.rdtype == dns.rdatatype.CNAME for rrset in combined.answer)
                assert not any(rrset.rdtype == dns.rdatatype.A for rrset in combined.answer)
            elif defect == "servfail":
                assert combined.rcode() == dns.rcode.SERVFAIL
                assert not combined.answer and not combined.authority
                return
            else:
                assert combined.rcode() == (3 if defect == "nxdomain" else 0)
                assert any(rrset.rdtype == dns.rdatatype.CNAME for rrset in combined.answer)
                assert bool(combined.authority) == (defect == "nxdomain")
                assert any(rrset.rdtype == dns.rdatatype.A for rrset in combined.answer) == (
                    defect != "nxdomain"
                )
            auth = await AnswerAuthentication(
                PositiveChains(upstream, {ROOT: fixture.keys[ROOT]})
            ).classify(combined, job, budget=CryptoBudget())
            assert auth.state == (
                "bogus" if defect == "bad_terminal" and alias != "explicit_cname" else "secure"
            )
            for rrset in combined.answer:
                if rrset.rdtype in (dns.rdatatype.CNAME, dns.rdatatype.DNAME):
                    assert rrset.ttl <= 20
        finally:
            await server.close()

    asyncio.run(run())


def test_elapsed_ttl_and_conflicting_observations_are_not_repaired():
    from ads_sandbox_egress.resolution import AcquiredAnswer

    q = dns.message.make_query("example.", "A")
    response = dns.message.make_response(q)
    response.answer.append(dns.rrset.from_text("example.", 30, "IN", "A", "1.1.1.1"))
    now = time.monotonic()
    acquired = AcquiredAnswer(
        q.question[0].name,
        q.question[0].rdtype,
        (response,),
        frozenset(),
        now + 30,
        received_at=(now - 2.2,),
    )
    result = assemble(acquired, deadline=now + 10, now=now)
    assert result.answer[0].ttl == 27 and response.answer[0].ttl == 30
    later = copy.deepcopy(response)
    later.answer[0].ttl = 30
    repeated = replace(acquired, messages=(response, later), received_at=(now - 2.2, now))
    assert assemble(repeated, deadline=now + 10, now=now).answer[0].ttl == 27
    later.answer[0] = dns.rrset.from_text("example.", 30, "IN", "A", "8.8.8.8")
    with pytest.raises(DNSSECUnrepresentable, match="conflicting"):
        assemble(repeated, deadline=now + 10, now=now)
    with pytest.raises(DNSSECUnrepresentable, match="timestamps"):
        assemble(replace(acquired, received_at=()), deadline=now + 10)


@pytest.mark.parametrize("separate", [False, True])
def test_in_packet_alias_negative_answer_and_newer_failure(separate):
    from ads_sandbox_egress.resolution import AcquiredAnswer

    now = time.monotonic()
    query = dns.message.make_query("www.example.", "A")
    response = dns.message.make_response(query)
    response.set_rcode(dns.rcode.NXDOMAIN)
    response.answer.append(
        dns.rrset.from_text("www.example.", 30, "IN", "CNAME", "missing.example.")
    )
    response.authority.extend(
        (
            dns.rrset.from_text(
                "example.", 30, "IN", "SOA", "ns.example. admin.example. 1 60 60 60 60"
            ),
            dns.rrset.from_text("example.", 30, "IN", "NSEC", "z.example. SOA NS NSEC RRSIG"),
        )
    )
    messages = [response]
    if separate:
        newer = dns.message.make_response(dns.message.make_query("missing.example.", "A"))
        newer.set_rcode(dns.rcode.SERVFAIL)
        messages.append(newer)
    acquired = AcquiredAnswer(
        query.question[0].name,
        query.question[0].rdtype,
        tuple(messages),
        frozenset(),
        now,
        received_at=tuple(now for _ in messages),
    )
    result = assemble(acquired, deadline=now + 10)
    assert result.rcode() == (dns.rcode.SERVFAIL if separate else dns.rcode.NXDOMAIN)
    assert bool(result.answer) != separate
    assert bool(result.authority) != separate
