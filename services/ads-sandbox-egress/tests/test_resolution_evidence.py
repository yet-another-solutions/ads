import asyncio
import ipaddress
import time

import dns.message
import dns.rcode
import dns.rdatatype
import dns.rrset
import pytest

from ads_sandbox_egress.dnssec_chain import PositiveChains
from ads_sandbox_egress.dnssec_validation import CryptoBudget
from ads_sandbox_egress.policy import RequestDenied
from ads_sandbox_egress.resolution import ResolutionJob, ResolutionLimits
from test_dns_transport import transport
from test_dnssec_chain import ROOT, PublicDNS
from test_resolution import resolver


@pytest.mark.parametrize("kind", ["HTTPS", "SVCB"])
@pytest.mark.parametrize("alias", [False, True])
def test_service_addresses_keep_relationship_and_dependency_ttls(kind, alias):
    calls = []

    class View:
        async def answer(self, query, *, deadline):
            question = query.question[0]
            name = question.name.to_text()
            calls.append((name, question.rdtype))
            result = dns.message.make_response(query)
            if question.rdtype == dns.rdatatype.from_text(kind):
                if name == "example." and alias:
                    result.answer.append(
                        dns.rrset.from_text(name, 0, "IN", kind, "0 alias.example.")
                    )
                else:
                    result.answer.append(
                        dns.rrset.from_text(
                            name,
                            60,
                            "IN",
                            kind,
                            "1 target.example. port=8443 ipv4hint=9.9.9.9",
                            "2 other.example. port=9443",
                        )
                    )
                    # Public Additional data must not become either endpoint.
                    result.additional.append(
                        dns.rrset.from_text("unrelated.example.", 0, "IN", "A", "8.8.8.8")
                    )
            elif question.rdtype == dns.rdatatype.A:
                result.answer.append(
                    dns.rrset.from_text(
                        name,
                        1 if name == "target.example." else 40,
                        "IN",
                        "A",
                        "1.1.1.1" if name == "target.example." else "1.0.0.1",
                    )
                )
            return result

    async def run():
        server = transport(View())
        _, port = await server.start("127.0.0.1", 0)
        try:
            start = time.monotonic()
            acquired = await resolver(upstream_port=port).acquire(
                "example.", dns.rdatatype.from_text(kind)
            )
            assert not acquired.direct_addresses
            assert acquired.addresses == frozenset(
                map(ipaddress.ip_address, ("1.1.1.1", "1.0.0.1"))
            )
            assert len(acquired.services) == (3 if alias else 2)
            primary = [item for item in acquired.services if not item.fallback]
            assert len(primary) == 2
            assert sum(item.fallback for item in acquired.services) == int(alias)
            by_target = {item.target.to_text(): item for item in primary}
            for target, address, port_value in zip(
                ("target.example.", "other.example."),
                ("1.1.1.1", "1.0.0.1"),
                (8443, 9443),
                strict=True,
            ):
                service = by_target[target]
                assert service.owner.to_text() == ("alias.example." if alias else "example.")
                assert service.target.to_text() == target
                assert service.addresses == frozenset((ipaddress.ip_address(address),))
                assert service.record.params[3].port == port_value
                assert (target, dns.rdatatype.A) in calls
                assert (target, dns.rdatatype.AAAA) in calls
            assert acquired.expires_at <= start + (0.5 if alias else 1.5)
            if alias:
                assert all(item.expires_at <= start + 0.5 for item in acquired.services)
            else:
                assert by_target["other.example."].expires_at > start + 35
            assert "ipv4hint" in by_target["target.example."].record.to_text()
        finally:
            await server.close()

    asyncio.run(run())


@pytest.mark.parametrize("case", ["additional", "wrong_type", "servfail", "nxdomain", "conflict"])
def test_addresses_never_come_from_unrelated_records_or_error_answers(case):
    class View:
        async def answer(self, query, *, deadline):
            result = dns.message.make_response(query)
            a = dns.rrset.from_text("example.", 30, "IN", "A", "1.1.1.1")
            if case == "additional":
                result.additional.append(a)
            elif case == "wrong_type":
                result.answer.append(
                    dns.rrset.from_text("example.", 30, "IN", "HTTPS", "1 target.example.")
                )
            else:
                result.answer.append(a)
            if case in ("servfail", "nxdomain"):
                result.set_rcode(dns.rcode.SERVFAIL if case == "servfail" else dns.rcode.NXDOMAIN)
            if case == "conflict":
                result.answer.append(
                    dns.rrset.from_text("example.", 30, "IN", "CNAME", "target.example.")
                )
            return result

    async def run():
        server = transport(View())
        _, port = await server.start("127.0.0.1", 0)
        try:
            operation = resolver(upstream_port=port).acquire("example.", dns.rdatatype.A)
            if case == "conflict":
                with pytest.raises(RequestDenied, match="conflicting_dns_alias"):
                    await operation
            else:
                result = await operation
                assert not result.direct_addresses and not result.addresses and not result.services
                assert len(result.messages) == 1
        finally:
            await server.close()

    asyncio.run(run())


def test_address_acquisition_and_dnssec_share_one_subquery_budget():
    fixture = PublicDNS()
    fixture.data[ROOT, dns.rdatatype.A] = (dns.rrset.from_text(ROOT, 60, "IN", "A", "1.1.1.1"),)

    async def run():
        server = transport(fixture)
        _, port = await server.start("127.0.0.1", 0)
        try:
            instance = resolver(upstream_port=port, limits=ResolutionLimits(subqueries=1))
            job = ResolutionJob(time.monotonic() + 5)
            answer = await instance.acquire(".", dns.rdatatype.A, job=job)
            assert answer.direct_addresses and job.subqueries == 1
            with pytest.raises(RequestDenied, match="dns_subquery_limit"):
                await PositiveChains(instance, {ROOT: fixture.keys[ROOT]}).authenticate(
                    ROOT, job, budget=CryptoBudget()
                )
        finally:
            await server.close()

    asyncio.run(run())


def test_acquisition_does_not_renew_existing_deadline(monkeypatch):
    async def run():
        instance = resolver()
        finished = False

        async def delayed(name, kind, job):
            nonlocal finished
            await asyncio.sleep(0.2)
            finished = True
            return dns.message.make_response(dns.message.make_query(name, kind))

        monkeypatch.setattr(instance, "exchange", delayed)
        started = time.monotonic()
        with pytest.raises(RequestDenied, match="dns_resolution_deadline"):
            await instance.acquire("example.", dns.rdatatype.A, job=ResolutionJob(started + 0.03))
        assert not finished

    asyncio.run(run())


@pytest.mark.parametrize("deadline", [float("nan"), float("inf"), 0])
def test_invalid_job_deadline_is_not_unbounded(deadline):
    with pytest.raises(ValueError):
        ResolutionJob(deadline)
