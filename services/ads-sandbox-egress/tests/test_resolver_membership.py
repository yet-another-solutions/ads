import asyncio
import ipaddress

import dns.message
import dns.name
import dns.rdatatype
import dns.rrset
import h11
import pytest

from ads_commons.egress import ProjectEgressSnapshot
from ads_sandbox_egress.configuration import PolicyStore
from ads_sandbox_egress.dnssec_answer import AnswerAuthentication
from ads_sandbox_egress.dnssec_chain import PositiveChains
from ads_sandbox_egress.membership import ConnectionMembership
from ads_sandbox_egress.policy import RequestDenied
from ads_sandbox_egress.request_authorization import (
    ConnectionTarget,
    RequestAuthorizer,
    RequestHead,
)
from ads_sandbox_egress.resolution import ResolutionLimits
from ads_sandbox_egress.resolver_membership import FreshMembership
from test_dns_transport import transport
from test_dnssec_chain import CHILD, HOST, ROOT, PublicDNS
from test_dnssec_validation import corrupt
from test_http1_proxy import settings
from test_normalization import nginx_helper as nginx_helper
from test_resolution import resolver


class DNS(PublicDNS):
    def __init__(self, *, ttl=60, broken=False):
        super().__init__()
        self.target = dns.name.from_text("cdn.nested.example.")
        self.target_ip = ipaddress.ip_address("1.0.0.1")
        a = dns.rrset.from_text(HOST, ttl, "IN", "A", "1.1.1.1")
        rrset, sigs = self.signed(a, CHILD)
        if broken:
            sigs = dns.rrset.from_rdata(HOST, ttl, corrupt(next(iter(sigs))))
        self.data[HOST, dns.rdatatype.A] = (rrset, sigs)
        target_a = dns.rrset.from_text(self.target, ttl, "IN", "A", str(self.target_ip))
        self.data[self.target, dns.rdatatype.A] = self.signed(target_a, CHILD)
        service = dns.rrset.from_text(
            HOST, ttl, "IN", "HTTPS", f"1 {self.target} port=8443 ipv4hint=9.9.9.9"
        )
        self.data[HOST, dns.rdatatype.HTTPS] = self.signed(service, CHILD)


def adapter(port, fixture, *, limits=None):
    return FreshMembership(
        AnswerAuthentication(
            PositiveChains(resolver(upstream_port=port, limits=limits), {ROOT: fixture.keys[ROOT]})
        )
    )


@pytest.mark.parametrize("broken", [False, True])
def test_real_membership_uses_independent_target_addresses_not_hint_or_trust_bit(broken):
    fixture = DNS(broken=broken)

    async def run():
        server = transport(fixture)
        _, port = await server.start("127.0.0.1", 0)
        owner = adapter(port, fixture)
        membership = ConnectionMembership(owner, owner.resolver.boundary.addresses)
        try:
            name = HOST.to_text().rstrip(".")
            evidence = await owner.resolve(name, authority_port=443, protocol="https")
            assert evidence.complete
            assert evidence.direct_addresses == frozenset((ipaddress.ip_address("1.1.1.1"),))
            assert {item.address for item in evidence.service_endpoints} == {fixture.target_ip}
            if broken:
                assert evidence.authentication == "bogus"
            # Actual membership remains independent of DNSSEC acceptance.
            await membership.require(name, fixture.target_ip, 8443, 443, protocol="https")
            calls = len(fixture.calls)
            await membership.require(name, fixture.target_ip, 8443, 443, protocol="https")
            assert len(fixture.calls) == calls
            for address, destination_port, authority_port in (
                ("9.9.9.9", 8443, 443),  # Uncorroborated public hint.
                (str(fixture.target_ip), 443, 443),  # No direct-target flattening.
                (str(fixture.target_ip), 8443, 444),  # Different service identity.
            ):
                with pytest.raises(RequestDenied):
                    await membership.require(
                        name,
                        ipaddress.ip_address(address),
                        destination_port,
                        authority_port,
                        protocol="https",
                    )
        finally:
            await membership.close()
            await server.close()

    asyncio.run(run())


def test_cache_and_https_lookup_are_scoped_to_protocol_and_authority_port():
    fixture = DNS()
    prefixed = dns.name.from_text("_9443._https." + HOST.to_text())
    service = dns.rrset.from_text(prefixed, 60, "IN", "HTTPS", f"1 {fixture.target} port=10443")
    fixture.data[prefixed, dns.rdatatype.HTTPS] = fixture.signed(service, CHILD)

    async def run():
        server = transport(fixture)
        _, port = await server.start("127.0.0.1", 0)
        owner = adapter(port, fixture)
        membership = ConnectionMembership(owner, owner.resolver.boundary.addresses)
        try:
            name = HOST.to_text().rstrip(".")
            await membership.require(name, fixture.target_ip, 10443, 9443, protocol="https")
            assert (prefixed, dns.rdatatype.HTTPS) in fixture.calls
            with pytest.raises(RequestDenied):
                await membership.require(name, fixture.target_ip, 10443, 443, protocol="https")
            assert (HOST, dns.rdatatype.HTTPS) in fixture.calls
            before = len(fixture.calls)
            with pytest.raises(RequestDenied):
                await membership.require(name, fixture.target_ip, 8443, 443, protocol="http")
            assert all(kind != dns.rdatatype.HTTPS for _, kind in fixture.calls[before:])
            assert len(membership._cache) == 3
        finally:
            await membership.close()
            await server.close()

    asyncio.run(run())


@pytest.mark.parametrize("case", ["private", "queries", "deadline", "empty", "failed_auth"])
def test_fresh_evidence_never_relaxes_mandatory_gates(case):
    fixture = DNS()

    class View:
        async def answer(self, query, *, deadline):
            if case == "empty":
                return dns.message.make_response(query)
            if case == "deadline":
                await asyncio.sleep(0.2)
            if case == "failed_auth" and query.question[0].rdtype == dns.rdatatype.DNSKEY:
                # Cryptographic evidence lookup fails, while the directly
                # acquired address and service relationships remain usable.
                result = dns.message.make_response(query)
                result.set_rcode(2)
                return result
            result = await fixture.answer(query, deadline=deadline)
            if case == "private":
                result.additional.append(
                    dns.rrset.from_text("unrelated.", 60, "IN", "A", "10.0.0.1")
                )
            return result

    async def run():
        server = transport(View())
        _, port = await server.start("127.0.0.1", 0)
        limits = (
            ResolutionLimits(subqueries=1)
            if case == "queries"
            else ResolutionLimits(deadline=0.03, exchange=0.02)
            if case == "deadline"
            else None
        )
        owner = adapter(port, fixture, limits=limits)
        membership = ConnectionMembership(owner, owner.resolver.boundary.addresses)
        try:
            operation = membership.require(
                HOST.to_text().rstrip("."),
                ipaddress.ip_address("1.1.1.1"),
                443,
                443,
                protocol="https",
            )
            if case == "failed_auth":
                await operation
                assert next(iter(membership._cache.values()))[0].authentication == "indeterminate"
            else:
                with pytest.raises(RequestDenied):
                    await operation
                assert not membership._cache
        finally:
            await membership.close()
            await server.close()

    asyncio.run(run())


def test_zero_ttl_relationship_is_current_only_and_next_lookup_is_fresh():
    fixture = DNS(ttl=0)

    async def run():
        server = transport(fixture)
        _, port = await server.start("127.0.0.1", 0)
        owner = adapter(port, fixture)
        cache = ConnectionMembership(owner, owner.resolver.boundary.addresses)
        try:
            for _ in range(2):
                previous = len(fixture.calls)
                await cache.require(
                    HOST.to_text().rstrip("."), fixture.target_ip, 8443, 443, protocol="https"
                )
                assert len(fixture.calls) > previous and not cache._cache
        finally:
            await cache.close()
            await server.close()

    asyncio.run(run())


@pytest.mark.parametrize("terminal", ["nodata", "servfail", "service", "unavailable", "private"])
def test_aliasmode_fallback_is_final_name_and_original_port_only(terminal):
    fixture = DNS()
    alias = dns.name.from_text("alias.nested.example.")
    fixture.data[HOST, dns.rdatatype.HTTPS] = fixture.signed(
        dns.rrset.from_text(HOST, 30, "IN", "HTTPS", f"0 {alias}"), CHILD
    )
    alias_a = dns.rrset.from_text(
        alias, 30, "IN", "A", "10.0.0.1" if terminal == "private" else "8.8.8.8"
    )
    fixture.data[alias, dns.rdatatype.A] = fixture.signed(alias_a, CHILD)
    if terminal == "unavailable":
        fixture.data[alias, dns.rdatatype.HTTPS] = fixture.signed(
            dns.rrset.from_text(alias, 30, "IN", "HTTPS", "0 ."), CHILD
        )
    if terminal == "service":
        fixture.data[alias, dns.rdatatype.HTTPS] = fixture.signed(
            dns.rrset.from_text(alias, 30, "IN", "HTTPS", f"1 {fixture.target} port=8443"), CHILD
        )

    class View:
        async def answer(self, query, *, deadline):
            result = await fixture.answer(query, deadline=deadline)
            q = query.question[0]
            if terminal == "servfail" and q.name == alias and q.rdtype == dns.rdatatype.HTTPS:
                result.set_rcode(2)
            return result

    async def run():
        server = transport(View())
        _, port = await server.start("127.0.0.1", 0)
        owner = adapter(port, fixture)
        cache = ConnectionMembership(owner, owner.resolver.boundary.addresses)
        try:
            name = HOST.to_text().rstrip(".")
            operation = cache.require(
                name, ipaddress.ip_address("8.8.8.8"), 443, 443, protocol="https"
            )
            if terminal in ("private", "unavailable"):
                with pytest.raises(RequestDenied):
                    await operation
            else:
                await operation
                with pytest.raises(RequestDenied):
                    await cache.require(
                        name, ipaddress.ip_address("8.8.8.8"), 5555, 443, protocol="https"
                    )
                if terminal == "service":
                    await cache.require(name, fixture.target_ip, 8443, 443, protocol="https")
        finally:
            await cache.close()
            await server.close()

    asyncio.run(run())


def test_pinned_parser_aliasmode_parameter_gap_is_explicit():
    # RFC 9460 says ignore AliasMode parameters, but dnspython 2.8.0 rejects
    # them on the wire. This is a capability-gap reproducer, NOT passing
    # support or permission to sanitize input before DNSSEC verification.
    import dns.exception

    value = next(
        iter(dns.rrset.from_text(HOST, 30, "IN", "HTTPS", "1 alias.nested.example. port=5555"))
    ).replace(priority=0)
    message = dns.message.make_response(dns.message.make_query(HOST, "HTTPS"))
    message.answer.append(dns.rrset.from_rdata(HOST, 30, value))
    with pytest.raises(dns.exception.FormError, match="parameters in AliasMode"):
        dns.message.from_wire(message.to_wire())


@pytest.mark.parametrize("version", ["http/1.1", "http/2"])
@pytest.mark.parametrize("case", ["allowed", "port_policy", "path_policy", "name_mismatch"])
def test_real_dns_and_nginx_authorization_preserve_authority_and_selected_endpoint(
    nginx_helper, version, case
):
    fixture = DNS(broken=True)

    async def run():
        server = transport(fixture)
        _, port = await server.start("127.0.0.1", 0)
        owner = adapter(port, fixture)
        cache = ConnectionMembership(owner, owner.resolver.boundary.addresses)
        policies = PolicyStore()
        name = HOST.to_text().rstrip(".")
        await policies.install(
            ProjectEgressSnapshot(
                1,
                settings(
                    "/allowed",
                    domain=name,
                    port=9443 if case == "port_policy" else 8443,
                    protocol="https",
                ),
            )
        )
        target = ConnectionTarget(
            fixture.target_ip,
            8443,
            True,
            "wrong.nested.example" if case == "name_mismatch" else name,
        )
        authorizer = RequestAuthorizer(target, policies, cache, nginx_helper)
        path = b"/wrong" if case == "path_policy" else b"/a/../allowed?raw=%2f"
        if version == "http/1.1":
            head = RequestHead.http1(
                h11.Request(method=b"GET", target=path, headers=[(b"host", name.encode())]), target
            )
        else:
            head = RequestHead.http2(
                (
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":authority", name.encode()),
                    (b":path", path),
                ),
                target,
            )
        try:
            if case == "allowed":
                result = await authorizer.authorize(head)
                assert result.normalized_path == b"/allowed"
                assert result.head is head and head.target == path
                assert head.authorities[0].host == name and head.authorities[0].port == 443
                assert target.address == fixture.target_ip and target.port == 8443
                assert next(iter(cache._cache.values()))[0].authentication == "bogus"
            else:
                with pytest.raises(RequestDenied):
                    await authorizer.authorize(head)
        finally:
            await cache.close()
            await policies.close()
            await server.close()

    asyncio.run(run())
