import asyncio
import ipaddress
from dataclasses import replace

import pytest

from ads_sandbox_egress.destinations import (
    SPECIAL_PREFIXES,
    DestinationBoundary,
    ResolverBoundary,
)
from ads_sandbox_egress.membership import (
    ConnectionMembership,
    ResolutionEvidence,
    ServiceEndpoint,
)
from ads_sandbox_egress.policy import RequestDenied


def boundary():
    return DestinationBoundary(
        (ipaddress.ip_network("8.8.4.0/24"),),
        (ipaddress.ip_network("2001:4860:ffff::/48"),),
        "fixture-v1",
    )


@pytest.mark.parametrize("prefix", SPECIAL_PREFIXES)
def test_registry_entire_prefix_is_prohibited(prefix):
    network = ipaddress.ip_network(prefix)
    for address in (network.network_address, network.broadcast_address):
        with pytest.raises(RequestDenied):
            boundary().require_public(str(address))


@pytest.mark.parametrize(
    "value",
    [
        "8.8.4.4",
        "2001:4860:ffff::1",
        "4000::1",
        "::ffff:8.8.8.8",
        "192.0.0.9",
        "192.0.0.10",
        "2001:1::1",
        "2001:3::1",
    ],
)
def test_infrastructure_translation_and_globally_reachable_exceptions(value):
    with pytest.raises(RequestDenied):
        boundary().require_public(value)


def test_public_and_mapped_peer():
    expected = boundary().require_public("8.8.8.8")
    boundary().require_peer(expected, "::ffff:8.8.8.8")
    with pytest.raises(RequestDenied):
        boundary().require_peer(expected, "1.1.1.1")
    with pytest.raises(RequestDenied):
        boundary().require_public("::ffff:127.0.0.1", socket_peer=True)


def resolver_boundary(**kwargs):
    return ResolverBoundary.discover(
        "nameserver 10.0.0.10\nnameserver 10.0.0.11\n"
        "search ads.svc.cluster.example svc.cluster.example cluster.example\n"
        "domain internal.example\n",
        "ads",
        boundary(),
        **kwargs,
    )


def test_additive_exclusions_and_override():
    resolver = resolver_boundary(
        upstreams=("1.1.1.1",),
        zones=("private.example",),
        exact_names=("public-management.example",),
    )
    assert tuple(map(str, resolver.upstreams)) == ("1.1.1.1",)
    for name in (
        "cluster.example",
        "x.cluster.example.",
        "X.INTERNAL.EXAMPLE",
        "private.example",
        "public-management.example",
        "1.0.0.127.in-addr.arpa",
    ):
        with pytest.raises(RequestDenied):
            resolver.check_name(name)
    for name in (
        ".",
        "com",
        "singlelabel",
        "notcluster.example",
        "cluster.example.external",
        "8.8.8.8.in-addr.arpa",
    ):
        assert resolver.check_name(name) == name


def test_upstream_order_and_empty_inventory_failure():
    assert tuple(map(str, resolver_boundary().upstreams)) == ("10.0.0.10", "10.0.0.11")
    with pytest.raises(ValueError):
        ResolverBoundary.discover("nameserver 1.1.1.1", "ads", boundary())
    with pytest.raises(ValueError):
        ResolverBoundary.discover("nameserver 1.1.1.1\nsearch svc.a svc.b", "ads", boundary())


def test_membership_concurrency_expiry_failure_and_cancellation():
    async def run():
        now = [100.0]
        address = ipaddress.ip_address("8.8.8.8")

        class Resolver:
            calls = 0
            expires = 101.0
            fail = False
            gate = asyncio.Event()

            async def resolve(self, name):
                self.calls += 1
                await self.gate.wait()
                if self.fail:
                    raise RequestDenied("lookup_failed")
                return ResolutionEvidence(
                    name, frozenset((address,)), frozenset(), self.expires, True, "bogus"
                )

        resolver = Resolver()
        cache = ConnectionMembership(resolver, boundary(), clock=lambda: now[0])
        first = asyncio.create_task(cache.require("example.com", address, 443, 443))
        second = asyncio.create_task(cache.require("example.com", address, 443, 443))
        await asyncio.sleep(0)
        first.cancel()
        resolver.gate.set()
        await asyncio.gather(first, return_exceptions=True)
        await second
        assert resolver.calls == 1  # Bogus authentication does not block membership.
        await cache.require("example.com", address, 443, 443)
        assert resolver.calls == 1
        now[0] = 101
        resolver.fail = True
        with pytest.raises(RequestDenied, match="lookup_failed"):
            await cache.require("example.com", address, 443, 443)
        assert resolver.calls == 2
        resolver.fail = False
        resolver.expires = 101  # Zero TTL is usable only for this transaction.
        await cache.require("example.com", address, 443, 443)
        await cache.require("example.com", address, 443, 443)
        assert resolver.calls == 4
        await cache.close()
        with pytest.raises(RequestDenied, match="connection_closed"):
            await cache.require("example.com", address, 443, 443)

    asyncio.run(run())


def test_service_endpoint_is_bound_to_original_service_and_both_ports():
    async def run():
        address = ipaddress.ip_address("8.8.8.8")
        endpoint = ServiceEndpoint("example.com", "cdn.example", address, 8443, 443)

        class Resolver:
            result = ResolutionEvidence(
                "example.com", frozenset(), frozenset((endpoint,)), 0, True, "insecure"
            )

            async def resolve(self, name):
                return self.result

        resolver = Resolver()
        cache = ConnectionMembership(resolver, boundary())
        await cache.require("example.com", address, 8443, 443)
        for actual, authority in ((443, 443), (8443, 80), (9443, 443)):
            with pytest.raises(RequestDenied):
                await cache.require("example.com", address, actual, authority)
        resolver.result = replace(resolver.result, complete=False)
        with pytest.raises(RequestDenied, match="incomplete"):
            await cache.require("example.com", address, 8443, 443)
        await cache.close()

    asyncio.run(run())
