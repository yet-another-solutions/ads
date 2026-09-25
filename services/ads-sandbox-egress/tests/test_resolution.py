import asyncio
import ipaddress

import dns.flags
import dns.message
import dns.name
import dns.rdatatype
import dns.rrset
import pytest

from ads_sandbox_egress.destinations import DestinationBoundary, ResolverBoundary
from ads_sandbox_egress.policy import RequestDenied
from ads_sandbox_egress.resolution import ResolutionLimits, UpstreamResolver


def resolver(**kwargs):
    addresses = DestinationBoundary((ipaddress.ip_network("8.8.4.0/24"),), (), "fixture")
    boundary = ResolverBoundary.discover(
        "nameserver 127.0.0.1\nsearch svc.cluster.example", "ads", addresses
    )
    return UpstreamResolver(boundary, **kwargs)


def answer(name="example.com", kind="A", *records):
    response = dns.message.make_response(dns.message.make_query(name, kind))
    if records:
        response.answer.append(
            dns.rrset.from_text(name.rstrip(".") + ".", 30, "IN", kind, *records)
        )
    return response


@pytest.mark.parametrize("section", ["answer", "authority", "additional"])
@pytest.mark.parametrize(
    "kind,value",
    [("A", "127.0.0.1"), ("AAAA", "::ffff:8.8.8.8"), ("HTTPS", "1 . ipv4hint=8.8.8.8,10.0.0.1")],
)
def test_all_received_sections_inspected_before_omission(section, kind, value):
    response = answer()
    getattr(response, section).append(
        dns.rrset.from_text("unrelated.example.", 30, "IN", kind, value)
    )
    with pytest.raises(RequestDenied):
        resolver().inspect(response)


def test_infrastructure_alias_denied_before_query():
    response = answer("example.com", "CNAME", "secret.cluster.example.")
    with pytest.raises(RequestDenied, match="infrastructure"):
        resolver().inspect(response)


def test_dns_service_and_numeric_owners_are_not_http_hosts():
    instance = resolver()
    instance._name(dns.name.from_text("_8443._https.example.com."))
    instance._name(dns.name.from_text("1234.example."))
    with pytest.raises(RequestDenied, match="infrastructure"):
        instance._name(dns.name.from_text("_service._tcp.cluster.example."))


def test_wrong_record_family_not_positive_membership(monkeypatch):
    async def run():
        async def exchange(*args, **kwargs):
            return answer("example.com", "AAAA", "2001:4860:4860::8888")

        monkeypatch.setattr("dns.asyncquery.udp", exchange)
        result = await resolver().acquire("example.com", dns.rdatatype.A)
        assert not result.addresses

    asyncio.run(run())


def test_traversal_no_cache_and_loop_boundary(monkeypatch):
    async def run():
        called = []
        cyclic = False

        async def exchange(query, where, **kwargs):
            name = query.question[0].name.to_text()
            called.append(name)
            if name == "example.com.":
                result = answer("example.com", "CNAME", "target.example.")
            elif cyclic:
                result = answer("target.example", "CNAME", "example.com.")
            else:
                result = answer("target.example", "A", "8.8.8.8")
            # Actual upstream boundary is faked; traversal and inspection are real.
            return result

        monkeypatch.setattr("dns.asyncquery.udp", exchange)
        instance = resolver()
        result = await instance.acquire("example.com", dns.rdatatype.A)
        assert result.addresses == frozenset((ipaddress.ip_address("8.8.8.8"),))
        assert len(result.messages) == 2
        await instance.acquire("example.com", dns.rdatatype.A)
        assert called == ["example.com.", "target.example."] * 2
        cyclic = True
        with pytest.raises(RequestDenied, match="alias_loop"):
            await instance.acquire("example.com", dns.rdatatype.A)

    asyncio.run(run())


def test_all_service_endpoints_not_only_best(monkeypatch):
    async def run():
        called = []

        async def exchange(query, where, **kwargs):
            question = query.question[0]
            name = question.name.to_text()
            called.append(name)
            if question.rdtype == dns.rdatatype.HTTPS:
                return answer("example.com", "HTTPS", "1 good.example.", "2 bad.example.")
            if question.rdtype == dns.rdatatype.AAAA:
                return answer(name, "AAAA")
            return answer(name, "A", "10.0.0.1" if name == "bad.example." else "8.8.8.8")

        monkeypatch.setattr("dns.asyncquery.udp", exchange)
        with pytest.raises(RequestDenied):
            await resolver().acquire("example.com", dns.rdatatype.HTTPS)
        assert "bad.example." in called
        with pytest.raises(RequestDenied, match="endpoint_limit"):
            await resolver(limits=ResolutionLimits(endpoints=1)).acquire(
                "example.com", dns.rdatatype.HTTPS
            )

    asyncio.run(run())


def test_real_udp_truncation_tcp_retry_and_fresh_second_lookup():
    async def run():
        calls = []

        def respond(wire, truncated):
            query = dns.message.from_wire(wire)
            assert query.flags & dns.flags.CD
            assert query.ednsflags & dns.flags.DO
            response = dns.message.make_response(query)
            if truncated:
                response.flags |= dns.flags.TC
            else:
                response.answer.append(dns.rrset.from_text("example.com.", 0, "IN", "A", "8.8.8.8"))
            return response.to_wire()

        class UDP(asyncio.DatagramProtocol):
            def connection_made(self, transport):
                self.transport = transport

            def datagram_received(self, data, addr):
                calls.append("udp")
                self.transport.sendto(respond(data, True), addr)

        async def tcp(reader, writer):
            try:
                length = int.from_bytes(await reader.readexactly(2), "big")
                wire = await reader.readexactly(length)
                calls.append("tcp")
                response = respond(wire, False)
                writer.write(len(response).to_bytes(2, "big") + response)
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(tcp, "127.0.0.1", 0)
        async with server:
            port = server.sockets[0].getsockname()[1]
            transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                UDP, local_addr=("127.0.0.1", port)
            )
            try:
                instance = resolver(upstream_port=port)
                for _ in range(2):
                    result = await instance.acquire("example.com", dns.rdatatype.A)
                    assert result.addresses == frozenset((ipaddress.ip_address("8.8.8.8"),))
                    assert len(result.messages) == 1
                assert calls == ["udp", "tcp", "udp", "tcp"]
            finally:
                transport.close()

    asyncio.run(run())
