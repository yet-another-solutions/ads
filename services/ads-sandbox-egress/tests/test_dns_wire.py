import asyncio
import struct

import dns.exception
import dns.message
import dns.name
import dns.rdatatype
import dns.rrset
import pytest

from ads_sandbox_egress.dns_wire import decode
from ads_sandbox_egress.dnssec_validation import CryptoBudget, check_signatures
from ads_sandbox_egress.policy import RequestDenied
from test_dns_transport import transport
from test_dnssec_validation import material, signature
from test_resolution import resolver


@pytest.mark.parametrize("kind", ["HTTPS", "SVCB"])
@pytest.mark.parametrize(
    "extra",
    [
        "port=5555",
        "ipv4hint=1.1.1.1",
        "ipv6hint=2606:4700::1111",
        "key65400=opaque",
        'alpn="h2" mandatory=alpn',
    ],
)
def test_alias_parameters_keep_signed_wire_identity_without_native_parser_mutation(kind, extra):
    q = dns.message.make_query("example.", kind)
    source = dns.rrset.from_text("example.", 60, "IN", kind, "1 target.example. " + extra)[0]
    source = source.replace(priority=0)
    rrset = dns.rrset.from_rdata("example.", 60, source)
    private, key = material()
    sigs = dns.rrset.from_rdata("example.", 60, signature(rrset, private, key))
    message = dns.message.make_response(q)
    message.answer.extend((rrset, sigs))
    wire = message.to_wire()
    with pytest.raises(dns.exception.FormError, match="AliasMode"):
        dns.message.from_wire(wire)
    result = decode(wire)
    restored = next(r for r in result.answer if r.rdtype == q.question[0].rdtype)
    assert restored[0].to_wire() == source.to_wire()
    assert restored[0].priority == 0 and restored[0].target == source.target
    assert check_signatures(
        restored,
        sigs,
        dns.rrset.from_rdata("example.", 60, key),
        now=1_800_000_000,
        budget=CryptoBudget(),
    ).valid
    with pytest.raises(dns.exception.FormError, match="AliasMode"):
        dns.message.from_wire(wire)


@pytest.mark.parametrize("tcp", [False, True])
@pytest.mark.parametrize("private", [False, True])
def test_real_upstream_exchange_handles_alias_parameters_and_checks_hints(tcp, private):
    calls = []

    class View:
        async def answer(self, query, *, deadline):
            q = query.question[0]
            calls.append((q.name, q.rdtype))
            result = dns.message.make_response(query)
            if q.name == dns.name.from_text("example.") and q.rdtype == dns.rdatatype.HTTPS:
                value = dns.rrset.from_text(
                    q.name,
                    30,
                    "IN",
                    "HTTPS",
                    "1 target.example. port=5555 ipv4hint="
                    + ("10.0.0.1" if private else "9.9.9.9"),
                )[0].replace(priority=0)
                result.answer.append(dns.rrset.from_rdata(q.name, 30, value))
                if tcp:
                    # Force UDP truncation and the actual upstream TCP retry.
                    result.additional.extend(
                        dns.rrset.from_text(f"padding{i}.", 30, "IN", "TXT", '"' + "x" * 200 + '"')
                        for i in range(8)
                    )
            if q.name == dns.name.from_text("target.example.") and q.rdtype == dns.rdatatype.A:
                result.answer.append(dns.rrset.from_text(q.name, 30, "IN", "A", "1.1.1.1"))
            return result

    async def run():
        server = transport(View())
        _, port = await server.start("127.0.0.1", 0)
        try:
            operation = resolver(upstream_port=port).acquire("example.", dns.rdatatype.HTTPS)
            if private:
                with pytest.raises(RequestDenied):
                    await operation
            else:
                result = await operation
                assert result.services and result.services[-1].fallback
                assert result.services[-1].addresses
                assert result.messages[0].answer[0][0].priority == 0
                if tcp:
                    assert calls.count((dns.name.from_text("example."), dns.rdatatype.HTTPS)) == 2
        finally:
            await server.close()

    asyncio.run(run())


@pytest.mark.parametrize("priority", [0, 1])
def test_duplicate_parameter_cannot_hide_a_prohibited_hint(priority):
    q = dns.message.make_query("example.", "HTTPS")
    name = q.question[0].name.to_wire()
    target = dns.name.from_text("target.example.").to_wire()
    # Deliberately bypass the record constructor: duplicate IPv4Hint values.
    data = (
        struct.pack("!H", priority)
        + target
        + (b"\x00\x04\x00\x04\x0a\x00\x00\x01" + b"\x00\x04\x00\x04\x01\x01\x01\x01")
    )
    wire = struct.pack("!HHHHHH", q.id, 0x8000, 1, 1, 0, 0)
    wire += name + struct.pack("!HH", 65, 1)
    wire += name + struct.pack("!HHIH", 65, 1, 30, len(data)) + data
    with pytest.raises(RequestDenied):
        decode(wire)


def test_recovery_does_not_ignore_other_malformed_records():
    q = dns.message.make_query("example.", "HTTPS")
    wire = q.to_wire() + b"\x00"
    with pytest.raises(RequestDenied):
        decode(wire)


@pytest.mark.parametrize("private", [False, True])
def test_mixed_modes_ignore_service_port_but_inspect_every_alias_alternative(private):
    calls = []

    class View:
        async def answer(self, query, *, deadline):
            q = query.question[0]
            calls.append((q.name.to_text(), q.rdtype))
            result = dns.message.make_response(query)
            if q.name.to_text() == "example." and q.rdtype == dns.rdatatype.HTTPS:
                result.answer.append(
                    dns.rrset.from_text(
                        q.name,
                        30,
                        "IN",
                        "HTTPS",
                        "0 first.example.",
                        "0 second.example.",
                        "1 ignored.example. port=5555",
                    )
                )
            elif q.rdtype == dns.rdatatype.A:
                result.answer.append(
                    dns.rrset.from_text(
                        q.name,
                        30,
                        "IN",
                        "A",
                        "10.0.0.1"
                        if private and q.name.to_text() == "second.example."
                        else "1.1.1.1",
                    )
                )
            return result

    async def run():
        server = transport(View())
        _, port = await server.start("127.0.0.1", 0)
        try:
            operation = resolver(upstream_port=port).acquire("example.", dns.rdatatype.HTTPS)
            if private:
                with pytest.raises(RequestDenied):
                    await operation
            else:
                result = await operation
                assert len(result.services) == 2 and all(v.fallback for v in result.services)
            assert not any(name == "ignored.example." for name, _ in calls)
            assert ("second.example.", dns.rdatatype.A) in calls
        finally:
            await server.close()

    asyncio.run(run())
