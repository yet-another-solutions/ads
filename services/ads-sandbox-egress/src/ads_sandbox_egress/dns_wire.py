"""Lossless local AliasMode compatibility for pinned dnspython.

No global parser mutation and no input-byte rewriting. RFC 9460 AliasMode
parameters are semantically ignored but remain signed data and must still be
inspected for prohibited hints. Recover ONLY the pinned parser's explicit
AliasMode-parameter rejection, never a generic malformed-message exception.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket

import dns.exception
import dns.immutable
import dns.message
import dns.name
import dns.opcode
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.svcbbase
import dns.wire

from ads_sandbox_egress.policy import RequestDenied


@dns.immutable.immutable  # type: ignore[attr-defined]  # Public runtime re-export.
class AliasService(dns.rdtypes.svcbbase.SVCBBase):
    def __init__(
        self,
        rdclass: dns.rdataclass.RdataClass,
        rdtype: dns.rdatatype.RdataType,
        target: dns.name.Name,
        params: dict[dns.rdtypes.svcbbase.ParamKey, dns.rdtypes.svcbbase.Param],
    ) -> None:
        super().__init__(rdclass, rdtype, 0, target, {})  # type: ignore[no-untyped-call]
        # ServiceMode mandatory/no-default-alpn constraints do not apply to
        # ignored AliasMode parameters. Preserve every wire value verbatim.
        self.params = dns.immutable.Dict(params)


def decode(wire: bytes) -> dns.message.Message:
    message = dns.message.from_wire(wire, continue_on_error=True)
    if message.opcode() != dns.opcode.QUERY:
        raise RequestDenied("dns_wire_opcode")
    for error in message.errors:
        if not isinstance(error.exception, dns.exception.FormError) or str(error.exception) != (
            "parameters in AliasMode"
        ):
            raise RequestDenied("dns_wire_malformed")
    parser = dns.wire.Parser(wire)
    _, _, questions, answers, authority, additional = parser.get_struct("!HHHHHH")
    for _ in range(questions):
        parser.get_name()
        parser.get_struct("!HH")
    recovered: set[int] = set()
    for section, count in zip(message.sections[1:], (answers, authority, additional), strict=True):
        for _ in range(count):
            name = parser.get_name()
            kind, rdclass, ttl, length = parser.get_struct("!HHIH")
            if kind not in (dns.rdatatype.SVCB, dns.rdatatype.HTTPS):
                parser.get_bytes(length)
                continue
            with parser.restrict_to(length):
                priority = parser.get_uint16()
                target = parser.get_name()
                error_offset = parser.current
                recover = priority == 0 and bool(parser.remaining())
                params = {}
                prior = -1
                while parser.remaining():
                    key, size = parser.get_struct("!HH")
                    if key <= prior:
                        raise RequestDenied("dns_service_parameter_order")
                    prior = key
                    parameter_key = dns.rdtypes.svcbbase.ParamKey.make(key)
                    raw = parser.get_bytes(size)
                    cls: type[dns.rdtypes.svcbbase.Param]
                    if key == dns.rdtypes.svcbbase.ParamKey.IPV4HINT:
                        cls = dns.rdtypes.svcbbase.IPv4HintParam
                    elif key == dns.rdtypes.svcbbase.ParamKey.IPV6HINT:
                        cls = dns.rdtypes.svcbbase.IPv6HintParam
                    else:
                        cls = dns.rdtypes.svcbbase.GenericParam
                    # Recognized hints remain fully inspectable. Other values
                    # are opaque signed bytes with no AliasMode semantics.
                    params[parameter_key] = cls.from_wire_parser(  # type: ignore[no-untyped-call]
                        dns.wire.Parser(raw)
                    )
                if not recover:
                    continue
                value = AliasService(
                    dns.rdataclass.RdataClass.make(rdclass),
                    dns.rdatatype.RdataType.make(kind),
                    target,
                    params,
                )
                rrset = message.find_rrset(section, name, rdclass, kind, create=True)
                rrset.add(value, ttl if ttl <= 0x7FFFFFFF else 0)
                recovered.add(error_offset)
    if parser.remaining() or recovered != {error.offset for error in message.errors}:
        raise RequestDenied("dns_wire_recovery_mismatch")
    message.errors.clear()
    return message


async def exchange(
    query: dns.message.Message,
    address: str,
    *,
    port: int,
    timeout: float,
    tcp: bool,
) -> dns.message.Message:
    """One bounded exchange to a literal configured upstream, no DNS recursion."""
    ip = ipaddress.ip_address(address)
    family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
    wire = query.to_wire()
    async with asyncio.timeout(timeout):
        if tcp:
            reader, writer = await asyncio.open_connection(address, port, family=family)
            try:
                writer.write(len(wire).to_bytes(2, "big") + wire)
                await writer.drain()
                size = int.from_bytes(await reader.readexactly(2), "big")
                result = decode(await reader.readexactly(size))
            finally:
                # DNS exchange has no reusable application flow; close now,
                # not an unbounded wait_closed beyond the query deadline.
                writer.close()
                writer.transport.abort()
        else:
            loop = asyncio.get_running_loop()
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.setblocking(False)
                await loop.sock_connect(sock, (address, port))
                await loop.sock_sendall(sock, wire)
                result = decode(await loop.sock_recv(sock, 65535))
        if not query.is_response(result):
            raise RequestDenied("dns_upstream_response_mismatch")
        return result
