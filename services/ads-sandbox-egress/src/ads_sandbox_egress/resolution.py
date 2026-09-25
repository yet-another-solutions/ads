"""Fresh bounded upstream evidence acquisition, not synthetic DNS publication.

The returned evidence MUST pass the separate DNSSEC view transformer before a
sandbox DNS reply. Acquired messages are not marked secure merely because an
upstream sets AD. No completed resolver result is cached here.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

import dns.asyncquery
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.ANY.CNAME
import dns.rdtypes.ANY.DNAME
import dns.rdtypes.IN.A
import dns.rdtypes.IN.AAAA
import dns.rdtypes.svcbbase

from ads_sandbox_egress.destinations import Address, ResolverBoundary
from ads_sandbox_egress.policy import RequestDenied


@dataclass(frozen=True, slots=True)
class ResolutionLimits:
    deadline: float = 10
    exchange: float = 2
    subqueries: int = 64
    aliases: int = 16
    endpoints: int = 16

    def __post_init__(self) -> None:
        if not (
            0 < self.exchange <= self.deadline <= 60
            and 1 <= self.subqueries <= 256
            and 1 <= self.aliases <= 64
            and 1 <= self.endpoints <= 64
        ):
            raise ValueError("invalid DNS resolution limits")


@dataclass(slots=True)
class ResolutionJob:
    deadline: float
    subqueries: int = 0
    endpoints: int = 0


@dataclass(frozen=True, slots=True)
class AcquiredAnswer:
    query_name: dns.name.Name
    query_type: dns.rdatatype.RdataType
    messages: tuple[dns.message.Message, ...]
    addresses: frozenset[Address]
    expires_at: float
    # DNSSEC classification and synthesis are deliberately NOT inferred here.


class UpstreamResolver:
    def __init__(
        self,
        boundary: ResolverBoundary,
        limits: ResolutionLimits | None = None,
        *,
        upstream_port: int = 53,
    ) -> None:
        if not 1 <= upstream_port <= 65535:
            raise ValueError("invalid trusted resolver port")
        self.boundary = boundary
        self.limits = limits or ResolutionLimits()
        self.upstream_port = upstream_port

    def _name(self, name: dns.name.Name) -> None:
        # DNS wire names may contain arbitrary octets; no lossy conversion or
        # escaped-ASCII reinterpretation at the infrastructure-name boundary.
        if not name.is_absolute():
            raise RequestDenied("relative_dns_evidence")
        try:
            value = b".".join(name.labels[:-1]).decode("ascii") if name != dns.name.root else "."
        except UnicodeDecodeError:
            raise RequestDenied("unsupported_dns_name") from None
        self.boundary.check_name(value)

    async def exchange(
        self, name: dns.name.Name, rdtype: dns.rdatatype.RdataType, job: ResolutionJob
    ) -> dns.message.Message:
        self._name(name)
        query = dns.message.make_query(name, rdtype, want_dnssec=True)
        # Obtain original defective data rather than asking upstream to conceal
        # it behind validation SERVFAIL. Local classification is still required.
        query.flags |= dns.flags.CD
        for upstream in self.boundary.upstreams:
            job.subqueries += 1
            if job.subqueries > self.limits.subqueries:
                raise RequestDenied("dns_subquery_limit")
            remaining = job.deadline - time.monotonic()
            if remaining <= 0:
                raise RequestDenied("dns_resolution_deadline")
            try:
                response = await dns.asyncquery.udp(
                    query,
                    str(upstream),
                    port=self.upstream_port,
                    timeout=min(self.limits.exchange, remaining),
                    raise_on_truncation=False,
                )
                # Even a truncated reply cannot hide a known prohibited record.
                self.inspect(response)
                if response.flags & dns.flags.TC:
                    job.subqueries += 1
                    if job.subqueries > self.limits.subqueries:
                        raise RequestDenied("dns_subquery_limit")
                    remaining = job.deadline - time.monotonic()
                    if remaining <= 0:
                        raise RequestDenied("dns_resolution_deadline")
                    response = await dns.asyncquery.tcp(
                        query,
                        str(upstream),
                        port=self.upstream_port,
                        timeout=min(self.limits.exchange, remaining),
                    )
                    self.inspect(response)
                    if response.flags & dns.flags.TC:
                        raise RequestDenied("dns_truncated_tcp")
                if response.rcode() not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
                    # Preserve the final upstream failure, including EDE, for
                    # the status layer. Never invent a cryptographic diagnosis.
                    if upstream != self.boundary.upstreams[-1]:
                        continue
                return response
            except (OSError, dns.exception.DNSException):
                continue
        raise RequestDenied("dns_upstream_unavailable")

    def inspect(self, response: dns.message.Message) -> None:
        for section in (response.answer, response.authority, response.additional):
            for rrset in section:
                self._name(rrset.name)
                for record in rrset:
                    if isinstance(record, (dns.rdtypes.IN.A.A, dns.rdtypes.IN.AAAA.AAAA)):
                        self.boundary.addresses.require_public(record.address)
                    # Check discovered target names before follow-up queries,
                    # including unrelated Additional names before any omission.
                    for attribute in ("target", "exchange", "replacement"):
                        target = getattr(record, attribute, None)
                        if isinstance(target, dns.name.Name):
                            self._name(target)
                    if isinstance(record, dns.rdtypes.svcbbase.SVCBBase):
                        for parameter in record.params.values():
                            if isinstance(
                                parameter,
                                (
                                    dns.rdtypes.svcbbase.IPv4HintParam,
                                    dns.rdtypes.svcbbase.IPv6HintParam,
                                ),
                            ):
                                for address in parameter.addresses:
                                    self.boundary.addresses.require_public(address)

    async def acquire(self, name: str, rdtype: dns.rdatatype.RdataType) -> AcquiredAnswer:
        if rdtype in (dns.rdatatype.AXFR, dns.rdatatype.IXFR):
            raise RequestDenied("unsupported_dns_query")
        query_name = dns.name.from_text(name)
        self._name(query_name)
        job = ResolutionJob(time.monotonic() + self.limits.deadline)
        messages: list[dns.message.Message] = []
        addresses: set[Address] = set()
        expires = [float("inf")]

        async def follow(
            current: dns.name.Name,
            kind: dns.rdatatype.RdataType,
            visited: frozenset[dns.name.Name],
            depth: int,
        ) -> None:
            if current in visited:
                raise RequestDenied("dns_alias_loop")
            if depth > self.limits.aliases:
                raise RequestDenied("dns_alias_limit")
            visited = visited | {current}
            response = await self.exchange(current, kind, job)
            messages.append(response)
            now = time.monotonic()
            next_name: dns.name.Name | None = None
            services: list[dns.rdtypes.svcbbase.SVCBBase] = []
            for rrset in response.answer:
                expires[0] = min(expires[0], now + rrset.ttl)
                for record in rrset:
                    if (
                        rrset.name == current
                        and rrset.rdtype == kind
                        and isinstance(record, (dns.rdtypes.IN.A.A, dns.rdtypes.IN.AAAA.AAAA))
                    ):
                        addresses.add(self.boundary.addresses.require_public(record.address))
                    elif (
                        rrset.name == current
                        and isinstance(record, dns.rdtypes.ANY.CNAME.CNAME)
                        and kind != dns.rdatatype.CNAME
                    ):
                        if next_name is not None and next_name != record.target:
                            raise RequestDenied("conflicting_dns_alias")
                        next_name = record.target
                    elif (
                        isinstance(record, dns.rdtypes.ANY.DNAME.DNAME)
                        and current != rrset.name
                        and current.is_subdomain(rrset.name)
                    ):
                        redirected = current.relativize(rrset.name).concatenate(record.target)
                        if next_name is not None and next_name != redirected:
                            raise RequestDenied("conflicting_dns_alias")
                        next_name = redirected
                    elif rrset.name == current and isinstance(
                        record, dns.rdtypes.svcbbase.SVCBBase
                    ):
                        services.append(record)
            if next_name is not None:
                await follow(next_name, kind, visited, depth + 1)
            aliases = [service for service in services if service.priority == 0]
            if aliases:
                if len(aliases) != 1 or len(services) != 1:
                    raise RequestDenied("conflicting_service_alias")
                if aliases[0].target != dns.name.root:
                    await follow(aliases[0].target, kind, visited, depth + 1)
            else:
                for service in services:
                    job.endpoints += 1
                    if job.endpoints > self.limits.endpoints:
                        raise RequestDenied("dns_endpoint_limit")
                    target = current if service.target == dns.name.root else service.target
                    for family in (dns.rdatatype.A, dns.rdatatype.AAAA):
                        # Address lookup starts a new record-type branch; only
                        # alias transitions consume depth, not this dependency.
                        await follow(target, family, frozenset(), depth)

        try:
            async with asyncio.timeout(self.limits.deadline):
                await follow(query_name, rdtype, frozenset(), 0)
        except TimeoutError:
            raise RequestDenied("dns_resolution_deadline") from None
        return AcquiredAnswer(query_name, rdtype, tuple(messages), frozenset(addresses), expires[0])
