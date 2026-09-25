"""Fresh bounded upstream evidence acquisition, not synthetic DNS publication.

The returned evidence MUST pass the separate DNSSEC view transformer before a
sandbox DNS reply. Acquired messages are not marked secure merely because an
upstream sets AD. No completed resolver result is cached here.
"""

from __future__ import annotations

import asyncio
import math
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

    def __post_init__(self) -> None:
        if (
            not math.isfinite(self.deadline)
            or self.deadline <= 0
            or any(
                type(value) is not int or value < 0 for value in (self.subqueries, self.endpoints)
            )
        ):
            raise ValueError("invalid shared resolution job")


@dataclass(frozen=True, slots=True)
class AcquiredService:
    owner: dns.name.Name
    target: dns.name.Name
    record: dns.rdtypes.svcbbase.SVCBBase
    addresses: frozenset[Address]
    expires_at: float
    fallback: bool = False


@dataclass(frozen=True, slots=True)
class AcquiredAnswer:
    query_name: dns.name.Name
    query_type: dns.rdatatype.RdataType
    messages: tuple[dns.message.Message, ...]
    addresses: frozenset[Address]
    expires_at: float
    direct_addresses: frozenset[Address] = frozenset()
    services: tuple[AcquiredService, ...] = ()
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

    async def acquire(
        self,
        name: str,
        rdtype: dns.rdatatype.RdataType,
        *,
        job: ResolutionJob | None = None,
    ) -> AcquiredAnswer:
        if rdtype in (dns.rdatatype.AXFR, dns.rdatatype.IXFR):
            raise RequestDenied("unsupported_dns_query")
        query_name = dns.name.from_text(name)
        self._name(query_name)
        job = job or ResolutionJob(time.monotonic() + self.limits.deadline)
        # Queue time, sibling address queries and DNSSEC dependencies never
        # receive a renewed deadline. The local cap may only shorten it.
        deadline = min(job.deadline, time.monotonic() + self.limits.deadline)
        messages: list[dns.message.Message] = []
        addresses: set[Address] = set()
        service_results: list[AcquiredService] = []

        async def follow(
            current: dns.name.Name,
            kind: dns.rdatatype.RdataType,
            visited: frozenset[dns.name.Name],
            depth: int,
            dependency_expiry: float = float("inf"),
            alias_record: dns.rdtypes.svcbbase.SVCBBase | None = None,
        ) -> tuple[frozenset[Address], float]:
            if current in visited:
                raise RequestDenied("dns_alias_loop")
            if depth > self.limits.aliases:
                raise RequestDenied("dns_alias_limit")
            visited = visited | {current}
            try:
                response = await self.exchange(current, kind, job)
            except RequestDenied as exc:
                if str(exc) != "dns_upstream_unavailable" or alias_record is None:
                    raise
                # No invented response: retain the actual alias evidence and
                # independently resolve the permitted final-name fallback.
                response = None
            if response is not None:
                messages.append(response)
            code = response.rcode() if response is not None else dns.rcode.SERVFAIL
            now = time.monotonic()
            resolved: set[Address] = set()
            expires = dependency_expiry
            if code != dns.rcode.NOERROR:
                # Preserve failure/negative data for classification, never
                # obtain positive relationship evidence from its Answer section.
                if alias_record is None or code == dns.rcode.NXDOMAIN:
                    return frozenset(), now
            next_name: dns.name.Name | None = None
            services: list[dns.rdtypes.svcbbase.SVCBBase] = []
            for rrset in (
                response.answer if response is not None and code == dns.rcode.NOERROR else ()
            ):
                for record in rrset:
                    if (
                        rrset.name == current
                        and rrset.rdtype == kind
                        and isinstance(record, (dns.rdtypes.IN.A.A, dns.rdtypes.IN.AAAA.AAAA))
                    ):
                        resolved.add(self.boundary.addresses.require_public(record.address))
                        expires = min(expires, now + rrset.ttl)
                    elif (
                        rrset.name == current
                        and isinstance(record, dns.rdtypes.ANY.CNAME.CNAME)
                        and kind != dns.rdatatype.CNAME
                    ):
                        if next_name is not None and next_name != record.target:
                            raise RequestDenied("conflicting_dns_alias")
                        next_name = record.target
                        expires = min(expires, now + rrset.ttl)
                    elif (
                        isinstance(record, dns.rdtypes.ANY.DNAME.DNAME)
                        and current != rrset.name
                        and current.is_subdomain(rrset.name)
                    ):
                        redirected = current.relativize(rrset.name).concatenate(record.target)
                        if next_name is not None and next_name != redirected:
                            raise RequestDenied("conflicting_dns_alias")
                        next_name = redirected
                        expires = min(expires, now + rrset.ttl)
                    elif (
                        rrset.name == current
                        and rrset.rdtype == kind
                        and isinstance(record, dns.rdtypes.svcbbase.SVCBBase)
                    ):
                        services.append(record)
                        expires = min(expires, now + rrset.ttl)
            if next_name is not None:
                if resolved or services:
                    raise RequestDenied("conflicting_dns_alias")
                branch, branch_expiry = await follow(
                    next_name, kind, visited, depth + 1, expires, alias_record
                )
                resolved.update(branch)
                expires = min(expires, branch_expiry)
            aliases = [service for service in services if service.priority == 0]
            if aliases:
                if len(aliases) != 1 or len(services) != 1:
                    raise RequestDenied("conflicting_service_alias")
                if aliases[0].target != dns.name.root:
                    branch, branch_expiry = await follow(
                        aliases[0].target, kind, visited, depth + 1, expires, aliases[0]
                    )
                    resolved.update(branch)
                    expires = min(expires, branch_expiry)
            else:
                for service in services:
                    job.endpoints += 1
                    if job.endpoints > self.limits.endpoints:
                        raise RequestDenied("dns_endpoint_limit")
                    target = current if service.target == dns.name.root else service.target
                    target_addresses: set[Address] = set()
                    target_expiry = expires
                    for family in (dns.rdatatype.A, dns.rdatatype.AAAA):
                        # Address lookup starts a new record-type branch; only
                        # alias transitions consume depth, not this dependency.
                        try:
                            branch, branch_expiry = await follow(
                                target, family, frozenset(), depth, expires
                            )
                        except RequestDenied as exc:
                            if str(exc) != "dns_upstream_unavailable":
                                raise
                            continue
                        target_addresses.update(branch)
                        # An empty optional family does not create evidence or
                        # erase a successful independently resolved family.
                        if branch:
                            target_expiry = min(target_expiry, branch_expiry)
                    addresses.update(target_addresses)
                    service_results.append(
                        AcquiredService(
                            current, target, service, frozenset(target_addresses), target_expiry
                        )
                    )
                if alias_record is not None and next_name is None:
                    # RFC 9460 section 3: SVCB-optional final-QNAME fallback
                    # after AliasMode, at the original authority port. It is
                    # not a direct address of the original authority.
                    job.endpoints += 1
                    if job.endpoints > self.limits.endpoints:
                        raise RequestDenied("dns_endpoint_limit")
                    fallback_addresses: set[Address] = set()
                    fallback_expiry = expires
                    for family in (dns.rdatatype.A, dns.rdatatype.AAAA):
                        try:
                            branch, branch_expiry = await follow(
                                current, family, frozenset(), depth, expires
                            )
                        except RequestDenied as exc:
                            if str(exc) != "dns_upstream_unavailable":
                                raise
                            continue
                        fallback_addresses.update(branch)
                        if branch:
                            fallback_expiry = min(fallback_expiry, branch_expiry)
                    addresses.update(fallback_addresses)
                    service_results.append(
                        AcquiredService(
                            current,
                            current,
                            alias_record,
                            frozenset(fallback_addresses),
                            fallback_expiry,
                            True,
                        )
                    )
            addresses.update(resolved)
            return frozenset(resolved), expires

        try:
            async with asyncio.timeout_at(deadline):
                direct, expires = await follow(query_name, rdtype, frozenset(), 0)
        except TimeoutError:
            raise RequestDenied("dns_resolution_deadline") from None
        if time.monotonic() >= deadline:
            raise RequestDenied("dns_resolution_deadline")
        return AcquiredAnswer(
            query_name,
            rdtype,
            tuple(messages),
            frozenset(addresses),
            min(expires, *(service.expires_at for service in service_results))
            if service_results
            else expires,
            direct,
            tuple(service_results),
        )
