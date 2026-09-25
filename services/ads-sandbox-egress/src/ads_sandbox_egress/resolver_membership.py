"""Fresh protocol-scoped membership, not an authentication permission bit.

RFC 9460 section 9 maps HTTP services to HTTPS records, not SVCB queries.
Plain HTTP is not silently upgraded; generic SVCB DNS acquisition remains
supported by UpstreamResolver independently of this HTTP membership adapter.
"""

from __future__ import annotations

import time

import dns.rdatatype
import dns.rdtypes.svcbbase

from ads_sandbox_egress.destinations import Address
from ads_sandbox_egress.dnssec_answer import AnswerAuthentication
from ads_sandbox_egress.dnssec_identity import DNSSECUnrepresentable
from ads_sandbox_egress.dnssec_validation import CryptoBudget
from ads_sandbox_egress.membership import ResolutionEvidence, ServiceEndpoint
from ads_sandbox_egress.policy import RequestDenied, canonical_host
from ads_sandbox_egress.resolution import AcquiredAnswer, ResolutionJob
from ads_sandbox_egress.resolution_answer import assemble


class FreshMembership:
    def __init__(self, authentication: AnswerAuthentication) -> None:
        self.authentication = authentication
        self.resolver = authentication.chains.resolver

    async def resolve(self, name: str, *, authority_port: int, protocol: str) -> ResolutionEvidence:
        name = canonical_host(name)
        if (
            protocol not in ("http", "https")
            or type(authority_port) is not int
            or not 1 <= authority_port <= 65535
        ):
            raise RequestDenied("invalid_membership_scope")
        job = ResolutionJob(time.monotonic() + self.resolver.limits.deadline)
        budget = CryptoBudget()
        results: list[AcquiredAnswer] = []
        queries = [(name, dns.rdatatype.A), (name, dns.rdatatype.AAAA)]
        if protocol == "https":
            service_name = name if authority_port == 443 else f"_{authority_port}._https.{name}"
            queries.append((service_name, dns.rdatatype.HTTPS))
        for owner, kind in queries:
            try:
                results.append(await self.resolver.acquire(owner, kind, job=job))
            except RequestDenied as exc:
                # An ordinary optional lookup failure produces NO positive
                # evidence. Known prohibited data or budget/deadline failures
                # are never treated as optional.
                if str(exc) != "dns_upstream_unavailable":
                    raise
        direct: set[Address] = set()
        endpoints: set[ServiceEndpoint] = set()
        expiry = float("inf")
        states = []
        for acquired in results:
            if acquired.query_type in (dns.rdatatype.A, dns.rdatatype.AAAA):
                direct.update(acquired.direct_addresses)
                if acquired.direct_addresses:
                    expiry = min(expiry, acquired.expires_at)
            for service in acquired.services:
                parameter = service.record.params.get(dns.rdtypes.svcbbase.ParamKey.PORT)
                port = (
                    parameter.port
                    if isinstance(parameter, dns.rdtypes.svcbbase.PortParam)
                    and not service.fallback
                    else authority_port
                )
                for address in service.addresses:
                    endpoints.add(
                        ServiceEndpoint(
                            name, service.target.to_text(), address, port, authority_port
                        )
                    )
                if service.addresses:
                    expiry = min(expiry, service.expires_at)
            messages = acquired.messages
            if acquired.query_type in (dns.rdatatype.A, dns.rdatatype.AAAA):
                try:
                    messages = (assemble(acquired, deadline=job.deadline),)
                except DNSSECUnrepresentable:
                    # Synthesis/assembly uncertainty does not erase separately
                    # complete public membership. It cannot claim secure DNS.
                    states.append("indeterminate")
                    continue
            for message in messages:
                try:
                    status = await self.authentication.classify(message, job, budget=budget)
                    states.append(status.state)
                except RequestDenied as exc:
                    if str(exc) != "dns_upstream_unavailable":
                        raise
                    # Failure to acquire cryptographic dependencies does not
                    # erase separately complete public-address relationships.
                    states.append("indeterminate")
        if time.monotonic() >= job.deadline:
            raise RequestDenied("dns_resolution_deadline")
        state = next(
            (value for value in ("bogus", "indeterminate", "insecure") if value in states),
            "secure" if states else "indeterminate",
        )
        usable = bool(direct or endpoints)
        return ResolutionEvidence(
            name,
            frozenset(direct),
            frozenset(endpoints),
            expiry if usable else time.monotonic(),
            usable,
            state,
        )
