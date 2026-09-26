"""Bounded certificate-status acquisition through separately originated public sockets.

URLs are untrusted certificate metadata: no redirects, proxy environment,
private-address exception, AIA chain repair, unrestricted HTTP client, cache or
recursive status fetch. The original TLS connection remains separately owned.
"""

from __future__ import annotations

import asyncio
import ipaddress
import time
from collections.abc import Awaitable, Callable
from dataclasses import replace
from datetime import UTC, datetime
from urllib.parse import urlsplit

import dns.rdatatype
import h11
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID

from ads_sandbox_egress.certificates import CertificateDefectRequiresMirror
from ads_sandbox_egress.crl_status import crl_set_revoked
from ads_sandbox_egress.crl_status import extension as get_extension
from ads_sandbox_egress.destinations import Address
from ads_sandbox_egress.http1 import HTTP1Channel
from ads_sandbox_egress.ocsp_status import inspect_status
from ads_sandbox_egress.origin_tls import OriginCertificate, OriginContext, inspect_origin
from ads_sandbox_egress.policy import canonical_host
from ads_sandbox_egress.resolution import ResolutionJob, UpstreamResolver
from ads_sandbox_egress.streams import OwnedStream
from ads_sandbox_egress.tls import UnmappableReason, UnmappableTLS

Connect = Callable[[Address, int], Awaitable[tuple[asyncio.StreamReader, asyncio.StreamWriter]]]


def status_urls(certificate: x509.Certificate) -> tuple[tuple[str, ...], tuple[str, ...]]:
    ocsp_urls: list[str] = []
    crl_urls: list[str] = []
    for extension in certificate.extensions:
        if extension.oid == ExtensionOID.AUTHORITY_INFORMATION_ACCESS:
            for item in extension.value:
                if item.access_method == AuthorityInformationAccessOID.OCSP:
                    if not isinstance(item.access_location, x509.UniformResourceIdentifier):
                        raise CertificateDefectRequiresMirror("unsupported_OCSP_locator")
                    ocsp_urls.append(item.access_location.value)
        elif extension.oid == ExtensionOID.CRL_DISTRIBUTION_POINTS:
            for point in extension.value:
                if not point.full_name:
                    raise UnmappableTLS(UnmappableReason.UNAVAILABLE_STATUS)
                for item in point.full_name or ():
                    if not isinstance(item, x509.UniformResourceIdentifier):
                        raise CertificateDefectRequiresMirror("unsupported_CRL_locator")
                    crl_urls.append(item.value)
    if len(ocsp_urls) + len(crl_urls) > 8:
        raise UnmappableTLS(UnmappableReason.UNAVAILABLE_STATUS)
    return tuple(dict.fromkeys(ocsp_urls)), tuple(dict.fromkeys(crl_urls))


def crl_revoked(
    wire: bytes, certificate: x509.Certificate, issuer: x509.Certificate, *, now: datetime
) -> bool:
    return crl_set_revoked((wire,), certificate, issuer, now=now)


class StatusAcquisition:
    def __init__(self, resolver: UpstreamResolver, origin: OriginContext, connect: Connect) -> None:
        self.resolver, self.origin, self.connect = resolver, origin, connect

    async def fetch(self, url: str, body: bytes | None, *, job: ResolutionJob) -> bytes:
        parsed = urlsplit(url)
        if (
            len(url) > 2048
            or parsed.scheme not in ("http", "https")
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or any(ord(char) <= 32 or ord(char) > 126 for char in url)
        ):
            raise UnmappableTLS(UnmappableReason.UNAVAILABLE_STATUS)
        host = canonical_host(parsed.hostname)
        self.resolver.boundary.check_name(host)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        try:
            address = ipaddress.ip_address(host)
            self.resolver.boundary.addresses.require_public(str(address))
            addresses = {address}
        except ValueError:
            addresses = set()
            for family in (dns.rdatatype.A, dns.rdatatype.AAAA):
                answer = await self.resolver.acquire(host, family, job=job)
                addresses.update(answer.direct_addresses)
        if not addresses:
            raise UnmappableTLS(UnmappableReason.UNAVAILABLE_STATUS)
        for address in addresses:
            self.resolver.boundary.addresses.require_public(str(address))
        selected = sorted(addresses, key=lambda value: (value.version, int(value)))[0]
        stream = None
        try:
            async with asyncio.timeout_at(job.deadline):
                reader, writer = await self.connect(selected, port)
                stream = OwnedStream.tcp(reader, writer)
                if parsed.scheme == "https":
                    tls, observed = await inspect_origin(
                        reader, writer, self.origin, host, (b"http/1.1",)
                    )
                    stream = OwnedStream.tls(tls)
                    if not observed.verified or observed.selected_alpn not in (None, b"http/1.1"):
                        raise UnmappableTLS(UnmappableReason.UNAVAILABLE_STATUS)
                channel = HTTP1Channel(stream.reader, stream.writer, client=True, idle_timeout=2)
                headers = [(b"host", parsed.netloc.encode("ascii")), (b"connection", b"close")]
                if body is not None:
                    headers.extend(
                        (
                            (b"content-type", b"application/ocsp-request"),
                            (b"content-length", str(len(body)).encode()),
                        )
                    )
                target = (parsed.path or "/") + ("?" + parsed.query if parsed.query else "")
                await channel.send(
                    h11.Request(
                        method=b"GET" if body is None else b"POST",
                        target=target.encode(),
                        headers=headers,
                    )
                )
                if body is not None:
                    await channel.send(h11.Data(data=body))
                await channel.send(h11.EndOfMessage())
                response = await channel.receive()
                if not isinstance(response, h11.Response) or response.status_code != 200:
                    raise UnmappableTLS(UnmappableReason.UNAVAILABLE_STATUS)
                if any(name == b"content-encoding" for name, _ in response.headers):
                    raise UnmappableTLS(UnmappableReason.UNAVAILABLE_STATUS)
                maximum = 65536 if body is not None else 2 * 1024**2
                data = bytearray()
                while True:
                    event = await channel.receive()
                    if isinstance(event, h11.EndOfMessage):
                        if event.headers:
                            raise UnmappableTLS(UnmappableReason.UNAVAILABLE_STATUS)
                        return bytes(data)
                    if not isinstance(event, h11.Data):
                        raise UnmappableTLS(UnmappableReason.UNAVAILABLE_STATUS)
                    data.extend(event.data)
                    if len(data) > maximum:
                        raise UnmappableTLS(UnmappableReason.UNAVAILABLE_STATUS)
        finally:
            if stream is not None:
                stream.abort()

    async def acquire(self, observed: OriginCertificate) -> OriginCertificate:
        chain = tuple(x509.load_der_x509_certificate(value) for value in observed.built_chain)
        statuses = list(observed.staples) + [None] * (len(chain) - len(observed.staples))
        revoked = set(observed.revoked)
        job = ResolutionJob(time.monotonic() + 10)
        count = 0
        try:
            async with asyncio.timeout_at(job.deadline):
                for depth, certificate in enumerate(chain):
                    urls, crls = status_urls(certificate)
                    if depth + 1 >= len(chain):
                        if certificate.issuer != certificate.subject and (urls or crls):
                            raise UnmappableTLS(UnmappableReason.UNAVAILABLE_STATUS)
                        continue
                    issuer = chain[depth + 1]
                    now = datetime.now(UTC)
                    must_staple = any(
                        extension.oid == ExtensionOID.TLS_FEATURE
                        for extension in certificate.extensions
                    )
                    if must_staple and statuses[depth] is None:
                        raise UnmappableTLS(UnmappableReason.UNAVAILABLE_STATUS)
                    if statuses[depth] is None and urls:
                        count += 1
                        if count > 16:
                            raise UnmappableTLS(UnmappableReason.UNAVAILABLE_STATUS)
                        request = (
                            ocsp.OCSPRequestBuilder()
                            .add_certificate(certificate, issuer, hashes.SHA1())
                            .build()
                            .public_bytes(serialization.Encoding.DER)
                        )
                        statuses[depth] = await self.fetch(urls[0], request, job=job)
                    if statuses[depth] is not None:
                        result = inspect_status(statuses[depth], certificate, issuer, now=now)
                        if result.defects <= {"revoked"} and "revoked" in result.defects:
                            revoked.add(depth)
                    # Inspect every advertised full CRL endpoint; no good
                    # alternative masks another authenticated revocation.
                    crl_wires: list[bytes] = []
                    delta_urls: set[str] = set()
                    for url in crls:
                        count += 1
                        if count > 16:
                            raise UnmappableTLS(UnmappableReason.UNAVAILABLE_STATUS)
                        wire = await self.fetch(url, None, job=job)
                        crl_wires.append(wire)
                        base = x509.load_der_x509_crl(wire)
                        for source in (certificate, base):
                            freshest = get_extension(source, x509.FreshestCRL)
                            for point in freshest or ():
                                if point.crl_issuer or not point.full_name:
                                    raise UnmappableTLS(UnmappableReason.UNAVAILABLE_STATUS)
                                for location in point.full_name:
                                    if not isinstance(location, x509.UniformResourceIdentifier):
                                        raise UnmappableTLS(UnmappableReason.UNAVAILABLE_STATUS)
                                    delta_urls.add(location.value)
                    for url in sorted(delta_urls):
                        count += 1
                        if count > 16:
                            raise UnmappableTLS(UnmappableReason.UNAVAILABLE_STATUS)
                        crl_wires.append(await self.fetch(url, None, job=job))
                    if crl_wires and crl_set_revoked(
                        tuple(crl_wires), certificate, issuer, now=now, signers=chain
                    ):
                        revoked.add(depth)
                return replace(observed, staples=tuple(statuses), revoked=tuple(sorted(revoked)))
        except CertificateDefectRequiresMirror:
            raise
        except Exception:
            raise UnmappableTLS(UnmappableReason.UNAVAILABLE_STATUS) from None
