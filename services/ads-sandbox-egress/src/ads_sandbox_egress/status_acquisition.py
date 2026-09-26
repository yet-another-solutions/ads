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
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID

from ads_sandbox_egress.certificates import CertificateDefectRequiresMirror
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
                if point.relative_name is not None or point.crl_issuer is not None or point.reasons:
                    raise CertificateDefectRequiresMirror("scoped_CRL_requires_composer")
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
    if not 1 <= len(wire) <= 2 * 1024**2:
        raise UnmappableTLS(UnmappableReason.UNAVAILABLE_STATUS)
    try:
        crl = x509.load_der_x509_crl(wire)
        public = issuer.public_key()
        if not isinstance(
            public,
            (
                rsa.RSAPublicKey,
                ec.EllipticCurvePublicKey,
                dsa.DSAPublicKey,
                ed25519.Ed25519PublicKey,
                ed448.Ed448PublicKey,
            ),
        ):
            raise CertificateDefectRequiresMirror("CRL_algorithm_requires_composer")
        if (
            crl.issuer != issuer.subject
            or not crl.is_signature_valid(public)
            or crl.next_update_utc is None
            or not crl.last_update_utc <= now < crl.next_update_utc
            or len(crl) > 100000
        ):
            raise ValueError
        usage = issuer.extensions.get_extension_for_class(x509.KeyUsage).value
        if not usage.crl_sign:
            raise ValueError
        for extension in crl.extensions:
            if extension.oid in (
                ExtensionOID.DELTA_CRL_INDICATOR,
                ExtensionOID.ISSUING_DISTRIBUTION_POINT,
            ):
                raise CertificateDefectRequiresMirror("scoped_CRL_requires_composer")
            if extension.critical:
                raise CertificateDefectRequiresMirror("critical_CRL_requires_composer")
            if extension.oid == ExtensionOID.AUTHORITY_KEY_IDENTIFIER and (
                extension.value.key_identifier is not None
                and extension.value.key_identifier
                != x509.SubjectKeyIdentifier.from_public_key(issuer.public_key()).digest
            ):
                raise ValueError
        entries = [entry for entry in crl if entry.serial_number == certificate.serial_number]
        if len(entries) > 1:
            raise ValueError
        if not entries:
            return False
        entry = entries[0]
        if entry.revocation_date_utc > now:
            raise ValueError
        if any(extension.critical for extension in entry.extensions):
            raise CertificateDefectRequiresMirror("critical_CRL_entry_requires_composer")
        try:
            if (
                entry.extensions.get_extension_for_class(x509.CRLReason).value.reason
                == x509.ReasonFlags.remove_from_crl
            ):
                raise CertificateDefectRequiresMirror("delta_CRL_requires_composer")
        except x509.ExtensionNotFound:
            pass
        return True
    except (ValueError, TypeError, x509.ExtensionNotFound):
        raise UnmappableTLS(UnmappableReason.UNAVAILABLE_STATUS) from None


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
            answer = await self.resolver.acquire(host, dns.rdatatype.A, job=job)
            addresses = set(answer.direct_addresses)
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
                    for url in crls:
                        count += 1
                        if count > 16:
                            raise UnmappableTLS(UnmappableReason.UNAVAILABLE_STATUS)
                        wire = await self.fetch(url, None, job=job)
                        if crl_revoked(wire, certificate, issuer, now=now):
                            revoked.add(depth)
                return replace(observed, staples=tuple(statuses), revoked=tuple(sorted(revoked)))
        except CertificateDefectRequiresMirror:
            raise
        except Exception:
            raise UnmappableTLS(UnmappableReason.UNAVAILABLE_STATUS) from None
