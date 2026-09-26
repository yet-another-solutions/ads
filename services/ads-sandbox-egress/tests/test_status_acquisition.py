import asyncio
import ipaddress
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import AuthorityInformationAccessOID

from ads_sandbox_egress.origin_tls import OriginCertificate
from ads_sandbox_egress.status_acquisition import StatusAcquisition, crl_revoked, status_urls
from ads_sandbox_egress.tls import UnmappableTLS
from test_certificates import pair_signer as pair_signer
from test_ocsp_status import material as material
from test_ocsp_status import wire
from test_resolution import resolver


def crl(material, case):
    now = material.now
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(material.issuer.subject)
        .last_update(now - timedelta(minutes=5))
        .next_update(
            now - timedelta(seconds=1) if case == "expired" else now + timedelta(minutes=5)
        )
    )
    if case in ("revoked", "future"):
        revoked = (
            x509.RevokedCertificateBuilder()
            .serial_number(material.leaf.serial_number)
            .revocation_date(
                now + timedelta(days=1) if case == "future" else now - timedelta(days=1)
            )
            .build()
        )
        builder = builder.add_revoked_certificate(revoked)
    result = builder.sign(material.key, hashes.SHA256()).public_bytes(Encoding.DER)
    return result[:-1] + bytes((result[-1] ^ 1,)) if case == "signature" else result


@pytest.mark.parametrize("case", ["good", "revoked", "expired", "future", "signature"])
def test_crl_crypto_freshness_and_exact_revocation_target(material, case):
    if case in ("good", "revoked"):
        assert crl_revoked(
            crl(material, case), material.leaf, material.issuer, now=material.now
        ) is (case == "revoked")
    else:
        with pytest.raises(UnmappableTLS, match="unavailable_status"):
            crl_revoked(crl(material, case), material.leaf, material.issuer, now=material.now)


def advertised(material, *, ocsp_url=None, crl_url=None):
    source = material.leaf
    builder = (
        x509.CertificateBuilder()
        .subject_name(source.subject)
        .issuer_name(source.issuer)
        .public_key(source.public_key())
        .serial_number(source.serial_number)
        .not_valid_before(source.not_valid_before_utc)
        .not_valid_after(source.not_valid_after_utc)
    )
    for extension in source.extensions:
        builder = builder.add_extension(extension.value, extension.critical)
    if ocsp_url is not None:
        builder = builder.add_extension(
            x509.AuthorityInformationAccess(
                [
                    x509.AccessDescription(
                        AuthorityInformationAccessOID.OCSP, x509.UniformResourceIdentifier(ocsp_url)
                    )
                ]
            ),
            False,
        )
    if crl_url is not None:
        builder = builder.add_extension(
            x509.CRLDistributionPoints(
                [
                    x509.DistributionPoint(
                        [x509.UniformResourceIdentifier(crl_url)], None, None, None
                    )
                ]
            ),
            False,
        )
    return replace(material, leaf=builder.sign(material.key, hashes.SHA256()))


@pytest.mark.parametrize(
    "kind,case",
    [
        ("ocsp", "good"),
        ("ocsp", "revoked"),
        ("ocsp", "unknown"),
        ("crl", "good"),
        ("crl", "revoked"),
        ("crl", "expired"),
        ("crl", "signature"),
        ("crl", "redirect"),
        ("crl", "framing"),
        ("crl", "large"),
    ],
)
def test_real_bounded_public_metadata_http_acquisition(material, kind, case):
    material = advertised(
        material,
        ocsp_url="http://1.1.1.1/ocsp" if kind == "ocsp" else None,
        crl_url="http://1.1.1.1/crl" if kind == "crl" else None,
    )
    observed = OriginCertificate(
        (material.leaf.public_bytes(Encoding.DER),),
        (material.leaf.public_bytes(Encoding.DER), material.issuer.public_bytes(Encoding.DER)),
        (),
        None,
    )

    async def run():
        tasks, writers, seen = set(), set(), []

        async def respond(reader, writer):
            writers.add(writer)
            try:
                request = await reader.readuntil(b"\r\n\r\n")
                seen.append(request)
                if kind == "ocsp":
                    size = int(request.split(b"content-length: ", 1)[1].split(b"\r\n", 1)[0])
                    await reader.readexactly(size)
                data = wire(material, case) if kind == "ocsp" else crl(material, case)
                if case == "large":
                    data = b"x" * (2 * 1024**2 + 1)
                if case == "redirect":
                    writer.write(
                        b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1/\r\n"
                        b"Content-Length: 0\r\n\r\n"
                    )
                elif case == "framing":
                    writer.write(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\nbad"
                    )
                else:
                    writer.write(
                        b"HTTP/1.1 200 OK\r\nContent-Length: "
                        + str(len(data)).encode()
                        + b"\r\nConnection: close\r\n\r\n"
                        + data
                    )
                await writer.drain()
            except (OSError, asyncio.IncompleteReadError):
                pass
            finally:
                writer.close()
                writers.discard(writer)

        def accept(reader, writer):
            task = asyncio.create_task(respond(reader, writer))
            tasks.add(task)
            task.add_done_callback(tasks.discard)

        listener = await asyncio.start_server(accept, "127.0.0.1", 0)

        async def connect(address, port):
            assert address == ipaddress.IPv4Address("1.1.1.1") and port == 80
            return await asyncio.open_connection(*listener.sockets[0].getsockname())

        acquisition = StatusAcquisition(resolver(), None, connect)
        try:
            if case in ("expired", "signature", "redirect", "framing", "large"):
                with pytest.raises(UnmappableTLS, match="unavailable_status"):
                    await acquisition.acquire(observed)
            else:
                result = await acquisition.acquire(observed)
                assert result.revoked == ((0,) if case == "revoked" else ())
                assert result.presented_chain == observed.presented_chain
                assert bool(result.staples[0]) is (kind == "ocsp")
            assert len(seen) == 1
            assert seen[0].startswith(b"POST /ocsp " if kind == "ocsp" else b"GET /crl ")
        finally:
            listener.close()
            await listener.wait_closed()
            for writer in tuple(writers):
                writer.transport.abort()
            for task in tuple(tasks):
                task.cancel()
            await asyncio.gather(*tuple(tasks), return_exceptions=True)

    asyncio.run(run())


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/crl",
        "http://10.0.0.1/crl",
        "http://[::1]/crl",
        "file:///etc/passwd",
        "http://secret:password@1.1.1.1/crl",
        "http://1.1.1.1/crl#fragment",
        "http://service.cluster.local/crl",
    ],
)
def test_metadata_cannot_escape_public_destination_gate(material, url):
    material = advertised(material, crl_url=url)
    observed = OriginCertificate(
        (material.leaf.public_bytes(Encoding.DER),),
        (material.leaf.public_bytes(Encoding.DER), material.issuer.public_bytes(Encoding.DER)),
        (),
        None,
    )
    dial = AsyncMock()
    acquisition = StatusAcquisition(resolver(), None, dial)

    async def run():
        with pytest.raises(UnmappableTLS):
            await acquisition.acquire(observed)
        dial.assert_not_awaited()

    asyncio.run(run())


def test_no_advertised_status_is_not_invented(material):
    assert status_urls(material.leaf) == ((), ())


@pytest.mark.parametrize("kind", ["ocsp", "crl"])
@pytest.mark.parametrize("expired", [False, True])
def test_acquisition_validates_at_receipt_without_extending_deadline(
    material, monkeypatch, kind, expired
):
    from ads_sandbox_egress import status_acquisition

    material = advertised(
        material,
        ocsp_url="http://1.1.1.1/ocsp" if kind == "ocsp" else None,
        crl_url="http://1.1.1.1/crl" if kind == "crl" else None,
    )
    observed = OriginCertificate(
        (material.leaf.public_bytes(Encoding.DER),),
        (material.leaf.public_bytes(Encoding.DER), material.issuer.public_bytes(Encoding.DER)),
        (),
        None,
    )
    clock = material.now - timedelta(seconds=1)

    class Clock:
        @staticmethod
        def now(zone):
            assert zone is UTC
            return clock

    monkeypatch.setattr(status_acquisition, "datetime", Clock)
    acquisition = StatusAcquisition(resolver(), None, AsyncMock())
    deadlines = []

    async def fetch(url, body, *, job):
        nonlocal clock
        deadlines.append(job.deadline)
        data = wire(material, "revoked") if kind == "ocsp" else crl(material, "revoked")
        received = datetime.now(UTC)
        clock = received + timedelta(hours=1) if expired else received
        return data

    monkeypatch.setattr(acquisition, "fetch", fetch)
    if expired and kind == "crl":
        with pytest.raises(UnmappableTLS, match="unavailable_status"):
            asyncio.run(acquisition.acquire(observed))
    else:
        result = asyncio.run(acquisition.acquire(observed))
        assert result.revoked == (() if expired else (0,))
    assert len(deadlines) == 1


def test_status_fetch_inspects_both_families_before_dial(monkeypatch):
    from types import SimpleNamespace

    import dns.rdatatype

    from ads_sandbox_egress.resolution import ResolutionJob

    upstream = resolver()
    calls = []

    async def acquire(host, family, *, job):
        calls.append(family)
        return SimpleNamespace(
            direct_addresses=(
                ipaddress.ip_address("1.1.1.1" if family == dns.rdatatype.A else "::1"),
            )
        )

    monkeypatch.setattr(upstream, "acquire", acquire)
    dial = AsyncMock()
    acquisition = StatusAcquisition(upstream, None, dial)

    async def run():
        import time

        from ads_sandbox_egress.policy import RequestDenied

        with pytest.raises(RequestDenied):
            await acquisition.fetch(
                "http://status.example/crl", None, job=ResolutionJob(time.monotonic() + 10)
            )
        assert calls == [dns.rdatatype.A, dns.rdatatype.AAAA]
        dial.assert_not_awaited()

    asyncio.run(run())
