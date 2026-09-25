import ssl
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

from ads_sandbox_egress.origin_tls import OriginContext
from ads_sandbox_egress.tls import TLSFailure
from test_tls import native as native


def certificate_fixture(tmp_path, defect):
    ca_key = ec.generate_private_key(ec.SECP256R1())
    key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Origin fixture CA")])
    now = datetime.now(UTC)
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=2))
        .not_valid_after(now + timedelta(days=10))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False), True
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False
        )
        .sign(ca_key, hashes.SHA256())
    )
    before = now + timedelta(days=1) if defect == "future" else now - timedelta(days=2)
    after = now - timedelta(days=1) if defect == "expired" else now + timedelta(days=2)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "origin.example")]))
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(before)
        .not_valid_after(after)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("origin.example")]), False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, False, False, False, False), True
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [
                    ExtendedKeyUsageOID.CLIENT_AUTH
                    if defect == "purpose"
                    else ExtendedKeyUsageOID.SERVER_AUTH
                ]
            ),
            False,
        )
    )
    if defect == "critical":
        leaf = leaf.add_extension(
            x509.UnrecognizedExtension(ObjectIdentifier("1.3.6.1.4.1.55555.999"), b"\x05\x00"),
            True,
        )
    signer = ec.generate_private_key(ec.SECP256R1()) if defect == "signature" else ca_key
    leaf = leaf.sign(signer, hashes.SHA256())
    private = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    cert_path, key_path = tmp_path / "origin.pem", tmp_path / "private.pem"
    cert_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    key_path.touch(mode=0o600)
    key_path.write_bytes(private)
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(cert_path, key_path)
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_name)
        .last_update(now - timedelta(minutes=1))
        .next_update(now + timedelta(days=1))
        .add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(leaf.serial_number)
            .revocation_date(now - timedelta(minutes=1))
            .build()
        )
        .sign(ca_key, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
    )
    return server, ca.public_bytes(serialization.Encoding.PEM), leaf, crl


@pytest.mark.parametrize(
    "defect,expected",
    [
        ("valid", set()),
        ("expired", {10}),
        ("future", {9}),
        ("hostname", {62}),
        ("unknown", {20, 21}),
        ("signature", {7}),
        ("purpose", {26}),
        ("critical", {34}),
        ("revoked", {23}),
        ("revocation-unavailable", {3}),
    ],
)
@pytest.mark.parametrize("selected", ["h2", "http/1.1", None])
def test_real_origin_chain_validation_without_repair(native, tmp_path, defect, expected, selected):
    library, _, _ = native
    server_context, ca, leaf, crl = certificate_fixture(tmp_path, defect)
    if selected:
        server_context.set_alpn_protocols([selected])
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    server = server_context.wrap_bio(incoming, outgoing, server_side=True)
    context = OriginContext(
        library,
        extra_trust=() if defect == "unknown" else (ca,),
        system_trust=False,
        crls=(crl,) if defect == "revoked" else (),
        check_revocation=defect in ("revoked", "revocation-unavailable"),
    )
    client = context.session(
        "wrong.example" if defect == "hostname" else "origin.example", (b"h2", b"http/1.1")
    )
    complete = False
    try:
        for _ in range(30):
            state = client.handshake()
            if data := client.drain():
                incoming.write(data)
            try:
                server.do_handshake()
                complete = True
            except ssl.SSLWantReadError:
                pass
            if data := outgoing.read():
                client.feed(data)
            if state == "complete" and complete:
                break
        assert client.established and complete
        outcome = client.certificate
        assert outcome.presented_chain == (leaf.public_bytes(serialization.Encoding.DER),)
        assert {issue.code for issue in outcome.issues} == expected
        assert outcome.verified == (not expected)
        assert outcome.selected_alpn == (selected.encode() if selected else None)
        assert outcome.built_chain[0] == outcome.presented_chain[0]
        assert all(
            issue.depth >= 0 and len(issue.certificate_sha256) == 64 for issue in outcome.issues
        )
        # Handshake observation itself sends zero HTTP application bytes.
        with pytest.raises(ssl.SSLWantReadError):
            server.read()
        with pytest.raises(TLSFailure, match="client_credentials"):
            client.resume((), b"not-a-key", None)
    finally:
        client.close()
        context.close()
        (tmp_path / "private.pem").unlink()
    assert not context._sessions


def test_origin_wrong_trust_and_invalid_offers_fail_closed(native):
    library, _, _ = native
    with pytest.raises(TLSFailure, match="trust_decode"):
        OriginContext(library, extra_trust=(b"not a certificate",), system_trust=False)
    context = OriginContext(library, system_trust=False)
    try:
        for offers in ((b"",), (b"x" * 256,)):
            with pytest.raises(TLSFailure, match="alpn_offer"):
                context.session("origin.example", offers)
            assert not context._sessions
    finally:
        context.close()
