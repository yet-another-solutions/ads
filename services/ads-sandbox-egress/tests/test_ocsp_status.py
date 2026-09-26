from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

from ads_sandbox_egress.certificates import CertificateDefectRequiresMirror, CertificatePairs
from ads_sandbox_egress.identity_store import IdentityStore
from ads_sandbox_egress.ocsp_status import inspect_status
from test_certificates import pair_signer as pair_signer
from test_certificates import pair_state as pair_state


@dataclass(repr=False)
class Material:
    leaf: x509.Certificate
    issuer: x509.Certificate
    key: ec.EllipticCurvePrivateKey
    now: datetime


@pytest.fixture
def material(pair_signer):
    now = datetime.now(UTC).replace(microsecond=0)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "origin.example")]))
        .issuer_name(pair_signer.certificate.subject)
        .public_key(ec.generate_private_key(ec.SECP256R1()).public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("origin.example")]), False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                pair_signer.certificate.public_key()
            ),
            False,
        )
        .sign(pair_signer.private_key, hashes.SHA256())
    )
    return Material(leaf, pair_signer.certificate, pair_signer.private_key, now)


def wire(material, case="good"):
    issuer = material.issuer
    cert = material.leaf
    now = material.now
    signer, key = issuer, material.key
    extras = []
    if case.startswith("delegated"):
        key = ec.generate_private_key(ec.SECP256R1())
        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OCSP responder")]))
            .issuer_name(issuer.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(
                now - timedelta(seconds=1)
                if case == "delegated-expired"
                else now + timedelta(days=1)
            )
        )
        if case != "delegated-no-eku":
            builder = builder.add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]), False
            )
        if case == "delegated-bad-ku":
            builder = builder.add_extension(
                x509.KeyUsage(False, False, False, False, False, False, False, False, False), True
            )
        signer = builder.sign(material.key, hashes.SHA256())
        extras = [signer]
    before = now + timedelta(minutes=1) if case == "future" else now - timedelta(minutes=1)
    after = now - timedelta(seconds=1) if case == "expired" else now + timedelta(minutes=5)
    status = (
        ocsp.OCSPCertStatus.REVOKED
        if case == "revoked"
        else ocsp.OCSPCertStatus.UNKNOWN
        if case == "unknown"
        else ocsp.OCSPCertStatus.GOOD
    )
    builder = (
        ocsp.OCSPResponseBuilder()
        .add_response(
            issuer if case == "wrong-cert" else cert,
            issuer,
            hashes.SHA256(),
            status,
            before,
            None if case == "no-next" else after,
            now - timedelta(days=1) if case == "revoked" else None,
            x509.ReasonFlags.key_compromise if case == "revoked" else None,
        )
        .responder_id(ocsp.OCSPResponderEncoding.HASH, signer)
    )
    if extras:
        builder = builder.certificates(extras)
    if case == "critical":
        builder = builder.add_extension(
            x509.UnrecognizedExtension(ObjectIdentifier("1.3.6.1.4.1.55555.1"), b"\x05\x00"), True
        )
    result = builder.sign(key, hashes.SHA256()).public_bytes(Encoding.DER)
    if case == "signature":
        result = result[:-1] + bytes((result[-1] ^ 1,))
    return result


@pytest.mark.parametrize(
    "case,defects",
    [
        ("good", set()),
        ("delegated", set()),
        ("revoked", {"revoked"}),
        ("unknown", {"unknown"}),
        ("expired", {"expired"}),
        ("future", {"future"}),
        ("no-next", {"freshness_unknown"}),
        ("signature", {"signature"}),
        ("wrong-cert", {"certificate_binding"}),
        ("critical", {"critical_extension"}),
        ("delegated-no-eku", {"responder_authority"}),
        ("delegated-bad-ku", {"responder_authority"}),
        ("delegated-expired", {"responder_time"}),
    ],
)
def test_cryptographic_status_and_issuer_binding(material, case, defects):
    result = inspect_status(wire(material, case), material.leaf, material.issuer, now=material.now)
    assert result.defects == defects
    assert result.good is (not defects)


@pytest.mark.parametrize(
    "value,defect",
    [
        (None, "missing"),
        (b"", "malformed"),
        (b"bad", "malformed"),
        (b"x" * 65537, "malformed"),
        (
            ocsp.OCSPResponseBuilder.build_unsuccessful(
                ocsp.OCSPResponseStatus.TRY_LATER
            ).public_bytes(Encoding.DER),
            "responder_failure",
        ),
    ],
)
def test_absent_and_unavailable_status_never_good(material, value, defect):
    result = inspect_status(value, material.leaf, material.issuer, now=material.now)
    assert result.defects == {defect} and not result.good


def test_responder_supplied_root_cannot_change_trusted_issuer(material, pair_signer):
    value = wire(material)
    other = replace(material, issuer=pair_signer.certificate)
    # Deliberately use a different leaf; even a valid issuer-signed response
    # cannot be replayed to another certificate serial number.
    result = inspect_status(value, other.issuer, other.issuer, now=other.now)
    assert not result.good and result.defects == {"certificate_binding"}


def test_success_pair_cannot_strip_unprocessed_status(material, pair_signer, pair_state):
    import ipaddress

    from ads_sandbox_egress.certificates import PairDestination
    from ads_sandbox_egress.origin_tls import OriginCertificate

    store = IdentityStore(*pair_state, capacity=2**20, create=True)
    try:
        observed = OriginCertificate(
            (material.leaf.public_bytes(Encoding.DER),),
            (material.leaf.public_bytes(Encoding.DER), material.issuer.public_bytes(Encoding.DER)),
            (),
            None,
            (wire(material, "revoked"),),
        )
        with pytest.raises(CertificateDefectRequiresMirror, match="status_requires"):
            CertificatePairs(store, pair_signer, "http://egress.invalid/crl/test").valid(
                PairDestination(ipaddress.ip_address("1.1.1.1"), 443, "origin.example"), observed
            )
        assert not store.key_names("tls")
    finally:
        store.close()
