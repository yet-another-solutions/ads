import subprocess
from dataclasses import replace
from datetime import timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding

from ads_sandbox_egress.crl_status import _REASONS, crl_set_revoked
from ads_sandbox_egress.status_acquisition import StatusAcquisition, status_urls
from ads_sandbox_egress.tls import UnmappableTLS
from test_certificates import pair_signer as pair_signer
from test_ocsp_status import material as material

URL = "http://1.1.1.1/scoped.crl"


def certificate(material, reasons=None, freshest=False):
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
    for item in source.extensions:
        builder = builder.add_extension(item.value, item.critical)
    builder = builder.add_extension(
        x509.CRLDistributionPoints(
            [x509.DistributionPoint([x509.UniformResourceIdentifier(URL)], None, reasons, None)]
        ),
        False,
    )
    if freshest:
        builder = builder.add_extension(
            x509.FreshestCRL(
                [
                    x509.DistributionPoint(
                        [x509.UniformResourceIdentifier("http://1.1.1.1/delta.crl")],
                        None,
                        None,
                        None,
                    )
                ]
            ),
            False,
        )
    return replace(material, leaf=builder.sign(material.key, hashes.SHA256()))


def crl(material, *, number=1, delta=None, reason=None, scope=None, url=URL, user=True):
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(material.issuer.subject)
        .last_update(material.now - timedelta(minutes=2) + timedelta(seconds=number))
        .next_update(material.now + timedelta(minutes=5))
        .add_extension(x509.CRLNumber(number), False)
        .add_extension(
            x509.IssuingDistributionPoint(
                [x509.UniformResourceIdentifier(url)], None, user, not user, scope, False, False
            ),
            True,
        )
    )
    if delta is not None:
        builder = builder.add_extension(x509.DeltaCRLIndicator(delta), True)
    if reason is not None:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(material.leaf.serial_number)
            .revocation_date(material.now - timedelta(minutes=3))
            .add_extension(x509.CRLReason(reason), False)
            .build()
        )
    return builder.sign(material.key, hashes.SHA256()).public_bytes(Encoding.DER)


@pytest.mark.parametrize(
    "case",
    [
        "good",
        "revoked",
        "hold-removed",
        "delta-revoked",
        "missing-base",
        "wrong-base",
        "wrong-name",
        "wrong-type",
        "partial-reasons",
        "all-reasons",
        "permanent-removed",
        "signature",
        "conflicting-delta",
    ],
)
def test_scope_delta_crypto_and_independent_validation(material, tmp_path, case):
    material = certificate(material, freshest=True)
    reason = x509.ReasonFlags
    base = crl(material)
    wires = [base]
    expected = False
    invalid = case in {
        "missing-base",
        "wrong-base",
        "wrong-name",
        "wrong-type",
        "partial-reasons",
        "permanent-removed",
        "signature",
        "conflicting-delta",
    }
    if case == "revoked":
        wires = [crl(material, reason=reason.key_compromise)]
        expected = True
    elif case in ("hold-removed", "permanent-removed"):
        wires = [
            crl(
                material,
                reason=reason.certificate_hold if case == "hold-removed" else reason.key_compromise,
            ),
            crl(material, number=2, delta=1, reason=reason.remove_from_crl),
        ]
    elif case in ("delta-revoked", "missing-base", "wrong-base", "conflicting-delta"):
        delta = crl(
            material, number=2, delta=5 if case == "wrong-base" else 1, reason=reason.key_compromise
        )
        wires = [base, delta] if case != "missing-base" else [delta]
        if case == "conflicting-delta":
            wires.append(delta)
        expected = True
    elif case == "wrong-name":
        wires = [crl(material, url="http://1.1.1.1/foreign.crl")]
    elif case == "wrong-type":
        wires = [crl(material, user=False)]
    elif case in ("partial-reasons", "all-reasons"):
        first = frozenset((reason.key_compromise,))
        wires = [crl(material, scope=first)]
        if case == "all-reasons":
            wires.append(crl(material, scope=_REASONS - first))
    elif case == "signature":
        wires = [base[:-1] + bytes((base[-1] ^ 1,))]
    if invalid:
        with pytest.raises(UnmappableTLS, match="unavailable_status"):
            crl_set_revoked(tuple(wires), material.leaf, material.issuer, now=material.now)
        return
    assert (
        crl_set_revoked(tuple(wires), material.leaf, material.issuer, now=material.now) is expected
    )
    (tmp_path / "issuer.pem").write_bytes(material.issuer.public_bytes(Encoding.PEM))
    (tmp_path / "leaf.pem").write_bytes(material.leaf.public_bytes(Encoding.PEM))
    (tmp_path / "crls.pem").write_bytes(
        b"".join(x509.load_der_x509_crl(value).public_bytes(Encoding.PEM) for value in wires)
    )
    checked = subprocess.run(
        [
            "openssl",
            "verify",
            "-CAfile",
            str(tmp_path / "issuer.pem"),
            "-CRLfile",
            str(tmp_path / "crls.pem"),
            "-crl_check",
            "-extended_crl",
            "-use_deltas",
            str(tmp_path / "leaf.pem"),
        ],
        capture_output=True,
        timeout=5,
    )
    assert (checked.returncode != 0) is expected, checked.stdout + checked.stderr
    if expected:
        assert b"certificate revoked" in checked.stderr


def test_acquisition_fetches_freshest_without_changing_deadline(material, monkeypatch):
    import asyncio
    from unittest.mock import AsyncMock

    from ads_sandbox_egress.origin_tls import OriginCertificate
    from test_resolution import resolver

    material = certificate(material, freshest=True)
    assert status_urls(material.leaf) == ((), (URL,))
    observed = OriginCertificate(
        (material.leaf.public_bytes(Encoding.DER),),
        (material.leaf.public_bytes(Encoding.DER), material.issuer.public_bytes(Encoding.DER)),
        (),
        None,
    )
    acquisition = StatusAcquisition(resolver(), None, AsyncMock())
    deadlines = []

    async def fetch(url, body, *, job):
        deadlines.append(job.deadline)
        assert body is None
        if url == URL:
            return crl(material)
        assert url == "http://1.1.1.1/delta.crl"
        return crl(material, number=2, delta=1, reason=x509.ReasonFlags.key_compromise)

    monkeypatch.setattr(acquisition, "fetch", fetch)
    result = asyncio.run(acquisition.acquire(observed))
    assert result.revoked == (0,)
    assert len(deadlines) == 2 and len(set(deadlines)) == 1


@pytest.mark.parametrize("case", ["revoked", "foreign-serial", "missing-signer", "wrong-signer"])
def test_indirect_crl_binds_entry_issuer_not_only_serial(material, case):
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CRL signer")])
    signer = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(material.issuer.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(material.now - timedelta(days=1))
        .not_valid_after(material.now + timedelta(days=1))
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, False, True, False, False), True
        )
        .sign(key if case == "wrong-signer" else material.key, hashes.SHA256())
    )
    source = material.leaf
    leaf = (
        x509.CertificateBuilder()
        .subject_name(source.subject)
        .issuer_name(source.issuer)
        .public_key(source.public_key())
        .serial_number(source.serial_number)
        .not_valid_before(source.not_valid_before_utc)
        .not_valid_after(source.not_valid_after_utc)
        .add_extension(
            x509.CRLDistributionPoints(
                [
                    x509.DistributionPoint(
                        [x509.UniformResourceIdentifier(URL)],
                        None,
                        None,
                        [x509.DirectoryName(name)],
                    )
                ]
            ),
            False,
        )
        .sign(material.key, hashes.SHA256())
    )
    entry_issuer = name if case == "foreign-serial" else material.issuer.subject
    entry = (
        x509.RevokedCertificateBuilder()
        .serial_number(leaf.serial_number)
        .revocation_date(material.now - timedelta(minutes=5))
        .add_extension(x509.CertificateIssuer([x509.DirectoryName(entry_issuer)]), True)
        .build()
    )
    value = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(name)
        .last_update(material.now - timedelta(minutes=1))
        .next_update(material.now + timedelta(minutes=5))
        .add_extension(
            x509.IssuingDistributionPoint(
                [x509.UniformResourceIdentifier(URL)], None, False, False, None, True, False
            ),
            True,
        )
        .add_revoked_certificate(entry)
        .sign(key, hashes.SHA256())
        .public_bytes(Encoding.DER)
    )
    signers = () if case == "missing-signer" else (signer,)
    if case in ("missing-signer", "wrong-signer"):
        with pytest.raises(UnmappableTLS, match="unavailable_status"):
            crl_set_revoked((value,), leaf, material.issuer, now=material.now, signers=signers)
    else:
        assert crl_set_revoked(
            (value,), leaf, material.issuer, now=material.now, signers=signers
        ) is (case == "revoked")
