"""Real validator feasibility before implementing intermediate-defect mirroring."""

import subprocess
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from test_certificates import pair_signer as pair_signer


@pytest.mark.parametrize("defect,error", [("valid", None), ("expired", 10), ("future", 9)])
def test_self_issued_chain_preserves_time_defect_without_weakening_path_length(
    pair_signer, tmp_path, defect, error
):
    now = datetime.now(UTC)
    bridge_key = ec.generate_private_key(ec.SECP384R1())
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    before = now + timedelta(days=1) if defect == "future" else now - timedelta(days=2)
    after = now - timedelta(days=1) if defect == "expired" else now + timedelta(days=2)
    bridge = (
        x509.CertificateBuilder()
        .subject_name(pair_signer.certificate.subject)
        .issuer_name(pair_signer.certificate.subject)
        .public_key(bridge_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(before)
        .not_valid_after(after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False), True
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(bridge_key.public_key()), False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                pair_signer.private_key.public_key()
            ),
            False,
        )
        .sign(pair_signer.private_key, hashes.SHA384())
    )
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "origin.example")]))
        .issuer_name(bridge.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=2))
        .not_valid_after(now + timedelta(days=2))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("origin.example")]), False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, False, False, False, False), True
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(bridge_key.public_key()), False
        )
        .sign(bridge_key, hashes.SHA384())
    )
    assert (
        pair_signer.certificate.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value.path_length
        == 0
    )
    assert bridge.subject == bridge.issuer
    bridge.verify_directly_issued_by(pair_signer.certificate)
    # Only public certificates are written, never any key material.
    for name, certificate in (
        ("root", pair_signer.certificate),
        ("bridge", bridge),
        ("leaf", leaf),
    ):
        (tmp_path / f"{name}.pem").write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    result = subprocess.run(
        [
            "openssl",
            "verify",
            "-x509_strict",
            "-purpose",
            "sslserver",
            "-verify_hostname",
            "origin.example",
            "-CAfile",
            str(tmp_path / "root.pem"),
            "-untrusted",
            str(tmp_path / "bridge.pem"),
            str(tmp_path / "leaf.pem"),
        ],
        capture_output=True,
        timeout=5,
        check=False,
    )
    output = result.stdout + result.stderr
    if error is None:
        assert result.returncode == 0, output.decode()
    else:
        assert result.returncode != 0
        assert f"error {error} at 1 depth lookup".encode() in output
        assert b"path length" not in output.lower()
        assert b"error 25 " not in output
