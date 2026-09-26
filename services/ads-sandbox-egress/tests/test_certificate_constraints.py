import ipaddress
import os
import subprocess

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtensionOID

from ads_sandbox_egress.certificate_validation import CertificateValidator
from ads_sandbox_egress.certificates import PairDestination, certificate_builder
from ads_sandbox_egress.origin_tls import OriginCertificate
from test_certificate_mirror import mirror_fixture, real_signer
from test_minted_anchor import _hierarchy
from test_origin_tls import certificate_fixture
from test_tls import native as native

PEM, DER = serialization.Encoding.PEM, serialization.Encoding.DER


def rebuild(source, key, signing, change):
    builder = (
        x509.CertificateBuilder()
        .subject_name(source.subject)
        .issuer_name(source.issuer)
        .public_key(key.public_key())
        .serial_number(source.serial_number)
        .not_valid_before(source.not_valid_before_utc)
        .not_valid_after(source.not_valid_after_utc)
    )
    for extension in source.extensions:
        transformed = change(extension)
        if transformed is not None:
            value, critical = transformed
            builder = builder.add_extension(value, critical)
    return builder.sign(signing, hashes.SHA384())


@pytest.mark.parametrize(
    "case,expected",
    [
        ("ca", {79, 82, 26}),
        ("ca-ku", {79, 81, 26, 32}),
        ("leaf-ku", {26}),
        ("path", {25}),
        ("noncritical-ca", {89}),
        ("missing-ku", {81, 92}),
    ],
)
def test_constraints_preserve_actual_native_failure_classes_and_independent_client_error(
    native, tmp_path, case, expected
):
    library, _, _ = native
    root, parent, parent_key, root_key = _hierarchy()

    def changed(extension):
        if case == "ca" and extension.oid == ExtensionOID.BASIC_CONSTRAINTS:
            return x509.BasicConstraints(False, None), True
        if case == "ca-ku" and extension.oid == ExtensionOID.KEY_USAGE:
            return x509.KeyUsage(True, False, False, False, False, False, True, False, False), True
        if case == "noncritical-ca" and extension.oid == ExtensionOID.BASIC_CONSTRAINTS:
            return extension.value, False
        if case == "missing-ku" and extension.oid == ExtensionOID.KEY_USAGE:
            return None
        return extension.value, extension.critical

    parent = rebuild(parent, parent_key, root_key, changed)
    if case == "path":
        root = rebuild(
            root,
            root_key,
            root_key,
            lambda ext: (
                x509.BasicConstraints(True, 0)
                if ext.oid == ExtensionOID.BASIC_CONSTRAINTS
                else ext.value,
                ext.critical,
            ),
        )
    _, _, original_leaf, _ = certificate_fixture(tmp_path, "valid")
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = certificate_builder(original_leaf, leaf_key, parent, "http://fixture.invalid/crl").sign(
        parent_key, hashes.SHA384()
    )
    if case == "leaf-ku":
        leaf = rebuild(
            leaf,
            leaf_key,
            parent_key,
            lambda ext: (
                x509.KeyUsage(False, True, False, False, False, False, False, False, False)
                if ext.oid == ExtensionOID.KEY_USAGE
                else ext.value,
                ext.critical,
            ),
        )
    findings = CertificateValidator(library, root.public_bytes(PEM)).observe(
        tuple(cert.public_bytes(PEM) for cert in (leaf, parent, root)), "origin.example"
    )
    assert {issue.code for issue in findings} == expected
    original = OriginCertificate(
        tuple(cert.public_bytes(DER) for cert in (leaf, parent)),
        tuple(cert.public_bytes(DER) for cert in (leaf, parent, root)),
        findings,
        None,
    )
    # Always exercise the actual CA-Job hierarchy, not a convenience root signer.
    signer = real_signer()
    mirror = mirror_fixture(library, signer)
    result = mirror.mirror(
        PairDestination(ipaddress.ip_address("1.1.1.1"), 443, "origin.example"), original
    )
    actual = mirror.validator.observe(result.certificate_chain, "origin.example")
    assert {issue.code for issue in actual} == expected
    if case != "path":
        assert {(issue.code, issue.depth) for issue in actual} == {
            (issue.code, issue.depth) for issue in findings
        }
    assert (
        signer.certificate.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value.path_length
        == 0
    )
    (tmp_path / "trusted.pem").write_bytes(mirror.validator.anchor)
    (tmp_path / "substitute.pem").write_bytes(result.certificate_chain[0])
    (tmp_path / "chain.pem").write_bytes(b"".join(result.certificate_chain[1:]))
    try:
        for executable in ("openssl", str(native[2])):
            proof = subprocess.run(
                [
                    executable,
                    "verify",
                    "-x509_strict",
                    "-purpose",
                    "sslserver",
                    "-CAfile",
                    str(tmp_path / "trusted.pem"),
                    "-untrusted",
                    str(tmp_path / "chain.pem"),
                    str(tmp_path / "substitute.pem"),
                ],
                capture_output=True,
                timeout=5,
                env={**os.environ, "LD_LIBRARY_PATH": str(native[1])},
            )
            if case == "noncritical-ca" and executable != "openssl":
                # OpenSSL 4 relaxed this field; ADS retains the OpenSSL 3 strict
                # compatibility finding and preserves it for strict clients.
                assert proof.returncode == 0
                assert (
                    not x509.load_pem_x509_certificate(result.certificate_chain[1])
                    .extensions.get_extension_for_class(x509.BasicConstraints)
                    .critical
                )
            else:
                assert proof.returncode != 0
                assert any(f"error {code} ".encode() in proof.stderr for code in expected)
    finally:
        (tmp_path / "private.pem").unlink()
