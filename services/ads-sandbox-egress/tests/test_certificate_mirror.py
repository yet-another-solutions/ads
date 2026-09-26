import hashlib
import ipaddress
import os
import ssl
import subprocess
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ads_sandbox_ca.certificates import mint
from ads_sandbox_egress.certificate_mirror import CertificateMirror
from ads_sandbox_egress.certificate_validation import CertificateValidator
from ads_sandbox_egress.certificates import (
    CertificateDefectRequiresMirror,
    EgressSigner,
    PairDestination,
    certificate_builder,
)
from ads_sandbox_egress.issuers import untrusted_issuer
from ads_sandbox_egress.origin_tls import OriginCertificate, VerificationIssue
from ads_sandbox_egress.tls import TLSContext, UnmappableTLS
from test_certificates import pair_signer as pair_signer
from test_minted_anchor import _hierarchy
from test_origin_tls import certificate_fixture
from test_tls import native as native

PEM, DER = serialization.Encoding.PEM, serialization.Encoding.DER


def mirror_fixture(library, signer):
    validator = CertificateValidator(
        library, b"".join(cert.public_bytes(PEM) for cert in (signer.certificate, *signer.chain))
    )
    process = untrusted_issuer(signer.certificate.not_valid_after_utc)
    return CertificateMirror(signer, process, validator, "http://egress.invalid/crl/test")


def real_signer():
    root, parent, parent_key, _ = _hierarchy()
    material = mint(
        parent.public_bytes(PEM) + root.public_bytes(PEM),
        parent_key.private_bytes(
            PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ),
    )
    return EgressSigner.load(
        material.certificate,
        material.private_key,
        (parent.public_bytes(PEM), root.public_bytes(PEM)),
    )


def observed(library, chain, anchors, hostname):
    issues = CertificateValidator(library, anchors).observe(
        tuple(certificate.public_bytes(PEM) for certificate in chain), hostname
    )
    return OriginCertificate(
        tuple(certificate.public_bytes(DER) for certificate in chain),
        tuple(certificate.public_bytes(DER) for certificate in chain),
        issues,
        b"h2",
    )


@pytest.mark.parametrize(
    "defect,code",
    [
        ("expired", 10),
        ("future", 9),
        ("hostname", 62),
        ("ip", 64),
        ("purpose", 26),
        ("critical", 34),
        ("signature", 7),
        ("unknown", 19),
        ("missing", 20),
    ],
)
def test_leaf_error_mirrors_real_native_and_independent_openssl(
    native, pair_signer, tmp_path, defect, code
):
    library, _, _ = native
    _, ca_pem, leaf, _ = certificate_fixture(tmp_path, defect)
    root = x509.load_pem_x509_certificate(ca_pem)
    chain = (leaf,) if defect == "missing" else (leaf, root)
    name = (
        "wrong.example"
        if defect == "hostname"
        else "1.1.1.1"
        if defect == "ip"
        else "origin.example"
    )
    anchors = (
        pair_signer.certificate.public_bytes(PEM) if defect in ("unknown", "missing") else ca_pem
    )
    original = observed(library, chain, anchors, name)
    assert code in {issue.code for issue in original.issues}
    mirror = mirror_fixture(library, pair_signer)
    result = mirror.mirror(PairDestination(ipaddress.ip_address("1.1.1.1"), 443, name), original)
    assert result.selected_alpn == b"h2"
    actual = mirror.validator.observe(result.certificate_chain, name)
    assert code in {issue.code for issue in actual}
    transformed = x509.load_pem_x509_certificate(result.certificate_chain[0])
    assert transformed.not_valid_before_utc == leaf.not_valid_before_utc
    assert transformed.not_valid_after_utc == leaf.not_valid_after_utc
    assert transformed.extensions.get_extension_for_class(x509.SubjectAlternativeName) == (
        leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    )
    # Only public certificates go to the independent command-line validator.
    (tmp_path / "trusted.pem").write_bytes(pair_signer.certificate.public_bytes(PEM))
    (tmp_path / "leaf.pem").write_bytes(result.certificate_chain[0])
    (tmp_path / "chain.pem").write_bytes(b"".join(result.certificate_chain[1:]))
    checked = subprocess.run(
        [
            "openssl",
            "verify",
            "-x509_strict",
            "-purpose",
            "sslserver",
            "-verify_ip" if defect == "ip" else "-verify_hostname",
            name,
            "-CAfile",
            str(tmp_path / "trusted.pem"),
            "-untrusted",
            str(tmp_path / "chain.pem"),
            str(tmp_path / "leaf.pem"),
        ],
        capture_output=True,
        timeout=5,
        check=False,
    )
    assert checked.returncode != 0
    assert f"error {code} ".encode() in checked.stderr
    assert "private_key=" not in repr(result)
    (tmp_path / "private.pem").unlink()


@pytest.mark.parametrize("defect,code", [("expired", 10), ("future", 9)])
@pytest.mark.parametrize("real_hierarchy", [False, True])
def test_intermediate_dates_do_not_add_leaf_time_or_path_length_defect(
    native, pair_signer, tmp_path, defect, code, real_hierarchy
):
    library, _, _ = native
    _, _, leaf, _ = certificate_fixture(tmp_path, "valid")
    key = ec.generate_private_key(ec.SECP384R1())
    now = datetime.now(UTC)
    # Source fixture deliberately uses a self-issued bridge so original native
    # outcomes contain only the intended intermediate time error.
    before = now + timedelta(days=1) if defect == "future" else now - timedelta(days=2)
    after = now + timedelta(days=2) if defect == "future" else now - timedelta(days=1)
    ca = pair_signer.certificate
    builder = (
        x509.CertificateBuilder()
        .subject_name(ca.subject)
        .issuer_name(ca.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(before)
        .not_valid_after(after)
    )
    for extension in ca.extensions:
        if extension.oid not in (
            x509.ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
            x509.ExtensionOID.SUBJECT_KEY_IDENTIFIER,
        ):
            builder = builder.add_extension(extension.value, extension.critical)
    intermediate = (
        builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
        .add_extension(
            x509.AuthorityKeyIdentifier(
                x509.SubjectKeyIdentifier.from_public_key(ca.public_key()).digest,
                [x509.DirectoryName(ca.issuer)],
                ca.serial_number,
            ),
            False,
        )
        .sign(pair_signer.private_key, hashes.SHA384())
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = certificate_builder(
        leaf, leaf_key, intermediate, "http://fixture.invalid/crl", cap_expiry=False
    ).sign(key, hashes.SHA384())
    original = observed(library, (leaf, intermediate, ca), ca.public_bytes(PEM), "origin.example")
    for label, cert in (("root", ca), ("bridge", intermediate), ("leaf", leaf)):
        (tmp_path / f"{label}.pem").write_bytes(cert.public_bytes(PEM))
    for executable in ("openssl", str(native[2])):
        proof = subprocess.run(
            [
                executable,
                "verify",
                "-x509_strict",
                "-purpose",
                "sslserver",
                "-CAfile",
                str(tmp_path / "root.pem"),
                "-untrusted",
                str(tmp_path / "bridge.pem"),
                str(tmp_path / "leaf.pem"),
            ],
            capture_output=True,
            timeout=5,
            env={**os.environ, "LD_LIBRARY_PATH": str(native[1])},
        )
        assert proof.returncode != 0
        assert f"error {code} at 1 depth lookup".encode() in proof.stderr
        assert b"error 19 " not in proof.stderr
    assert {(issue.code, issue.depth) for issue in original.issues} == {(code, 1)}
    mirror = mirror_fixture(library, real_signer() if real_hierarchy else pair_signer)
    result = mirror.mirror(
        PairDestination(ipaddress.ip_address("1.1.1.1"), 443, "origin.example"), original
    )
    assert {
        (issue.code, issue.depth)
        for issue in mirror.validator.observe(result.certificate_chain, "origin.example")
    } == {(code, 1)}
    (tmp_path / "private.pem").unlink()


def test_simultaneous_expiry_and_hostname_are_both_preserved(native, pair_signer, tmp_path):
    library, _, _ = native
    _, ca, leaf, _ = certificate_fixture(tmp_path, "expired")
    original = observed(library, (leaf, x509.load_pem_x509_certificate(ca)), ca, "wrong.example")
    assert {issue.code for issue in original.issues} == {10, 62}
    mirror = mirror_fixture(library, pair_signer)
    result = mirror.mirror(
        PairDestination(ipaddress.ip_address("1.1.1.1"), 443, "wrong.example"), original
    )
    assert {
        issue.code for issue in mirror.validator.observe(result.certificate_chain, "wrong.example")
    } == {10, 62}
    (tmp_path / "private.pem").unlink()


def test_incomplete_support_is_not_relabelled_unmappable(native, pair_signer, tmp_path):
    library, _, _ = native
    _, ca, leaf, _ = certificate_fixture(tmp_path, "valid")
    original = observed(library, (leaf, x509.load_pem_x509_certificate(ca)), ca, "origin.example")
    mirror = mirror_fixture(library, pair_signer)
    destination = PairDestination(ipaddress.ip_address("1.1.1.1"), 443, "origin.example")
    with pytest.raises(ValueError, match="stable"):
        mirror.mirror(destination, original)
    revoked = replace(
        original,
        issues=(VerificationIssue(23, 0, hashlib.sha256(original.built_chain[0]).hexdigest()),),
    )
    with pytest.raises(CertificateDefectRequiresMirror, match="not_implemented"):
        mirror.mirror(destination, revoked)
    with pytest.raises(UnmappableTLS, match="unrepresentable"):
        mirror.mirror(destination, replace(revoked, issues=(VerificationIssue(10, 0, "0" * 64),)))
    with pytest.raises(UnmappableTLS, match="malformed"):
        mirror.mirror(
            destination, replace(revoked, built_chain=(b"broken",), presented_chain=(b"broken",))
        )
    (tmp_path / "private.pem").unlink()


@pytest.mark.parametrize("defect,code", [("expired", 10), ("hostname", 62), ("signature", 7)])
def test_real_tls_client_receives_original_failure_not_clean_certificate(
    native, pair_signer, tmp_path, defect, code
):
    library, _, _ = native
    _, ca, leaf, _ = certificate_fixture(tmp_path, defect)
    name = "wrong.example" if defect == "hostname" else "origin.example"
    original = observed(library, (leaf, x509.load_pem_x509_certificate(ca)), ca, name)
    mirror = mirror_fixture(library, pair_signer)
    replacement = mirror.mirror(
        PairDestination(ipaddress.ip_address("1.1.1.1"), 443, name), original
    )
    context = TLSContext(library, (library.generate_ech("cover.example"),))
    server = context.session()
    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_context.load_verify_locations(cadata=pair_signer.certificate.public_bytes(PEM).decode())
    client_context.set_alpn_protocols(["h2"])
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    client = client_context.wrap_bio(incoming, outgoing, server_hostname=name)
    failed = False
    try:
        for _ in range(30):
            try:
                client.do_handshake()
            except ssl.SSLWantReadError:
                pass
            except ssl.SSLCertVerificationError as error:
                assert error.verify_code == code
                failed = True
                break
            if data := outgoing.read():
                server.feed(data)
            state = server.handshake()
            if state == "hello":
                server.resume(
                    replacement.certificate_chain,
                    replacement.private_key,
                    replacement.selected_alpn,
                )
                server.handshake()
            if data := server.drain():
                incoming.write(data)
        assert failed
        assert not server.established
    finally:
        server.close()
        context.close()
        (tmp_path / "private.pem").unlink()
    assert not context._sessions


def test_outcome_guard_refuses_to_serve_a_repaired_or_changed_defect(native, pair_signer, tmp_path):
    library, _, _ = native
    _, ca, leaf, _ = certificate_fixture(tmp_path, "valid")
    original = observed(library, (leaf, x509.load_pem_x509_certificate(ca)), ca, "origin.example")
    claimed = replace(
        original,
        issues=(VerificationIssue(10, 0, hashlib.sha256(original.built_chain[0]).hexdigest()),),
    )
    mirror = mirror_fixture(library, pair_signer)
    with pytest.raises(CertificateDefectRequiresMirror, match="outcome_mismatch"):
        mirror.mirror(
            PairDestination(ipaddress.ip_address("1.1.1.1"), 443, "origin.example"), claimed
        )
    (tmp_path / "private.pem").unlink()


def test_process_issuer_binding_and_local_crl_url_are_required(native, pair_signer):
    library, _, _ = native
    process = untrusted_issuer(pair_signer.certificate.not_valid_after_utc)
    validator = CertificateValidator(library, pair_signer.certificate.public_bytes(PEM))
    with pytest.raises(ValueError, match="URL"):
        CertificateMirror(pair_signer, process, validator, "https://user:password@example/crl")
    with pytest.raises(ValueError, match="key mismatch"):
        CertificateMirror(
            pair_signer,
            replace(process, private_key=ec.generate_private_key(ec.SECP384R1())),
            validator,
            "http://egress.invalid/crl/test",
        )
    with pytest.raises(ValueError, match="independent"):
        CertificateMirror(
            pair_signer,
            replace(
                process, certificate=pair_signer.certificate, private_key=pair_signer.private_key
            ),
            validator,
            "http://egress.invalid/crl/test",
        )


def test_unknown_issuer_uses_same_process_root_without_trusting_it(native, pair_signer, tmp_path):
    library, _, _ = native
    _, ca, leaf, _ = certificate_fixture(tmp_path, "valid")
    original = observed(
        library,
        (leaf, x509.load_pem_x509_certificate(ca)),
        pair_signer.certificate.public_bytes(PEM),
        "origin.example",
    )
    mirror = mirror_fixture(library, pair_signer)
    destination = PairDestination(ipaddress.ip_address("1.1.1.1"), 443, "origin.example")
    first, second = (mirror.mirror(destination, original) for _ in range(2))
    assert (
        first.certificate_chain[-1]
        == second.certificate_chain[-1]
        == (mirror.untrusted.certificate.public_bytes(PEM))
    )
    assert first.private_key != second.private_key
    assert {
        issue.code for issue in mirror.validator.observe(first.certificate_chain, "origin.example")
    } == {19}
    (tmp_path / "private.pem").unlink()
