"""Trust-format compatibility proof; the proposed CA format is NOT deployed."""

import ipaddress
import subprocess
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtensionOID, NameOID

from ads_sandbox_ca.certificates import mint
from ads_sandbox_egress.certificate_validation import CertificateValidator
from ads_sandbox_egress.certificates import CertificatePairs, EgressSigner, PairDestination
from ads_sandbox_egress.identity_store import IdentityStore
from test_certificates import observation
from test_certificates import pair_state as pair_state
from test_tls import native as native

PEM = serialization.Encoding.PEM


def _hierarchy():
    now = datetime.now(UTC).replace(microsecond=0)

    def ca(name, depth, issuer=None, issuer_key=None):
        key = ec.generate_private_key(ec.SECP384R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        signer = issuer_key or key
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer.subject if issuer else subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=3))
            .add_extension(x509.BasicConstraints(ca=True, path_length=depth), True)
            .add_extension(
                x509.KeyUsage(False, False, False, False, False, True, True, False, False), True
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()), False
            )
            .sign(signer, hashes.SHA384())
        )
        return certificate, key

    root, root_key = ca("Fixture root", 2)
    parent, parent_key = ca("Fixture parent", 1, root, root_key)
    return root, parent, parent_key


def test_same_key_anchor_candidate_fixes_real_minted_only_trust_and_crl_checks(
    native, pair_state, tmp_path
):
    library, _, _ = native
    root, parent, parent_key = _hierarchy()
    material = mint(
        parent.public_bytes(PEM) + root.public_bytes(PEM),
        parent_key.private_bytes(
            PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ),
    )
    signer = EgressSigner.load(
        material.certificate,
        material.private_key,
        (parent.public_bytes(PEM), root.public_bytes(PEM)),
    )
    certificate = signer.certificate
    builder = (
        x509.CertificateBuilder()
        .subject_name(certificate.subject)
        .issuer_name(certificate.subject)
        .public_key(certificate.public_key())
        .serial_number(certificate.serial_number)
        .not_valid_before(certificate.not_valid_before_utc)
        .not_valid_after(certificate.not_valid_after_utc)
    )
    for extension in certificate.extensions:
        if extension.oid != ExtensionOID.AUTHORITY_KEY_IDENTIFIER:
            builder = builder.add_extension(extension.value, extension.critical)
    proposed = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.private_key.public_key()), False
    ).sign(signer.private_key, hashes.SHA384())
    proposed.verify_directly_issued_by(proposed)
    certificate.verify_directly_issued_by(parent)
    spki = serialization.PublicFormat.SubjectPublicKeyInfo
    assert proposed.public_key().public_bytes(serialization.Encoding.DER, spki) == (
        certificate.public_key().public_bytes(serialization.Encoding.DER, spki)
    )
    assert proposed.not_valid_after_utc == certificate.not_valid_after_utc
    assert proposed.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length == 0
    store = IdentityStore(*pair_state, capacity=2**20, create=True)
    try:
        pair = CertificatePairs(store, signer, "http://egress.invalid/crl/test").valid(
            PairDestination(ipaddress.ip_address("1.1.1.1"), 443, "origin.example"),
            observation(tmp_path),
        )
        now = datetime.now(UTC)
        crl = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(certificate.subject)
            .last_update(now - timedelta(minutes=1))
            .next_update(now + timedelta(hours=1))
            .sign(signer.private_key, hashes.SHA384())
            .public_bytes(PEM)
        )
        current = CertificateValidator(library, material.certificate)
        assert current.observe(pair.certificate_chain, "origin.example") == ()
        assert {
            (issue.code, issue.depth)
            for issue in current.observe(
                pair.certificate_chain, "origin.example", crls=(crl,), check_revocation=True
            )
        } == {(3, 1)}
        candidate = CertificateValidator(library, proposed.public_bytes(PEM))
        assert (
            candidate.observe(
                pair.certificate_chain, "origin.example", crls=(crl,), check_revocation=True
            )
            == ()
        )
        # Public data only. Neither the parent key nor the egress key is written.
        for name, value in {
            "issued": material.certificate,
            "proposed": proposed.public_bytes(PEM),
            "leaf": pair.certificate_chain[0],
            "chain": b"".join(pair.certificate_chain[1:]),
            "crl": crl,
        }.items():
            (tmp_path / f"{name}.pem").write_bytes(value)

        def verify(anchor, revocation):
            return subprocess.run(
                [
                    "openssl",
                    "verify",
                    "-purpose",
                    "sslserver",
                    "-CAfile",
                    str(tmp_path / f"{anchor}.pem"),
                    "-untrusted",
                    str(tmp_path / "chain.pem"),
                    *(
                        ["-crl_check_all", "-CRLfile", str(tmp_path / "crl.pem")]
                        if revocation
                        else []
                    ),
                    str(tmp_path / "leaf.pem"),
                ],
                capture_output=True,
                timeout=5,
                check=False,
            )

        failed = verify("issued", False)
        assert failed.returncode != 0
        assert b"unable to get issuer certificate" in failed.stderr
        for revocation in (False, True):
            result = verify("proposed", revocation)
            assert result.returncode == 0, (result.stdout + result.stderr).decode()
    finally:
        store.close()
        (tmp_path / "private.pem").unlink()
