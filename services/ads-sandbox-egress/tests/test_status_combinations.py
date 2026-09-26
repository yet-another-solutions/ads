import ipaddress
import re
import subprocess
from contextlib import closing
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding

from ads_sandbox_egress.certificate_mirror import CertificateMirror
from ads_sandbox_egress.certificates import PairDestination, certificate_builder
from ads_sandbox_egress.crl import CRLRepository
from ads_sandbox_egress.identity_store import IdentityStore
from test_certificate_mirror import mirror_fixture, observed
from test_certificates import pair_signer as pair_signer
from test_certificates import pair_state as pair_state
from test_ocsp_status import material as material
from test_tls import native as native


@pytest.mark.parametrize("defect", ["expired", "future", "keycert", "ca"])
def test_invalid_intermediate_and_revocation_remain_simultaneously_visible(
    material, native, pair_signer, pair_state, tmp_path, defect
):
    now = datetime.now(UTC)
    key = ec.generate_private_key(ec.SECP384R1())
    issuer = material.issuer
    builder = (
        x509.CertificateBuilder()
        .subject_name(issuer.subject)
        .issuer_name(issuer.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(
            now + timedelta(days=1) if defect == "future" else now - timedelta(days=2)
        )
        .not_valid_after(
            now - timedelta(days=1) if defect == "expired" else now + timedelta(days=2)
        )
        .add_extension(x509.BasicConstraints(ca=defect != "ca", path_length=None), True)
        .add_extension(
            x509.KeyUsage(
                False, False, False, False, False, defect != "keycert", True, False, False
            ),
            True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
        .add_extension(
            x509.AuthorityKeyIdentifier(
                x509.SubjectKeyIdentifier.from_public_key(issuer.public_key()).digest,
                [x509.DirectoryName(issuer.issuer)],
                issuer.serial_number,
            ),
            False,
        )
    )
    intermediate = builder.sign(material.key, hashes.SHA384())
    leaf = certificate_builder(
        material.leaf,
        ec.generate_private_key(ec.SECP256R1()),
        intermediate,
        "http://1.1.1.1/origin.crl",
        cap_expiry=False,
        bind_issuer_certificate=True,
    ).sign(key, hashes.SHA384())
    original = observed(
        native[0], (leaf, intermediate, issuer), issuer.public_bytes(Encoding.PEM), "origin.example"
    )
    assert original.issues
    original = replace(original, revoked=(0,))
    with closing(IdentityStore(*pair_state, capacity=2**20, create=True)) as store:
        repository = CRLRepository(store)
        mirror = mirror_fixture(native[0], pair_signer)
        mirror = CertificateMirror(
            pair_signer,
            mirror.untrusted,
            mirror.validator,
            f"http://egress.invalid/crl/{pair_signer.fingerprint}.der",
            crls=repository,
        )
        candidate = mirror.mirror(
            PairDestination(ipaddress.ip_address("1.1.1.1"), 443, "origin.example"), original
        )
        chain = tuple(
            x509.load_pem_x509_certificate(value) for value in candidate.certificate_chain
        )
        assert chain[1].not_valid_before_utc == intermediate.not_valid_before_utc
        assert chain[1].not_valid_after_utc == intermediate.not_valid_after_utc
        locations = [
            cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
            .value[0]
            .full_name[0]
            .value
            for cert in chain[:2]
        ]
        crls = tuple(
            repository.get(
                urlsplit(location).path.rsplit("/", 1)[1].removesuffix(".der"), now=now
            ).crl.public_bytes(Encoding.PEM)
            for location in locations
        )
        actual = mirror.validator.observe(
            candidate.certificate_chain, "origin.example", crls=crls, check_revocation=True
        )
        assert {(issue.code, issue.depth) for issue in actual} == (
            {(issue.code, issue.depth) for issue in original.issues} | {(23, 0)}
        )
        (tmp_path / "anchor.pem").write_bytes(pair_signer.certificate.public_bytes(Encoding.PEM))
        (tmp_path / "leaf.pem").write_bytes(candidate.certificate_chain[0])
        (tmp_path / "chain.pem").write_bytes(b"".join(candidate.certificate_chain[1:]))
        (tmp_path / "crls.pem").write_bytes(b"".join(crls))
        checked = subprocess.run(
            [
                "openssl",
                "verify",
                "-x509_strict",
                "-purpose",
                "sslserver",
                "-CAfile",
                str(tmp_path / "anchor.pem"),
                "-untrusted",
                str(tmp_path / "chain.pem"),
                "-CRLfile",
                str(tmp_path / "crls.pem"),
                "-crl_check_all",
                str(tmp_path / "leaf.pem"),
            ],
            capture_output=True,
            timeout=5,
        )
        assert checked.returncode != 0
        codes = set(map(int, re.findall(rb"error (\d+) at", checked.stderr)))
        # The CLI stops at fatal revocation before checking later certificate
        # times/usages. A second independent chain-only pass exposes those
        # unchanged defects; the native continuing callback above checks both.
        plain = subprocess.run(
            [
                "openssl",
                "verify",
                "-x509_strict",
                "-purpose",
                "sslserver",
                "-CAfile",
                str(tmp_path / "anchor.pem"),
                "-untrusted",
                str(tmp_path / "chain.pem"),
                str(tmp_path / "leaf.pem"),
            ],
            capture_output=True,
            timeout=5,
        )
        assert plain.returncode != 0
        codes.update(map(int, re.findall(rb"error (\d+) at", plain.stderr)))
        assert codes == {issue.code for issue in actual}, checked.stderr
