import ipaddress
import os
import subprocess
from datetime import UTC, datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from ads_sandbox_egress.certificate_status import CertificateStatusComposer, substitute_status
from ads_sandbox_egress.certificates import (
    CertificatePairs,
    PairDestination,
)
from ads_sandbox_egress.identity_store import IdentityStore
from ads_sandbox_egress.ocsp_status import inspect_status
from ads_sandbox_egress.origin_tls import OriginCertificate
from test_certificate_mirror import mirror_fixture
from test_certificates import pair_signer as pair_signer
from test_certificates import pair_state as pair_state
from test_ocsp_status import material as material
from test_ocsp_status import wire
from test_tls import native as native


@pytest.mark.parametrize(
    "case",
    [
        "good",
        "revoked",
        "unknown",
        "expired",
        "future",
        "signature",
        "no-next",
        "critical",
    ],
)
def test_substituted_status_keeps_exact_known_outcome(
    material, pair_signer, pair_state, native, tmp_path, case
):
    library, directory, executable = native
    store = IdentityStore(*pair_state, capacity=2**20, create=True)
    try:
        observed = OriginCertificate(
            (material.leaf.public_bytes(Encoding.DER),),
            (material.leaf.public_bytes(Encoding.DER), material.issuer.public_bytes(Encoding.DER)),
            (),
            b"h2",
            (wire(material, case),),
        )
        destination = PairDestination(ipaddress.ip_address("1.1.1.1"), 443, "origin.example")
        pairs = CertificatePairs(store, pair_signer, "http://egress.invalid/crl/test")
        composed = CertificateStatusComposer(pairs, mirror_fixture(library, pair_signer)).compose(
            destination, observed
        )
        leaf = x509.load_pem_x509_certificate(composed.certificate_chain[0])
        before = inspect_status(
            observed.staples[0], material.leaf, material.issuer, now=datetime.now(UTC)
        )
        after = inspect_status(
            composed.staples[0], leaf, pair_signer.certificate, now=datetime.now(UTC)
        )
        assert before.defects == after.defects
        assert before.good is after.good
        assert leaf.serial_number != material.leaf.serial_number
        assert composed.selected_alpn == b"h2"
        # Independent signature verification of the new response/serial
        # binding, rather than only testing the production verifier twice.
        status_path, cert_path, ca_path = (
            tmp_path / n for n in ("status.der", "cert.pem", "ca.pem")
        )
        status_path.write_bytes(composed.staples[0])
        cert_path.write_bytes(composed.certificate_chain[0])
        ca_path.write_bytes(pair_signer.certificate.public_bytes(Encoding.PEM))
        result = subprocess.run(
            [
                str(executable),
                "ocsp",
                "-respin",
                str(status_path),
                "-issuer",
                str(ca_path),
                "-sha256",
                "-cert",
                str(cert_path),
                "-CAfile",
                str(ca_path),
                "-no_nonce",
            ],
            env=dict(os.environ, LD_LIBRARY_PATH=str(directory), OPENSSL_CONF="/dev/null"),
            capture_output=True,
            timeout=5,
        )
        if case == "signature":
            assert b"Response Verify Failure" in result.stderr
        else:
            assert b"Response verify OK" in result.stderr
        if case in ("good", "revoked", "unknown"):
            assert b": " + case.encode() in result.stdout
        if case == "good":
            second = CertificateStatusComposer(pairs, mirror_fixture(library, pair_signer)).compose(
                destination, observed
            )
            assert second.certificate_chain == composed.certificate_chain
            assert second.private_key == composed.private_key
    finally:
        store.close()


@pytest.mark.parametrize("case", ["wrong-cert"])
def test_unimplemented_status_outcomes_never_become_good(material, pair_signer, case):
    result = substitute_status(
        wire(material, case),
        material.leaf,
        material.issuer,
        material.leaf,
        pair_signer.certificate,
        pair_signer.private_key,
        now=material.now,
    )
    assert inspect_status(
        result, material.leaf, pair_signer.certificate, now=material.now
    ).defects == {"certificate_binding"}


@pytest.mark.parametrize(
    "case",
    [
        "delegated-no-eku",
        "delegated-expired",
        "delegated-critical",
        "delegated-bad-ku",
        "delegated-no-eku-expired",
    ],
)
def test_delegated_status_defects_never_become_good(material, pair_signer, case):
    original = wire(material, case)
    now = datetime.now(UTC)
    candidate = substitute_status(
        original,
        material.leaf,
        material.issuer,
        material.leaf,
        pair_signer.certificate,
        pair_signer.private_key,
        now=now,
    )
    before = inspect_status(original, material.leaf, material.issuer, now=now)
    after = inspect_status(candidate, material.leaf, pair_signer.certificate, now=now)
    assert not before.good and not after.good
    assert before.defects == after.defects
    if case == "delegated-no-eku-expired":
        assert before.defects == {"responder_authority", "responder_time"}


def test_missing_status_is_not_fabricated(material, pair_signer):
    assert (
        substitute_status(
            None,
            material.leaf,
            material.issuer,
            material.leaf,
            pair_signer.certificate,
            pair_signer.private_key,
            now=material.now,
        )
        is None
    )


def test_must_staple_extension_survives_candidate_without_status(
    material, pair_signer, pair_state, native, monkeypatch
):
    # Add TLS_FEATURE using a real certificate builder, never editing DER
    # without re-signing. Origin chain observation is this fixture boundary.
    from cryptography.hazmat.primitives import hashes

    from ads_sandbox_egress.certificates import certificate_builder

    source = (
        certificate_builder(
            material.leaf, material.key, material.issuer, "http://egress.invalid/crl/test"
        )
        .add_extension(x509.TLSFeature([x509.TLSFeatureType.status_request]), False)
        .sign(material.key, hashes.SHA256())
    )
    observed = OriginCertificate(
        (source.public_bytes(Encoding.DER),),
        (source.public_bytes(Encoding.DER), material.issuer.public_bytes(Encoding.DER)),
        (),
        None,
    )
    store = IdentityStore(*pair_state, capacity=2**20, create=True)
    try:
        composer = CertificateStatusComposer(
            CertificatePairs(store, pair_signer, "http://egress.invalid/crl/test"),
            mirror_fixture(native[0], pair_signer),
        )
        result = composer.compose(
            PairDestination(ipaddress.ip_address("1.1.1.1"), 443, "origin.example"), observed
        )
        leaf = x509.load_pem_x509_certificate(result.certificate_chain[0])
        assert leaf.extensions.get_extension_for_class(x509.TLSFeature) == (
            source.extensions.get_extension_for_class(x509.TLSFeature)
        )
        assert not result.staples
    finally:
        store.close()
