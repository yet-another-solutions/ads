import hashlib
import ipaddress
import os
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ads_sandbox_egress.certificates import (
    CertificateDefectRequiresMirror,
    CertificatePairs,
    EgressSigner,
    PairDestination,
)
from ads_sandbox_egress.identity_store import IdentityStore, StateIdentity, StateUnavailable
from ads_sandbox_egress.issuers import untrusted_issuer
from ads_sandbox_egress.origin_tls import OriginCertificate, VerificationIssue
from ads_sandbox_egress.tls import TLSFailure
from test_origin_tls import certificate_fixture


@dataclass(repr=False)
class PairCustody:
    directory: Path
    identity: StateIdentity
    wrapping_key: bytes = field(repr=False)

    def __iter__(self):
        return iter((self.directory, self.identity, self.wrapping_key))

    def __getitem__(self, index):
        return (self.directory, self.identity, self.wrapping_key)[index]

    def __repr__(self):
        return "PairCustody(private material redacted)"


@pytest.fixture
def pair_state(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    wrap = os.urandom(32)
    identity = StateIdentity(
        uuid4(), uuid4(), uuid4(), uuid4(), "pvc", "custody", hashlib.sha256(wrap).hexdigest()
    )
    return PairCustody(state, identity, wrap)


@pytest.fixture
def pair_signer():
    # Explicitly trusted, self-signed fixture. This is not a claim about how the
    # real intermediate-signed minted CA is installed in arbitrary client stores.
    issuer = untrusted_issuer((datetime.now(UTC) + timedelta(days=3)).replace(microsecond=0))
    return EgressSigner.load(
        issuer.certificate.public_bytes(serialization.Encoding.PEM),
        issuer.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )


def observation(tmp_path):
    _, root, leaf, _ = certificate_fixture(tmp_path, "valid")
    pem = serialization.Encoding.DER
    # Origin observation is the named fixture boundary for pair storage tests.
    # Real two-leg TLS tests independently establish/verify origin observations.
    return OriginCertificate(
        (leaf.public_bytes(pem),),
        (leaf.public_bytes(pem), x509.load_pem_x509_certificate(root).public_bytes(pem)),
        (),
        b"h2",
    )


def test_success_pairs_retain_a_b_a_across_encrypted_recovery(pair_state, pair_signer, tmp_path):
    store = IdentityStore(*pair_state, capacity=2**20, create=True)
    destination = PairDestination(ipaddress.ip_address("1.1.1.1"), 443, "origin.example")
    first = observation(tmp_path)
    second_path = tmp_path / "second"
    second_path.mkdir()
    second = observation(second_path)
    pairs = CertificatePairs(store, pair_signer, "http://egress.invalid/crl/test")
    a = pairs.valid(destination, first)
    b = pairs.valid(destination, second)
    assert a != b
    assert pairs.valid(destination, first) == a
    certificate = x509.load_pem_x509_certificate(a.certificate_chain[0])
    source = x509.load_der_x509_certificate(first.presented_chain[0])
    assert certificate.subject == source.subject
    assert certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName) == (
        source.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    )
    assert certificate.not_valid_after_utc <= pair_signer.certificate.not_valid_after_utc
    certificate.verify_directly_issued_by(pair_signer.certificate)
    assert a.selected_alpn == b"h2"
    store.close()
    assert a.private_key not in (pair_state[0] / "identity.sqlite").read_bytes()
    recovered = IdentityStore(*pair_state, capacity=2**20)
    try:
        recovered_pairs = CertificatePairs(recovered, pair_signer, "http://egress.invalid/crl/test")
        assert recovered_pairs.valid(destination, first) == a
        assert recovered_pairs.valid(destination, second) == b
        changed_locator = CertificatePairs(
            recovered, pair_signer, "http://egress.invalid/different-crl"
        )
        with pytest.raises(StateUnavailable, match="locator"):
            changed_locator.valid(destination, first)
        # Same leaf/destination with a newly discovered validation failure MUST
        # NOT return its retained clean substitution.
        bad = replace(
            first,
            issues=(
                VerificationIssue(23, 0, hashlib.sha256(first.presented_chain[0]).hexdigest()),
            ),
        )
        with pytest.raises(CertificateDefectRequiresMirror):
            recovered_pairs.valid(destination, bad)
        assert recovered_pairs.valid(destination, first) == a
        other = replace(destination, port=8443)
        assert recovered_pairs.valid(other, first) != a
    finally:
        recovered.close()
        (tmp_path / "private.pem").unlink()
        (second_path / "private.pem").unlink()


def test_missing_mapping_is_not_corrupt_or_retired_state(pair_state):
    store = IdentityStore(*pair_state, capacity=2**20, create=True)
    try:
        assert store.find_key("tls/absent") is None
        store.prepare_key("tls/one", "tls", b"public", b"private")
        store.advance("tls/one", "prepared", "published")
        store.advance("tls/one", "published", "active")
        store.advance("tls/one", "active", "retiring")
        store.retire("tls/one", now=1)
        with pytest.raises(StateUnavailable):
            store.find_key("tls/one")
    finally:
        store.close()
    with pytest.raises(StateUnavailable):
        store.find_key("tls/absent")


def test_signer_cannot_load_wrong_key_or_lose_expiry(pair_signer):
    different = ec.generate_private_key(ec.SECP384R1())
    with pytest.raises(TLSFailure, match="minted_signer"):
        EgressSigner.load(
            pair_signer.certificate.public_bytes(serialization.Encoding.PEM),
            different.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        )
    assert (
        pair_signer.certificate.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value.path_length
        == 0
    )


@pytest.mark.parametrize(
    "url",
    [
        "http://user:password@egress.invalid/crl",
        "https://egress.invalid/crl?secret=bad",
        "http://egress.invalid/crl#fragment",
        "http://egress.invalid/\ncrl",
        "ftp://egress.invalid/crl",
    ],
)
def test_crl_locator_is_explicit_and_contains_no_credentials(pair_state, pair_signer, url):
    store = IdentityStore(*pair_state, capacity=2**20, create=True)
    try:
        with pytest.raises(ValueError, match="CRL"):
            CertificatePairs(store, pair_signer, url)
    finally:
        store.close()
