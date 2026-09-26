import ipaddress

import pytest
from cryptography.hazmat.primitives import serialization

from ads_sandbox_egress.certificate_validation import CertificateValidator
from ads_sandbox_egress.certificates import CertificatePairs, PairDestination
from ads_sandbox_egress.identity_store import IdentityStore
from ads_sandbox_egress.tls import TLSFailure
from test_certificates import observation
from test_certificates import pair_signer as pair_signer
from test_certificates import pair_state as pair_state
from test_origin_tls import certificate_fixture
from test_tls import native as native


def test_native_candidate_outcome_uses_only_minted_trust(native, pair_signer, pair_state, tmp_path):
    library, _, _ = native
    validator = CertificateValidator(
        library, pair_signer.certificate.public_bytes(serialization.Encoding.PEM)
    )
    store = IdentityStore(*pair_state, capacity=2**20, create=True)
    try:
        original = observation(tmp_path)
        pairs = CertificatePairs(store, pair_signer, "http://egress.invalid/crl/test")
        pair = pairs.valid(
            PairDestination(ipaddress.ip_address("1.1.1.1"), 443, "origin.example"),
            original,
        )
        assert validator.observe(pair.certificate_chain, "origin.example") == ()
        assert {
            issue.code for issue in validator.observe(pair.certificate_chain, "wrong.example")
        } == {62}
        assert {
            issue.code
            for issue in validator.observe(
                pair.certificate_chain, "origin.example", check_revocation=True
            )
        } == {3}
        # The origin's independently trusted CA must not be made client-trusted.
        separate = tmp_path / "separate"
        separate.mkdir()
        _, root, _, _ = certificate_fixture(separate, "valid")
        original_chain = ((separate / "origin.pem").read_bytes(), root)
        assert {issue.code for issue in validator.observe(original_chain, "origin.example")} == {19}
        (separate / "private.pem").unlink()
    finally:
        store.close()
        (tmp_path / "private.pem").unlink()


def test_native_candidate_decoder_is_fail_closed(native, pair_signer):
    library, _, _ = native
    validator = CertificateValidator(
        library, pair_signer.certificate.public_bytes(serialization.Encoding.PEM)
    )
    with pytest.raises(TLSFailure, match="decode"):
        validator.observe((b"invalid certificate",), "origin.example")
    with pytest.raises(TLSFailure, match="limit"):
        validator.observe((), "origin.example")
