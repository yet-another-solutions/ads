import os
from pathlib import Path

import pytest

from ech_probe import native_paths, run_probe


@pytest.fixture
def native_root():
    value = os.environ.get("ADS_EGRESS_OPENSSL4_ROOT")
    if value is None:
        pytest.skip("real OpenSSL 4.0.2 shared libraries/CLI not provisioned")
    root = Path(value)
    native_paths(root)  # Explicit but invalid configuration is failure, not skip.
    return root


@pytest.mark.parametrize("selected", ["http/1.1", "h2", None])
def test_genuine_ech_inner_hello_pause_origin_selection_resume(native_root, selected):
    result = run_probe(native_root, origin_alpn=selected)
    assert result["ech_accepted"] is True
    assert result["paused_before_certificate"] is True
    assert result["upstream_contact_after_pause"] is True
    assert result["selected_alpn"] == selected
    assert result["callback_calls"] == 2
    assert result["client_certificate_validation"] is True
    assert result["origin_certificate_validation"] is True
    assert result["application_exchange"] is True
    assert result["python_generated_and_reloaded_key"] is True
    assert result["ech_config_version"] == "0xfe0d"


@pytest.mark.parametrize("mode", ["plain", "grease"])
def test_plain_and_grease_are_not_mislabeled_ech(native_root, mode):
    result = run_probe(native_root, mode=mode)
    assert result["ech_accepted"] is False
    assert result["application_exchange"] is True


def test_foreign_ech_key_never_becomes_inner_identity_or_opaque_forwarding(native_root):
    result = run_probe(native_root, mode="foreign")
    assert result["ech_accepted"] is False
    assert result["rejected_before_upstream"] is True
    assert result["application_exchange"] is False


def test_ech_does_not_disable_client_hostname_verification(native_root):
    result = run_probe(native_root, mode="bad-certificate")
    assert result["ech_accepted"] is True
    assert result["certificate_failure_preserved"] is True
    assert result["application_exchange"] is False


def test_missing_native_libraries_fail_before_listening(tmp_path):
    with pytest.raises(ValueError, match="OpenSSL 4"):
        native_paths(tmp_path)
