from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta, timezone
from uuid import uuid4

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

from ads_commons.egress_trust import load_egress, load_public, manifest, read_file
from ads_sandbox_ca.certificates import mint
from ads_sandbox_ca.outputs import write_outputs
from ads_sandbox_egress.issuers import untrusted_issuer
from test_ca_material import bundle, hierarchy, key_pem, make_ca

PEM = serialization.Encoding.PEM


@pytest.fixture
def outputs(tmp_path):
    root, parent, key = hierarchy()
    company, _ = make_ca("Company")
    material = mint(bundle(root, parent), key_pem(key), company.public_bytes(PEM))
    public, private = tmp_path / "public", tmp_path / "private"
    public.mkdir()
    private.mkdir()
    attempt = uuid4()
    write_outputs(public, private, material, attempt)
    return public, private, attempt, material, parent, company


def test_initializer_outputs_are_accepted_with_guest_egress_trust_separation(outputs):
    public, private, attempt, material, parent, company = outputs
    guest = load_public(public, attempt)
    assert guest.pem == material.certificate + material.chain
    assert guest.certificate.not_valid_after_utc == parent.not_valid_after_utc
    assert company.public_bytes(PEM) not in guest.pem
    assert parent.public_bytes(PEM) in guest.pem
    assert material.private_key not in guest.pem
    assert guest.signing_chain[-1].issuer == guest.signing_chain[-1].subject
    egress = load_egress(public, private, attempt)
    assert egress.public == guest
    assert egress.additional_trust == (company,)
    assert egress.signing_chain[0] == parent
    assert (
        egress.private_key.public_key().public_numbers()
        == guest.certificate.public_key().public_numbers()
    )
    assert "private_key=" not in repr(egress)


def test_guest_never_reads_extra_or_private_files(outputs):
    public, private, attempt, material, *_ = outputs
    (public / "egress-only-trust.pem").unlink()
    for path in private.iterdir():
        path.unlink()
    private.rmdir()
    assert load_public(public, attempt).pem == material.certificate + material.chain
    with pytest.raises(FileNotFoundError):
        load_egress(public, private, attempt)


@pytest.mark.parametrize(
    "field,value",
    [
        ("format", 2),
        ("format", True),
        ("format", "1"),
        ("role", "private"),
        ("attempt", str(uuid4())),
        ("sha256", "0" * 64),
        ("sha256", "ABC"),
        ("not_after", "2030-01-01T00:00:00"),
        ("not_after", "2030-01-01T00:00:00+01:00"),
        ("not_after", "2030-01-01T00:00:00+00:00"),
        ("unexpected", 1),
    ],
)
def test_guest_rejects_manifest_tampering(outputs, field, value):
    public, _, attempt, *_ = outputs
    path = public / "complete.json"
    data = json.loads(path.read_bytes())
    data[field] = value
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        load_public(public, attempt)


def test_duplicate_json_missing_marker_and_symlink_rejected(outputs):
    public, _, attempt, *_ = outputs
    path = public / "complete.json"
    original = path.read_bytes()
    path.write_bytes(original.rstrip()[:-1] + b', "format": 1}')
    with pytest.raises(ValueError, match="duplicate"):
        manifest(public, "public", attempt)
    path.unlink()
    with pytest.raises(FileNotFoundError):
        load_public(public, attempt)
    target = public / "other"
    target.write_bytes(original)
    path.symlink_to(target)
    with pytest.raises(OSError):
        load_public(public, attempt)


@pytest.mark.parametrize("content", [b"", b"PRIVATE KEY", b"x" * 65537])
def test_invalid_or_oversized_certificate_rejected(outputs, content):
    public, _, attempt, *_ = outputs
    (public / "trusted-egress-ca.pem").write_bytes(content)
    with pytest.raises(ValueError):
        load_public(public, attempt)


def test_multiple_certificates_not_guest_trust_bundle(outputs):
    public, _, attempt, material, parent, _ = outputs
    (public / "trusted-egress-ca.pem").write_bytes(material.certificate + parent.public_bytes(PEM))
    with pytest.raises(ValueError, match="only the minted"):
        load_public(public, attempt)


def test_private_generation_and_key_mismatch_rejected(outputs):
    public, private, attempt, *_ = outputs
    path = private / "complete.json"
    data = json.loads(path.read_bytes())
    original = dict(data)
    data["sha256"] = "0" * 64
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="generations"):
        load_egress(public, private, attempt)
    path.write_text(json.dumps(original))
    _, other_key = make_ca("Wrong")
    (private / "trusted-egress-ca.key").write_bytes(key_pem(other_key))
    with pytest.raises(ValueError, match="certificate/key"):
        load_egress(public, private, attempt)


def test_egress_rejects_private_material_in_public_bundle(outputs):
    public, private, attempt, material, *_ = outputs
    (public / "egress-only-trust.pem").write_bytes(material.private_key)
    with pytest.raises(ValueError, match="public certificates"):
        load_egress(public, private, attempt)
    # Guest trust intentionally does not depend on the egress-only bundle.
    assert load_public(public, attempt).pem == material.certificate + material.chain


@pytest.mark.parametrize("mutation", ["missing", "incomplete", "duplicate", "extra", "private"])
def test_guest_rejects_invalid_signing_chain(outputs, mutation):
    public, _, attempt, material, parent, company = outputs
    path = public / "signing-chain.pem"
    if mutation == "missing":
        path.unlink()
    else:
        path.write_bytes(
            {
                "incomplete": parent.public_bytes(PEM),
                "duplicate": material.chain + material.chain,
                "extra": material.chain + company.public_bytes(PEM),
                "private": material.private_key,
            }[mutation]
        )
    with pytest.raises((ValueError, InvalidSignature, FileNotFoundError)):
        load_public(public, attempt)


def test_egress_rejects_wrong_parent_chain_and_identical_directories(outputs):
    public, private, attempt, _, _, _ = outputs
    root, parent, _ = hierarchy()
    (public / "signing-chain.pem").write_bytes(bundle(root, parent))
    with pytest.raises((ValueError, InvalidSignature)):
        load_egress(public, private, attempt)
    with pytest.raises((ValueError, InvalidSignature)):
        load_public(public, attempt)
    with pytest.raises(ValueError, match="separate"):
        load_egress(public, public, attempt)


def test_nonregular_and_oversized_manifest_rejected(outputs):
    public, _, attempt, *_ = outputs
    with pytest.raises(ValueError):
        read_file(public, "complete.json", 1)
    (public / "complete.json").unlink()
    (public / "complete.json").mkdir()
    with pytest.raises((ValueError, IsADirectoryError)):
        load_public(public, attempt)


def test_fifo_and_path_traversal_are_rejected_without_blocking(outputs, tmp_path):
    public, _, attempt, *_ = outputs
    path = public / "complete.json"
    path.unlink()
    os.mkfifo(path)
    with pytest.raises(ValueError, match="invalid CA material"):
        load_public(public, attempt)
    with pytest.raises(ValueError, match="leaf"):
        read_file(public, "../private/trusted-egress-ca.key")
    link = tmp_path / "linked"
    link.symlink_to(public)
    with pytest.raises(OSError):
        load_public(link, attempt)


def test_untrusted_issuer_is_process_local_independent_and_exact_expiry(outputs):
    public, private, attempt, _, parent, _ = outputs
    before = {
        str(path): path.read_bytes()
        for directory in (public, private)
        for path in directory.iterdir()
    }
    trusted = load_egress(public, private, attempt)
    first = untrusted_issuer(trusted.public.manifest.not_after)
    second = untrusted_issuer(trusted.public.manifest.not_after)
    assert first.certificate != second.certificate
    assert (
        first.private_key.public_key().public_numbers()
        != second.private_key.public_key().public_numbers()
    )
    for issuer in (first, second):
        issuer.certificate.verify_directly_issued_by(issuer.certificate)
        assert issuer.certificate.not_valid_after_utc == parent.not_valid_after_utc
        assert issuer.certificate.issuer == issuer.certificate.subject
        with pytest.raises(ValueError):
            issuer.certificate.verify_directly_issued_by(parent)
        assert "private_key=" not in repr(issuer)
    assert before == {
        str(path): path.read_bytes()
        for directory in (public, private)
        for path in directory.iterdir()
    }


@pytest.mark.parametrize(
    "expiry",
    [
        datetime.now(),
        datetime.now(UTC) - timedelta(seconds=1),
        datetime.now(UTC) + timedelta(days=1),
        (datetime.now(timezone(timedelta(hours=1))) + timedelta(days=1)).replace(microsecond=0),
    ],
)
def test_untrusted_issuer_cannot_extend_or_round_expiry(expiry):
    with pytest.raises(ValueError):
        untrusted_issuer(expiry)
