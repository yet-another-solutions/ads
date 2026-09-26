from __future__ import annotations

import json
import sys
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from ads_sandbox_ca.certificates import certificates, mint
from ads_sandbox_ca.outputs import (
    ADDITIONAL_TRUST,
    MANIFEST,
    PRIVATE_KEY,
    PUBLIC_CERTIFICATE,
    SIGNING_CHAIN,
    write_outputs,
)

PEM = serialization.Encoding.PEM


def key_pem(key):
    return key.private_bytes(PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def make_ca(name, *, key=None, issuer=None, signer=None, path_length=None, **changes):
    key = key or ec.generate_private_key(ec.SECP384R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(UTC).replace(microsecond=0)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer.subject if issuer else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(changes.get("before", now - timedelta(days=1)))
        .not_valid_after(changes.get("after", now + timedelta(days=365)))
        .add_extension(
            x509.BasicConstraints(changes.get("ca", True), path_length=path_length),
            critical=changes.get("critical", True),
        )
        .add_extension(
            x509.KeyUsage(
                False, False, False, False, False, changes.get("signing", True), True, False, False
            ),
            critical=True,
        )
    )
    if changes.get("unsupported"):
        builder = builder.add_extension(
            x509.NameConstraints([x509.DNSName(".example.test")], None), critical=True
        )
    if changes.get("eku"):
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
    return builder.sign(signer or key, hashes.SHA384()), key


def hierarchy(**changes):
    root, root_key = make_ca("Root", after=datetime.now(UTC) + timedelta(days=730))
    parent, key = make_ca(
        "Intermediate",
        issuer=root,
        signer=root_key,
        path_length=changes.pop("path_length", 1),
        **changes,
    )
    return root, parent, key


def bundle(root, parent):
    return parent.public_bytes(PEM) + root.public_bytes(PEM)


def test_chain_exact_expiry_key_separation_and_extra_trust():
    root, parent, key = hierarchy()
    company, _ = make_ca("Company")
    result = mint(bundle(root, parent), key_pem(key), company.public_bytes(PEM))
    child = x509.load_pem_x509_certificate(result.certificate)
    child.verify_directly_issued_by(parent)
    parent.verify_directly_issued_by(root)
    assert child.not_valid_after_utc == parent.not_valid_after_utc
    assert child.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length == 0
    child_key = serialization.load_pem_private_key(result.private_key, None)
    assert child_key.public_key().public_numbers() == child.public_key().public_numbers()
    assert result.private_key != key_pem(key)
    assert key_pem(key) not in result.certificate + result.chain + result.additional_trust
    assert result.additional_trust == company.public_bytes(PEM)
    assert company.public_bytes(PEM) not in result.chain
    assert "PRIVATE KEY" not in repr(result)
    assert mint(bundle(root, parent), key_pem(key)).certificate != result.certificate


@pytest.mark.parametrize(
    "changes",
    [
        {"path_length": 0},
        {"critical": False},
        {"ca": False, "path_length": None},
        {"signing": False},
        {"after": -timedelta(hours=1)},
        {"before": timedelta(hours=1)},
        {"unsupported": True},
        {"eku": True},
    ],
)
def test_unsuitable_intermediate_fails_closed(changes):
    # Collection can precede execution by more than the validity offset.
    now = datetime.now(UTC)
    changes = {
        name: now + value if isinstance(value, timedelta) else value
        for name, value in changes.items()
    }
    root, parent, key = hierarchy(**changes)
    with pytest.raises(ValueError):
        mint(bundle(root, parent), key_pem(key))


def test_future_intermediate_rejection_survives_delayed_collection(monkeypatch):
    from ads_sandbox_ca import certificates as implementation

    later = datetime.now(UTC) + timedelta(hours=2)

    class Later(datetime):
        @classmethod
        def now(cls, tz=None):
            return later.astimezone(tz)

    monkeypatch.setattr(sys.modules[__name__], "datetime", Later)
    monkeypatch.setattr(implementation, "datetime", Later)
    parameters = test_unsuitable_intermediate_fails_closed.pytestmark[0].args[1]
    for changes in parameters:
        test_unsuitable_intermediate_fails_closed(changes)


@pytest.mark.parametrize(
    ("offset", "valid"),
    [
        (timedelta(seconds=-1), False),
        (timedelta(), True),
        (timedelta(hours=1, seconds=-1), True),
        (timedelta(hours=1), False),
    ],
)
def test_intermediate_validity_boundaries(monkeypatch, offset, valid):
    from ads_sandbox_ca import certificates as implementation

    before = datetime.now(UTC).replace(microsecond=0)
    root, parent, key = hierarchy(before=before, after=before + timedelta(hours=1))

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return (before + offset).astimezone(tz)

    monkeypatch.setattr(implementation, "datetime", Clock)
    if valid:
        child = x509.load_pem_x509_certificate(mint(bundle(root, parent), key_pem(key)).certificate)
        child.verify_directly_issued_by(parent)
    else:
        with pytest.raises(ValueError, match="CA is not currently valid"):
            mint(bundle(root, parent), key_pem(key))


def test_root_only_mismatched_key_wrong_chain_and_early_ancestor_rejected():
    root, parent, key = hierarchy()
    other, other_key = make_ca("Other")
    with pytest.raises(ValueError, match="root-backed"):
        mint(parent.public_bytes(PEM), key_pem(key))
    with pytest.raises(ValueError):
        mint(root.public_bytes(PEM) * 2, key_pem(key))
    with pytest.raises(ValueError, match="do not match"):
        mint(bundle(root, parent), key_pem(other_key))
    with pytest.raises((ValueError, TypeError)):
        mint(bundle(other, parent), key_pem(key))
    early_root, early_key = make_ca("Short Root", after=datetime.now(UTC) + timedelta(days=1))
    long_parent, long_key = make_ca(
        "Long Parent", issuer=early_root, signer=early_key, path_length=1
    )
    with pytest.raises(ValueError, match="ancestor expires"):
        mint(bundle(early_root, long_parent), key_pem(long_key))


@pytest.mark.parametrize("suffix", [b"garbage", b"-----BEGIN PRIVATE KEY-----", b"x" * 4194305])
def test_certificate_only_bundle_rejects_unparsed_or_secret_material(suffix):
    root, parent, key = hierarchy()
    with pytest.raises(ValueError):
        mint(bundle(root, parent), key_pem(key), root.public_bytes(PEM) + suffix)


def test_empty_extra_is_allowed_but_empty_signer_is_not():
    assert certificates(b" \n", optional=True) == []
    with pytest.raises(ValueError):
        certificates(b"")


def test_weak_key_and_restrictive_root_rejected():
    root, root_key = make_ca("Restricted Root", path_length=1)
    parent, key = make_ca("Intermediate", issuer=root, signer=root_key, path_length=1)
    with pytest.raises(ValueError, match="path length"):
        mint(bundle(root, parent), key_pem(key))
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    root, parent, key = hierarchy(key=weak)
    with pytest.raises(ValueError, match="weak"):
        mint(bundle(root, parent), key_pem(key))


def test_pair_outputs_are_disjoint_complete_and_not_overwritten(tmp_path):
    root, parent, key = hierarchy()
    company, _ = make_ca("Company")
    material = mint(bundle(root, parent), key_pem(key), company.public_bytes(PEM))
    public, private = tmp_path / "public", tmp_path / "private"
    public.mkdir()
    private.mkdir()
    attempt = uuid4()
    write_outputs(public, private, material, attempt)
    assert {p.name for p in public.iterdir()} == {
        PUBLIC_CERTIFICATE,
        SIGNING_CHAIN,
        ADDITIONAL_TRUST,
        MANIFEST,
    }
    assert {p.name for p in private.iterdir()} == {PRIVATE_KEY, MANIFEST}
    assert all(b"PRIVATE KEY" not in p.read_bytes() for p in public.iterdir())
    assert (private / PRIVATE_KEY).stat().st_mode & 0o777 == 0o600
    assert private.stat().st_mode & 0o777 == 0o700
    public_manifest = json.loads((public / MANIFEST).read_bytes())
    private_manifest = json.loads((private / MANIFEST).read_bytes())
    assert public_manifest.pop("role") == "public"
    assert private_manifest.pop("role") == "private"
    assert public_manifest == private_manifest
    assert public_manifest["attempt"] == str(attempt)
    assert public_manifest["not_after"] == parent.not_valid_after_utc.isoformat()
    with pytest.raises(ValueError, match="fresh"):
        write_outputs(public, private, material, attempt)
    with pytest.raises(ValueError, match="separate"):
        write_outputs(public, public, material, attempt)


def test_interrupted_publication_never_emits_both_markers(tmp_path, monkeypatch):
    from ads_sandbox_ca import outputs

    root, parent, key = hierarchy()
    material = mint(bundle(root, parent), key_pem(key))
    public, private = tmp_path / "public", tmp_path / "private"
    public.mkdir()
    private.mkdir()
    original = outputs.durable_file

    def fail(directory, name, content, mode):
        if name == PRIVATE_KEY:
            raise OSError("fixture disk failure")
        original(directory, name, content, mode)

    monkeypatch.setattr(outputs, "durable_file", fail)
    with pytest.raises(OSError):
        write_outputs(public, private, material, uuid4())
    assert not (public / MANIFEST).exists() and not (private / MANIFEST).exists()
    with pytest.raises(ValueError, match="fresh"):
        write_outputs(public, private, material, uuid4())
