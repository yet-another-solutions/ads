"""Legacy trust regression and approved full signing-chain trust proof."""

import importlib.machinery
import importlib.util
import ipaddress
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtensionOID, NameOID

from ads_commons.egress_trust import load_public
from ads_sandbox_ca.certificates import mint
from ads_sandbox_ca.outputs import write_outputs
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
    return root, parent, parent_key, root_key


def test_same_key_anchor_candidate_fixes_real_minted_only_trust_and_crl_checks(
    native, pair_state, tmp_path
):
    library, _, _ = native
    root, parent, parent_key, _ = _hierarchy()
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
        current = CertificateValidator(library, material.certificate, partial_chain=True)
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


def test_full_chain_boot_trust_with_real_installer_and_revocation(native, pair_state, tmp_path):
    library, _, _ = native
    root, parent, parent_key, root_key = _hierarchy()
    material = mint(
        parent.public_bytes(PEM) + root.public_bytes(PEM),
        parent_key.private_bytes(
            PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ),
    )
    public, private = tmp_path / "public", tmp_path / "private"
    public.mkdir()
    private.mkdir()
    attempt = uuid4()
    write_outputs(public, private, material, attempt)
    # The ordinary immutable CA output works unchanged; no new CA or rotation.
    trusted = load_public(public, attempt)
    assert trusted.pem == material.certificate + material.chain
    signer = EgressSigner.load(
        material.certificate,
        material.private_key,
        (parent.public_bytes(PEM), root.public_bytes(PEM)),
    )
    store = IdentityStore(*pair_state, capacity=2**20, create=True)
    try:
        pair = CertificatePairs(store, signer, "http://egress.invalid/crl/test").valid(
            PairDestination(ipaddress.ip_address("1.1.1.1"), 443, "origin.example"),
            observation(tmp_path),
        )
        validator = CertificateValidator(library, trusted.pem)
        assert validator.observe(pair.certificate_chain, "origin.example") == ()

        def crl(certificate, key, revoked=None):
            now = datetime.now(UTC)
            builder = (
                x509.CertificateRevocationListBuilder()
                .issuer_name(certificate.subject)
                .last_update(now - timedelta(minutes=1))
                .next_update(now + timedelta(hours=1))
                .add_extension(
                    x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), False
                )
            )
            if revoked is not None:
                builder = builder.add_revoked_certificate(
                    x509.RevokedCertificateBuilder()
                    .serial_number(revoked.serial_number)
                    .revocation_date(now - timedelta(minutes=1))
                    .build()
                )
            return builder.sign(key, hashes.SHA384()).public_bytes(PEM)

        leaf_crl = crl(signer.certificate, signer.private_key)
        parent_crl = crl(parent, parent_key)
        root_crl = crl(root, root_key)
        all_crls = (leaf_crl, parent_crl, root_crl)
        # Delivering certificate chain is NOT a substitute for issuer CRLs.
        missing = validator.observe(
            pair.certificate_chain, "origin.example", crls=(leaf_crl,), check_revocation=True
        )
        assert {issue.code for issue in missing} == {3}
        assert (
            validator.observe(
                pair.certificate_chain, "origin.example", crls=all_crls, check_revocation=True
            )
            == ()
        )
        revoked = validator.observe(
            pair.certificate_chain,
            "origin.example",
            crls=(leaf_crl, crl(parent, parent_key, signer.certificate), root_crl),
            check_revocation=True,
        )
        assert {(issue.code, issue.depth) for issue in revoked} == {(23, 1)}

        script = (
            Path(__file__).resolve().parents[2]
            / "ads-sandbox-base/scripts/ads-install-egress-trust"
        )
        loader = importlib.machinery.SourceFileLoader("install_egress_trust", str(script))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        assert spec is not None
        installer = importlib.util.module_from_spec(spec)
        loader.exec_module(installer)
        local, system, etc, hooks = (
            tmp_path / name for name in ("local", "system", "etc", "hooks")
        )
        for directory in (local, system, etc, hooks):
            directory.mkdir()
        config = tmp_path / "ca.conf"
        config.write_text("")
        command = (
            "update-ca-certificates",
            "--fresh",
            "--localcertsdir",
            str(local),
            "--certsdir",
            str(system),
            "--etccertsdir",
            str(etc),
            "--certsconf",
            str(config),
            "--hooksdir",
            str(hooks),
        )
        installer.install(trusted.pem, local, command)
        assert len(list((local / "ads-egress").glob("*.crt"))) == 3
        assert len(list(etc.glob("*.0"))) == 3
        (tmp_path / "leaf.pem").write_bytes(pair.certificate_chain[0])
        (tmp_path / "crls.pem").write_bytes(b"".join(all_crls))
        for trust_option, trust_path in (
            ("-CAfile", etc / "ca-certificates.crt"),
            ("-CApath", etc),
        ):
            for revocation in (False, True):
                result = subprocess.run(
                    [
                        "openssl",
                        "verify",
                        "-purpose",
                        "sslserver",
                        "-verify_hostname",
                        "origin.example",
                        "-no-CAfile",
                        "-no-CApath",
                        "-no-CAstore",
                        trust_option,
                        str(trust_path),
                        *(
                            ["-crl_check_all", "-CRLfile", str(tmp_path / "crls.pem")]
                            if revocation
                            else []
                        ),
                        str(tmp_path / "leaf.pem"),
                    ],
                    capture_output=True,
                    timeout=5,
                    check=False,
                )
                assert result.returncode == 0, (result.stdout + result.stderr).decode()
        # Reinstallation removes only stale ADS entries and preserves baseline CAs.
        (local / "baseline.crt").write_bytes(root.public_bytes(PEM))
        (local / "ads-egress.crt").write_bytes(material.certificate)
        (local / "ads-egress/stale.crt").write_bytes(material.certificate)
        installer.install(trusted.pem, local, command)
        assert (local / "baseline.crt").read_bytes() == root.public_bytes(PEM)
        assert not (local / "ads-egress.crt").exists()
        assert not (local / "ads-egress/stale.crt").exists()
        assert len(list((local / "ads-egress").glob("*.crt"))) == 3
    finally:
        store.close()
        (tmp_path / "private.pem").unlink()
        (private / "trusted-egress-ca.key").unlink()
