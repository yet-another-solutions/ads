"""Independent client fetches the actual local CRL for the substituted serial."""

import asyncio
import ipaddress
import os
from dataclasses import replace
from datetime import UTC, datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from ads_sandbox_egress.certificate_status import CertificateStatusComposer
from ads_sandbox_egress.certificates import CertificatePairs, PairDestination
from ads_sandbox_egress.crl import CRLRepository
from ads_sandbox_egress.identity_store import IdentityStore
from ads_sandbox_egress.origin_tls import VerificationIssue
from test_certificate_mirror import mirror_fixture
from test_certificates import observation
from test_certificates import pair_signer as pair_signer
from test_certificates import pair_state as pair_state
from test_crl import start_service
from test_tls import native as native


@pytest.mark.parametrize("signature_defect", [False, True])
def test_independent_openssl_downloads_substituted_revocation(
    native, pair_signer, pair_state, tmp_path, signature_defect
):
    import hashlib

    store = IdentityStore(*pair_state, capacity=2**20, create=True)
    repository = CRLRepository(store)
    original = observation(tmp_path)
    original = replace(original, revoked=(0,))
    if signature_defect:
        wire = original.built_chain[0]
        damaged = wire[:-1] + bytes((wire[-1] ^ 1,))
        original = replace(
            original,
            presented_chain=(damaged, *original.presented_chain[1:]),
            built_chain=(damaged, *original.built_chain[1:]),
            issues=(VerificationIssue(7, 0, hashlib.sha256(damaged).hexdigest()),),
        )
    assert not original.verified

    async def run():
        service, _ = await start_service(repository)
        process = None
        try:
            location = service.url(pair_signer.fingerprint)
            mirror = mirror_fixture(native[0], pair_signer)
            # Constructor binds the route prefix, not a replaceable public URL.
            from ads_sandbox_egress.certificate_mirror import CertificateMirror

            mirror = CertificateMirror(
                mirror.signer, mirror.untrusted, mirror.validator, location, crls=repository
            )
            composer = CertificateStatusComposer(
                CertificatePairs(store, pair_signer, location), mirror
            )
            candidate = composer.compose(
                PairDestination(ipaddress.ip_address("1.1.1.1"), 443, "origin.example"), original
            )
            leaf = x509.load_pem_x509_certificate(candidate.certificate_chain[0])
            publication = repository.get(pair_signer.fingerprint, now=datetime.now(UTC))
            assert publication.crl.get_revoked_certificate_by_serial_number(leaf.serial_number)
            native_issues = mirror.validator.observe(
                candidate.certificate_chain,
                "origin.example",
                crls=(publication.crl.public_bytes(Encoding.PEM),),
                check_revocation=True,
            )
            assert {item.code for item in native_issues} == ({23, 7} if signature_defect else {23})
            (tmp_path / "candidate.pem").write_bytes(candidate.certificate_chain[0])
            (tmp_path / "anchor.pem").write_bytes(
                pair_signer.certificate.public_bytes(Encoding.PEM)
            )
            env = {key: value for key, value in os.environ.items() if "proxy" not in key.lower()}
            process = await asyncio.create_subprocess_exec(
                "openssl",
                "verify",
                "-CAfile",
                str(tmp_path / "anchor.pem"),
                "-crl_check",
                "-crl_download",
                "-verify_hostname",
                "origin.example",
                str(tmp_path / "candidate.pem"),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
            async with asyncio.timeout(5):
                out, err = await process.communicate()
            assert process.returncode != 0
            assert b"certificate revoked" in out + err, (out, err)
        finally:
            if process is not None and process.returncode is None:
                process.kill()
                await process.wait()
            await service.close()
            assert not service._tasks and not service._writers

    try:
        asyncio.run(run())
    finally:
        store.close()
