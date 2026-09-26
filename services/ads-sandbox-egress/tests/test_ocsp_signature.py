import subprocess
from dataclasses import replace
from datetime import UTC, datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding

from ads_sandbox_egress.certificate_status import substitute_status
from ads_sandbox_egress.ocsp_der import DER, _envelope, sequence
from ads_sandbox_egress.ocsp_status import inspect_status
from test_certificates import pair_signer as pair_signer
from test_ocsp_status import material as material
from test_ocsp_status import wire


def rsa_material(material):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    source = material.issuer
    builder = (
        x509.CertificateBuilder()
        .subject_name(source.subject)
        .issuer_name(source.subject)
        .public_key(key.public_key())
        .serial_number(source.serial_number)
        .not_valid_before(source.not_valid_before_utc)
        .not_valid_after(source.not_valid_after_utc)
    )
    for extension in source.extensions:
        if not isinstance(
            extension.value, (x509.AuthorityKeyIdentifier, x509.SubjectKeyIdentifier)
        ):
            builder = builder.add_extension(extension.value, extension.critical)
    return replace(material, issuer=builder.sign(key, hashes.SHA256()), key=key)


def pss_wire(material, case):
    status, response, basic, _ = _envelope(wire(material))
    digest = hashes.SHA1() if case == "defaults" else hashes.SHA256()
    mgf_digest = hashes.SHA1() if case in ("defaults", "mixed-mgf") else hashes.SHA384()
    salt = 20 if case == "defaults" else 17
    digest_der = DER(0x30, bytes.fromhex("06096086480165030402010500"))
    mgf_der = DER(
        0x30,
        bytes.fromhex("06052b0e03021a0500")
        if case == "mixed-mgf"
        else bytes.fromhex("06096086480165030402020500"),
    )
    parameters = (
        []
        if case == "defaults"
        else [
            sequence(0xA0, [digest_der]),
            sequence(
                0xA1, [sequence(0x30, [DER(6, bytes.fromhex("2a864886f70d010108")), mgf_der])]
            ),
            sequence(0xA2, [DER(2, bytes((salt,)))]),
        ]
    )
    if case == "mixed-mgf":
        parameters.pop(1)  # DER omits the default MGF1-SHA1 parameter.
    if case == "duplicate":
        parameters.append(parameters[-1])
    elif case == "trailer":
        parameters.append(sequence(0xA3, [DER(2, b"\x02")]))
    elif case == "negative":
        parameters[-1] = sequence(0xA2, [DER(2, b"\xff")])
    basic[1] = sequence(
        0x30, [DER(6, bytes.fromhex("2a864886f70d01010a")), sequence(0x30, parameters)]
    )
    signature = material.key.sign(
        basic[0].wire(), padding.PSS(mgf=padding.MGF1(mgf_digest), salt_length=salt), digest
    )
    if case == "signature":
        signature = signature[:-1] + bytes((signature[-1] ^ 1,))
    basic[2] = DER(3, b"\0" + signature)
    response[1] = DER(4, sequence(0x30, basic).wire())
    status[1] = sequence(0xA0, [sequence(0x30, response)])
    return sequence(0x30, status).wire()


@pytest.mark.parametrize(
    "case", ["defaults", "explicit", "mixed-mgf", "signature", "duplicate", "trailer", "negative"]
)
def test_pss_parameters_and_independent_openssl(material, pair_signer, tmp_path, case):
    material = rsa_material(material)
    value = pss_wire(material, case)
    # RSA generation/signing can cross the fixture's rounded second. Inspect
    # only after production has emitted producedAt; never weaken future checks.
    material = replace(material, now=datetime.now(UTC))
    result = inspect_status(value, material.leaf, material.issuer, now=material.now)
    expected = (
        {"signature"}
        if case == "signature"
        else {"unsupported"}
        if case == "trailer"
        else {"malformed"}
        if case in ("duplicate", "negative")
        else set()
    )
    assert result.defects == expected
    if case in ("duplicate", "negative", "trailer"):
        return
    (tmp_path / "issuer.pem").write_bytes(material.issuer.public_bytes(Encoding.PEM))
    (tmp_path / "response.der").write_bytes(value)
    checked = subprocess.run(
        [
            "openssl",
            "ocsp",
            "-respin",
            str(tmp_path / "response.der"),
            "-CAfile",
            str(tmp_path / "issuer.pem"),
            "-verify_other",
            str(tmp_path / "issuer.pem"),
            "-no_check_time",
        ],
        capture_output=True,
        timeout=5,
    )
    assert (b"Response verify OK" in checked.stderr) is (case != "signature"), checked.stderr
    substituted = substitute_status(
        value,
        material.leaf,
        material.issuer,
        material.leaf,
        pair_signer.certificate,
        pair_signer.private_key,
        now=material.now,
    )
    assert (
        inspect_status(
            substituted, material.leaf, pair_signer.certificate, now=material.now
        ).defects
        == expected
    )
