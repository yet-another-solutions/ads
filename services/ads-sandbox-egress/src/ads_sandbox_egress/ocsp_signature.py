"""Strict public DER decoding of OCSP RSA-PSS signature parameters."""

from __future__ import annotations

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from ads_sandbox_egress.ocsp_der import DER, _envelope

_HASHES: dict[bytes, type[hashes.HashAlgorithm]] = {
    bytes.fromhex("2b0e03021a"): hashes.SHA1,
    bytes.fromhex("608648016503040204"): hashes.SHA224,
    bytes.fromhex("608648016503040201"): hashes.SHA256,
    bytes.fromhex("608648016503040202"): hashes.SHA384,
    bytes.fromhex("608648016503040203"): hashes.SHA512,
}


def _hash(value: DER) -> hashes.HashAlgorithm:
    fields = value.children(0x30)
    if (
        not 1 <= len(fields) <= 2
        or fields[0].tag != 6
        or len(fields) == 2
        and fields[1].wire() != b"\x05\x00"
    ):
        raise ValueError("OCSP PSS hash parameters")
    algorithm = _HASHES.get(fields[0].value)
    if algorithm is None:
        raise UnsupportedAlgorithm("OCSP PSS digest")
    return algorithm()


def _integer(value: DER) -> int:
    if (
        value.tag != 2
        or not 1 <= len(value.value) <= 3
        or value.value[0] & 128
        or len(value.value) > 1
        and value.value[0] == 0
        and not value.value[1] & 128
    ):
        raise ValueError("OCSP PSS integer")
    return int.from_bytes(value.value, "big")


def pss_parameters(wire: bytes) -> tuple[padding.PSS, hashes.HashAlgorithm]:
    _, _, basic, _ = _envelope(wire)
    algorithm = basic[1].children(0x30)
    if len(algorithm) != 2 or algorithm[0].wire() != bytes.fromhex("06092a864886f70d01010a"):
        raise ValueError("OCSP PSS AlgorithmIdentifier")
    digest: hashes.HashAlgorithm = hashes.SHA1()
    mgf_digest: hashes.HashAlgorithm = hashes.SHA1()
    salt_length = 20
    previous = 0x9F
    for field in algorithm[1].children(0x30):
        if not previous < field.tag <= 0xA3:
            raise ValueError("OCSP PSS duplicate or unordered parameter")
        previous = field.tag
        children = field.children(field.tag)
        if len(children) != 1:
            raise ValueError("OCSP PSS explicit parameter")
        child = children[0]
        if field.tag == 0xA0:
            digest = _hash(child)
        elif field.tag == 0xA1:
            mgf = child.children(0x30)
            if len(mgf) != 2 or mgf[0].wire() != bytes.fromhex("06092a864886f70d010108"):
                raise UnsupportedAlgorithm("OCSP PSS mask generation")
            mgf_digest = _hash(mgf[1])
        elif field.tag == 0xA2:
            salt_length = _integer(child)
            if salt_length > 1024:
                raise ValueError("OCSP PSS salt budget")
        elif _integer(child) != 1:
            raise UnsupportedAlgorithm("OCSP PSS trailer")
    return padding.PSS(mgf=padding.MGF1(mgf_digest), salt_length=salt_length), digest
