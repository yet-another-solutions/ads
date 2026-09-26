"""Small strict DER envelope editor for certificate-bound OCSP substitution.

Cryptography parses/validates certificates and OCSP first. This module only
preserves fields its public response builder cannot set, then signs the entire
new ResponseData. No private library APIs, native pointer tricks or BER parsing.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


@dataclass(frozen=True)
class DER:
    tag: int
    value: bytes

    def wire(self) -> bytes:
        size = len(self.value)
        encoded = size.to_bytes(max(1, (size.bit_length() + 7) // 8), "big")
        length = bytes((size,)) if size < 128 else bytes((128 + len(encoded),)) + encoded
        return bytes((self.tag,)) + length + self.value

    def children(self, tag: int) -> list[DER]:
        if self.tag != tag:
            raise ValueError("unexpected OCSP envelope")
        return parse(self.value)


def parse(wire: bytes) -> list[DER]:
    if len(wire) > 65536:
        raise ValueError("OCSP DER budget")
    result: list[DER] = []
    offset = 0
    while offset < len(wire):
        if len(result) >= 256 or offset + 2 > len(wire):
            raise ValueError("OCSP DER envelope bound")
        tag, size = wire[offset], wire[offset + 1]
        offset += 2
        if tag & 31 == 31:
            raise ValueError("OCSP high tag unsupported")
        if size & 128:
            count = size & 127
            if not 1 <= count <= 3 or offset + count > len(wire) or wire[offset] == 0:
                raise ValueError("noncanonical OCSP DER length")
            size = int.from_bytes(wire[offset : offset + count], "big")
            offset += count
            if size < 128:
                raise ValueError("nonminimal OCSP DER length")
        if offset + size > len(wire):
            raise ValueError("truncated OCSP DER")
        result.append(DER(tag, wire[offset : offset + size]))
        offset += size
    return result


def sequence(tag: int, children: list[DER]) -> DER:
    return DER(tag, b"".join(child.wire() for child in children))


def _envelope(wire: bytes) -> tuple[list[DER], list[DER], list[DER], list[DER]]:
    outer = parse(wire)
    if len(outer) != 1:
        raise ValueError("OCSP outer envelope")
    status = outer[0].children(0x30)
    if len(status) != 2 or status[0].wire() != b"\x0a\x01\x00":
        raise ValueError("OCSP successful response required")
    wrapper = status[1].children(0xA0)
    if len(wrapper) != 1:
        raise ValueError("OCSP response wrapper")
    response = wrapper[0].children(0x30)
    if len(response) != 2 or response[0].wire() != bytes.fromhex("06092b0601050507300101"):
        raise ValueError("OCSP BasicResponse required")
    basic_wrapper = response[1].children(0x04)
    if len(basic_wrapper) != 1:
        raise ValueError("OCSP basic wrapper")
    basic = basic_wrapper[0].children(0x30)
    if not 3 <= len(basic) <= 4:
        raise ValueError("OCSP basic response fields")
    tbs = basic[0].children(0x30)
    return status, response, basic, tbs


def preserve_fields(
    candidate: bytes,
    source: bytes,
    signing_key: ec.EllipticCurvePrivateKey,
    *,
    wrong_serial: int | None = None,
    invalid_signature: bool = False,
    source_index: int = 0,
) -> bytes:
    status, response, basic, tbs = _envelope(candidate)
    _, _, _, original = _envelope(source)
    start = 1 if tbs[0].tag == 0xA0 else 0
    original_start = 1 if original[0].tag == 0xA0 else 0
    if (
        tbs[start].tag not in (0xA1, 0xA2)
        or original[original_start].tag not in (0xA1, 0xA2)
        or tbs[start + 1].tag != 0x18
        or original[original_start + 1].tag != 0x18
    ):
        raise ValueError("OCSP ResponseData shape")
    tbs[start + 1] = original[original_start + 1]  # exact producedAt
    singles = tbs[start + 2].children(0x30)
    originals = original[original_start + 2].children(0x30)
    if len(singles) != 1 or not 1 <= len(originals) <= 16 or not 0 <= source_index < len(originals):
        raise ValueError("OCSP bounded selected response required")
    single, prior = singles[0].children(0x30), originals[source_index].children(0x30)
    if prior[-1].tag == 0xA1:
        if single[-1].tag == 0xA1:
            single.pop()
        single.append(prior[-1])  # exact SingleResponse extensions
    if wrong_serial is not None:
        if not 0 < wrong_serial < 2**160:
            raise ValueError("bounded deliberately mismatched serial")
        certid = single[0].children(0x30)
        if len(certid) != 4 or certid[-1].tag != 2:
            raise ValueError("OCSP CertID fields")
        integer = wrong_serial.to_bytes((wrong_serial.bit_length() + 7) // 8, "big")
        if integer[0] & 128:
            integer = b"\0" + integer
        certid[-1] = DER(2, integer)
        single[0] = sequence(0x30, certid)
    originals[source_index] = sequence(0x30, single)
    tbs[start + 2] = sequence(0x30, originals)
    basic[0] = sequence(0x30, tbs)
    signature = signing_key.sign(basic[0].wire(), ec.ECDSA(hashes.SHA256()))
    if invalid_signature:
        signature = signature[:-1] + bytes((signature[-1] ^ 1,))
    basic[2] = DER(3, b"\0" + signature)
    response[1] = DER(4, sequence(0x30, basic).wire())
    status[1] = sequence(0xA0, [sequence(0x30, response)])
    result = sequence(0x30, status).wire()
    if len(result) > 65536:
        raise ValueError("substituted OCSP size budget")
    return result


def single_critical(wire: bytes, index: int) -> bool:
    _, _, _, tbs = _envelope(wire)
    start = 1 if tbs[0].tag == 0xA0 else 0
    singles = tbs[start + 2].children(0x30)
    if not 1 <= len(singles) <= 16 or not 0 <= index < len(singles):
        raise ValueError("OCSP selected extension scope")
    single = singles[index].children(0x30)
    if single[-1].tag != 0xA1:
        return False
    wrapper = single[-1].children(0xA1)
    if len(wrapper) != 1:
        raise ValueError("OCSP extensions wrapper")
    critical = False
    for extension in wrapper[0].children(0x30):
        fields = extension.children(0x30)
        if len(fields) not in (2, 3) or fields[0].tag != 6 or fields[-1].tag != 4:
            raise ValueError("OCSP extension fields")
        if len(fields) == 3:
            if fields[1].wire() not in (b"\x01\x01\xff", b"\x01\x01\x00"):
                raise ValueError("OCSP extension critical flag")
            critical |= fields[1].value == b"\xff"
    return critical
