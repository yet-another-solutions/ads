from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import ocsp

from ads_sandbox_egress.certificate_status import substitute_status
from ads_sandbox_egress.ocsp_der import DER, _envelope, parse, preserve_fields, sequence
from ads_sandbox_egress.ocsp_status import inspect_status
from test_certificates import pair_signer as pair_signer
from test_ocsp_status import material as material
from test_ocsp_status import wire


@pytest.mark.parametrize("defect", ["produced", "single-critical", "both"])
def test_public_der_editor_retains_unexposed_signed_fields(material, pair_signer, defect):
    source = wire(material)
    status, response, basic, tbs = _envelope(source)
    if defect in ("produced", "both"):
        tbs[1] = DER(0x18, (material.now + timedelta(hours=1)).strftime("%Y%m%d%H%M%SZ").encode())
    if defect in ("single-critical", "both"):
        singles = tbs[2].children(0x30)
        single = singles[0].children(0x30)
        extension = DER(0x30, bytes.fromhex("06032a03040101ff04020500"))
        single.append(sequence(0xA1, [sequence(0x30, [extension])]))
        tbs[2] = sequence(0x30, [sequence(0x30, single)])
    basic[0] = sequence(0x30, tbs)
    response[1] = DER(4, sequence(0x30, basic).wire())
    status[1] = sequence(0xA0, [sequence(0x30, response)])
    template = sequence(0x30, status).wire()
    source = preserve_fields(source, template, material.key)
    now = datetime.now(UTC)
    inspected = inspect_status(source, material.leaf, material.issuer, now=now)
    expected = (
        {"future"}
        if defect == "produced"
        else {"critical_extension"}
        if defect == "single-critical"
        else {"future", "critical_extension"}
    )
    assert inspected.defects == expected
    result = substitute_status(
        source,
        material.leaf,
        material.issuer,
        material.leaf,
        pair_signer.certificate,
        pair_signer.private_key,
        now=now,
    )
    assert (
        inspect_status(result, material.leaf, pair_signer.certificate, now=now).defects == expected
    )
    assert ocsp.load_der_ocsp_response(result).produced_at_utc == (
        ocsp.load_der_ocsp_response(source).produced_at_utc
    )
    assert ocsp.load_der_ocsp_response(result).public_bytes(Encoding.DER) == result


@pytest.mark.parametrize(
    "wire",
    [
        b"\x30",
        b"\x30\x80",
        b"\x30\x81\x01\x00",
        b"\x30\x82\x00\x80",
        b"\x1f\x00",
        b"\x30\x02\x00",
        b"x" * 65537,
    ],
)
def test_strict_bounded_der_rejects_malformed_envelope(wire):
    with pytest.raises(ValueError):
        parse(wire)


def test_multiple_status_response_rebinds_selected_single_not_unrelated_records(material):
    good, unrelated = wire(material), wire(material, "wrong-cert")
    status, response, basic, tbs = _envelope(good)
    _, _, _, other = _envelope(unrelated)
    tbs[2] = sequence(0x30, [*other[2].children(0x30), *tbs[2].children(0x30)])
    basic[0] = sequence(0x30, tbs)
    response[1] = DER(4, sequence(0x30, basic).wire())
    status[1] = sequence(0xA0, [sequence(0x30, response)])
    original = preserve_fields(good, sequence(0x30, status).wire(), material.key, source_index=1)
    now = datetime.now(UTC)
    checked = inspect_status(original, material.leaf, material.issuer, now=now)
    assert checked.good and checked.index == 1
    substituted = substitute_status(
        original,
        material.leaf,
        material.issuer,
        material.leaf,
        material.issuer,
        material.key,
        now=now,
    )
    result = inspect_status(substituted, material.leaf, material.issuer, now=now)
    assert result.good and result.index == 1
    assert len(tuple(ocsp.load_der_ocsp_response(substituted).responses)) == 2
