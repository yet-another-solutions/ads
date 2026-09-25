"""Real cryptographic evidence, deliberately without an assumed trust chain."""

import asyncio
import base64
import shutil
import time

import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa

from ads_sandbox_egress.dnssec_validation import (
    CryptoBudget,
    check_ds,
    check_signatures,
    fingerprint,
)
from ads_sandbox_egress.policy import RequestDenied
from test_dns_transport import transport

NOW = 1_800_000_000
ZONE = dns.name.from_text("example.")


def material(algorithm=15, flags=256, protocol=3):
    if algorithm in (5, 7, 8, 10):
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    elif algorithm in (13, 14):
        private = ec.generate_private_key(ec.SECP256R1() if algorithm == 13 else ec.SECP384R1())
    elif algorithm == 16:
        private = ed448.Ed448PrivateKey.generate()
    else:
        private = ed25519.Ed25519PrivateKey.generate()
    key = dns.dnssec.make_dnskey(private.public_key(), algorithm, flags=flags, protocol=protocol)
    return private, key


def records(name="www.example.", kind="A", *data):
    return dns.rrset.from_text(name, 60, "IN", kind, *(data or ("1.1.1.1",)))


def signature(rrset, private, key, inception=NOW - 60, expiration=NOW + 600, signer=ZONE):
    return dns.dnssec.sign(rrset, private, signer, key, inception=inception, expiration=expiration)


def check(rrset, signatures, keys, *, now=NOW, budget=None):
    return check_signatures(
        rrset,
        dns.rrset.from_rdata(rrset.name, 60, *signatures) if signatures else None,
        dns.rrset.from_rdata(ZONE, 60, *keys),
        now=now,
        budget=budget or CryptoBudget(),
    )


def corrupt(sig):
    return sig.replace(signature=bytes([sig.signature[0] ^ 1]) + sig.signature[1:])


def codes(result):
    return {failure.defect for failure in result.failures}


@pytest.mark.parametrize("algorithm", [5, 7, 8, 10, 13, 14, 15, 16])
def test_real_supported_signature_algorithms_not_tied_to_synthetic_generation(algorithm):
    private, key = material(algorithm)
    rrset = records()
    sig = signature(rrset, private, key)
    result = check(rrset, (sig,), (key,))
    assert (
        result.valid and not result.failures and not result.unsupported and not result.limitations
    )
    assert result.verified[0].signature == sig and result.verified[0].key == key
    assert not result.verified[0].wildcard


@pytest.mark.parametrize(
    "defect",
    [
        "expired",
        "future",
        "invalid",
        "expired_invalid",
        "flags",
        "protocol",
        "missing_sig",
        "missing_key",
    ],
)
def test_exact_signature_evidence_defects(defect):
    private, key = material(
        flags=0 if defect == "flags" else 256, protocol=2 if defect == "protocol" else 3
    )
    rrset = records()
    sig = signature(
        rrset,
        private,
        key,
        inception=NOW + 30 if defect == "future" else NOW - 600,
        expiration=NOW - 1 if defect.startswith("expired") else NOW + 600,
    )
    if "invalid" in defect:
        sig = corrupt(sig)
    result = check(
        rrset,
        () if defect == "missing_sig" else (sig,),
        (material()[1],) if defect == "missing_key" else (key,),
    )
    expected = {
        "expired": {"signature_expired"},
        "future": {"signature_not_yet_valid"},
        "invalid": {"signature_invalid"},
        "expired_invalid": {"signature_expired", "signature_invalid"},
        "flags": {"dnskey_flags"},
        "protocol": {"dnskey_protocol"},
        "missing_sig": {"signature_missing"},
        "missing_key": {"dnskey_missing"},
    }[defect]
    assert not result.valid and codes(result) == expected
    assert not result.limitations


def test_valid_alternative_wins_without_discarding_failed_path_relationships():
    private, key = material()
    rrset = records()
    good = signature(rrset, private, key)
    expired = corrupt(signature(rrset, private, key, inception=NOW - 600, expiration=NOW - 1))
    other = good.replace(algorithm=253)
    result = check(rrset, (expired, other, good), (key,))
    assert result.valid and len(result.verified) == 1
    assert result.verified[0].signature == good
    assert codes(result) == {"signature_expired", "signature_invalid"}
    assert all(item.record == fingerprint(expired) for item in result.failures)
    assert result.unsupported == (fingerprint(other),)


def test_short_key_tag_collision_does_not_hide_valid_full_key():
    private, key = material()
    rrset = records()
    wire = bytearray(key.key)
    for offset in range(2, len(wire), 2):
        if wire[offset] != wire[0]:
            wire[0], wire[offset] = wire[offset], wire[0]
            break
    wrong = key.replace(key=bytes(wire))
    assert wrong != key and dns.dnssec.key_id(wrong) == dns.dnssec.key_id(key)
    sig = signature(rrset, private, key)
    result = check(rrset, (sig,), (wrong, key))
    assert result.valid and result.verified[0].key == key
    assert codes(result) == {"signature_invalid"}
    assert result.failures[0].key == fingerprint(wrong)


@pytest.mark.parametrize("field", ["signer", "labels"])
def test_valid_bytes_cannot_supply_a_foreign_zone_or_impossible_label_count(field):
    private, key = material()
    rrset = records()
    sig = signature(rrset, private, key)
    if field == "signer":
        sig = sig.replace(signer=dns.name.from_text("other."))
    else:
        sig = sig.replace(labels=40)
    result = check(rrset, (sig,), (key,))
    assert not result.valid and codes(result) == {"signer_scope"}


def test_wildcard_signature_does_not_claim_nonexistence_proof_or_secure_answer():
    private, key = material()
    wildcard = records("*.example.")
    sig = signature(wildcard, private, key)
    expanded = records()
    result = check(expanded, (sig,), (key,))
    assert result.valid and result.verified[0].wildcard
    assert not hasattr(result, "secure")  # Authentication/proof owner still required.


@pytest.mark.parametrize("digest", [1, 2, 4])
def test_ds_matches_actual_full_dnskey_with_supported_digest(digest):
    _, key = material(flags=257)
    ds = dns.dnssec.make_ds(ZONE, key, digest, validating=True)
    result = check_ds(
        dns.rrset.from_rdata(ZONE, 60, ds),
        dns.rrset.from_rdata(ZONE, 60, key),
        budget=CryptoBudget(),
    )
    assert result.matched == (key,) and result.supported_paths == 1
    assert not result.failures and not result.unsupported


@pytest.mark.parametrize("unknown", ["algorithm", "digest"])
@pytest.mark.parametrize("supported", ["absent", "good", "mismatch"])
def test_unsupported_ds_never_conceals_a_supported_failing_or_valid_path(unknown, supported):
    _, key = material(flags=257)
    ds = dns.dnssec.make_ds(ZONE, key, 2)
    unsupported = (
        ds.replace(algorithm=253) if unknown == "algorithm" else ds.replace(digest_type=255)
    )
    values = [unsupported]
    if supported != "absent":
        values.append(ds if supported == "good" else ds.replace(digest=b"x" * 32))
    result = check_ds(
        dns.rrset.from_rdata(ZONE, 60, *values),
        dns.rrset.from_rdata(ZONE, 60, key),
        budget=CryptoBudget(),
    )
    assert result.unsupported == (fingerprint(unsupported),)
    assert result.supported_paths == (0 if supported == "absent" else 1)
    assert result.matched == ((key,) if supported == "good" else ())
    assert codes(result) == ({"ds_mismatch"} if supported == "mismatch" else set())


def test_ds_digest_match_does_not_repair_key_eligibility():
    _, key = material(flags=0, protocol=2)
    ds = dns.dnssec.make_ds(ZONE, key, 2)
    result = check_ds(
        dns.rrset.from_rdata(ZONE, 60, ds),
        dns.rrset.from_rdata(ZONE, 60, key),
        budget=CryptoBudget(),
    )
    assert result.matched == (key,)
    assert codes(result) == {"dnskey_flags", "dnskey_protocol"}


def test_empty_ds_is_not_unsigned_proof_or_an_invented_delegation():
    _, key = material()
    with pytest.raises(RequestDenied, match="delegation_inputs"):
        check_ds(
            dns.rrset.RRset(ZONE, dns.rdataclass.IN, dns.rdatatype.DS),
            dns.rrset.from_rdata(ZONE, 60, key),
            budget=CryptoBudget(),
        )


def test_missing_key_is_distinct_from_complete_acquisition_or_digest_mismatch():
    _, key = material()
    ds = dns.dnssec.make_ds(ZONE, key, 2)
    result = check_ds(
        dns.rrset.from_rdata(ZONE, 60, ds),
        dns.rrset.RRset(ZONE, dns.rdataclass.IN, dns.rdatatype.DNSKEY),
        budget=CryptoBudget(),
    )
    assert not result.matched and codes(result) == {"dnskey_missing"}


def test_explicit_local_serial_time_limit_does_not_blame_the_origin():
    private, key = material()
    rrset = records()
    sig = signature(rrset, private, key).replace(inception=2**32 - 30, expiration=30)
    result = check(rrset, (sig,), (key,), now=10)
    assert not result.valid and not result.failures
    assert result.limitations == (fingerprint(sig),)


def test_crypto_budget_shared_across_checks_not_reset_for_each_rrset():
    private, key = material()
    rrset = records()
    sig = signature(rrset, private, key)
    budget = CryptoBudget(2)
    assert check(rrset, (sig,), (key,), budget=budget).valid
    ds = dns.dnssec.make_ds(ZONE, key, 2)
    assert check_ds(
        dns.rrset.from_rdata(ZONE, 60, ds), dns.rrset.from_rdata(ZONE, 60, key), budget=budget
    ).matched
    with pytest.raises(RequestDenied, match="crypto_budget"):
        check(rrset, (sig,), (key,), budget=budget)


@pytest.mark.parametrize("bad", ["class", "foreign", "empty", "wrong_type", "wrong_sig_owner"])
def test_scope_validation_before_crypto(bad):
    private, key = material()
    rrset = records()
    sigs = dns.rrset.from_rdata(rrset.name, 60, signature(rrset, private, key))
    keys = dns.rrset.from_rdata(ZONE, 60, key)
    if bad == "class":
        rrset.rdclass = dns.rdataclass.CH
    elif bad == "foreign":
        rrset.name = dns.name.from_text("other.")
    elif bad == "empty":
        rrset.clear()
    elif bad == "wrong_type":
        keys = records("example.")
    else:
        sigs.name = dns.name.from_text("other.example.")
    with pytest.raises(RequestDenied):
        check_signatures(rrset, sigs, keys, now=NOW, budget=CryptoBudget())


def test_evidence_counts_and_wire_are_bounded_before_crypto():
    private, key = material()
    rrset = records()
    signatures = [signature(rrset, private, key, inception=NOW - 100 - i) for i in range(65)]
    with pytest.raises(RequestDenied, match="scope_or_limit"):
        check(rrset, signatures, (key,))
    large = dns.rrset.from_rdata(ZONE, 60, key.replace(key=b"x" * 65535))
    with pytest.raises(RequestDenied, match="wire_limit"):
        check_signatures(rrset, None, large, now=NOW, budget=CryptoBudget())


@pytest.mark.parametrize(
    "case", ["valid", "expired", "valid_alternative", "all_bad", "ds_mismatch"]
)
def test_independent_delv_agrees_on_positive_chain_success_and_defects(tmp_path, case):
    if shutil.which("delv") is None:
        pytest.skip("independent BIND delv unavailable")
    root_private, root_key = material(flags=257)
    private, key = material(flags=257)
    now = int(time.time())
    root_keys = dns.rrset.from_rdata(dns.name.root, 60, root_key)
    keys = dns.rrset.from_rdata(ZONE, 60, key)
    answer = records()
    ds = dns.dnssec.make_ds(ZONE, key, 2)
    if case == "ds_mismatch":
        ds = ds.replace(digest=b"x" * 32)
    delegation = dns.rrset.from_rdata(ZONE, 60, ds)
    good = signature(answer, private, key, now - 600, now + 600)
    expired = signature(answer, private, key, now - 600, now - 1)
    sigs = (
        (expired,)
        if case == "expired"
        else (expired, good)
        if case == "valid_alternative"
        else (expired, corrupt(good))
        if case == "all_bad"
        else (good,)
    )
    sigset = dns.rrset.from_rdata(answer.name, 60, *sigs)
    checked = check_signatures(answer, sigset, keys, now=now, budget=CryptoBudget())
    matched = check_ds(delegation, keys, budget=CryptoBudget())
    expected = case in ("valid", "valid_alternative")
    assert (checked.valid and bool(matched.matched)) is expected
    if case == "all_bad":
        assert codes(checked) == {"signature_expired", "signature_invalid"}
    if case == "valid_alternative":
        assert codes(checked) == {"signature_expired"} and checked.valid

    def signed_by(rrset, secret, public, signer):
        sig = signature(rrset, secret, public, now - 600, now + 600, signer)
        return rrset, dns.rrset.from_rdata(rrset.name, 60, sig)

    fixture = {
        (dns.name.root, dns.rdatatype.DNSKEY): signed_by(
            root_keys, root_private, root_key, dns.name.root
        ),
        (ZONE, dns.rdatatype.DS): signed_by(delegation, root_private, root_key, dns.name.root),
        (ZONE, dns.rdatatype.DNSKEY): signed_by(keys, private, key, ZONE),
        (answer.name, answer.rdtype): (answer, sigset),
    }

    class View:
        async def answer(self, query, *, deadline):
            # Named external authoritative fixture, not a production DNSSEC
            # classifier or synthesizer. Delv obtains and verifies all keys.
            result = dns.message.make_response(query)
            result.flags |= dns.flags.RA
            result.flags &= ~dns.flags.AD
            question = query.question[0]
            result.answer.extend(fixture[(question.name, question.rdtype)])
            return result

    anchor = tmp_path / "upstream-public.anchor"
    anchor.write_text(
        'trust-anchors { "." static-key 257 3 15 "'
        + base64.b64encode(root_key.key).decode()
        + '"; };\n'
    )

    async def run():
        service = transport(View())
        host, port = await service.start("127.0.0.1", 0)
        process = None
        try:
            process = await asyncio.create_subprocess_exec(
                "delv",
                "@" + host,
                "-p",
                str(port),
                "-a",
                str(anchor),
                "www.example.",
                "A",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            out, err = await asyncio.wait_for(process.communicate(), 5)
            output = out + err
            assert (b"fully validated" in output) is expected, output
            if not expected:
                assert b"resolution failed" in output, output
        finally:
            if process is not None and process.returncode is None:
                process.kill()
                await process.communicate()
            await service.close()
        assert not service._tasks and service._accepted == 0

    asyncio.run(run())
