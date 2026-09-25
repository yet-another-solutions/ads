import itertools

import dns.edns
import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype
import dns.rrset
import pytest

from ads_sandbox_egress.dnssec_answer import MessageAuthentication, RecordAuthentication
from ads_sandbox_egress.dnssec_chain import ZoneAuthentication
from ads_sandbox_egress.dnssec_response import diagnostics, fallback, render, resolution_failure
from ads_sandbox_egress.dnssec_validation import Failure, SignatureCheck
from ads_sandbox_egress.policy import RequestDenied


def evidence(state="secure"):
    return MessageAuthentication(state, (), ())


def query(edns, do, ad, cd, kind="A"):
    value = dns.message.make_query("example.", kind, use_edns=0 if edns else None)
    value.flags = dns.flags.RD | (dns.flags.AD if ad else 0) | (dns.flags.CD if cd else 0)
    if edns:
        value.use_edns(edns=0, ednsflags=dns.flags.DO if do else 0, payload=4096)
    return value


@pytest.mark.parametrize("state", ["secure", "insecure", "bogus"])
@pytest.mark.parametrize("do,ad,cd", tuple(itertools.product((False, True), repeat=3)))
@pytest.mark.parametrize("edns", [False, True])
def test_flag_matrix_never_inherits_upstream_ad_or_repairs_bogus(state, do, ad, cd, edns):
    q = query(edns, do, ad, cd)
    candidate = dns.message.make_response(q)
    candidate.flags |= dns.flags.AA | dns.flags.AD
    candidate.answer.append(dns.rrset.from_text("example.", 30, "IN", "A", "1.1.1.1"))
    candidate.authority.append(
        dns.rrset.from_text("example.", 30, "IN", "NSEC", "z.example. A RRSIG NSEC")
    )
    response = render(q, candidate, evidence(state), safe_udp_payload=1232)
    parsed = dns.message.from_wire(response.to_wire())
    assert parsed.id == q.id and parsed.question == q.question
    assert not parsed.flags & dns.flags.AA
    assert bool(parsed.flags & dns.flags.CD) == cd
    assert bool(parsed.flags & dns.flags.AD) == (state == "secure" and (ad or edns and do))
    assert parsed.rcode() == (dns.rcode.SERVFAIL if state == "bogus" and not cd else 0)
    assert bool(parsed.answer) == (state != "bogus" or cd)
    assert bool(parsed.authority) == (edns and do and (state != "bogus" or cd))
    assert parsed.edns == (0 if edns else -1)
    assert parsed.payload == (1232 if edns else 0)
    assert candidate.flags & dns.flags.AA and candidate.answer


@pytest.mark.parametrize("state", ["secure", "insecure", "bogus", "indeterminate"])
@pytest.mark.parametrize("edns,cd", tuple(itertools.product((False, True), repeat=2)))
def test_local_synthesis_failure_is_not_crypto_success_even_with_cd(state, edns, cd):
    q = query(edns, False, True, cd)
    result = fallback(q, evidence(state), safe_udp_payload=1232)
    assert result.rcode() == dns.rcode.SERVFAIL and not result.flags & dns.flags.AD
    assert not result.answer and not result.authority and not result.additional
    assert bool(result.flags & dns.flags.CD) == cd
    assert bool(result.options) == edns
    if edns:
        assert result.options[-1].code == 0
        assert result.options[-1].text.startswith("ADS cannot faithfully")


def test_diagnostics_keep_multiple_verified_defects_but_not_failed_alternatives():
    rrset = dns.rrset.from_text("example.", 30, "IN", "A", "1.1.1.1")
    check = SignatureCheck((), (Failure("signature_expired"), Failure("signature_invalid")), (), ())
    good_record = RecordAuthentication(rrset, "secure", (check,))
    bad_record = RecordAuthentication(rrset, "bogus", (check,))
    assert not diagnostics(MessageAuthentication("secure", (good_record,), ()))
    result = diagnostics(MessageAuthentication("bogus", (bad_record,), ()))
    assert [int(item.code) for item in result] == [6, 7]
    zone = ZoneAuthentication(rrset.name, "bogus", signatures=(check,))
    assert [
        int(item.code) for item in diagnostics(MessageAuthentication("bogus", (), (zone,)))
    ] == [6, 7]


@pytest.mark.parametrize("edns", [False, True])
def test_upstream_servfail_is_reported_not_locally_verified_and_text_is_not_leaked(edns):
    q = query(edns, True, True, True)
    upstream = dns.message.make_response(dns.message.make_query("example.", "A", use_edns=0))
    upstream.flags |= dns.flags.AD
    upstream.set_rcode(dns.rcode.SERVFAIL)
    upstream.use_edns(
        options=[
            dns.edns.EDEOption(7, "untrusted credential-looking free text"),
            dns.edns.EDEOption(7, "duplicate"),
        ]
    )
    upstream.answer.append(dns.rrset.from_text("example.", 60, "IN", "A", "1.1.1.1"))
    result = resolution_failure(q, upstream, safe_udp_payload=1232)
    assert result.rcode() == dns.rcode.SERVFAIL and not result.answer
    assert not result.flags & dns.flags.AD
    assert len(result.options) == int(edns)
    assert b"credential" not in result.to_wire()
    if edns:
        assert result.options[0].code == 7
        assert result.options[0].text == "Reported by upstream resolver"


@pytest.mark.parametrize(
    "kind,data",
    [
        ("DNSKEY", "257 3 15 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
        ("DS", "1 15 2 " + "00" * 32),
        ("NSEC", "z.example. A RRSIG NSEC"),
    ],
)
def test_explicit_security_type_query_keeps_answer_without_do(kind, data):
    q = query(False, False, False, False, kind)
    candidate = dns.message.make_response(q)
    candidate.answer.append(dns.rrset.from_text("example.", 60, "IN", kind, data))
    result = render(q, candidate, evidence(), safe_udp_payload=1232)
    assert result.answer == candidate.answer


def test_explicit_dnskey_through_alias_survives_do_clear_without_unrelated_keys():
    q = query(False, False, False, False, "DNSKEY")
    candidate = dns.message.make_response(q)
    candidate.answer.extend(
        (
            dns.rrset.from_text("example.", 60, "IN", "CNAME", "target.example."),
            dns.rrset.from_text(
                "target.example.",
                60,
                "IN",
                "DNSKEY",
                "257 3 15 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            ),
        )
    )
    candidate.additional.append(
        dns.rrset.from_text(
            "unrelated.example.",
            60,
            "IN",
            "DNSKEY",
            "257 3 15 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        )
    )
    result = render(q, candidate, evidence(), safe_udp_payload=1232)
    assert result.answer == candidate.answer
    assert not result.additional and not result.flags & dns.flags.AD


@pytest.mark.parametrize("bad", ["question", "indeterminate", "resolution"])
def test_unverified_candidate_cannot_use_render(bad):
    q = query(True, True, True, True)
    candidate = dns.message.make_response(q)
    auth = evidence()
    if bad == "question":
        candidate.question = dns.message.make_query("other.", "A").question
    elif bad == "indeterminate":
        auth = evidence("indeterminate")
    else:
        candidate.set_rcode(dns.rcode.SERVFAIL)
    with pytest.raises(RequestDenied):
        render(q, candidate, auth, safe_udp_payload=1232)
