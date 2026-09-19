from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

from ads_policy.contract import (
    DEFAULT_REQUEST,
    DEFAULT_RESPONSE,
    Capability,
    CheckKind,
    Effect,
    Interception,
    InterceptionPoint,
    IsolationLevel,
    Policy,
    Side,
    Switch,
)
from ads_policy.output import inspect_payload
from ads_policy.pdp import PolicyDecisionPoint
from ads_policy.policy import compose, load_policy
from policy_helpers import policy_request

AWS = "AKIAQYLPMN5HHHFPZAM2"
SECRETS = frozenset({CheckKind.SECRETS})
BOTH = frozenset(CheckKind)

MIRROR = {
    "id": "net.egress.allowlist",
    "capability": "net.egress",
    "resourceClass": "allowlist",
    "levels": ["local", "container", "vm"],
}
INTERNET = {
    "id": "net.egress.internet",
    "capability": "net.egress",
    "resourceClass": "internet",
    "levels": ["local"],
}
DOCUMENT: dict[str, Any] = {
    "schemaVersion": "ads.governance/v1",
    "version": "org-1",
    "mode": "enforce",
    "egressAllowlist": ["mirror.interlab"],
    "rules": [MIRROR, INTERNET],
}


def _document_with_inspection(
    policy_interception: object = None, **rule_inspections: object
) -> dict[str, Any]:
    rules = [
        {**rule, "inspect": rule_inspections[rule["id"]]}
        if rule["id"] in rule_inspections
        else rule
        for rule in (MIRROR, INTERNET)
    ]
    document = {**DOCUMENT, "rules": rules}
    if policy_interception is not None:
        document["interception"] = policy_interception
    return document


def _interception_of_egress_to(policy: Policy, host: str) -> Interception:
    return (
        PolicyDecisionPoint(policy)
        .decide(policy_request(Capability.NET_EGRESS, f"https://{host}/"))
        .interception
    )


def test_a_document_that_says_nothing_resolves_both_sides_to_enforced_defaults() -> None:
    policy = load_policy(_document_with_inspection())
    assert policy.interception == Interception()
    resolved = _interception_of_egress_to(policy, "mirror.interlab")
    assert resolved.side(InterceptionPoint.REQUEST) == DEFAULT_REQUEST
    assert resolved.side(InterceptionPoint.RESPONSE) == DEFAULT_RESPONSE


def test_injection_is_checked_only_on_the_response_by_default() -> None:
    assert DEFAULT_REQUEST.checks == SECRETS
    assert DEFAULT_RESPONSE.checks == BOTH


def test_by_default_injections_are_only_recorded_while_secrets_are_enforced() -> None:
    assert DEFAULT_RESPONSE.switch_for(CheckKind.INJECTION) is Switch.REVIEW
    assert DEFAULT_RESPONSE.switch_for(CheckKind.SECRETS) is Switch.ENFORCE


def test_a_reviewed_check_follows_a_side_that_is_off_or_in_review() -> None:
    reviewed = frozenset({CheckKind.INJECTION})
    assert Side(BOTH, Switch.OFF, reviewed).switch_for(CheckKind.INJECTION) is Switch.OFF
    assert Side(BOTH, Switch.REVIEW, reviewed).switch_for(CheckKind.INJECTION) is Switch.REVIEW
    assert Side(SECRETS).switch_for(CheckKind.INJECTION) is Switch.OFF


def test_a_side_may_name_the_checks_it_only_records() -> None:
    policy = load_policy(
        _document_with_inspection({"response": {"checks": ["secrets", "injection"], "review": []}})
    )
    side = policy.interception.response
    assert side is not None
    assert side.switch_for(CheckKind.INJECTION) is Switch.ENFORCE


def test_a_reviewed_check_the_side_does_not_run_is_a_broken_document() -> None:
    with pytest.raises(ValueError, match=r"review names checks the side does not run"):
        load_policy(
            _document_with_inspection(
                {"response": {"checks": ["secrets"], "review": ["injection"]}}
            )
        )


def test_a_dev_policy_may_enforce_a_check_the_org_only_records(policy: Policy) -> None:
    enforcing = _with(policy, Interception(response=Side(checks=BOTH)), version="dev-1")
    composed = compose(policy, enforcing).interception.response
    assert composed is not None
    assert composed.switch_for(CheckKind.INJECTION) is Switch.ENFORCE


def test_a_dev_policy_may_not_turn_an_enforced_check_into_a_record(policy: Policy) -> None:
    org = _with(policy, Interception(response=Side(checks=BOTH)))
    relaxing = _with(
        policy,
        Interception(response=Side(checks=BOTH, review=frozenset({CheckKind.INJECTION}))),
        version="dev-1",
    )
    composed = compose(org, relaxing).interception.response
    assert composed is not None
    assert composed.switch_for(CheckKind.INJECTION) is Switch.ENFORCE


def test_recording_a_check_instead_of_enforcing_it_is_a_different_policy() -> None:
    enforced = load_policy(
        _document_with_inspection({"response": {"checks": ["secrets", "injection"], "review": []}})
    )
    recorded = load_policy(
        _document_with_inspection({"response": {"checks": ["secrets", "injection"]}})
    )
    assert enforced.digest() != recorded.digest()


def test_a_side_names_its_switch_and_its_checks() -> None:
    policy = load_policy(
        _document_with_inspection({"response": {"on": "review", "checks": ["secrets"]}})
    )
    assert policy.interception.response == Side(checks=SECRETS, on=Switch.REVIEW)
    assert policy.interception.request is None


def test_a_side_without_checks_runs_its_usual_ones() -> None:
    policy = load_policy(_document_with_inspection({"response": {"on": "off"}}))
    assert policy.interception.response == Side(
        checks=BOTH, on=Switch.OFF, review=DEFAULT_RESPONSE.review
    )


def test_a_side_without_a_switch_is_enforced() -> None:
    policy = load_policy(_document_with_inspection({"response": {"checks": ["injection"]}}))
    side = policy.interception.response
    assert side is not None
    assert side.on is Switch.ENFORCE


@pytest.mark.parametrize("value", ["enforce", "review", "off"])
def test_every_switch_the_document_may_carry(value: str) -> None:
    side = load_policy(_document_with_inspection({"request": {"on": value}})).interception.request
    assert side is not None
    assert side.on is Switch(value)


@pytest.mark.parametrize(
    ("section", "message"),
    [
        (["off"], "must be a mapping of prompt, request and response"),
        ({"request": "off"}, "must be a mapping of on and checks"),
        ({"request": {"on": "maybe"}}, r"interception\.request\.on must be one of"),
        ({"response": {"checks": ["telepathy"]}}, r"interception\.response\.checks must be"),
        ({"response": {"checks": "secrets"}}, r"interception\.response\.checks must be"),
    ],
)
def test_a_malformed_section_is_a_broken_document(section: object, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        load_policy(_document_with_inspection(section))


def test_an_outbound_injection_check_is_refused_rather_than_ignored() -> None:
    with pytest.raises(ValueError, match=r"request cannot check \['injection'\]"):
        load_policy(_document_with_inspection({"request": {"checks": ["secrets", "injection"]}}))


def test_a_broken_rule_section_names_the_rule() -> None:
    with pytest.raises(ValueError, match="rule 'net.egress.internet' inspect.response.on"):
        load_policy(
            _document_with_inspection(**{"net.egress.internet": {"response": {"on": "maybe"}}})
        )


def test_the_same_capability_is_read_differently_for_the_mirror_and_the_internet() -> None:
    policy = load_policy(
        _document_with_inspection(
            **{
                "net.egress.allowlist": {"response": {"on": "review", "checks": ["secrets"]}},
                "net.egress.internet": {"response": {"checks": ["secrets", "injection"]}},
            }
        )
    )
    mirror = _interception_of_egress_to(policy, "mirror.interlab").side(InterceptionPoint.RESPONSE)
    internet = _interception_of_egress_to(policy, "example.com").side(InterceptionPoint.RESPONSE)
    assert mirror == Side(checks=SECRETS, on=Switch.REVIEW)
    assert internet == Side(checks=BOTH, on=Switch.ENFORCE, review=DEFAULT_RESPONSE.review)


def test_a_row_takes_what_it_leaves_unstated_from_the_policy() -> None:
    policy = load_policy(
        _document_with_inspection(
            {"request": {"on": "off"}},
            **{"net.egress.internet": {"response": {"on": "review"}}},
        )
    )
    resolved = _interception_of_egress_to(policy, "example.com")
    assert resolved.side(InterceptionPoint.REQUEST).on is Switch.OFF
    assert resolved.side(InterceptionPoint.RESPONSE).on is Switch.REVIEW


def test_a_row_that_says_nothing_reads_as_the_policy_does() -> None:
    policy = load_policy(_document_with_inspection({"response": {"on": "off"}}))
    resolved = _interception_of_egress_to(policy, "mirror.interlab")
    assert resolved.side(InterceptionPoint.RESPONSE).on is Switch.OFF


def test_a_refusal_carries_its_row_s_reading_for_review_mode() -> None:
    policy = load_policy(
        _document_with_inspection(**{"net.egress.internet": {"request": {"on": "review"}}})
    )
    decision = PolicyDecisionPoint(policy).decide(
        policy_request(
            Capability.NET_EGRESS, "https://example.com/", level=IsolationLevel.CONTAINER
        )
    )
    assert decision.effect is Effect.DENY
    assert decision.interception.side(InterceptionPoint.REQUEST).on is Switch.REVIEW


def test_a_payload_side_is_not_the_call_point() -> None:
    with pytest.raises(ValueError, match="call is not a payload side"):
        Interception().side(InterceptionPoint.CALL)


def test_reading_a_row_differently_is_a_different_policy_version() -> None:
    policy = load_policy(_document_with_inspection())
    reread = load_policy(
        _document_with_inspection(**{"net.egress.internet": {"response": {"on": "off"}}})
    )
    assert reread.digest() != policy.digest()


def test_switching_the_policy_level_is_a_different_policy() -> None:
    policy = load_policy(_document_with_inspection())
    switched_off = load_policy(_document_with_inspection({"response": {"on": "off"}}))
    assert switched_off.digest() != policy.digest()


def test_the_order_of_checks_does_not_change_the_version() -> None:
    one = load_policy(_document_with_inspection({"response": {"checks": ["secrets", "injection"]}}))
    two = load_policy(_document_with_inspection({"response": {"checks": ["injection", "secrets"]}}))
    assert one.digest() == two.digest()


def test_secrets_are_looked_for_only_when_named() -> None:
    carrying_a_key = f"KEY={AWS}\n"
    secrets_named = inspect_payload(carrying_a_key, InterceptionPoint.RESPONSE, checks=SECRETS)
    injection_only = inspect_payload(
        carrying_a_key, InterceptionPoint.RESPONSE, checks=frozenset({CheckKind.INJECTION})
    )
    assert secrets_named.effect is Effect.TRANSFORM
    assert injection_only.effect is Effect.ALLOW


def test_no_checks_find_nothing() -> None:
    decision = inspect_payload(f"KEY={AWS}", InterceptionPoint.REQUEST, checks=frozenset())
    assert decision.effect is Effect.ALLOW


def _with(policy: Policy, interception: Interception, **changes: Any) -> Policy:
    return replace(policy, interception=interception, **changes)


def test_a_dev_policy_may_switch_a_side_up(policy: Policy) -> None:
    org = _with(policy, Interception(request=Side(checks=SECRETS, on=Switch.OFF)))
    dev = _with(policy, Interception(request=Side(checks=SECRETS)), version="dev-1")
    composed = compose(org, dev).interception.request
    assert composed is not None
    assert composed.on is Switch.ENFORCE


def test_a_dev_policy_may_not_switch_a_side_down(policy: Policy) -> None:
    dev = _with(policy, Interception(response=Side(checks=BOTH, on=Switch.OFF)), version="dev-1")
    composed = compose(policy, dev).interception.response
    assert composed is not None
    assert composed.on is Switch.ENFORCE


def test_a_dev_policy_may_add_a_check_but_not_remove_one(policy: Policy) -> None:
    org = _with(policy, Interception(response=Side(checks=SECRETS)))
    dev = _with(
        policy,
        Interception(response=Side(checks=frozenset({CheckKind.INJECTION}))),
        version="dev-1",
    )
    composed = compose(org, dev).interception.response
    assert composed is not None
    assert composed.checks == BOTH


def test_a_dev_policy_silent_about_a_side_keeps_the_org_s_switched_off_side(
    policy: Policy,
) -> None:
    off = Side(checks=BOTH, on=Switch.OFF)
    org = _with(policy, Interception(response=off))
    dev = _with(policy, Interception(), version="dev-1")
    assert compose(org, dev).interception.response == off


def test_a_dev_policy_tightening_the_top_reaches_a_row_the_org_relaxed() -> None:
    org = load_policy(
        _document_with_inspection(
            **{"net.egress.allowlist": {"response": {"on": "off", "checks": ["secrets"]}}}
        )
    )
    dev = load_policy(
        {**_document_with_inspection({"response": {"on": "enforce"}}), "version": "dev-1"}
    )
    composed = compose(org, dev)
    side = _interception_of_egress_to(composed, "mirror.interlab").side(InterceptionPoint.RESPONSE)
    assert side.on is Switch.ENFORCE


def test_review_sits_between_off_and_enforce() -> None:
    assert Switch.OFF.stricter(Switch.REVIEW) is Switch.REVIEW
    assert Switch.REVIEW.stricter(Switch.ENFORCE) is Switch.ENFORCE
