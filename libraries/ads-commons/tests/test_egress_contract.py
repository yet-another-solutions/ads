from __future__ import annotations

import copy

import msgspec
import pytest

from ads_commons.egress import ProjectEgressSettings

RULE = {
    "domain": "*.Example.COM",
    "port": 443,
    "protocol": "https",
    "protocol_settings": {"method": "any", "upgrades": "any"},
}


def decode(rule):
    return msgspec.convert({"rules": [rule]}, type=ProjectEgressSettings)


def test_defaults_and_canonical_equality():
    first = decode(RULE)
    other = copy.deepcopy(RULE)
    other.update(domain="*.example.com", sub_protocol="any")
    other["protocol_settings"]["paths"] = []
    assert first == decode(other)
    assert first.mode == "whitelist"
    assert first.rules[0].sub_protocol == "any"
    assert first.rules[0].protocol_settings.paths == ()
    assert msgspec.json.decode(msgspec.json.encode(first), type=ProjectEgressSettings) == first


@pytest.mark.parametrize("field", ["domain", "port", "protocol", "protocol_settings"])
def test_required_rule_fields(field):
    rule = copy.deepcopy(RULE)
    del rule[field]
    with pytest.raises(msgspec.ValidationError):
        decode(rule)


@pytest.mark.parametrize("field", ["method", "upgrades"])
@pytest.mark.parametrize("value", [msgspec.UNSET, None, "", [], ["unknown"], False])
def test_required_protocol_fields(field, value):
    rule = copy.deepcopy(RULE)
    if value is msgspec.UNSET:
        del rule["protocol_settings"][field]
    else:
        rule["protocol_settings"][field] = value
    with pytest.raises(msgspec.ValidationError):
        decode(rule)


@pytest.mark.parametrize(
    "domain",
    [
        "",
        "*.*.com",
        "a*.com",
        "a.*.com",
        ".com",
        "a..com",
        "*.com.",
        "-a.com",
        "a_.com",
        "é.com",
        "a" * 64 + ".com",
    ],
)
def test_invalid_domains(domain):
    with pytest.raises(msgspec.ValidationError):
        decode({**RULE, "domain": domain})


@pytest.mark.parametrize("domain", ["*", "*.com", "*.example.com", "example.com", "xn--9ca.com"])
def test_valid_domains(domain):
    assert decode({**RULE, "domain": domain}).rules[0].domain == domain


@pytest.mark.parametrize(
    "field,value",
    [
        ("port", 0),
        ("port", 65536),
        ("port", True),
        ("port", "443"),
        ("protocol", "tcp"),
        ("sub_protocol", None),
        ("sub_protocol", ""),
        ("authentication", {}),
        ("unknown", True),
    ],
)
def test_invalid_rule_fields(field, value):
    with pytest.raises(msgspec.ValidationError):
        decode({**RULE, field: value})


@pytest.mark.parametrize(
    "field,value",
    [
        ("paths", None),
        ("paths", [{"pattern": "/x", "case_insensitive": None}]),
        ("paths", [{"pattern": "x"}]),
        ("upgrades", ["websocket", "websocket"]),
        ("method", "get"),
        ("method", ["GET"]),
        ("method", "arbitrary"),
    ],
)
def test_invalid_protocol_settings(field, value):
    rule = copy.deepcopy(RULE)
    rule["protocol_settings"][field] = value
    with pytest.raises(msgspec.ValidationError):
        decode(rule)


@pytest.mark.parametrize(
    "upgrades", ["any", "none", ["http/2"], ["websocket"], ["http/2", "websocket"]]
)
def test_supported_upgrades(upgrades):
    rule = copy.deepcopy(RULE)
    rule["protocol_settings"]["upgrades"] = upgrades
    decode(rule)


def test_order_and_no_cross_rule_lint():
    second = {**RULE, "domain": "other.example"}
    value = msgspec.convert(
        {"mode": "blacklist", "rules": [RULE, second, RULE]}, type=ProjectEgressSettings
    )
    assert [r.domain for r in value.rules] == ["*.example.com", "other.example", "*.example.com"]
