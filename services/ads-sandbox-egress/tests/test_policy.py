from dataclasses import replace

import pytest

from ads_commons.egress import (
    EgressPath,
    EgressRule,
    ProjectEgressSettings,
    ProjectEgressSnapshot,
    ProtocolSettings,
)
from ads_sandbox_egress.policy import (
    PolicyRequest,
    RequestDenied,
    ant_matches,
    authority,
    canonical_host,
    consistent_identity,
    permitted,
)


def rule(domain="example.com", **options):
    return EgressRule(
        domain, 443, "https", ProtocolSettings(**{"method": "GET", "upgrades": "none", **options})
    )


def snapshot(*rules, mode="whitelist"):
    return ProjectEgressSnapshot(1, ProjectEgressSettings(rules, mode))


REQUEST = PolicyRequest(("example.com",), 443, "https", "http/1.1", "GET", b"/a")


@pytest.mark.parametrize("mode", ["whitelist", "blacklist"])
def test_complete_rule_no_partial_combination(mode):
    policy = snapshot(rule("other.example"), rule(method="POST"), mode=mode)
    assert permitted(policy, REQUEST) is (mode == "blacklist")
    assert permitted(snapshot(rule(), mode=mode), REQUEST) is (mode == "whitelist")


@pytest.mark.parametrize(
    "pattern,name,match",
    [
        ("*", "a.b.example.com", True),
        ("*.example.com", "a.example.com", True),
        ("*.example.com", "example.com", False),
        ("*.example.com", "a.b.example.com", False),
        ("*.com", "a.com", True),
        ("*.com", "a.b.com", False),
        ("example.com", "a.example.com", False),
    ],
)
def test_domain_depth(pattern, name, match):
    assert permitted(snapshot(rule(pattern)), replace(REQUEST, names=(name,))) is match


@pytest.mark.parametrize(
    "pattern,path,match",
    [
        (b"/a/*", b"/a/b/c", False),
        (b"/a/**", b"/a", True),
        (b"/a/**", b"/a/b/c", True),
        (b"/**/x", b"/x", True),
        (b"/**/x", b"/a/b/x", True),
        (b"/a/?", b"/a/b", True),
        (b"/a/?", b"/a/bc", False),
        (b"/a", b"/a/", False),
        (b"/%61", b"/a", False),
    ],
)
def test_ant_segments(pattern, path, match):
    assert ant_matches(pattern, path) is match


def test_case_defaults_and_explicit_override():
    restriction = rule(paths=(EgressPath("/A"),))
    assert not permitted(snapshot(restriction), REQUEST)
    assert not permitted(snapshot(restriction, mode="blacklist"), REQUEST)
    assert permitted(snapshot(rule(paths=(EgressPath("/A", False),)), mode="blacklist"), REQUEST)
    assert permitted(snapshot(rule(paths=(EgressPath("/A", True),))), REQUEST)


def test_missing_identity_is_not_invented():
    unnamed = replace(REQUEST, names=())
    assert not permitted(snapshot(rule()), unnamed)
    assert permitted(snapshot(rule("*")), unnamed)
    assert not permitted(snapshot(rule(), mode="blacklist"), unnamed)
    assert permitted(snapshot(rule(method="POST"), mode="blacklist"), unnamed)


@pytest.mark.parametrize("mode", ["whitelist", "blacklist"])
@pytest.mark.parametrize(
    "upgrades,selected",
    [("none", False), ("any", True), (("websocket",), True), (("http/2",), False)],
)
def test_transition_complete_match(mode, upgrades, selected):
    request = replace(REQUEST, upgrade="websocket")
    assert permitted(snapshot(rule(upgrades=upgrades), mode=mode), request) is (
        selected if mode == "whitelist" else not selected
    )


def test_connect_exception_and_no_implicit_target_gate():
    policy = snapshot(rule(upgrades="any", method="any"))
    assert not permitted(policy, replace(REQUEST, method="CONNECT"))
    assert permitted(
        policy, replace(REQUEST, method="CONNECT", sub_protocol="http/2", upgrade="websocket")
    )
    assert permitted(policy, replace(REQUEST, upgrade="websocket"))
    assert not permitted(None, REQUEST)


@pytest.mark.parametrize(
    "value", ["0177.0.0.1", "127.1", "1234", "a..com", "a.com..", "a%2ecom", "é.com"]
)
def test_host_invalid(value):
    with pytest.raises(RequestDenied):
        canonical_host(value)


@pytest.mark.parametrize(
    "value",
    [
        "a.com:",
        "a.com:0",
        "a.com:65536",
        "a.com:+443",
        "u@a.com",
        "a.com/x",
        "[::1]x",
        "::1",
        "[a.com]",
        " a.com",
        "[fe80::1%eth0]",
    ],
)
def test_authority_invalid(value):
    with pytest.raises(RequestDenied):
        authority(value, 443)


def test_identity_normalization_and_conflicts():
    first = authority("EXAMPLE.COM.:443", 443)
    assert first == authority("example.com", 443)
    assert consistent_identity((first,), "Example.Com.") == ("example.com",)
    assert consistent_identity((None,), "example.com") == ("example.com",)
    assert consistent_identity((None,), None) == ()
    assert authority("[2001:4860:4860::8888]:443", 80).port == 443
    for sources, tls in [
        ((first, None), None),
        ((first, authority("example.com:80", 443)), None),
        ((first,), "other.example"),
    ]:
        with pytest.raises(RequestDenied):
            consistent_identity(sources, tls)


def test_match_work_is_bounded():
    with pytest.raises(RequestDenied, match="path_match_limit"):
        ant_matches(b"/" + b"?" * 8190, b"/" + b"a" * 8190)
