from __future__ import annotations

import re

import pytest

from ads_policy.secrets import Finding, entropy, find_secrets, redact, translate


@pytest.mark.parametrize(
    ("go", "sample"),
    [
        (r"pat[[:alnum:]]{4}", "patAb12"),
        (r"\b(p8e-(?i)[a-z0-9]{4})\b", "p8e-AB12"),
        (r"(?i)\b(pscale_pw_(?i)[\w-]{4,})", "PSCALE_PW_abcd"),
        (r"sha256~[\w-]{4}(?:[^\w-]|\z)", "sha256~abcd"),
    ],
)
def test_go_patterns_become_python_ones(go: str, sample: str) -> None:
    assert re.search(translate(go), sample) is not None


def test_an_untranslated_posix_class_compiles_but_silently_means_something_else() -> None:
    with pytest.warns(FutureWarning):
        assert re.search(r"pat[[:alnum:]]{4}", "patAb12") is None


def test_a_word_scores_lower_than_a_key() -> None:
    assert entropy("session_secret") < entropy("Xj9k2Lm4Qp7Rt5Vw8Zc1Nb3")


def test_entropy_of_nothing_is_nothing() -> None:
    assert entropy("") == 0.0


def test_every_vendored_rule_compiles() -> None:
    assert len(find_secrets("")) == 0
    assert find_secrets("AKIAQYLPMN5HHHFPZAM2")[0].rule_id == "aws-access-token"


def test_a_finding_points_at_the_secret() -> None:
    text = "before AKIAQYLPMN5HHHFPZAM2 after"
    finding = find_secrets(text)[0]
    assert text[finding.start : finding.end] == finding.secret


def test_redaction_keeps_the_offsets_of_earlier_findings() -> None:
    text = "aaa SECRET1 bbb SECRET2 ccc"
    findings = (Finding("one", "SECRET1", 4, 11), Finding("two", "SECRET2", 16, 23))
    assert redact(text, findings) == "aaa [redacted:one] bbb [redacted:two] ccc"


def test_redacting_nothing_changes_nothing() -> None:
    assert redact("untouched", ()) == "untouched"


def test_a_key_matched_by_several_rules_is_cut_once() -> None:
    text = "export KEY=AKIAQYLPMN5HHHFPZAM2"
    payload = redact(text, find_secrets(text))
    assert "AKIAQYLPMN5HHHFPZAM2" not in payload
    assert payload.count("[redacted:") == 1
    assert payload.startswith("export KEY=")


def test_the_wider_of_two_overlapping_findings_wins() -> None:
    inner = Finding("narrow", "BCD", 1, 4)
    outer = Finding("wide", "ABCDE", 0, 5)
    assert redact("ABCDE tail", (inner, outer)) == "[redacted:wide] tail"
