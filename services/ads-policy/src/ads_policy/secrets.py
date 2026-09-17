from __future__ import annotations

import math
import re
import tomllib
from collections import Counter
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

RULES = Path(__file__).parent / "rules" / "gitleaks.toml"

_GO_POSIX_CLASSES_IN_PYTHON = {
    "[:alnum:]": "a-zA-Z0-9",
    "[:alpha:]": "a-zA-Z",
    "[:digit:]": "0-9",
    "[:lower:]": "a-z",
    "[:upper:]": "A-Z",
    "[:xdigit:]": "0-9a-fA-F",
    "[:space:]": r" \t\n\r\f\v",
    "[:punct:]": r"!-/:-@\[-`{-~",
    "[:word:]": r"\w",
}
_INLINE_IGNORECASE = re.compile(r"\(\?i\)")


def translate(pattern: str) -> str:
    for posix_class, python_class in _GO_POSIX_CLASSES_IN_PYTHON.items():
        pattern = pattern.replace(posix_class, python_class)
    pattern = pattern.replace(r"\z", r"\Z")
    if "(?i)" in pattern:
        pattern = _with_ignorecase_moved_to_front(pattern)
    return pattern


def _with_ignorecase_moved_to_front(pattern: str) -> str:
    return "(?i)" + _INLINE_IGNORECASE.sub("", pattern)


def entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    total = len(value)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    secret: str
    start: int
    end: int


class _Allowlist:
    def __init__(self, raw: dict[str, Any]) -> None:
        self._on_match = raw.get("regexTarget", "secret") in ("match", "line")
        self._regexes = [re.compile(translate(r)) for r in raw.get("regexes", ())]
        self._stopwords = [word.lower() for word in raw.get("stopwords", ())]

    def blocks(self, match: str, secret: str) -> bool:
        subject = match if self._on_match else secret
        if any(regex.search(subject) for regex in self._regexes):
            return True
        return any(word in secret.lower() for word in self._stopwords)


def _allowlists_singular_or_plural(raw: dict[str, Any]) -> list[_Allowlist]:
    blocks: list[_Allowlist] = []
    for key in ("allowlist", "allowlists"):
        value = raw.get(key)
        if not value:
            continue
        entries = value if isinstance(value, list) else [value]
        blocks += [_Allowlist(entry) for entry in entries]
    return blocks


class _Rule:
    def __init__(self, raw: dict[str, Any], shared: list[_Allowlist]) -> None:
        self.id = str(raw["id"])
        self._regex = re.compile(translate(str(raw["regex"])))
        self._keywords = tuple(str(k).lower() for k in raw.get("keywords", ()))
        self._entropy = float(raw.get("entropy", 0.0))
        self._group = int(raw.get("secretGroup", 0)) or None
        self._allow = _allowlists_singular_or_plural(raw) + shared

    def find(self, text: str, lowered: str) -> list[Finding]:
        if self._keywords and not self._mentions_a_keyword(lowered):
            return []
        found: list[Finding] = []
        for match in self._regex.finditer(text):
            index = self._group or (1 if match.groups() else 0)
            secret = match.group(index) or ""
            if not secret:
                continue
            if self._entropy and entropy(secret) < self._entropy:
                continue
            if any(block.blocks(match.group(0), secret) for block in self._allow):
                continue
            found.append(Finding(self.id, secret, *match.span(index)))
        return found

    def _mentions_a_keyword(self, lowered: str) -> bool:
        return any(word in lowered for word in self._keywords)


@lru_cache(maxsize=1)
def _rules_parsed_once() -> tuple[_Rule, ...]:
    document = tomllib.loads(RULES.read_text())
    shared = _allowlists_singular_or_plural(document)
    return tuple(_Rule(raw, shared) for raw in document["rules"] if "regex" in raw)


def find_secrets(text: str) -> tuple[Finding, ...]:
    lowered = text.lower()
    found = [finding for rule in _rules_parsed_once() for finding in rule.find(text, lowered)]
    return tuple(sorted(found, key=lambda f: (f.start, f.end)))


def redact(text: str, findings: tuple[Finding, ...]) -> str:
    payload = text
    for finding in _widest_non_overlapping_latest_first(findings):
        payload = f"{payload[: finding.start]}[redacted:{finding.rule_id}]{payload[finding.end :]}"
    return payload


def _widest_non_overlapping_latest_first(findings: tuple[Finding, ...]) -> list[Finding]:
    ordered = sorted(findings, key=lambda f: (f.start, f.start - f.end))
    kept: list[Finding] = []
    for finding in ordered:
        if kept and finding.start < kept[-1].end:
            continue
        kept.append(finding)
    return list(reversed(kept))
