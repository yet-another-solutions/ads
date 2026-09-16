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

#: Go's regexp takes three things Python's does not. Everything else carries over,
#: because RE2 is the smaller language: it has no backreferences or lookaround to
#: translate away.
_POSIX = {
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
    """Rewrite a Go pattern into the equivalent Python one."""
    for posix, expansion in _POSIX.items():
        pattern = pattern.replace(posix, expansion)
    pattern = pattern.replace(r"\z", r"\Z")
    if "(?i)" in pattern:
        # Go takes the flag anywhere and more than once; Python only at the front.
        pattern = "(?i)" + _INLINE_IGNORECASE.sub("", pattern)
    return pattern


def entropy(value: str) -> float:
    """Shannon entropy in bits per character. A word scores low, a key high."""
    if not value:
        return 0.0
    counts = Counter(value)
    total = len(value)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


@dataclass(frozen=True, slots=True)
class Finding:
    """One secret, and where in the payload it sits so it can be cut out."""

    rule_id: str
    secret: str
    start: int
    end: int


class _Allowlist:
    """What a rule refuses to call a secret: known placeholders and example values."""

    def __init__(self, raw: dict[str, Any]) -> None:
        self._on_match = raw.get("regexTarget", "secret") in ("match", "line")
        self._regexes = [re.compile(translate(r)) for r in raw.get("regexes", ())]
        self._stopwords = [word.lower() for word in raw.get("stopwords", ())]

    def blocks(self, match: str, secret: str) -> bool:
        subject = match if self._on_match else secret
        if any(regex.search(subject) for regex in self._regexes):
            return True
        return any(word in secret.lower() for word in self._stopwords)


def _allowlists(raw: dict[str, Any]) -> list[_Allowlist]:
    """The file spells it both ways, singular and plural, and either may be a list."""
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
        self._allow = _allowlists(raw) + shared

    def find(self, text: str, lowered: str) -> list[Finding]:
        # The keyword prefilter is what keeps 200-odd regexes affordable: without a
        # hint of the vendor's name in the payload the pattern cannot match anyway.
        if self._keywords and not any(word in lowered for word in self._keywords):
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


@lru_cache(maxsize=1)
def _rules() -> tuple[_Rule, ...]:
    """Parsed once per process: reading and compiling the set costs ~50 ms."""
    document = tomllib.loads(RULES.read_text())
    shared = _allowlists(document)
    return tuple(_Rule(raw, shared) for raw in document["rules"] if "regex" in raw)


def find_secrets(text: str) -> tuple[Finding, ...]:
    """Every credential the rule set recognises, in the order they appear."""
    lowered = text.lower()
    found = [finding for rule in _rules() for finding in rule.find(text, lowered)]
    return tuple(sorted(found, key=lambda f: (f.start, f.end)))


def redact(text: str, findings: tuple[Finding, ...]) -> str:
    """Cut the secrets out, latest first so earlier spans keep their offsets.

    One secret often trips several rules — a key matches both its vendor's pattern and
    the generic one — and those matches overlap. Cutting each in turn would splice the
    text through a hole already made, so overlaps are dropped: the widest match wins
    and the rest are already inside it.
    """
    payload = text
    for finding in _widest(findings):
        payload = f"{payload[: finding.start]}[redacted:{finding.rule_id}]{payload[finding.end :]}"
    return payload


def _widest(findings: tuple[Finding, ...]) -> list[Finding]:
    """Non-overlapping spans, latest first, preferring the longer of any two."""
    ordered = sorted(findings, key=lambda f: (f.start, f.start - f.end))
    kept: list[Finding] = []
    for finding in ordered:
        if kept and finding.start < kept[-1].end:
            continue
        kept.append(finding)
    return list(reversed(kept))
