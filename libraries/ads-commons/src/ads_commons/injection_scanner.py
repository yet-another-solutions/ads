from __future__ import annotations

import msgspec

SCAN_PATH = "/scan"


class ScanRequest(msgspec.Struct, frozen=True):
    texts: list[str]


class TextVerdict(msgspec.Struct, frozen=True):
    score: float
    injection: bool


class ScanResponse(msgspec.Struct, frozen=True):
    verdicts: list[TextVerdict]

    @property
    def injection_found(self) -> bool:
        return any(verdict.injection for verdict in self.verdicts)

    @property
    def highest_score(self) -> float:
        return max((verdict.score for verdict in self.verdicts), default=0.0)
