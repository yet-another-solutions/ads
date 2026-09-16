from __future__ import annotations

import os

#: Set when the image is built, from the release it is built for. Unset means a
#: developer's own run, which is said as such rather than passed off as a release.
BUILD_ENV = "ADS_BUILD"


def identity(service: str) -> str:
    """Which build of which service took a decision, as the journal records it.

    A payload finding is read by code shipped in the image — the rule set, how it was
    translated, the markers — none of which is part of the policy hash. Two builds can
    read the same payload differently, and this is what tells their rows apart.
    """
    return f"{service} {os.environ.get(BUILD_ENV, '').strip() or 'dev'}"
