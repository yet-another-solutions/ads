"""ADS shared browser login, sessions and look."""

from pathlib import Path

STATIC_DIRECTORY = Path(__file__).parent / "static"

__version__ = "0.0.1"

__all__ = ["STATIC_DIRECTORY"]
