"""ADS shared browser login, sessions and look."""

from pathlib import Path

STATIC_DIRECTORY = Path(__file__).parent / "static"
TEMPLATE_DIRECTORY = Path(__file__).parent / "templates"

__version__ = "0.0.1"

__all__ = ["STATIC_DIRECTORY", "TEMPLATE_DIRECTORY"]
