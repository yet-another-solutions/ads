"""Stamp release-owned chart inputs in CI before helm package (no cluster access)."""

import argparse
import json
import re
from pathlib import Path


def stamp(chart: Path, version: str, session_size: str) -> None:
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9]+(?:[.-][a-z0-9]+)*)?", version):
        raise ValueError("version must be a DNS-safe release version without the v prefix")
    if len("ads-sandbox-golden-v" + version) > 63:
        raise ValueError("golden resource name would exceed 63 characters")
    if not re.fullmatch(r"[0-9]+(?:Ki|Mi|Gi|Ti|Pi|k|M|G|T|P)?", session_size):
        raise ValueError("session_size must be an integer storage quantity")
    metadata = chart / "Chart.yaml"
    text = metadata.read_text()
    text = re.sub(r"^version: .*", f"version: {version}", text, flags=re.M)
    text = re.sub(r"^appVersion: .*", f'appVersion: "{version}"', text, flags=re.M)
    metadata.write_text(text)
    # Keep existing service image pins aligned with the release too.
    values = chart / "values.yaml"
    values.write_text(re.sub(r"^(\s+tag:) .*", rf'\1 "{version}"', values.read_text(), flags=re.M))
    # JSON is YAML; Helm loads it with fromYaml. No install-time size override.
    (chart / "files" / "sandbox-release.yaml").write_text(
        json.dumps({"sessionSize": session_size}) + "\n"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--chart", type=Path, default=Path("charts/ads"))
    parser.add_argument("--version", required=True)
    parser.add_argument("--session-size", required=True)
    args = parser.parse_args()
    stamp(args.chart, args.version, args.session_size)
