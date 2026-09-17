"""Run the identity reconciliation in the installed ADS Python environment.

Invoke on the admin node. The issuer URL is a nonsecret argument; secrets enter
via stdin. No application endpoint, image build, or workload rollout is added.
"""

import argparse
import subprocess
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    args = parser.parse_args()
    if not args.url.startswith("https://"):
        parser.error("Keycloak must use HTTPS")
    pod = subprocess.check_output([
        "kubectl", "-n", "ads", "get", "pods", "-l", "app.kubernetes.io/component=ads",
        "-o", "jsonpath={.items[0].metadata.name}",
    ], text=True)
    if not pod:
        raise RuntimeError("ADS pod selector did not match")
    code = Path(__file__).with_name("keycloak.py").read_text()
    return subprocess.run([
        "kubectl", "-n", "ads", "exec", "-i", pod, "--", "env",
        "ADS_SLICE6_KEYCLOAK_URL=" + args.url, "python", "-c", code,
    ], input=sys.stdin.buffer.read()).returncode


if __name__ == "__main__":
    raise SystemExit(main())
