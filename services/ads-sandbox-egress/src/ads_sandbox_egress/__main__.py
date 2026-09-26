from __future__ import annotations

import sys

from ads_sandbox_egress.runtime import main

if __name__ == "__main__":
    try:
        main()
    except Exception:
        # No secret-bearing exception repr, environment dump or raw wire bytes.
        print("egress runtime failed closed", file=sys.stderr)
        sys.exit(3)
