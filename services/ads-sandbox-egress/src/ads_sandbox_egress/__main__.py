from __future__ import annotations

import sys
import traceback

from ads_sandbox_egress.runtime import main

if __name__ == "__main__":
    try:
        main()
    except Exception:
        # No swallowing: full traceback to stderr for diagnosis.
        print("egress runtime failed closed", file=sys.stderr)
        traceback.print_exc()
        sys.exit(3)
