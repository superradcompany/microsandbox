"""CLI entry point — execs the bundled msb binary.

Resolution order:
  1. ``MSB_PATH`` environment variable
  2. Wheel-bundled ``microsandbox/_bundled/bin/msb``
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def main() -> None:
    override = os.environ.get("MSB_PATH")
    msb = override or str(Path(__file__).parent / "_bundled" / "bin" / "msb")

    if not os.path.isfile(msb):
        sys.stderr.write(
            f"microsandbox: msb binary not found at {msb}. "
            "Set MSB_PATH or reinstall the package.\n"
        )
        sys.exit(127)

    os.execv(msb, ["msb", *sys.argv[1:]])
