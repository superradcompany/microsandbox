"""CLI entry point using explicit overrides, runtime home, then the wheel fallback."""

from __future__ import annotations

import os
import sys


def main() -> None:
    # Package import has registered the wheel fallback. Use the same native
    # pair resolver as sandbox launch, including persisted paths and home.
    from microsandbox._microsandbox import resolved_cli_msb_path

    try:
        msb = resolved_cli_msb_path()
    except Exception as error:
        sys.stderr.write(f"microsandbox: {error}\n")
        sys.exit(127)

    os.execv(msb, ["msb", *sys.argv[1:]])
