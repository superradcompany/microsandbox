"""Resolve paths to bundled msb and libkrunfw binaries.

The Python SDK bundles msb + libkrunfw inside the wheel at
``microsandbox/_bundled/{bin,lib}/``.  At runtime these paths are resolved
via ``importlib.resources`` so they work regardless of install location.

Environment variable overrides (for local dev against unreleased builds):
  - ``MICROSANDBOX_MSB_PATH`` — absolute path to ``msb`` binary

libkrunfw is located by the Rust resolver relative to ``msb`` (``../lib/``),
which matches the wheel bundle layout. Pass ``libkrunfw_path`` to
``Sandbox.create(...)`` for per-sandbox overrides.
"""

from __future__ import annotations

import os
from importlib.resources import files
from pathlib import Path

_BUNDLED = files("microsandbox._bundled")


def msb_path() -> Path:
    """Return the absolute path to the ``msb`` binary."""
    override = os.environ.get("MICROSANDBOX_MSB_PATH")
    if override:
        return Path(override)
    return Path(str(_BUNDLED.joinpath("bin", "msb")))
