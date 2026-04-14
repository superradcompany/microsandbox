"""Resolve paths to bundled msb and libkrunfw binaries.

The Python SDK bundles msb + libkrunfw inside the wheel at
``microsandbox/_bundled/{bin,lib}/``.  At runtime these paths are resolved
via ``importlib.resources`` so they work regardless of install location.

Environment variable overrides (for local dev against unreleased builds):
  - ``MICROSANDBOX_MSB_PATH`` — absolute path to ``msb`` binary
  - ``MICROSANDBOX_LIBKRUNFW_PATH`` — absolute path to ``libkrunfw`` shared library
"""

from __future__ import annotations

import os
import sys
from importlib.resources import files
from pathlib import Path

_BUNDLED = files("microsandbox._bundled")


def msb_path() -> Path:
    """Return the absolute path to the ``msb`` binary."""
    override = os.environ.get("MICROSANDBOX_MSB_PATH")
    if override:
        return Path(override)
    return Path(str(_BUNDLED.joinpath("bin", "msb")))


def libkrunfw_path() -> Path:
    """Return the absolute path to the ``libkrunfw`` shared library."""
    override = os.environ.get("MICROSANDBOX_LIBKRUNFW_PATH")
    if override:
        return Path(override)

    if sys.platform == "darwin":
        name = "libkrunfw.5.dylib"
    else:
        name = "libkrunfw.so.5.2.1"

    return Path(str(_BUNDLED.joinpath("lib", name)))
