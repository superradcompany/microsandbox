"""Resolve paths to bundled msb and libkrunfw binaries.

The Python SDK bundles msb + libkrunfw inside the wheel at
``microsandbox/_bundled/{bin,lib}/``.  At runtime these paths are resolved
via ``importlib.resources`` so they work regardless of install location.

To override the resolved msb binary (e.g. for local dev against an
unreleased build), set the ``MSB_PATH`` env var. The Rust resolver
honours it natively as its highest-precedence tier — no SDK-side
wrapping needed.

libkrunfw is located by the Rust resolver relative to ``msb`` (``../lib/``),
which matches the wheel bundle layout. Pass ``libkrunfw_path`` to
``Sandbox.create(...)`` for per-sandbox overrides.
"""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path

_BUNDLED = files("microsandbox._bundled")


def msb_path() -> Path:
    """Return the absolute path to the bundled ``msb`` binary."""
    return Path(str(_BUNDLED.joinpath("bin", "msb")))
