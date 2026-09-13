"""Resolve paths to bundled msb and libkrunfw binaries.

The Python SDK bundles msb + libkrunfw inside the wheel at
``microsandbox/_bundled/{bin,lib}/``.  Package paths are discovered
via ``importlib.resources`` and registered as fallbacks after the resolved
runtime home (``MSB_HOME``, or ``~/.microsandbox`` by default).

To override the resolved msb binary (e.g. for local dev against an
unreleased build), set the ``MSB_PATH`` env var. The Rust resolver
honours it natively as its highest-precedence tier — no SDK-side
wrapping needed.

libkrunfw is located by the Rust resolver relative to ``msb`` (``../lib/``),
which matches the wheel bundle layout. To override it, set the
``MSB_LIBKRUNFW_PATH`` env var (highest precedence) or call
``microsandbox.set_libkrunfw_path(...)`` once at startup. libkrunfw is a
process-level concern (one dylib per process address space), so per-sandbox
overrides aren't supported.
"""

from __future__ import annotations

import os
from importlib.resources import files
from pathlib import Path

_BUNDLED = files("microsandbox._bundled")


def _msb_filename() -> str:
    """Return the platform-specific bundled CLI filename."""
    return "msb.exe" if os.name == "nt" else "msb"


def msb_path() -> Path:
    """Return the absolute path to the bundled ``msb`` binary."""
    # Python 3.10 namespace-package resources accept only one component per call.
    return Path(str(_BUNDLED.joinpath("bin").joinpath(_msb_filename())))
