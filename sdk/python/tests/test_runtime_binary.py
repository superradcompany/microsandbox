"""Verify the Python-to-native bridge for the bundled msb binary."""

from __future__ import annotations

import os

import pytest

from microsandbox._microsandbox import (
    resolved_msb_path,
    set_runtime_msb_path,
)
from microsandbox._runtime import msb_path as _msb_path


def test_bridge_functions_are_exposed():
    assert callable(set_runtime_msb_path)
    assert callable(resolved_msb_path)


def test_native_resolver_returns_bundled_path():
    bundled = _msb_path()
    if not bundled.exists():
        pytest.skip("bundled msb not present (wheel not built with binary)")

    expected = os.environ.get("MSB_PATH") or str(bundled)
    assert resolved_msb_path() == expected
    assert os.path.exists(expected)
