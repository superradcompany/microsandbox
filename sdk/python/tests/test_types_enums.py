"""Unit tests for the typed enum string semantics.

These pin the `enum.StrEnum` behavior that the Python 3.10 backport in
`microsandbox.types` must match: members compare equal to their values
and stringify to their values under both `str()` and `format()`.
"""

from __future__ import annotations

from microsandbox import LogLevel, PullPolicy


def test_enum_members_compare_equal_to_values() -> None:
    assert PullPolicy.IF_MISSING == "if-missing"
    assert LogLevel.INFO == "info"


def test_enum_members_stringify_to_values() -> None:
    assert str(PullPolicy.IF_MISSING) == "if-missing"
    assert f"{PullPolicy.IF_MISSING}" == "if-missing"
    assert format(LogLevel.WARN) == "warn"
