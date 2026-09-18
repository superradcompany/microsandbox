"""Policy spelling and rejection must agree with the native capture API."""

import pytest

from microsandbox import GuestFlush, Snapshot


def test_guest_flush_values():
    assert [str(policy) for policy in GuestFlush] == ["auto", "required", "skip"]


async def test_invalid_flush_is_rejected_before_source_lookup():
    with pytest.raises(ValueError, match="guest flush"):
        await Snapshot.create("invalid", from_sandbox="not-a-sandbox", guest_flush="unknown")
