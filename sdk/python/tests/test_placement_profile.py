"""Tests for selecting host-owned placement profiles."""

import pytest

from microsandbox import Sandbox


def test_create_accepts_placement_profile_name() -> None:
    # Keyword validation runs before Sandbox.create needs an event loop. Reaching the loop error
    # proves the profile name crossed the Python boundary without starting a sandbox.
    with pytest.raises(RuntimeError, match="no running event loop"):
        Sandbox.create(
            "placement-profile-probe",
            image="/__microsandbox_missing_rootfs__",
            placement_profile="latency",
        )


def test_create_rejects_non_string_placement_profile() -> None:
    with pytest.raises(TypeError):
        Sandbox.create(
            "placement-profile-probe",
            image="/__microsandbox_missing_rootfs__",
            placement_profile=42,
        )
