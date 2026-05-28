"""Unit tests for `MountConfig` stat-virt + host-perms policy plumbing.

These tests exercise only the Python dataclass layer; no native binary
required.
"""

from __future__ import annotations

import pytest

from microsandbox import (
    DiskImageFormat,
    HostPermissions,
    MountConfig,
    MountKind,
    StatVirtualization,
)


def test_bind_default_omits_policies() -> None:
    mc = MountConfig(kind=MountKind.BIND, bind="/host/data")
    d = mc._to_dict()
    assert "stat_virtualization" not in d
    assert "host_permissions" not in d
    assert d["bind"] == "/host/data"


def test_bind_accepts_policy_strings() -> None:
    mc = MountConfig(
        kind=MountKind.BIND,
        bind="/host/data",
        readonly=True,
        stat_virtualization="relaxed",
        host_permissions="mirror",
    )
    assert mc._to_dict() == {
        "readonly": True,
        "noexec": False,
        "bind": "/host/data",
        "stat_virtualization": "relaxed",
        "host_permissions": "mirror",
    }


def test_bind_with_relaxed_and_mirror_serializes_lowercase() -> None:
    mc = MountConfig(
        kind=MountKind.BIND,
        bind="/host/data",
        stat_virtualization=StatVirtualization.RELAXED,
        host_permissions=HostPermissions.MIRROR,
    )
    d = mc._to_dict()
    assert d["stat_virtualization"] == "relaxed"
    assert d["host_permissions"] == "mirror"


def test_named_with_off_serializes() -> None:
    mc = MountConfig(
        kind=MountKind.NAMED,
        named="my-vol",
        stat_virtualization=StatVirtualization.OFF,
    )
    d = mc._to_dict()
    assert d["named"] == "my-vol"
    assert d["stat_virtualization"] == "off"
    assert "host_permissions" not in d


def test_tmpfs_rejects_stat_virt_at_serialization() -> None:
    mc = MountConfig(
        kind=MountKind.TMPFS,
        size_mib=64,
        stat_virtualization=StatVirtualization.RELAXED,
    )
    with pytest.raises(ValueError, match="only valid for BIND/NAMED"):
        mc._to_dict()


def test_tmpfs_rejects_host_perms_at_serialization() -> None:
    mc = MountConfig(
        kind=MountKind.TMPFS,
        host_permissions=HostPermissions.MIRROR,
    )
    with pytest.raises(ValueError, match="only valid for BIND/NAMED"):
        mc._to_dict()


def test_disk_rejects_stat_virt_at_serialization() -> None:
    mc = MountConfig(
        kind=MountKind.DISK,
        disk="/host/data.qcow2",
        format=DiskImageFormat.QCOW2,
        stat_virtualization=StatVirtualization.OFF,
    )
    with pytest.raises(ValueError, match="only valid for BIND/NAMED"):
        mc._to_dict()


def test_stat_virtualization_str_values() -> None:
    assert StatVirtualization.STRICT.value == "strict"
    assert StatVirtualization.RELAXED.value == "relaxed"
    assert StatVirtualization.OFF.value == "off"


def test_host_permissions_str_values() -> None:
    assert HostPermissions.PRIVATE.value == "private"
    assert HostPermissions.MIRROR.value == "mirror"
