"""Unit tests for `MountConfig` stat-virt + host-perms policy plumbing.

These tests exercise only the Python dataclass layer; no native binary
required.
"""

from __future__ import annotations

import pytest

from microsandbox import (
    DeploymentProfile,
    DiskImageFormat,
    HostPermissions,
    MountConfig,
    MountKind,
    NamedVolumeMode,
    SecurityProfile,
    StatVirtualization,
    Volume,
    VolumeKind,
)


def test_bind_default_omits_policies() -> None:
    mc = MountConfig(kind=MountKind.BIND, bind="/host/data")
    d = mc._to_dict()
    assert "stat_virtualization" not in d
    assert "host_permissions" not in d
    assert d["bind"] == "/host/data"


def test_bind_rejects_policy_strings() -> None:
    mc = MountConfig(
        kind=MountKind.BIND,
        bind="/host/data",
        readonly=True,
        stat_virtualization="relaxed",
        host_permissions="mirror",
    )
    with pytest.raises(TypeError, match=r"MountConfig\.stat_virtualization"):
        mc._to_dict()


def test_bind_serializes_security_mount_flags() -> None:
    mc = MountConfig(
        kind=MountKind.BIND,
        bind="/host/data",
        nosuid=True,
        nodev=True,
    )
    d = mc._to_dict()
    assert d["nosuid"] is True
    assert d["nodev"] is True


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


def test_bind_owner_serializes() -> None:
    mc = MountConfig(
        kind=MountKind.BIND,
        bind="/host/data",
        override_uid=1000,
        override_gid=1000,
    )
    d = mc._to_dict()
    assert d["override_uid"] == 1000
    assert d["override_gid"] == 1000


def test_bind_owner_omitted_when_unset() -> None:
    d = MountConfig(kind=MountKind.BIND, bind="/host/data")._to_dict()
    assert "override_uid" not in d
    assert "override_gid" not in d


def test_owner_must_be_paired() -> None:
    mc = MountConfig(kind=MountKind.BIND, bind="/host/data", override_uid=1000)
    with pytest.raises(ValueError, match="together"):
        mc._to_dict()


def test_owner_rejected_on_tmpfs() -> None:
    mc = MountConfig(kind=MountKind.TMPFS, override_uid=1000, override_gid=1000)
    with pytest.raises(ValueError, match="BIND/NAMED"):
        mc._to_dict()


@pytest.mark.parametrize("value", [True, -1, 1.5, 2**32, "1000"])
def test_owner_rejects_invalid_python_values(value: object) -> None:
    mc = MountConfig(
        kind=MountKind.BIND,
        bind="/host/data",
        override_uid=value,  # type: ignore[arg-type]
        override_gid=1000,
    )
    with pytest.raises(ValueError, match="integer between"):
        mc._to_dict()


def test_owner_rejects_stat_virtualization_off() -> None:
    mc = MountConfig(
        kind=MountKind.BIND,
        bind="/host/data",
        stat_virtualization=StatVirtualization.OFF,
        override_uid=1000,
        override_gid=1000,
    )
    with pytest.raises(ValueError, match="cannot be combined"):
        mc._to_dict()


def test_owner_rejects_explicit_named_disk() -> None:
    mc = MountConfig(
        kind=MountKind.NAMED,
        named="disk-volume",
        named_kind=VolumeKind.DISK,
        override_uid=1000,
        override_gid=1000,
    )
    with pytest.raises(ValueError, match="disk-backed"):
        mc._to_dict()


def test_volume_factories_forward_mount_metadata_policies() -> None:
    bind = Volume.bind(
        "/host/data",
        stat_virtualization=StatVirtualization.RELAXED,
        host_permissions=HostPermissions.MIRROR,
        uid=0,
        gid=0,
    )
    assert bind._to_dict()["stat_virtualization"] == "relaxed"
    assert bind._to_dict()["host_permissions"] == "mirror"
    assert bind._to_dict()["override_uid"] == 0
    assert bind._to_dict()["override_gid"] == 0

    named = Volume.named("cache", uid=1000, gid=1000)
    assert named._to_dict()["override_uid"] == 1000
    assert named._to_dict()["override_gid"] == 1000


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


def test_inactive_named_mode_is_validated_before_mount_dispatch() -> None:
    mc = MountConfig(
        kind=MountKind.BIND,
        bind="/host/data",
        named_mode="existing",  # type: ignore[arg-type]
    )

    with pytest.raises(TypeError, match=r"MountConfig\.named_mode"):
        mc._to_dict()


def test_named_mode_uses_canonical_enum_name() -> None:
    mc = MountConfig(
        kind=MountKind.NAMED,
        named="my-vol",
        named_mode=NamedVolumeMode.ENSURE_EXISTS,
    )

    assert mc._to_dict()["named_mode"] == "ensure-exists"


def test_stat_virtualization_str_values() -> None:
    assert StatVirtualization.STRICT.value == "strict"
    assert StatVirtualization.RELAXED.value == "relaxed"
    assert StatVirtualization.OFF.value == "off"


def test_host_permissions_str_values() -> None:
    assert HostPermissions.PRIVATE.value == "private"
    assert HostPermissions.MIRROR.value == "mirror"


def test_security_profile_str_values() -> None:
    assert SecurityProfile.DEFAULT.value == "default"
    assert SecurityProfile.RESTRICTED.value == "restricted"


def test_deployment_profile_str_values() -> None:
    assert DeploymentProfile.SINGLE_TENANT.value == "single-tenant"
    assert DeploymentProfile.MULTI_TENANT.value == "multi-tenant"
