"""Owned storage must cross the native boundary without a legacy source."""

import pytest

from microsandbox import HostPermissions, MountConfig, MountKind, Volume, VolumeKind


def test_owned_directory_has_an_exclusive_wire_selector() -> None:
    mount = MountConfig(kind=MountKind.OWNED, quota_mib=512, override_uid=0, override_gid=0)
    wire = mount._to_dict()
    assert wire["owned"] == "dir"
    assert wire["quota_mib"] == 512
    assert wire["override_uid"] == wire["override_gid"] == 0
    assert not {"named", "bind", "tmpfs", "disk"}.intersection(wire)


def test_owned_disk_preserves_capacity_and_mount_flags() -> None:
    wire = MountConfig(
        kind=MountKind.OWNED, owned_kind=VolumeKind.DISK,
        size_mib=10240, noexec=True, nosuid=True, nodev=True,
    )._to_dict()
    assert wire["owned"] == "disk"
    assert wire["size_mib"] == 10240
    assert wire["noexec"] and wire["nosuid"] and wire["nodev"]
    assert not {"named", "bind", "tmpfs", "disk"}.intersection(wire)


@pytest.mark.parametrize("source", ["bind", "named", "disk", "fstype"])
def test_owned_rejects_conflicting_sources(source: str) -> None:
    with pytest.raises(ValueError, match="cannot specify"):
        MountConfig(kind=MountKind.OWNED, **{source: "other"})._to_dict()


@pytest.mark.parametrize("size", [None, 0, -1, True, 1.5, 2**32])
def test_owned_disk_requires_an_exact_positive_capacity(size: object) -> None:
    with pytest.raises(ValueError):
        MountConfig(
            kind=MountKind.OWNED, owned_kind=VolumeKind.DISK, size_mib=size,
        )._to_dict()


def test_owned_rejects_settings_for_the_other_storage_kind() -> None:
    with pytest.raises(ValueError, match="size_mib is only valid"):
        MountConfig(kind=MountKind.OWNED, size_mib=64)._to_dict()
    with pytest.raises(ValueError, match="quota_mib is only valid"):
        MountConfig(
            kind=MountKind.OWNED, owned_kind=VolumeKind.DISK, size_mib=64, quota_mib=0,
        )._to_dict()
    with pytest.raises(ValueError, match="metadata policies"):
        MountConfig(
            kind=MountKind.OWNED, owned_kind=VolumeKind.DISK,
            size_mib=64, host_permissions=HostPermissions.PRIVATE,
        )._to_dict()


def test_owned_kind_cannot_be_ignored_on_a_legacy_mount() -> None:
    with pytest.raises(ValueError, match="only valid for OWNED"):
        MountConfig(
            kind=MountKind.NAMED, named="other", owned_kind=VolumeKind.DIRECTORY,
        )._to_dict()


def test_owned_factory_forwards_storage_and_owner() -> None:
    directory = Volume.owned(quota_mib=512, uid=1000, gid=1000)._to_dict()
    assert directory["owned"] == "dir"
    assert directory["quota_mib"] == 512
    assert directory["override_uid"] == directory["override_gid"] == 1000
    disk = Volume.owned(kind=VolumeKind.DISK, size_mib=10240)._to_dict()
    assert disk["owned"] == "disk" and disk["size_mib"] == 10240


def test_owned_factory_rejects_bool_capacity() -> None:
    with pytest.raises(ValueError, match="integer between"):
        Volume.owned(kind=VolumeKind.DISK, size_mib=True)
