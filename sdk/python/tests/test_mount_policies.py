"""Unit tests for `MountConfig` stat-virt + host-perms policy plumbing.

These tests exercise only the Python dataclass layer; no native binary
required.
"""

from __future__ import annotations

import json
from pathlib import Path

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


def _hide_path_fixture_cases() -> list[dict]:
    """Load the shared cross-SDK hide_path-pattern disposition fixture.

    Anchor to the workspace root (the nearest ancestor ``Cargo.toml`` declaring
    ``[workspace]``) and resolve the fixture from there, so a nested checkout
    with its own copy cannot be picked up and the path has a single definition.
    """
    relative = Path("packages/microsandbox-types/rust/tests/fixtures/hide_path/patterns.json")
    for directory in Path(__file__).resolve().parents:
        manifest = directory / "Cargo.toml"
        if manifest.is_file() and "[workspace]" in manifest.read_text():
            fixture = directory / relative
            if not fixture.is_file():
                raise AssertionError(f"shared hide-path fixture missing at {fixture}")
            return json.loads(fixture.read_text())
    raise AssertionError("workspace root (Cargo.toml with [workspace]) not found")


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


def test_bind_serializes_hide_path() -> None:
    mc = MountConfig(
        kind=MountKind.BIND,
        bind="/host/data",
        readonly=True,
        hide_path=[".env", "sub/secret"],
    )
    d = mc._to_dict()
    assert d["hide_path"] == [".env", "sub/secret"]


def test_writable_bind_rejects_path_hide_path_pattern() -> None:
    mc = MountConfig(kind=MountKind.BIND, bind="/host/data", hide_path=["sub/secret"])
    with pytest.raises(ValueError, match="is a path pattern"):
        mc._to_dict()


def test_writable_bind_accepts_name_and_dir_only_hide_path() -> None:
    mc = MountConfig(kind=MountKind.BIND, bind="/host/data", hide_path=[".env", "node_modules/"])
    assert mc._to_dict()["hide_path"] == [".env", "node_modules/"]


def test_bind_omits_hide_path_when_empty_or_none() -> None:
    assert "hide_path" not in MountConfig(kind=MountKind.BIND, bind="/host/data")._to_dict()
    mount = MountConfig(kind=MountKind.BIND, bind="/host/data", hide_path=[])
    assert "hide_path" not in mount._to_dict()


def test_non_bind_rejects_hide_path() -> None:
    for kind, kw in (
        (MountKind.NAMED, {"named": "vol"}),
        (MountKind.TMPFS, {"size_mib": 64}),
        (MountKind.DISK, {"disk": "/host/d.qcow2"}),
    ):
        mc = MountConfig(kind=kind, hide_path=[".env"], **kw)  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="hide_path is only valid for BIND"):
            mc._to_dict()


def test_volume_bind_accepts_hide_path() -> None:
    mc = Volume.bind("/host/data", hide_path=[".env", "secret"])
    d = mc._to_dict()
    assert d["bind"] == "/host/data"
    assert d["hide_path"] == [".env", "secret"]


def test_volume_bind_omits_hide_path_when_unset() -> None:
    d = Volume.bind("/host/data")._to_dict()
    assert "hide_path" not in d


def test_apply_mount_contract_carries_hide_path() -> None:
    mc = MountConfig(kind=MountKind.BIND, bind="/host/data", hide_path=[".env"])
    d = mc._to_dict()
    # apply_mount reads "hide_path" from this dict; the value must round-trip.
    assert d["bind"] == "/host/data"
    assert d["hide_path"] == [".env"]


def test_mountconfig_positional_order_unchanged() -> None:
    # `hide_path` was appended after every pre-existing field, so the 19th positional
    # argument is still `owned_kind` (not `hide_path`).
    m = MountConfig(
        MountKind.OWNED,  # kind
        None,  # bind
        None,  # named
        None,  # named_mode
        None,  # named_kind
        None,  # quota_mib
        None,  # size_mib
        False,  # readonly
        False,  # noexec
        False,  # nosuid
        False,  # nodev
        None,  # disk
        None,  # format
        None,  # fstype
        None,  # stat_virtualization
        None,  # host_permissions
        None,  # override_uid
        None,  # override_gid
        VolumeKind.DIRECTORY,  # owned_kind
    )
    assert m.owned_kind == VolumeKind.DIRECTORY
    assert m.hide_path is None


def test_mountconfig_rejects_wire_separators() -> None:
    for bad in ["a,b", "a:b", "a\nb", "a\x00b"]:
        mc = MountConfig(kind=MountKind.BIND, bind="/host/data", hide_path=[bad])
        with pytest.raises(ValueError, match="must not contain"):
            mc._to_dict()


def test_mountconfig_rejects_leading_hash() -> None:
    mc = MountConfig(kind=MountKind.BIND, bind="/host/data", hide_path=["#secret"])
    with pytest.raises(ValueError, match="must not start with '#'"):
        mc._to_dict()
    # An escaped literal `#` stays valid.
    assert MountConfig(kind=MountKind.BIND, bind="/host/data", hide_path=["\\#x"])._to_dict()[
        "hide_path"
    ] == ["\\#x"]


def test_mountconfig_rejects_surrounding_whitespace() -> None:
    for bad in [" .env", ".env ", " !secret"]:
        mc = MountConfig(kind=MountKind.BIND, bind="/host/data", hide_path=[bad])
        with pytest.raises(ValueError, match="leading or trailing whitespace"):
            mc._to_dict()


def test_mountconfig_rejects_empty_pattern() -> None:
    mc = MountConfig(kind=MountKind.BIND, bind="/host/data", hide_path=[""])
    with pytest.raises(ValueError, match="must not be empty"):
        mc._to_dict()


def test_mountconfig_rejects_non_canonical_patterns() -> None:
    for bad in ["./secret", "//secret", "a//b", "!", ".", "..", "a/./b", "a/../b"]:
        mc = MountConfig(kind=MountKind.BIND, bind="/host/data", hide_path=[bad], readonly=True)
        with pytest.raises(ValueError):
            mc._to_dict()


def test_mountconfig_accepts_non_canonical_lookalikes() -> None:
    # Read-only so path-shaped lookalikes stay valid at the pattern level.
    for ok in ["..foo", "...", "a/..foo/b", "!keep.txt", "node_modules/"]:
        mc = MountConfig(kind=MountKind.BIND, bind="/host/data", hide_path=[ok], readonly=True)
        assert mc._to_dict()["hide_path"] == [ok]


def test_mountconfig_rejects_hide_path_on_non_bind() -> None:
    # _to_dict is the boundary that produces the dict apply_mount consumes; any
    # hide_path on a non-bind arm must be rejected here, never silently dropped.
    # (The native apply_mount guard for hand-built dicts is covered by
    # sdk/python/tests/test_mount_hide_path_native.py.)
    for kind, kw in (
        (MountKind.NAMED, {"named": "vol"}),
        (MountKind.OWNED, {"owned_kind": VolumeKind.DIRECTORY}),
    ):
        mc = MountConfig(kind=kind, hide_path=[".env"], **kw)  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="hide_path is only valid for BIND"):
            mc._to_dict()


def test_hide_path_pattern_fixture_dispositions_match_mountconfig_boundary() -> None:
    cases = _hide_path_fixture_cases()
    assert cases, "fixture must not be empty"

    for case in cases:
        mc = MountConfig(
            kind=MountKind.BIND,
            bind="/host/data",
            readonly=case["readonly"],
            hide_path=[case["pattern"]],
        )
        expect = case["expect"]
        if expect == "accept":
            mc._to_dict()
        elif expect == "reject":
            with pytest.raises(ValueError):
                mc._to_dict()
        else:
            raise AssertionError(f"unknown fixture expectation {expect!r}")
