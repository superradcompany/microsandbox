"""Unit tests for the typed enum string semantics.

These pin the `enum.StrEnum` behavior that the Python 3.10 backport in
`microsandbox.types` must match: members compare equal to their values
and stringify to their values under both `str()` and `format()`.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from microsandbox import (
    BackendKind,
    DiskImageFormat,
    ImageArchiveFormat,
    LogLevel,
    MountConfig,
    MountKind,
    NetworkDestination,
    PatchConfig,
    PortBinding,
    PullPolicy,
    Rlimit,
    RootDisk,
    Sandbox,
    SecurityProfile,
    ViolationPolicy,
    Volume,
    default_backend_kind,
    set_default_backend,
)


def test_enum_members_compare_equal_to_values() -> None:
    assert PullPolicy.IF_MISSING == "if-missing"
    assert LogLevel.INFO == "info"


def test_enum_members_stringify_to_values() -> None:
    assert str(PullPolicy.IF_MISSING) == "if-missing"
    assert f"{PullPolicy.IF_MISSING}" == "if-missing"
    assert format(LogLevel.WARN) == "warn"


def test_native_enum_outputs_are_enum_members() -> None:
    assert isinstance(default_backend_kind(), BackendKind)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("pull_policy", "always"),
        ("log_level", "debug"),
        ("security", "restricted"),
    ],
)
def test_sandbox_create_rejects_raw_enum_strings(field: str, value: str) -> None:
    with pytest.raises(TypeError):
        Sandbox.create("enum-probe", image="alpine", **{field: value})


def test_native_methods_reject_raw_enum_strings() -> None:
    with pytest.raises(TypeError, match="BackendKind"):
        set_default_backend("local")
    with pytest.raises(TypeError, match="VolumeKind"):
        Volume.create("enum-probe", kind="dir")


@pytest.mark.parametrize(
    "operation",
    [
        lambda: MountConfig(kind="bind", bind="/tmp")._to_dict(),
        lambda: RootDisk.disk("disk.raw", format="raw")._to_dict(),
        lambda: PatchConfig(kind="text", path="/tmp/x", content="x")._to_dict(),
        lambda: NetworkDestination(kind="any")._to_dict(),
        lambda: PortBinding(8000, 8000, protocol="tcp")._to_dict(),
        lambda: Rlimit(resource="cpu", soft=1, hard=1)._to_dict(),
        lambda: ViolationPolicy(fallback="block")._to_dict(),
    ],
)
def test_python_config_types_reject_raw_enum_strings(operation: Callable[[], object]) -> None:
    with pytest.raises(TypeError):
        operation()


def test_new_enum_domains_have_canonical_values() -> None:
    assert ImageArchiveFormat.DOCKER.value == "docker"
    assert DiskImageFormat.RAW.value == "raw"
    assert SecurityProfile.RESTRICTED.value == "restricted"
    assert MountKind.NAMED.value == "named"
