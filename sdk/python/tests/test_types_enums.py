"""Unit tests for the typed enum string semantics.

These pin the `enum.StrEnum` behavior that the Python 3.10 backport in
`microsandbox.types` must match: members compare equal to their values
and stringify to their values under both `str()` and `format()`.
"""

from __future__ import annotations

from collections.abc import Callable
from types import MappingProxyType

import pytest

from microsandbox import (
    Action,
    BackendKind,
    ChangeKind,
    DeploymentProfile,
    DiskImageFormat,
    ExecEventType,
    ImageArchiveFormat,
    LogLevel,
    ModificationDisposition,
    MountConfig,
    MountKind,
    NamedVolumeMode,
    Network,
    NetworkDestination,
    NetworkPolicy,
    Patch,
    PatchConfig,
    PlannedChangeKind,
    PortBinding,
    Protocol,
    PullEventType,
    PullPolicy,
    ResourceConvergenceState,
    ResourceKind,
    Rlimit,
    RootDisk,
    Rule,
    Sandbox,
    Secret,
    SecretChangeKind,
    SecurityProfile,
    Stdin,
    StdinMode,
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
        ("deployment_profile", "single-tenant"),
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
    with pytest.raises(TypeError, match="NamedVolumeMode"):
        Volume.named("enum-probe", mode="existing")


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
    assert DeploymentProfile.SINGLE_TENANT.value == "single-tenant"
    assert ImageArchiveFormat.DOCKER.value == "docker"
    assert DiskImageFormat.RAW.value == "raw"
    assert SecurityProfile.RESTRICTED.value == "restricted"
    assert MountKind.NAMED.value == "named"
    assert NamedVolumeMode.ENSURE_EXISTS.value == "ensure-exists"
    assert Stdin.pipe()._mode is StdinMode.PIPE
    assert ExecEventType.STDIN_ERROR.value == "stdin_error"
    assert PullEventType.LAYER_DOWNLOAD_VERIFYING.value == "layer_download_verifying"
    assert PlannedChangeKind.SECRET.value == "secret"
    assert ChangeKind.UPDATED.value == "updated"
    assert SecretChangeKind.HOSTS_UPDATED.value == "hosts updated"
    assert ModificationDisposition.REQUIRES_RESTART.value == "requires restart"
    assert ResourceKind.CPUS.value == "cpus"
    assert ResourceConvergenceState.GUEST_REFUSED.value == "guest-refused"


@pytest.mark.parametrize(
    ("kwargs", "expected_type"),
    [
        ({"volumes": {"/data": {"bind": "/tmp"}}}, "MountConfig"),
        (
            {"patches": [{"kind": "text", "path": "/tmp/x", "content": "x"}]},
            "PatchConfig",
        ),
        (
            {
                "ports": [
                    {
                        "host_port": 8000,
                        "guest_port": 80,
                        "protocol": "tcp",
                    }
                ]
            },
            "PortBinding",
        ),
        ({"network": {"custom_policy": {"default_egress": "deny"}}}, "Network"),
        (
            {
                "secrets": [
                    {
                        "env_var": "API_KEY",
                        "value": "secret",
                        "allow_hosts": ["example.com"],
                    }
                ]
            },
            "SecretEntry",
        ),
    ],
)
def test_native_config_boundaries_reject_raw_dicts(
    kwargs: dict[str, object], expected_type: str
) -> None:
    with pytest.raises(TypeError, match=expected_type):
        Sandbox.create("enum-boundary-probe", image="alpine", **kwargs)


def test_native_config_boundaries_reject_duck_typed_objects() -> None:
    class MountLike:
        def _to_dict(self) -> dict[str, object]:
            return {"bind": "/tmp"}

    class InitLike:
        def _to_dict(self) -> dict[str, object]:
            return {"cmd": "auto"}

    with pytest.raises(TypeError, match="MountConfig"):
        Sandbox.create(
            "enum-boundary-probe",
            image="alpine",
            volumes={"/data": MountLike()},
        )

    with pytest.raises(TypeError, match="init must be str, Mapping"):
        Sandbox.create("enum-boundary-probe", image="alpine", init=InitLike())


def test_native_config_boundaries_accept_concrete_types() -> None:
    # Successful synchronous conversion reaches future construction, which
    # fails outside an asyncio loop. Match a minimal baseline to distinguish
    # that expected failure from a configuration-boundary rejection.
    with pytest.raises(RuntimeError) as baseline:
        Sandbox.create("enum-boundary-baseline", image="alpine")

    with pytest.raises(type(baseline.value)) as concrete:
        Sandbox.create(
            "enum-boundary-concrete",
            image="alpine",
            deployment_profile=DeploymentProfile.SINGLE_TENANT,
            init=MappingProxyType({"cmd": "auto"}),
            volumes={"/data": Volume.bind("/tmp")},
            patches=[Patch.file("/tmp/x", b"\x00\xff")],
            network=Network.none(),
            secrets=[
                Secret.env(
                    "API_KEY",
                    value="secret",
                    allow_hosts=("example.com",),
                )
            ],
        )

    assert str(concrete.value) == str(baseline.value)


def test_sandbox_create_accepts_documented_container_protocols() -> None:
    # Exercise non-dict Mapping and non-list Sequence implementations so the
    # native parser stays aligned with the public create signature.
    with pytest.raises(RuntimeError) as baseline:
        Sandbox.create("container-protocol-baseline", image="alpine")

    with pytest.raises(type(baseline.value)) as accepted:
        Sandbox.create(
            "container-protocols",
            image="alpine",
            env=MappingProxyType({"MODE": "test"}),
            labels=MappingProxyType({"suite": "unit"}),
            scripts=MappingProxyType({"ready": "true"}),
            volumes=MappingProxyType({"/data": Volume.bind("/tmp")}),
            patches=(Patch.file("/tmp/x", b"data"),),
            ports=MappingProxyType({8000: 80}),
            secrets=(
                Secret.env(
                    "API_KEY",
                    value="secret",
                    allow_hosts=("example.com",),
                ),
            ),
        )

    assert str(accepted.value) == str(baseline.value)


def test_sandbox_create_accepts_nested_network_port_bindings() -> None:
    with pytest.raises(RuntimeError) as baseline:
        Sandbox.create("nested-ports-baseline", image="alpine")

    with pytest.raises(type(baseline.value)) as accepted:
        Sandbox.create(
            "nested-ports",
            image="alpine",
            network=Network(ports=(PortBinding.tcp(8000, 80),)),
        )

    assert str(accepted.value) == str(baseline.value)


def test_sandbox_create_treats_explicit_none_as_omitted() -> None:
    with pytest.raises(RuntimeError) as baseline:
        Sandbox.create("explicit-none-baseline", image="alpine")

    with pytest.raises(type(baseline.value)) as accepted:
        Sandbox.create(
            "explicit-none",
            image="alpine",
            env=None,
            labels=None,
            scripts=None,
            registry_auth=None,
            volumes=None,
            patches=None,
            ports=None,
            network=None,
            secrets=None,
        )

    assert str(accepted.value) == str(baseline.value)

    with pytest.raises(ValueError, match="image= or from_snapshot= is required"):
        Sandbox.create("explicit-none-image", image=None)

    with pytest.raises(FileNotFoundError, match="snapshot artifact not found"):
        Sandbox.create(
            "explicit-none-image-with-snapshot",
            image=None,
            from_snapshot="definitely-missing-snapshot",
        )


def test_inactive_mount_enum_fields_are_still_validated() -> None:
    config = MountConfig(
        kind=MountKind.BIND,
        bind="/tmp",
        named_mode=DiskImageFormat.RAW,  # type: ignore[arg-type]
    )

    with pytest.raises(TypeError, match=r"MountConfig\.named_mode"):
        config._to_dict()


def test_wrong_enum_classes_do_not_cross_matching_wire_values() -> None:
    with pytest.raises(TypeError, match=r"Rule\.protocol"):
        Network(
            policy=NetworkPolicy(
                rules=(Rule.allow(protocol=Action.ALLOW),)  # type: ignore[arg-type]
            )
        )._to_dict()

    with pytest.raises(TypeError, match=r"PortBinding\.protocol"):
        PortBinding(8000, 8000, protocol=Protocol.TCP)._to_dict()  # type: ignore[arg-type]
