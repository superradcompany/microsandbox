"""Restore is a distinct operation, never a create call with an ignored field."""

import pytest

from microsandbox import Network, NetworkPolicy, Sandbox, SecurityProfile


@pytest.mark.parametrize("option", ["image", "network", "cmd", "replace", "detached", "entrypoint"])
def test_restore_rejects_create_options(option):
    with pytest.raises(TypeError, match="unexpected restore option"):
        Sandbox.restore("missing", name="restore-validation", **{option: None})


@pytest.mark.parametrize("option", ["from_snapshot", "forked", "disk_only", "snapshot_base"])
def test_create_rejects_restore_options(option):
    with pytest.raises(TypeError):
        Sandbox.create("restore-validation", image="alpine", **{option: None})


@pytest.mark.asyncio
async def test_restore_missing_artifact_does_not_boot(tmp_path):
    with pytest.raises(FileNotFoundError):
        await Sandbox.restore(tmp_path / "missing", name="restore-validation", forked=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["restore", "restore_with_progress"])
async def test_missing_resource_opt_out_is_restore_only(tmp_path, method):
    with pytest.raises(FileNotFoundError):
        result = getattr(Sandbox, method)(
            tmp_path / "missing", name="restore-opt-out",
            allow_missing_resources=True, external_mount_policy="strict",
        )
        if method == "restore":
            await result
        else:
            await result.result()
    with pytest.raises(TypeError):
        Sandbox.create("fresh", image="alpine", allow_missing_resources=True)


@pytest.mark.asyncio
async def test_restore_accepts_explicit_destination_controls(tmp_path):
    with pytest.raises(FileNotFoundError):
        await Sandbox.restore(
            tmp_path / "missing", name="restore-controls", disk_only=True,
            cpus=2, memory=512, network_policy=NetworkPolicy.none(),
            max_tcp_connections=0, max_udp_connections=7,
            disable_network=True, security=SecurityProfile.DEFAULT, max_duration=0, idle_timeout=0,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["restore", "restore_with_progress"])
@pytest.mark.parametrize("limits", [
    {},
    {"max_tcp_connections": None, "max_udp_connections": None},
    {"max_tcp_connections": 0, "max_udp_connections": 7},
    {"max_tcp_connections": 64, "max_udp_connections": 0},
    {"max_connections": None, "max_tcp_connections": 0},
])
async def test_restore_connection_limits_reach_artifact_validation(tmp_path, method, limits):
    # A missing artifact proves these options reach restore, never fresh creation.
    with pytest.raises(FileNotFoundError):
        result = getattr(Sandbox, method)(tmp_path / "missing", name="restore-limits", **limits)
        if method == "restore":
            await result
        else:
            await result.result()


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["restore", "restore_with_progress"])
async def test_restore_legacy_tcp_alias_warns_and_accepts_udp(tmp_path, method):
    with (
        pytest.warns(DeprecationWarning, match="use max_tcp_connections"),
        pytest.raises(FileNotFoundError),
    ):
        result = getattr(Sandbox, method)(
            tmp_path / "missing", name="restore-limits", max_connections=0, max_udp_connections=7,
        )
        if method == "restore":
            await result
        else:
            await result.result()


@pytest.mark.parametrize("method", ["restore", "restore_with_progress"])
@pytest.mark.parametrize("tcp", [0, 64])
def test_restore_rejects_duplicate_tcp_aliases(method, tcp):
    with pytest.raises(ValueError, match="mutually exclusive"):
        getattr(Sandbox, method)(
            "missing", name="restore-limits", max_connections=0, max_tcp_connections=tcp,
        )


@pytest.mark.parametrize("method", ["restore", "restore_with_progress"])
@pytest.mark.parametrize(
    "option", ["max_connections", "max_tcp_connections", "max_udp_connections"],
)
def test_restore_rejects_negative_connection_limits(method, option):
    with pytest.raises(OverflowError):
        getattr(Sandbox, method)("missing", name="restore-limits", **{option: -1})


def test_restore_policy_rejects_broad_network_configuration():
    with pytest.raises(TypeError):
        Sandbox.restore("missing", name="restore-controls", network_policy=Network.none())


@pytest.mark.parametrize("value", [-1, float("nan"), float("inf")])
@pytest.mark.parametrize("option", ["max_duration", "idle_timeout"])
def test_restore_duration_rejects_invalid_values(option, value):
    with pytest.raises(ValueError):
        Sandbox.restore("missing", name="restore-controls", **{option: value})
