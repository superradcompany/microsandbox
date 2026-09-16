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
async def test_restore_accepts_explicit_destination_controls(tmp_path):
    with pytest.raises(FileNotFoundError):
        await Sandbox.restore(
            tmp_path / "missing", name="restore-controls", disk_only=True,
            cpus=2, memory=512, network_policy=NetworkPolicy.none(), max_connections=0,
            disable_network=True, security=SecurityProfile.DEFAULT, max_duration=0, idle_timeout=0,
        )


def test_restore_policy_rejects_broad_network_configuration():
    with pytest.raises(TypeError):
        Sandbox.restore("missing", name="restore-controls", network_policy=Network.none())


@pytest.mark.parametrize("value", [-1, float("nan"), float("inf")])
@pytest.mark.parametrize("option", ["max_duration", "idle_timeout"])
def test_restore_duration_rejects_invalid_values(option, value):
    with pytest.raises(ValueError):
        Sandbox.restore("missing", name="restore-controls", **{option: value})
