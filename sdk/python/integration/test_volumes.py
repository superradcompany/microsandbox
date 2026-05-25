"""Volume integration tests."""

from __future__ import annotations

import pytest

from microsandbox import Volume


@pytest.mark.asyncio
async def test_volume_lifecycle_metadata_and_host_fs(volume_factory):
    volume = await volume_factory("py-sdk-vol", quota_mib=64, labels={"team": "python"})
    handle = await Volume.get(volume.name)

    assert handle.name == volume.name
    assert handle.quota_mib == 64
    assert handle.labels["team"] == "python"
    assert handle.created_at is not None
    assert handle.used_bytes >= 0

    volumes = await Volume.list()
    assert any(item.name == volume.name for item in volumes)

    fs = handle.fs
    await fs.mkdir("nested")
    await fs.write("nested/greeting.txt", b"hello-volume\n")
    assert await fs.exists("nested/greeting.txt") is True
    assert await fs.read_text("nested/greeting.txt") == "hello-volume\n"
    entries = await fs.list("nested")
    assert any(entry.path.endswith("greeting.txt") for entry in entries)
    await fs.remove_file("nested/greeting.txt")
    assert await fs.exists("nested/greeting.txt") is False


@pytest.mark.asyncio
async def test_named_volume_mount_into_sandbox(volume_factory, sandbox_factory):
    volume = await volume_factory("py-sdk-named-vol")
    handle = await Volume.get(volume.name)
    await handle.fs.write("greeting.txt", b"hello-from-host-volume\n")

    sandbox = await sandbox_factory(
        "py-sdk-vol-mount",
        volumes={"/data": Volume.named(volume.name)},
    )
    out = await sandbox.shell("cat /data/greeting.txt")
    assert out.success is True
    assert out.stdout_text == "hello-from-host-volume\n"


@pytest.mark.asyncio
async def test_tmpfs_mount_enforces_size_limit(sandbox_factory):
    sandbox = await sandbox_factory(
        "py-sdk-tmpfs",
        volumes={"/scratch": Volume.tmpfs(size_mib=4)},
    )

    small = await sandbox.shell(
        "dd if=/dev/zero of=/scratch/small bs=1M count=1 status=none && echo small-ok",
        timeout=30.0,
    )
    assert small.success is True
    assert small.stdout_text == "small-ok\n"

    too_large = await sandbox.shell(
        "dd if=/dev/zero of=/scratch/big bs=1M count=8 status=none 2>&1; echo done",
        timeout=30.0,
    )
    assert too_large.success is True
    assert "No space left" in too_large.stdout_text
