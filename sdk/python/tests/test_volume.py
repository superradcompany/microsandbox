"""Tests for volume management."""

import pytest

from microsandbox import Volume


@pytest.mark.asyncio
async def test_volume_create_remove():
    """Test creating and removing a named volume."""
    vol = await Volume.create("test-vol-py")
    try:
        assert vol.name == "test-vol-py"

        handles = await Volume.list()
        names = [h.name for h in handles]
        assert "test-vol-py" in names
    finally:
        await Volume.remove("test-vol-py")


@pytest.mark.asyncio
async def test_volume_get():
    """Test getting a volume handle."""
    await Volume.create("test-vol-get-py")
    try:
        handle = await Volume.get("test-vol-get-py")
        assert handle.name == "test-vol-get-py"
    finally:
        await Volume.remove("test-vol-get-py")


@pytest.mark.asyncio
async def test_volume_mount_bind(sandbox_name):
    """Test bind mount via Volume.bind factory."""
    mount = Volume.bind("/tmp", readonly=True)
    assert mount["bind"] == "/tmp"
    assert mount["readonly"] is True


@pytest.mark.asyncio
async def test_volume_mount_tmpfs():
    """Test tmpfs mount via Volume.tmpfs factory."""
    mount = Volume.tmpfs(size_mib=100)
    assert mount["tmpfs"] is True
    assert mount["size_mib"] == 100


@pytest.mark.asyncio
async def test_volume_mount_named():
    """Test named mount via Volume.named factory."""
    mount = Volume.named("my-data")
    assert mount["named"] == "my-data"
