"""Tests for sandbox filesystem operations."""

import pytest

from microsandbox import Sandbox


@pytest.mark.asyncio
async def test_fs_write_read(sandbox_name):
    """Test writing and reading a file inside the sandbox."""
    async with await Sandbox.create(sandbox_name, image="alpine", replace=True) as sb:
        await sb.fs.write("/tmp/test.txt", b"hello world")
        content = await sb.fs.read_text("/tmp/test.txt")
        assert content == "hello world"


@pytest.mark.asyncio
async def test_fs_read_bytes(sandbox_name):
    """Test reading a file as bytes."""
    async with await Sandbox.create(sandbox_name, image="alpine", replace=True) as sb:
        await sb.fs.write("/tmp/data.bin", b"\x00\x01\x02\x03")
        data = await sb.fs.read("/tmp/data.bin")
        assert data == b"\x00\x01\x02\x03"


@pytest.mark.asyncio
async def test_fs_list(sandbox_name):
    """Test listing directory contents."""
    async with await Sandbox.create(sandbox_name, image="alpine", replace=True) as sb:
        entries = await sb.fs.list("/")
        paths = [e.path for e in entries]
        assert any("etc" in p for p in paths)


@pytest.mark.asyncio
async def test_fs_mkdir_exists_remove(sandbox_name):
    """Test creating, checking, and removing a directory."""
    async with await Sandbox.create(sandbox_name, image="alpine", replace=True) as sb:
        await sb.fs.mkdir("/tmp/testdir")
        assert await sb.fs.exists("/tmp/testdir")
        await sb.fs.remove_dir("/tmp/testdir")
        assert not await sb.fs.exists("/tmp/testdir")


@pytest.mark.asyncio
async def test_fs_stat(sandbox_name):
    """Test getting file metadata."""
    async with await Sandbox.create(sandbox_name, image="alpine", replace=True) as sb:
        await sb.fs.write("/tmp/stat-test.txt", b"content")
        meta = await sb.fs.stat("/tmp/stat-test.txt")
        assert meta.kind == "file"
        assert meta.size == 7


@pytest.mark.asyncio
async def test_fs_read_stream(sandbox_name):
    """Test streaming file read."""
    async with await Sandbox.create(sandbox_name, image="alpine", replace=True) as sb:
        await sb.fs.write("/tmp/stream.txt", b"chunk1chunk2chunk3")
        chunks = []
        stream = await sb.fs.read_stream("/tmp/stream.txt")
        async for chunk in stream:
            chunks.append(chunk)
        assert b"".join(chunks) == b"chunk1chunk2chunk3"


@pytest.mark.asyncio
async def test_fs_copy_rename(sandbox_name):
    """Test copy and rename operations."""
    async with await Sandbox.create(sandbox_name, image="alpine", replace=True) as sb:
        await sb.fs.write("/tmp/original.txt", b"original")
        await sb.fs.copy("/tmp/original.txt", "/tmp/copied.txt")
        assert await sb.fs.exists("/tmp/copied.txt")
        content = await sb.fs.read_text("/tmp/copied.txt")
        assert content == "original"

        await sb.fs.rename("/tmp/copied.txt", "/tmp/renamed.txt")
        assert await sb.fs.exists("/tmp/renamed.txt")
        assert not await sb.fs.exists("/tmp/copied.txt")
