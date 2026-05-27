"""Sandbox filesystem integration tests."""

from __future__ import annotations

import pytest

from microsandbox import FilesystemError


@pytest.mark.asyncio
async def test_fs_file_directory_and_metadata_operations(sandbox_factory):
    sandbox = await sandbox_factory("py-sdk-fs")
    fs = sandbox.fs

    await fs.mkdir("/tmp/py-sdk")
    await fs.write("/tmp/py-sdk/a.txt", b"alpha\n")
    assert await fs.read("/tmp/py-sdk/a.txt") == b"alpha\n"
    assert await fs.read_text("/tmp/py-sdk/a.txt") == "alpha\n"
    assert await fs.exists("/tmp/py-sdk/a.txt") is True
    assert await fs.exists("/tmp/py-sdk/missing.txt") is False

    metadata = await fs.stat("/tmp/py-sdk/a.txt")
    assert metadata.kind == "file"
    assert metadata.size == len(b"alpha\n")
    assert isinstance(metadata.readonly, bool)

    entries = await fs.list("/tmp/py-sdk")
    assert any(entry.path.endswith("a.txt") and entry.kind == "file" for entry in entries)

    await fs.copy("/tmp/py-sdk/a.txt", "/tmp/py-sdk/b.txt")
    assert await fs.read_text("/tmp/py-sdk/b.txt") == "alpha\n"

    await fs.rename("/tmp/py-sdk/b.txt", "/tmp/py-sdk/c.txt")
    assert await fs.exists("/tmp/py-sdk/b.txt") is False
    assert await fs.read_text("/tmp/py-sdk/c.txt") == "alpha\n"

    await fs.remove("/tmp/py-sdk/c.txt")
    await fs.remove("/tmp/py-sdk/a.txt")
    await fs.remove_dir("/tmp/py-sdk")
    assert await fs.exists("/tmp/py-sdk") is False

    with pytest.raises(FilesystemError):
        await fs.read("/tmp/py-sdk/missing.txt")


@pytest.mark.asyncio
async def test_fs_streams_and_host_copy_roundtrip(sandbox_factory, tmp_path):
    sandbox = await sandbox_factory("py-sdk-fs-stream")
    fs = sandbox.fs

    async with await fs.write_stream("/tmp/stream.txt") as sink:
        await sink.write(b"hello ")
        await sink.write(b"stream\n")

    read_stream = await fs.read_stream("/tmp/stream.txt")
    assert await read_stream.collect() == b"hello stream\n"

    await fs.write("/tmp/iter.txt", b"chunked\n")
    iter_stream = await fs.read_stream("/tmp/iter.txt")
    chunks = [chunk async for chunk in iter_stream]
    assert b"".join(chunks) == b"chunked\n"

    host_src = tmp_path / "host-src.txt"
    host_dst = tmp_path / "host-dst.txt"
    host_src.write_text("from-host\n", encoding="utf-8")

    await fs.copy_from_host(str(host_src), "/tmp/from-host.txt")
    assert await fs.read_text("/tmp/from-host.txt") == "from-host\n"

    await fs.copy_to_host("/tmp/from-host.txt", str(host_dst))
    assert host_dst.read_text(encoding="utf-8") == "from-host\n"
