"""Streaming file read — create a file in the sandbox and stream it back in chunks."""

import asyncio

from microsandbox import Sandbox

FILE_SIZE = 10 * 1024 * 1024  # 10 MiB


async def main():
    print("Creating sandbox (image=alpine)")

    sb = await Sandbox.create(
        "fs-read-stream",
        image="alpine",
        cpus=1,
        memory=512,
        replace=True,
    )

    # Create a 10 MiB file with random data inside the sandbox.
    await sb.shell("dd if=/dev/urandom of=/tmp/data.bin bs=1M count=10")

    # Stream the file back in chunks.
    stream = await sb.fs.read_stream("/tmp/data.bin")
    total_bytes = 0
    chunk_count = 0

    async for chunk in stream:
        chunk_count += 1
        total_bytes += len(chunk)
        print(f"Chunk {chunk_count}: {len(chunk)} bytes")

    print(f"Done — {chunk_count} chunks, {total_bytes} bytes total")
    assert total_bytes == FILE_SIZE, f"expected {FILE_SIZE} bytes, got {total_bytes}"

    await sb.stop_and_wait()
    print("Sandbox stopped.")


asyncio.run(main())
