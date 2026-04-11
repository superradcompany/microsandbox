"""Streaming metrics — subscribe to sandbox resource usage at a regular interval."""

import asyncio

from microsandbox import Sandbox


async def main():
    print("Creating sandbox (image=alpine)")

    sb = await Sandbox.create(
        "metrics-stream",
        image="alpine",
        cpus=1,
        memory=512,
        replace=True,
    )

    # Generate some CPU load in the background.
    await sb.shell("dd if=/dev/urandom of=/dev/null bs=1M count=100 &")

    # Stream metrics every second, print 5 samples.
    count = 0
    async for m in await sb.metrics_stream(interval=1.0):
        print(
            f"[{count}] CPU: {m.cpu_percent:.1f}%, "
            f"Mem: {m.memory_bytes // 1024 // 1024} MB, "
            f"Disk R/W: {m.disk_read_bytes}/{m.disk_write_bytes} bytes"
        )
        count += 1
        if count >= 5:
            break

    print(f"Collected {count} metric samples")

    await sb.stop_and_wait()
    print("Sandbox stopped.")


asyncio.run(main())
