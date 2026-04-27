"""Disk image volume example — attach raw and qcow2 host images at guest paths."""

import asyncio
import os

from microsandbox import DiskImageFormat, Sandbox, Volume


async def main():
    data_dir = os.path.realpath(
        os.path.join(os.path.dirname(__file__), "sample-images")
    )
    raw_path = os.path.join(data_dir, "ext4-seeded.raw")
    qcow2_path = os.path.join(data_dir, "ext4-seeded.qcow2")

    sb = await Sandbox.create(
        "volume-disk",
        image="alpine",
        volumes={
            "/seed": Volume.disk(
                raw_path, format=DiskImageFormat.RAW, fstype="ext4", readonly=True
            ),
            "/data": Volume.disk(
                qcow2_path, format=DiskImageFormat.QCOW2, fstype="ext4"
            ),
        },
        replace=True,
    )

    seed = await sb.shell("cat /seed/hello.txt")
    print(seed.stdout_text)

    await sb.shell("echo 'written from sandbox' > /data/created.txt")
    back = await sb.shell("cat /data/created.txt")
    print(back.stdout_text)

    await sb.stop_and_wait()


asyncio.run(main())
