"""Disk image volume example — attach raw and qcow2 host images at guest paths."""

import asyncio
import os

from microsandbox import DiskImageFormat, Sandbox, Volume


async def main():
    data_dir = os.path.realpath(
        os.path.join(os.path.dirname(__file__), "..", "..", "volume-disk-data")
    )
    raw_path = os.path.join(data_dir, "ext4-seeded.raw")
    qcow2_path = os.path.join(data_dir, "ext4-seeded.qcow2")

    print("Mounting:")
    print(f"  /seed (raw, ro) <- {raw_path}")
    print(f"  /data (qcow2, rw) <- {qcow2_path}")

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

    # Verify the read-only seed mount.
    print("\n=== /seed (read-only) ===")
    listing = await sb.shell("ls -la /seed")
    print(listing.stdout_text, end="")

    hello = await sb.shell("cat /seed/hello.txt")
    print(f"hello.txt: {hello.stdout_text.strip()}")

    release = await sb.shell("cat /seed/notes/release.txt")
    print(f"notes/release.txt: {release.stdout_text.strip()}")

    manifest = await sb.shell("cat /seed/lib/data.json")
    print(f"lib/data.json:\n{manifest.stdout_text}")

    # Confirm writes are blocked on the read-only mount.
    blocked = await sb.shell("touch /seed/should-fail 2>&1 || true")
    print(f"attempted /seed write -> {blocked.stdout_text.strip()}")

    # Demonstrate writes to the writable qcow2 mount.
    print("\n=== /data (read-write) ===")
    await sb.shell("echo 'written from inside the sandbox' > /data/created.txt")
    readback = await sb.shell("cat /data/created.txt")
    print(f"created.txt: {readback.stdout_text.strip()}")

    qcow_hello = await sb.shell("cat /data/hello.txt")
    print(f"hello.txt: {qcow_hello.stdout_text.strip()}")

    await sb.stop_and_wait()
    print("\nSandbox stopped.")


asyncio.run(main())
