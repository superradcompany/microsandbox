"""Snapshot a stopped sandbox, then boot a fresh sandbox from it."""

import asyncio

from microsandbox import Sandbox, Snapshot


async def main():
    baseline = await Sandbox.create(
        "snapshot-baseline",
        image="alpine",
        replace=True,
    )
    # `sync` flushes the guest page cache before halt; otherwise the
    # snapshot can race ahead of the writes.
    await baseline.shell("echo 'shipped via snapshot' > /root/marker.txt && sync")

    # Snapshots are stopped-only.
    await baseline.stop_and_wait()

    h = await Sandbox.get("snapshot-baseline")
    snap = await h.snapshot("snapshot-baseline-state")
    print(f"created snapshot: {snap.digest}")
    print(f"                  {snap.path}")

    # `snapshot=` is a peer of `image=`; the fork starts with the captured
    # upper layer in place.
    fork = await Sandbox.create(
        "snapshot-fork",
        snapshot="snapshot-baseline-state",
        replace=True,
    )
    output = await fork.shell("cat /root/marker.txt")
    print(f"fork sees: {output.stdout_text.strip()}")

    await fork.stop_and_wait()

    await Sandbox.remove("snapshot-baseline")
    await Sandbox.remove("snapshot-fork")
    await Snapshot.remove("snapshot-baseline-state")


asyncio.run(main())
