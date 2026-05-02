"""Snapshot a stopped sandbox, then boot a fresh sandbox from it.

Demonstrates the core v1 disk-snapshot flow:
  1. Stand up a baseline sandbox and customize it.
  2. Stop it.
  3. Snapshot the writable upper layer to a content-addressed
     artifact under ~/.microsandbox/snapshots/<name>/.
  4. Boot a brand-new sandbox from that snapshot — the captured
     filesystem state is the new sandbox's starting point.
"""

import asyncio

from microsandbox import Sandbox, Snapshot


async def main():
    # 1. Stand up a baseline sandbox and customize it.
    baseline = await Sandbox.create(
        "snapshot-baseline",
        image="alpine",
        replace=True,
    )
    # The trailing `sync` flushes the guest's page cache to upper.ext4
    # before the VM halts. Without it the captured snapshot can race
    # ahead of the writes and miss them.
    await baseline.shell("echo 'shipped via snapshot' > /root/marker.txt && sync")

    # 2. Stop it. Snapshots are stopped-only in v1.
    await baseline.stop_and_wait()

    # 3. Snapshot the stopped sandbox via the lookup-by-name handle.
    h = await Sandbox.get("snapshot-baseline")
    snap = await h.snapshot("snapshot-baseline-state")
    print(f"created snapshot: {snap.digest}")
    print(f"                  {snap.path}")

    # 4. Boot a fresh sandbox from the snapshot. The new sandbox
    #    starts with the captured upper layer, so /root/marker.txt
    #    is already present. `snapshot=` is a peer of `image=`.
    fork = await Sandbox.create(
        "snapshot-fork",
        snapshot="snapshot-baseline-state",
        replace=True,
    )
    output = await fork.shell("cat /root/marker.txt")
    print(f"fork sees: {output.stdout_text.strip()}")

    await fork.stop_and_wait()

    # Cleanup.
    await Sandbox.remove("snapshot-baseline")
    await Sandbox.remove("snapshot-fork")
    await Snapshot.remove("snapshot-baseline-state")


asyncio.run(main())
