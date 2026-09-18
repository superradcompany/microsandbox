// Snapshot a stopped sandbox, then boot a fresh sandbox from it.
//
// Demonstrates the disk-snapshot flow:
//   1. Stand up a baseline sandbox and customize it.
//   2. Stop it.
//   3. Save a disk snapshot in the source sandbox's snapshot group.
//   4. Boot a brand-new sandbox from that snapshot — the captured
//      filesystem state is the new sandbox's starting point.

import { Sandbox, Snapshot } from "microsandbox";

// 1. Stand up a baseline sandbox and customize it.
{
  await using baseline = await Sandbox.builder("snapshot-baseline")
    .image("alpine")
    .replace()
    .create();
  // The trailing `sync` flushes the guest's page cache to upper.ext4
  // before the VM halts. Without it the captured snapshot can race
  // ahead of the writes and miss them.
  await baseline.shell("echo 'shipped via snapshot' > /root/marker.txt && sync");
  // 2. Stop this example's source before capture.
}

// 3. Snapshot the stopped sandbox via the lookup-by-name handle.
const h = await Sandbox.get("snapshot-baseline");
const snap = await h.snapshot("snapshot-baseline-state");
console.log(`created snapshot: ${snap.digest}`);
console.log(`                  ${snap.path}`);

// 4. Boot a fresh sandbox from the snapshot. The new sandbox starts
//    with the captured upper layer, so /root/marker.txt is already
//    present.
{
  const fork = await Sandbox.restore(snap.path)
    .name("snapshot-fork")
    .restore();
  const out = (await fork.shell("cat /root/marker.txt")).stdout();
  console.log(`fork sees: ${out.trim()}`);
  await fork.stop();
}

// Cleanup.
await Sandbox.remove("snapshot-baseline");
await Sandbox.remove("snapshot-fork");
await Snapshot.remove("snapshot-baseline:snapshot-baseline-state");
