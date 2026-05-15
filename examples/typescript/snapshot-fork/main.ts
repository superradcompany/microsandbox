// Snapshot a stopped sandbox, then boot a fresh sandbox from it.
//
// Demonstrates the core v1 disk-snapshot flow:
//   1. Stand up a baseline sandbox and customize it.
//   2. Stop it.
//   3. Snapshot the writable upper layer to a content-addressed
//      artifact under ~/.microsandbox/snapshots/<name>/.
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
  // 2. Stop it. Snapshots are stopped-only in v1.
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
  await using fork = await Sandbox.builder("snapshot-fork")
    .fromSnapshot("snapshot-baseline-state")
    .replace()
    .create();
  const out = (await fork.shell("cat /root/marker.txt")).stdout();
  console.log(`fork sees: ${out.trim()}`);
}

// Cleanup.
await Sandbox.remove("snapshot-baseline");
await Sandbox.remove("snapshot-fork");
await Snapshot.remove("snapshot-baseline-state");
