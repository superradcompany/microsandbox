//! Snapshot a stopped sandbox, then boot a fresh sandbox from it.
//!
//! Demonstrates the core v1 disk-snapshot flow:
//!   1. Stand up a baseline sandbox and customize it.
//!   2. Stop it.
//!   3. Snapshot the writable upper layer to a content-addressed
//!      artifact under `~/.microsandbox/snapshots/<name>/`.
//!   4. Boot a brand-new sandbox from that snapshot — the captured
//!      filesystem state is the new sandbox's starting point.
//!
//! See [examples/README.md](../../../README.md) for prerequisites and usage.

use microsandbox::Sandbox;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Stand up a baseline sandbox and customize it.
    let baseline = Sandbox::builder("snapshot-baseline")
        .image("alpine")
        .replace()
        .create()
        .await?;
    // The trailing `sync` flushes the guest's page cache to upper.ext4
    // before the VM halts. Without it the captured snapshot can race
    // ahead of the writes and miss them.
    baseline
        .shell("echo 'shipped via snapshot' > /root/marker.txt && sync")
        .await?;

    // 2. Stop it. Snapshots are stopped-only in v1.
    baseline.stop_and_wait().await?;

    // 3. Snapshot the stopped sandbox via the lookup-by-name handle.
    let h = Sandbox::get("snapshot-baseline").await?;
    let snap = h.snapshot("snapshot-baseline-state").await?;
    println!("created snapshot: {}", snap.digest());
    println!("                  {}", snap.path().display());

    // 4. Boot a fresh sandbox from the snapshot. The new sandbox
    //    starts with the captured upper layer, so /root/marker.txt
    //    is already present.
    let fork = Sandbox::builder("snapshot-fork")
        .from_snapshot("snapshot-baseline-state")
        .replace()
        .create()
        .await?;
    let output = fork.shell("cat /root/marker.txt").await?;
    println!("fork sees: {}", output.stdout()?.trim());

    fork.stop_and_wait().await?;

    // Cleanup.
    Sandbox::remove("snapshot-baseline").await?;
    Sandbox::remove("snapshot-fork").await?;
    microsandbox::Snapshot::remove("snapshot-baseline-state", false).await?;

    Ok(())
}
