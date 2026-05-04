//! Snapshot a stopped sandbox, then boot a fresh sandbox from it.

use microsandbox::Sandbox;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let baseline = Sandbox::builder("snapshot-baseline")
        .image("alpine")
        .replace()
        .create()
        .await?;
    // `sync` flushes the guest page cache before halt; otherwise the
    // snapshot can race ahead of the writes.
    baseline
        .shell("echo 'shipped via snapshot' > /root/marker.txt && sync")
        .await?;

    // Snapshots are stopped-only.
    baseline.stop_and_wait().await?;

    let h = Sandbox::get("snapshot-baseline").await?;
    let snap = h.snapshot("snapshot-baseline-state").await?;
    println!("created snapshot: {}", snap.digest());
    println!("                  {}", snap.path().display());

    let fork = Sandbox::builder("snapshot-fork")
        .from_snapshot("snapshot-baseline-state")
        .replace()
        .create()
        .await?;
    let output = fork.shell("cat /root/marker.txt").await?;
    println!("fork sees: {}", output.stdout()?.trim());

    fork.stop_and_wait().await?;

    Sandbox::remove("snapshot-baseline").await?;
    Sandbox::remove("snapshot-fork").await?;
    microsandbox::Snapshot::remove("snapshot-baseline-state", false).await?;

    Ok(())
}
