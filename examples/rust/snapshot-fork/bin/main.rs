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

    // Capture this example after stopping the source.
    baseline.stop().await?;

    let h = Sandbox::get("snapshot-baseline").await?;
    let created = h.snapshot("snapshot-baseline-state").await?;
    let snap = created.checkpoint;
    println!("created checkpoint: {}", snap.id());
    println!("        reference: {}", snap.reference().value());

    let fork = snap
        .spawn_sandbox_with(|options| options.name("snapshot-fork"))
        .await?;
    let output = fork.shell("cat /root/marker.txt").await?;
    assert_eq!(output.stdout()?.trim(), "shipped via snapshot");
    println!("fork sees: {}", output.stdout()?.trim());

    fork.stop().await?;

    Sandbox::remove("snapshot-baseline").await?;
    Sandbox::remove("snapshot-fork").await?;
    created.snapshot.remove().await?;

    Ok(())
}
