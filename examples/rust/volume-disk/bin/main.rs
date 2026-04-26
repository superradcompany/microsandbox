//! Disk image volume example — attach raw and qcow2 host images at guest paths.
//!
//! See [examples/README.md](../../../README.md) for prerequisites and usage.

use std::path::PathBuf;

use microsandbox::{Sandbox, sandbox::DiskImageFormat};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let data_dir = manifest_dir
        .join("sample-images")
        .canonicalize()
        .map_err(|e| {
            format!(
                "missing sample-images submodule at {}/sample-images ({e}). \
             Run `git submodule update --init --recursive` first.",
                manifest_dir.display()
            )
        })?;
    let raw_path = data_dir.join("ext4-seeded.raw");
    let qcow2_path = data_dir.join("ext4-seeded.qcow2");

    println!("Mounting:");
    println!("  /seed (raw, ro) ← {}", raw_path.display());
    println!("  /data (qcow2, rw) ← {}", qcow2_path.display());

    // Mount the raw image read-only at /seed (carries pre-seeded files),
    // and the qcow2 image read-write at /data so the example can both
    // read seeded content and persist new writes.
    let sandbox = Sandbox::builder("volume-disk")
        .image("alpine")
        .volume("/seed", |v| {
            v.disk(&raw_path)
                .format(DiskImageFormat::Raw)
                .fstype("ext4")
                .readonly()
        })
        .volume("/data", |v| {
            v.disk(&qcow2_path)
                .format(DiskImageFormat::Qcow2)
                .fstype("ext4")
        })
        .replace()
        .create()
        .await?;

    // Verify the read-only seed mount.
    println!("\n=== /seed (read-only) ===");
    let listing = sandbox.shell("ls -la /seed").await?;
    print!("{}", listing.stdout()?);

    let hello = sandbox.shell("cat /seed/hello.txt").await?;
    println!("hello.txt: {}", hello.stdout()?.trim());

    let release = sandbox.shell("cat /seed/notes/release.txt").await?;
    println!("notes/release.txt: {}", release.stdout()?.trim());

    let manifest = sandbox.shell("cat /seed/lib/data.json").await?;
    println!("lib/data.json:\n{}", manifest.stdout()?);

    // Confirm writes are blocked on the read-only mount.
    let blocked = sandbox
        .shell("touch /seed/should-fail 2>&1 || true")
        .await?;
    println!("attempted /seed write → {}", blocked.stdout()?.trim());

    // Demonstrate writes to the writable qcow2 mount.
    println!("\n=== /data (read-write) ===");
    sandbox
        .shell("echo 'written from inside the sandbox' > /data/created.txt")
        .await?;
    let readback = sandbox.shell("cat /data/created.txt").await?;
    println!("created.txt: {}", readback.stdout()?.trim());

    // Pre-seeded content is visible in the qcow2 too (same source as raw).
    let qcow_hello = sandbox.shell("cat /data/hello.txt").await?;
    println!("hello.txt: {}", qcow_hello.stdout()?.trim());

    sandbox.stop_and_wait().await?;
    println!("\nSandbox stopped.");
    Ok(())
}
