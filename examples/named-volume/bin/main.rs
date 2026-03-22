//! Named volume example — persistent storage across sandboxes.
//!
//! See [examples/README.md](../../README.md) for prerequisites and usage.

use microsandbox::{sandbox::Sandbox, size::SizeExt, volume::Volume};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a named volume.
    let data = Volume::builder("my-data").quota(100.mib()).create().await?;

    // Sandbox A writes to the volume.
    let writer = Sandbox::builder("writer")
        .image("alpine:latest")
        .volume("/data", |v| v.named(data.name()))
        .overwrite()
        .create()
        .await?;

    writer
        .shell("echo 'hello from sandbox A' > /data/message.txt", ())
        .await?;

    writer.stop_and_wait().await?;

    // Sandbox B reads from the same volume.
    let reader = Sandbox::builder("reader")
        .image("alpine:latest")
        .volume("/data", |v| v.named(data.name()).readonly())
        .overwrite()
        .create()
        .await?;

    let output = reader.shell("cat /data/message.txt", ()).await?;
    println!("{}", output.stdout()?);

    reader.stop_and_wait().await?;

    // Clean up.
    Sandbox::remove("writer").await?;
    Sandbox::remove("reader").await?;
    Volume::remove("my-data").await?;

    Ok(())
}
