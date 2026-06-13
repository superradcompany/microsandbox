//! Named volume — persistent storage shared across sandboxes.

use microsandbox::{Sandbox, Volume, size::SizeExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let data = Volume::builder("my-data").quota(100.mib()).create().await?;

    let writer = Sandbox::builder("writer")
        .image("alpine")
        .volume("/data", |v| v.named(data.name()))
        .replace()
        .create()
        .await?;

    writer
        .shell("echo 'hello from sandbox A' > /data/message.txt")
        .await?;

    writer.stop().await?;

    let reader = Sandbox::builder("reader")
        .image("alpine")
        .volume("/data", |v| v.named(data.name()).readonly())
        .replace()
        .create()
        .await?;

    let output = reader.shell("cat /data/message.txt").await?;
    println!("{}", output.stdout()?);

    reader.stop().await?;

    Sandbox::remove("writer").await?;
    Sandbox::remove("reader").await?;
    Volume::remove("my-data").await?;

    Ok(())
}
