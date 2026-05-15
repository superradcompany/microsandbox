//! Streaming file read — create a file in the sandbox and stream it back in chunks.

use microsandbox::Sandbox;

const FILE_SIZE: usize = 10 * 1024 * 1024; // 10 MiB

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sandbox = Sandbox::builder("fs-read-stream")
        .image("alpine")
        .cpus(1)
        .memory(512)
        .replace()
        .create()
        .await?;

    sandbox
        .shell("dd if=/dev/urandom of=/tmp/data.bin bs=1M count=10")
        .await?;

    let mut stream = sandbox.fs().read_stream("/tmp/data.bin").await?;
    let mut total_bytes = 0;
    let mut chunk_count = 0;

    while let Some(chunk) = stream.recv().await? {
        chunk_count += 1;
        total_bytes += chunk.len();
        println!("Chunk {chunk_count}: {} bytes", chunk.len());
    }

    println!("Done — {chunk_count} chunks, {total_bytes} bytes total");
    assert_eq!(
        total_bytes, FILE_SIZE,
        "expected {FILE_SIZE} bytes, got {total_bytes}"
    );

    sandbox.stop_and_wait().await?;
    Ok(())
}
