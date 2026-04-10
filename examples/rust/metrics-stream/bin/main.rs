//! Streaming metrics — subscribe to sandbox resource usage at a regular interval.

use std::time::Duration;

use futures::StreamExt;
use microsandbox::Sandbox;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Creating sandbox (image=alpine)");

    let sandbox = Sandbox::builder("metrics-stream")
        .image("alpine")
        .cpus(1)
        .memory(512)
        .replace()
        .create()
        .await?;

    // Generate some CPU load in the background.
    sandbox
        .shell("dd if=/dev/urandom of=/dev/null bs=1M count=100 &")
        .await?;

    // Stream metrics every second, print 5 samples.
    let mut stream = Box::pin(sandbox.metrics_stream(Duration::from_secs(1)));
    let mut count = 0;

    while let Some(result) = stream.next().await {
        let m = result?;
        println!(
            "[{count}] CPU: {:.1}%, Mem: {} MB, Disk R/W: {}/{} bytes",
            m.cpu_percent,
            m.memory_bytes / 1024 / 1024,
            m.disk_read_bytes,
            m.disk_write_bytes,
        );
        count += 1;
        if count >= 5 {
            break;
        }
    }

    println!("Collected {count} metric samples");

    sandbox.stop_and_wait().await?;
    println!("Sandbox stopped.");

    Ok(())
}
