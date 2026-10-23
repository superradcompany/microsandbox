//! Read captured exec.log entries from a stopped sandbox.

use microsandbox::logs::{LogOptions, LogSource};
use microsandbox::sandbox::Sandbox;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let sb = Sandbox::builder("logs-read")
        .image("alpine")
        .cpus(1)
        .memory(512)
        .replace()
        .create()
        .await?;

    let _ = sb
        .shell("echo line one; echo line two; echo error line 1>&2; echo line three")
        .await?;

    sb.stop().await?;

    let handle = Sandbox::get("logs-read").await?;

    // Default sources are user-program output (stdout/stderr/output).
    let entries = handle.logs(&LogOptions::default()).await?;
    println!(
        "\n== default sources (stdout+stderr+output): {} entries",
        entries.len()
    );

    // Adding `System` mixes in lifecycle markers and runtime/kernel diagnostics.
    let with_system = handle
        .logs(&LogOptions {
            sources: vec![
                LogSource::Stdout,
                LogSource::Stderr,
                LogSource::Output,
                LogSource::System,
            ],
            ..Default::default()
        })
        .await?;
    println!(
        "\n== including system (runtime/kernel + lifecycle markers): {} entries",
        with_system.len()
    );

    let tail = handle
        .logs(&LogOptions {
            tail: Some(1),
            ..Default::default()
        })
        .await?;
    println!("\n== tail=1: {} entries", tail.len());

    Ok(())
}
