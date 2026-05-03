//! Read captured exec.log entries from a stopped sandbox.

use microsandbox::sandbox::{LogOptions, LogSource, Sandbox};

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

    sb.stop_and_wait().await?;

    let handle = Sandbox::get("logs-read").await?;

    // Default sources are user-program output (stdout/stderr/output).
    let entries = handle.logs(&LogOptions::default())?;
    println!(
        "\n== default sources (stdout+stderr+output): {} entries",
        entries.len()
    );
    for e in &entries {
        print_entry(e);
    }

    // Adding `System` mixes in lifecycle markers and runtime/kernel diagnostics.
    let with_system = handle.logs(&LogOptions {
        sources: vec![
            LogSource::Stdout,
            LogSource::Stderr,
            LogSource::Output,
            LogSource::System,
        ],
        ..Default::default()
    })?;
    println!(
        "\n== including system (runtime/kernel + lifecycle markers): {} entries",
        with_system.len()
    );

    let tail = handle.logs(&LogOptions {
        tail: Some(1),
        ..Default::default()
    })?;
    println!("\n== tail=1: {} entries", tail.len());
    if let Some(e) = tail.first() {
        print_entry(e);
    }

    Ok(())
}

fn print_entry(e: &microsandbox::sandbox::LogEntry) {
    let id = e
        .session_id
        .map(|i| format!("id={i:>3}"))
        .unwrap_or_else(|| "id=---".into());
    println!(
        "  [{}] {} {}: {}",
        e.timestamp.to_rfc3339(),
        id,
        source_label(e.source),
        String::from_utf8_lossy(&e.data).trim_end()
    );
}

fn source_label(s: LogSource) -> &'static str {
    match s {
        LogSource::Stdout => "stdout",
        LogSource::Stderr => "stderr",
        LogSource::Output => "output",
        LogSource::System => "system",
    }
}
