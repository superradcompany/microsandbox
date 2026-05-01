use microsandbox::sandbox::{LogOptions, LogSource, Sandbox};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let name = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "svc".to_string());
    let handle = Sandbox::get(&name).await?;

    let entries = handle.logs(&LogOptions::default())?;
    println!("== default sources (stdout+stderr+output): {} entries", entries.len());
    for e in &entries {
        let body = String::from_utf8_lossy(&e.data);
        let id = e
            .session_id
            .map(|i| format!("id={i:>3}"))
            .unwrap_or_else(|| "id=---".into());
        println!(
            "  [{}] {} {}: {}",
            e.timestamp.to_rfc3339(),
            id,
            source_label(e.source),
            body.trim_end()
        );
    }

    let with_system = handle.logs(&LogOptions {
        sources: vec![LogSource::Stdout, LogSource::Stderr, LogSource::System],
        ..Default::default()
    })?;
    println!("\n== including system: {} entries", with_system.len());

    let tail_one = handle.logs(&LogOptions {
        tail: Some(1),
        ..Default::default()
    })?;
    println!("\n== tail=1: {} entries", tail_one.len());
    if let Some(e) = tail_one.first() {
        println!(
            "  [{}] {}: {}",
            e.timestamp.to_rfc3339(),
            source_label(e.source),
            String::from_utf8_lossy(&e.data).trim_end()
        );
    }

    Ok(())
}

fn source_label(s: LogSource) -> &'static str {
    match s {
        LogSource::Stdout => "stdout",
        LogSource::Stderr => "stderr",
        LogSource::Output => "output",
        LogSource::System => "system",
    }
}
