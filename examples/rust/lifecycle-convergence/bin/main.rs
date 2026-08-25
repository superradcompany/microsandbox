//! Live lifecycle convergence and identity-safety example.

use std::{collections::BTreeMap, time::Instant};

use microsandbox::{
    MicrosandboxError, Sandbox,
    sandbox::{DestroyOptions, SandboxStatus},
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

type Timings = BTreeMap<&'static str, f64>;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn elapsed_ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1_000.0
}

fn assert_marker(actual: &str, expected: &str) -> Result<(), Box<dyn std::error::Error>> {
    if actual == expected {
        Ok(())
    } else {
        Err(format!("expected marker {expected:?}, got {actual:?}").into())
    }
}

async fn read_marker(sandbox: &Sandbox) -> Result<String, Box<dyn std::error::Error>> {
    Ok(sandbox
        .shell("printf '%s' \"$LIFECYCLE_MARKER\"")
        .await?
        .stdout()?)
}

async fn cleanup(name: &str) {
    let Ok(handle) = Sandbox::get(name).await else {
        return;
    };
    let _ = handle
        .destroy_with(DestroyOptions {
            force: true,
            ..Default::default()
        })
        .await;
}

async fn run(name: &str) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let image = std::env::var("MSB_E2E_IMAGE").unwrap_or_else(|_| "alpine:3.19".to_string());
    let platform =
        std::env::var("MSB_E2E_PLATFORM").unwrap_or_else(|_| std::env::consts::OS.into());
    let total = Instant::now();
    let mut timings = Timings::new();

    let started = Instant::now();
    let created = Sandbox::builder(name)
        .image(image.clone())
        .cpus(1)
        .memory(256)
        .env("LIFECYCLE_MARKER", "original")
        .find_or_create()
        .await?;
    timings.insert("find_or_create_new", elapsed_ms(started));
    let original_id = created.id();

    let started = Instant::now();
    let reused = Sandbox::builder(name)
        .image(image.clone())
        .memory(768)
        .env("LIFECYCLE_MARKER", "ignored")
        .find_or_create()
        .await?;
    timings.insert("find_or_create_existing", elapsed_ms(started));
    if reused.id() != original_id {
        return Err("find_or_create changed the persisted identity".into());
    }
    assert_marker(&read_marker(&reused).await?, "original")?;

    let handle = Sandbox::get(name).await?;
    let started = Instant::now();
    let connected = handle.connect_or_start().await?;
    timings.insert("connect_or_start", elapsed_ms(started));
    if connected.id() != original_id {
        return Err("connect_or_start changed the persisted identity".into());
    }

    let started = Instant::now();
    connected.wait_for_status(SandboxStatus::Running).await?;
    timings.insert("wait_for_running", elapsed_ms(started));

    let started = Instant::now();
    assert_marker(&read_marker(&connected).await?, "original")?;
    timings.insert("exec", elapsed_ms(started));

    let started = Instant::now();
    let restarted = connected.restart().await?;
    timings.insert("restart", elapsed_ms(started));
    if restarted.id() != original_id {
        return Err("restart changed the persisted identity".into());
    }
    assert_marker(&read_marker(&restarted).await?, "original")?;

    let stale = Sandbox::get(name).await?;
    let started = Instant::now();
    restarted.destroy().await?;
    timings.insert("destroy_original", elapsed_ms(started));

    let replacement = Sandbox::builder(name)
        .image(image)
        .cpus(1)
        .memory(256)
        .env("LIFECYCLE_MARKER", "replacement")
        .find_or_create()
        .await?;
    if replacement.id() == original_id {
        return Err("replacement reused the destroyed sandbox identity".into());
    }

    let started = Instant::now();
    match stale.destroy().await {
        Err(MicrosandboxError::SandboxReplaced { .. }) => {}
        Err(error) => return Err(format!("unexpected stale receiver error: {error}").into()),
        Ok(()) => return Err("stale receiver acted on the replacement".into()),
    }
    timings.insert("stale_identity_rejection", elapsed_ms(started));
    assert_marker(&read_marker(&replacement).await?, "replacement")?;

    let started = Instant::now();
    replacement.destroy().await?;
    timings.insert("destroy_replacement", elapsed_ms(started));
    timings.insert("total", elapsed_ms(total));

    Ok(serde_json::json!({
        "sdk": "rust",
        "platform": platform,
        "sandbox": name,
        "identity": original_id.as_str(),
        "checks": 10,
        "timings_ms": timings,
        "result": "pass"
    }))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let name = std::env::var("MSB_E2E_NAME")
        .unwrap_or_else(|_| format!("lifecycle-rust-{}", std::process::id()));
    cleanup(&name).await;
    let result = run(&name).await;
    if result.is_err() {
        cleanup(&name).await;
    }
    println!("MSB_LIFECYCLE_METRICS {}", serde_json::to_string(&result?)?);
    Ok(())
}
