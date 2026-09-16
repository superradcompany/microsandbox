//! Live lifecycle convergence and identity-safety example.

use std::{collections::BTreeMap, time::Instant};

use microsandbox::{
    MicrosandboxError, Sandbox,
    sandbox::{DestroyOptions, RestartOptions, SandboxStatus},
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

async fn run_concurrency_checks(
    name: &str,
    image: &str,
    timings: &mut Timings,
) -> Result<(), Box<dyn std::error::Error>> {
    let race_name = format!("{name}-race");
    cleanup(&race_name).await;

    let started = Instant::now();
    let create = |marker: &'static str| {
        Sandbox::builder(&race_name)
            .image(image)
            .cpus(1)
            .memory(256)
            .env("LIFECYCLE_MARKER", marker)
            .connect_or_create()
    };
    let (first, second, third, fourth) = tokio::try_join!(
        create("candidate-0"),
        create("candidate-1"),
        create("candidate-2"),
        create("candidate-3"),
    )?;
    timings.insert("concurrent_connect_or_create", elapsed_ms(started));
    let raced = [first, second, third, fourth];
    let race_id = raced[0].id();
    if raced.iter().any(|sandbox| sandbox.id() != race_id) {
        return Err("concurrent connect_or_create callers selected different identities".into());
    }
    let marker = read_marker(&raced[0]).await?;
    if !["candidate-0", "candidate-1", "candidate-2", "candidate-3"].contains(&marker.as_str()) {
        return Err(
            format!("concurrent creation persisted an unexpected marker: {marker:?}").into(),
        );
    }

    raced[0].stop().await?;
    let handles = tokio::try_join!(
        Sandbox::get(&race_name),
        Sandbox::get(&race_name),
        Sandbox::get(&race_name),
        Sandbox::get(&race_name),
    )?;
    let started = Instant::now();
    let (first, second, third, fourth) = tokio::try_join!(
        handles.0.connect_or_start(),
        handles.1.connect_or_start(),
        handles.2.connect_or_start(),
        handles.3.connect_or_start(),
    )?;
    timings.insert("concurrent_connect_or_start", elapsed_ms(started));
    let connected = [first, second, third, fourth];
    if connected.iter().any(|sandbox| sandbox.id() != race_id) {
        return Err("concurrent connect_or_start callers selected different identities".into());
    }
    assert_marker(&read_marker(&connected[0]).await?, &marker)?;

    connected[0].stop().await?;
    let started = Instant::now();
    let detached = Sandbox::get(&race_name)
        .await?
        .connect_or_start_detached()
        .await?;
    timings.insert("connect_or_start_detached", elapsed_ms(started));
    if detached.id() != race_id || detached.owns_lifecycle() {
        return Err(
            "detached connect_or_start changed identity or took lifecycle ownership".into(),
        );
    }

    let started = Instant::now();
    let forced = detached
        .restart_with(RestartOptions {
            force: true,
            timeout: std::time::Duration::from_secs(5),
            detached: false,
        })
        .await?;
    timings.insert("restart_force", elapsed_ms(started));
    if forced.id() != race_id || !forced.owns_lifecycle() {
        return Err(
            "forced restart changed identity or failed to return an attached handle".into(),
        );
    }
    assert_marker(&read_marker(&forced).await?, &marker)?;

    let started = Instant::now();
    let detached_restart = forced
        .restart_with(RestartOptions {
            force: false,
            timeout: std::time::Duration::from_secs(3),
            detached: true,
        })
        .await?;
    timings.insert("restart_detached_timeout", elapsed_ms(started));
    if detached_restart.id() != race_id || detached_restart.owns_lifecycle() {
        return Err("detached restart changed identity or took lifecycle ownership".into());
    }
    assert_marker(&read_marker(&detached_restart).await?, &marker)?;

    let started = Instant::now();
    detached_restart
        .destroy_with(DestroyOptions {
            force: true,
            timeout: std::time::Duration::from_secs(5),
        })
        .await?;
    timings.insert("destroy_force_timeout", elapsed_ms(started));
    Ok(())
}

async fn run(name: &str) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let image = std::env::var("MSB_E2E_IMAGE").unwrap_or_else(|_| "alpine:3.19".to_string());
    let platform =
        std::env::var("MSB_E2E_PLATFORM").unwrap_or_else(|_| std::env::consts::OS.into());
    let total = Instant::now();
    let mut timings = Timings::new();

    run_concurrency_checks(name, &image, &mut timings).await?;

    let started = Instant::now();
    let created = Sandbox::builder(name)
        .image(image.clone())
        .cpus(1)
        .memory(256)
        .env("LIFECYCLE_MARKER", "original")
        .connect_or_create()
        .await?;
    timings.insert("connect_or_create_new", elapsed_ms(started));
    let original_id = created.id();

    let started = Instant::now();
    let reused = Sandbox::builder(name)
        .image(image.clone())
        .memory(768)
        .env("LIFECYCLE_MARKER", "ignored")
        .connect_or_create()
        .await?;
    timings.insert("connect_or_create_existing", elapsed_ms(started));
    if reused.id() != original_id {
        return Err("connect_or_create changed the persisted identity".into());
    }
    assert_marker(&read_marker(&reused).await?, "original")?;

    // Strict start resumes an existing stopped identity without accepting creation options.
    reused.stop().await?;
    let started = Instant::now();
    let resumed = Sandbox::start(name).await?;
    timings.insert("start", elapsed_ms(started));
    if resumed.id() != original_id {
        return Err("start changed the persisted identity".into());
    }
    assert_marker(&read_marker(&resumed).await?, "original")?;

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
        .connect_or_create()
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
        "checks": 17,
        "timings_ms": timings,
        "result": "pass"
    }))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let name = std::env::var("MSB_E2E_NAME")
        .unwrap_or_else(|_| format!("lifecycle-rust-{}", std::process::id()));
    cleanup(&name).await;
    cleanup(&format!("{name}-race")).await;
    let result = run(&name).await;
    if result.is_err() {
        cleanup(&name).await;
        cleanup(&format!("{name}-race")).await;
    }
    println!("MSB_LIFECYCLE_METRICS {}", serde_json::to_string(&result?)?);
    Ok(())
}
