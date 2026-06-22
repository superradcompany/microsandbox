//! Cloud backend lifecycle and live-log example.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures::StreamExt;
use microsandbox::logs::{LogSource, LogStreamOptions};
use microsandbox::sandbox::SandboxStatus;
use microsandbox::{BackendKind, CloudBackend, Sandbox, set_default_backend};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    configure_cloud_backend()?;

    let suffix = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let name = format!("rust-cloud-{suffix}");

    println!("creating {name} on the cloud backend");
    let sandbox = Sandbox::builder(&name)
        .image("alpine:3.19")
        .cpus(1)
        .memory(512)
        .entrypoint([
            "/bin/sh",
            "-lc",
            "for i in 1 2 3; do echo rust-cloud-$i; sleep 1; done",
        ])
        .max_duration(60)
        .replace()
        .create()
        .await?;

    println!("status after create: {:?}", sandbox.status().await?);

    let exec = sandbox
        .shell("printf 'cloud exec from rust\\n'; uname -m")
        .await?;
    println!("exec status: {:?}", exec.status());
    print!("{}", exec.stdout()?);

    let mut logs = sandbox
        .log_stream(&LogStreamOptions {
            sources: vec![LogSource::Stdout, LogSource::Stderr, LogSource::System],
            follow: true,
            ..Default::default()
        })
        .await?;

    for _ in 0..3 {
        match tokio::time::timeout(Duration::from_secs(20), logs.next()).await {
            Ok(Some(Ok(entry))) => println!(
                "[{} {:?}] {}",
                entry.timestamp.to_rfc3339(),
                entry.source,
                String::from_utf8_lossy(&entry.data).trim_end()
            ),
            Ok(Some(Err(err))) => return Err(err.into()),
            Ok(None) => break,
            Err(_) => {
                println!("timed out waiting for another log entry");
                break;
            }
        }
    }

    sandbox.stop().await?;
    wait_until_stopped(&name).await?;
    Sandbox::remove(&name).await?;
    println!("removed {name}");

    Ok(())
}

fn configure_cloud_backend() -> anyhow::Result<()> {
    let cloud = if let Ok(profile) = std::env::var("MSB_PROFILE") {
        CloudBackend::from_profile(profile.trim())?
    } else {
        CloudBackend::from_env()?
    };
    set_default_backend(cloud);

    let kind = microsandbox::default_backend().kind();
    if kind != BackendKind::Cloud {
        anyhow::bail!("expected cloud backend, got {kind:?}");
    }
    Ok(())
}

async fn wait_until_stopped(name: &str) -> anyhow::Result<()> {
    for _ in 0..30 {
        let handle = Sandbox::get(name).await?;
        if handle.status_snapshot() == SandboxStatus::Stopped {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    anyhow::bail!("sandbox {name} did not stop within 30s")
}
