//! Windows WHP lifecycle and bind-mount regression coverage.
//!
//! Run this ignored test with the matching candidate runtime and guest agent.
//! CI runs this exact test in its own process with an isolated `MSB_HOME`.

#![cfg(all(windows, feature = "local"))]

use std::fs;
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use microsandbox::{MicrosandboxError, Sandbox};
use test_utils::msb_test;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const IMAGE: &str = "mirror.gcr.io/library/alpine:3.22";

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn check_guest(sandbox: &Sandbox, command: &str, expected: &str) -> Result<()> {
    let output = sandbox.shell(command).await?;
    ensure!(output.status().success, "guest command failed");
    ensure!(
        output.stdout()?.trim() == expected,
        "unexpected guest output"
    );
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[msb_test]
async fn windows_whp_lifecycle_and_bind_confinement() -> Result<()> {
    let fixtures = tempfile::tempdir()?;
    // Spaces and a drive prefix exercise Windows host-path handling as well as
    // guest I/O. The outside file is synthetic; no real host data is accessed.
    let shared = fixtures.path().join("shared files");
    let outside = fixtures.path().join("outside");
    fs::create_dir(&shared)?;
    fs::create_dir(&outside)?;
    fs::write(shared.join("host.txt"), "host-fixture")?;
    fs::write(outside.join("sentinel.txt"), "outside-fixture")?;
    let junction = shared.join("escape");
    let result = Command::new("cmd.exe")
        .args(["/d", "/c", "mklink", "/J"])
        .arg(&junction)
        .arg(&outside)
        .output()?;
    ensure!(result.status.success(), "could not create junction fixture");

    let name = format!("windows-whp-{}", std::process::id());
    let sandbox = Sandbox::builder(&name)
        .image(IMAGE)
        .cpus(1)
        .memory(512)
        .volume("/work", |mount| mount.bind(&shared))
        .volume("/readonly", |mount| mount.bind(&shared).readonly())
        .create()
        .await
        .context("boot Windows WHP guest")?;

    // Keep assertions fallible so shutdown and removal run even when a guest
    // check fails. Never accept a skipped or unsupported VM as a passing test.
    let checks: Result<()> = async {
        check_guest(&sandbox, "printf windows-whp-ready", "windows-whp-ready").await?;
        ensure!(
            sandbox.fs().read_to_string("/work/host.txt").await? == "host-fixture",
            "bind mount did not expose its ordinary file"
        );
        check_guest(&sandbox, "ls -1 /work", "host.txt").await?;
        ensure!(
            sandbox
                .fs()
                .read("/work/escape/sentinel.txt")
                .await
                .is_err(),
            "junction escaped the authorized bind root"
        );
        check_guest(&sandbox, "printf guest-fixture > /work/guest.txt", "").await?;
        ensure!(
            fs::read_to_string(shared.join("guest.txt"))? == "guest-fixture",
            "guest write did not reach the authorized host directory"
        );
        check_guest(
            &sandbox,
            "if printf forbidden > /readonly/forbidden.txt 2>/dev/null; then exit 1; fi",
            "",
        )
        .await?;
        ensure!(
            !shared.join("forbidden.txt").exists(),
            "read-only mount allowed a write"
        );
        ensure!(fs::read_to_string(outside.join("sentinel.txt"))? == "outside-fixture");
        Ok(())
    }
    .await;

    let stopped = sandbox.stop_with_timeout(Duration::from_secs(30)).await;
    if stopped.is_err() {
        // Preserve the graceful-stop failure while still releasing the test VM.
        let _ = sandbox.kill().await;
    }
    drop(sandbox);
    let removed = Sandbox::remove(&name).await;
    fs::remove_dir(&junction)?;
    checks?;
    stopped.context("stop Windows WHP guest")?;
    removed.context("remove Windows WHP guest")?;
    ensure!(matches!(
        Sandbox::get(&name).await,
        Err(MicrosandboxError::SandboxNotFound(_))
    ));
    Ok(())
}
