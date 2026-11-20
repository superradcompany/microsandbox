//! Real-VM regression coverage for file overlays inside read-only shares.
//!
//! Run with `cargo test -p microsandbox --test readonly_file_mount -- --ignored`.

use std::fs;
use std::time::Duration;

use anyhow::{Result, ensure};
use microsandbox::{Sandbox, sandbox::SecurityProfile};
use test_utils::msb_test;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const IMAGE: &str = "mirror.gcr.io/library/alpine";

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

/// An existing file under a read-only share must be maskable without writing
/// to the parent mount. Run as guest root: mode bits alone cannot reproduce EROFS.
#[msb_test]
async fn file_overlay_inside_readonly_share_preserves_confinement() -> Result<()> {
    let fixture = tempfile::tempdir()?;
    // macOS's temporary directory traverses /var -> /private/var. Resolve only
    // this owned test fixture so production bind-path validation stays enabled.
    let root = fs::canonicalize(fixture.path())?;
    let shared = root.join("shared");
    let mask = root.join("mask");
    fs::create_dir(&shared)?;
    fs::write(shared.join("secret.txt"), "host-secret")?;
    fs::write(shared.join("visible.txt"), "visible-fixture")?;
    fs::write(&mask, "")?;

    for profile in [SecurityProfile::Default, SecurityProfile::Restricted] {
        let name = format!("readonly-file-overlay-{}", std::process::id());
        let sandbox = Sandbox::builder(&name)
            .image(IMAGE)
            .cpus(1)
            .memory(256)
            .max_duration(Duration::from_secs(120))
            .security(profile)
            .volume("/work", |m| m.bind(&shared).readonly())
            .volume("/work/secret.txt", |m| m.bind(&mask).readonly())
            .create()
            .await?;
        // Finish VM cleanup before returning a guest assertion failure.
        let checks: Result<()> = async {
            ensure!(sandbox.fs().read("/work/secret.txt").await?.is_empty());
            ensure!(sandbox.fs().read_to_string("/work/visible.txt").await? == "visible-fixture");
            for path in ["/work/new.txt", "/work/visible.txt", "/work/secret.txt"] {
                ensure!(
                    sandbox.fs().write(path, "forbidden").await.is_err(),
                    "write allowed: {path}"
                );
            }
            ensure!(fs::read_to_string(shared.join("secret.txt"))? == "host-secret");
            ensure!(fs::read_to_string(shared.join("visible.txt"))? == "visible-fixture");
            ensure!(!shared.join("new.txt").exists());
            ensure!(fs::read(&mask)?.is_empty());
            Ok(())
        }
        .await;
        let stopped = sandbox.stop_with_timeout(Duration::from_secs(30)).await;
        if stopped.is_err() {
            let _ = sandbox.kill().await;
        }
        drop(sandbox);
        let removed = Sandbox::remove(&name).await;
        checks?;
        stopped?;
        removed?;
    }
    Ok(())
}
