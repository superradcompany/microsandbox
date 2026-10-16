//! Opt-in live cancellation regression, including native Windows without a CGO toolchain.
//! Run with an isolated MSB_HOME and an explicit, compatible MSB_PATH.

#![cfg(feature = "local")]

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, bail, ensure};
use microsandbox::sandbox::SandboxStatus;
use microsandbox::{MicrosandboxError, Sandbox};
use tokio_util::task::AbortOnDropHandle;

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires an isolated MSB_HOME, MSB_PATH, and a working hypervisor"]
async fn cancelled_ephemeral_create_reclaims_booting_vm() -> anyhow::Result<()> {
    let home = PathBuf::from(std::env::var("MSB_HOME").context("set an isolated MSB_HOME")?);
    std::env::var("MSB_PATH").context("set MSB_PATH to the tested runtime")?;
    let name = format!("cancel-ephemeral-native-{}", std::process::id());
    let directory = home.join("sandboxes").join(&name);
    let image = std::env::var("MSB_TEST_IMAGE").unwrap_or_else(|_| "alpine:3.21".into());
    let builder = || {
        Sandbox::builder(&name)
            .image(image.as_str())
            .memory(256)
            .root_disk(256)
            .disable_network()
            .ephemeral(true)
    };

    let result = async {
        // Drive creation independently while catalog reads await the same backend's
        // initialization. Polling create only between reads would deadlock that setup.
        let mut creation = AbortOnDropHandle::new(tokio::spawn(builder().create()));
        tokio::time::timeout(Duration::from_secs(180), async {
            loop {
                tokio::select! {
                    result = &mut creation => {
                        let sandbox = result.context("creation task failed")?
                            .context("create failed before the runtime began booting")?;
                        sandbox.stop().await?;
                        bail!("create completed before the test observed a booting runtime");
                    }
                    _ = tokio::time::sleep(Duration::from_millis(2)) => {
                        if let Ok(handle) = Sandbox::get(&name).await
                            && handle.status_snapshot() == SandboxStatus::Starting
                            && std::fs::metadata(directory.join("logs/runtime.log"))
                                .is_ok_and(|metadata| metadata.len() > 0)
                        {
                            // A real runtime has begun booting, but create has not
                            // returned its handle. This is the cancellation window.
                            return Ok::<_, anyhow::Error>(());
                        }
                    }
                }
            }
        })
        .await
        .context("never observed the booting runtime")??;
        creation.abort();
        match creation.await {
            Err(error) if error.is_cancelled() => {}
            Ok(Ok(sandbox)) => {
                sandbox.stop().await?;
                bail!("creation completed before cancellation took effect");
            }
            Ok(Err(error)) => {
                return Err(error).context("creation failed instead of being cancelled");
            }
            Err(error) => {
                return Err(error).context("creation task failed instead of being cancelled");
            }
        }

        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                if matches!(
                    Sandbox::get(&name).await,
                    Err(MicrosandboxError::SandboxNotFound(_))
                ) && !directory.exists()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .context("cancelled create retained its catalog row or private disk")?;

        // Do not boot a replacement until both checks pass: startup maintenance
        // must not mask the cancellation cleanup under test.
        let replacement = builder().create().await.context("same-name recreation")?;
        let output = replacement.shell("echo replacement-alive").await?;
        replacement.stop().await?;
        ensure!(
            output.status().success,
            "replacement could not execute after cancellation cleanup"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;

    // Bound cleanup even when a regression leaves the original VM or replacement.
    if let Ok(handle) = Sandbox::get(&name).await {
        let _ = handle.kill_with_timeout(Duration::from_secs(5)).await;
        let _ = handle.remove().await;
    }
    result
}
