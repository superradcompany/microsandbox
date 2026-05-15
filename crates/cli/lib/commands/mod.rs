//! CLI command implementations.

use microsandbox::sandbox::{RootfsSource, Sandbox, SandboxStatus};

use crate::ui;

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub mod common;
pub mod create;
pub mod exec;
pub mod image;
pub mod inspect;
pub mod install;
pub mod list;
pub mod logs;
pub mod metrics;
pub mod ps;
pub mod pull;
pub mod registry;
pub mod remove;
pub mod run;
pub mod self_cmd;
pub mod snapshot;
pub mod start;
pub mod stop;
pub mod uninstall;
pub mod volume;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Stop the sandbox if we own its lifecycle (i.e., we started it).
///
/// When connecting to an already-running sandbox, this is a no-op.
pub async fn maybe_stop(sandbox: &Sandbox) {
    if sandbox.owns_lifecycle()
        && let Err(e) = sandbox.stop_and_wait().await
    {
        ui::warn(&format!("failed to stop sandbox: {e}"));
    }
}

/// Resolve an existing sandbox by name and ensure it is accessible.
///
/// If the sandbox is already running, connects to the existing sandbox process
/// via the agent relay socket. If stopped or crashed, starts it with a spinner.
///
/// For OCI-backed sandboxes that are being (re)started, runs a pull-if-missing
/// pass first so any cache artifacts deleted since the last run (layer EROFS,
/// fsmeta, VMDK) are regenerated before the VM tries to use them.
pub async fn resolve_and_start(name: &str, quiet: bool) -> anyhow::Result<Sandbox> {
    let handle = Sandbox::get(name).await?;

    match handle.status() {
        SandboxStatus::Running | SandboxStatus::Draining => {
            // Connect to the running sandbox process via the agent relay.
            Ok(handle.connect().await?)
        }
        SandboxStatus::Stopped | SandboxStatus::Crashed => {
            if let Ok(config) = handle.config()
                && let RootfsSource::Oci(ref reference) = config.image
            {
                image::pull_if_missing(reference, quiet).await?;
            }

            let spinner = if quiet {
                ui::Spinner::quiet()
            } else {
                ui::Spinner::start("Starting", name)
            };
            match handle.start().await {
                Ok(s) => {
                    spinner.finish_clear();
                    Ok(s)
                }
                Err(e) => {
                    spinner.finish_clear();
                    Err(e.into())
                }
            }
        }
        SandboxStatus::Paused => {
            anyhow::bail!(
                "sandbox '{}' is in state {:?} and cannot be started",
                name,
                handle.status()
            );
        }
    }
}
