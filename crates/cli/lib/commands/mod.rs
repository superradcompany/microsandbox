//! CLI command implementations.

use microsandbox::sandbox::{RootfsSource, Sandbox, SandboxStatus};

use crate::ui;

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub mod branch;
pub mod common;
pub mod completion;
pub mod context;
pub mod copy;
pub mod create;
pub mod exec;
pub mod image;
pub mod inspect;
pub mod install;
pub mod jobs;
pub mod list;
pub mod logs;
pub mod metrics;
pub mod modify;
pub mod pause;
pub mod ping;
pub mod ps;
pub mod pull;
pub mod registry;
pub mod remove;
pub mod restart;
pub mod restore;
pub mod run;
pub mod sandbox;
pub mod self_cmd;
pub mod snapshot;
#[cfg(feature = "ssh")]
pub mod ssh;
pub mod start;
pub mod stop;
pub mod storage;
pub mod touch;
pub mod uninstall;
pub mod volume;
pub mod wait;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Stop the sandbox if we own its lifecycle (i.e., we started it).
///
/// When connecting to an already-running sandbox, this is a no-op.
pub async fn maybe_stop(sandbox: &Sandbox) {
    if sandbox.owns_lifecycle() {
        if let Err(e) = sandbox.stop().await {
            ui::warn(&format!("failed to stop sandbox: {e}"));
        }
        // Exec, run and SSH can exit with the guest's status before main's
        // finalizer runs. Complete any scheduled cleanup before that exit.
        finish_stopped_memory_cleanup().await;
    }
}

/// Finish local stop cleanup before a command calls `process::exit`.
pub(crate) async fn finish_stopped_memory_cleanup() {
    let backend = microsandbox::backend::default_backend();
    if let Some(local) = backend.as_local() {
        local.finish_stopped_memory_cleanup().await;
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

    match handle.status_snapshot() {
        SandboxStatus::Running | SandboxStatus::Draining => {
            // Rebuild a live sandbox. Local connects to the agent relay now;
            // cloud agent operations establish their WebSocket lazily.
            let sandbox = handle.connect().await?;
            if sandbox.local().is_some() && sandbox.client().is_legacy_protocol() && !quiet {
                // TODO(upgrade-0.6): Remove in 0.6.x or later once live-sandbox
                // compatibility for versions before 0.5 is no longer supported.
                ui::warn(&format!(
                    "sandbox \"{name}\" was started before microsandbox 0.5; exec/shell still work temporarily, but filesystem and SFTP need stop/start"
                ));
            }
            Ok(sandbox)
        }
        SandboxStatus::Stopped | SandboxStatus::Crashed => {
            if let Ok(config) = handle.config()
                && let RootfsSource::Oci(ref oci) = config.spec.image
            {
                let materialization = if matches!(
                    &oci.root_disk,
                    Some(microsandbox::sandbox::RootDisk::Flat { .. })
                ) {
                    pull::PullMaterialization::Flat
                } else {
                    pull::PullMaterialization::Layered
                };
                image::pull_if_missing(&oci.reference, quiet, materialization).await?;
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
        SandboxStatus::Created | SandboxStatus::Starting | SandboxStatus::Paused => {
            anyhow::bail!(
                "sandbox '{}' is in state {:?} and cannot be started",
                name,
                handle.status_snapshot()
            );
        }
    }
}
