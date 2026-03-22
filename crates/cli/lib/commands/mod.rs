//! CLI command implementations.

use microsandbox::sandbox::{Sandbox, SandboxStatus};

use crate::ui;

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub mod create;
pub mod exec;
pub mod inspect;
pub mod list;
pub mod ps;
pub mod pull;
pub mod remove;
pub mod run;
pub mod shell;
pub mod start;
pub mod stop;
pub mod volume;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Resolve an existing sandbox by name and ensure it is started.
///
/// If the sandbox is stopped or crashed, it will be started with a spinner.
/// Returns an error if the sandbox is already running in another process or
/// is in an unexpected state.
pub async fn resolve_and_start(name: &str, quiet: bool) -> anyhow::Result<Sandbox> {
    let handle = Sandbox::get(name).await?;

    match handle.status() {
        SandboxStatus::Running | SandboxStatus::Draining => {
            anyhow::bail!(
                "sandbox '{}' is already running in another process; \
                 cross-process access is not yet supported",
                name
            );
        }
        SandboxStatus::Stopped | SandboxStatus::Crashed => {
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
                    spinner.finish_error();
                    Err(e.into())
                }
            }
        }
        _ => {
            anyhow::bail!(
                "sandbox '{}' is in state {:?} and cannot be started",
                name,
                handle.status()
            );
        }
    }
}
