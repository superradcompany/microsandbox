//! Configured-context sandbox creation with unified creation-progress reporting.

use tokio::task::JoinHandle;

use crate::{CreationProgressHandle, MicrosandboxResult, Sandboxes, context::configured_context};

use super::{Sandbox, SandboxConfig};

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Sandbox {
    /// Create a sandbox from a config with image-pull, snapshot-preparation, and activation
    /// progress.
    ///
    /// Events are best-effort and never block creation. Await the task for the authoritative
    /// result; dropping the progress receiver does not cancel it. Abort the task to cancel.
    /// Uses the configured context.
    pub fn create_with_progress(
        config: SandboxConfig,
    ) -> MicrosandboxResult<(CreationProgressHandle, JoinHandle<MicrosandboxResult<Self>>)> {
        Sandboxes {
            context: configured_context(),
        }
        .create_with_progress(config)
    }

    /// Create a detached sandbox from a config with the same creation-progress stream.
    ///
    /// Like [`Self::create_with_progress`] but spawns the sandbox process in detached mode so the
    /// sandbox survives after the creating process exits. Uses the configured context.
    pub fn create_detached_with_progress(
        config: SandboxConfig,
    ) -> MicrosandboxResult<(CreationProgressHandle, JoinHandle<MicrosandboxResult<Self>>)> {
        Sandboxes {
            context: configured_context(),
        }
        .create_detached_with_progress(config)
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::env;

    use tempfile::tempdir;
    use tokio::runtime::Builder;

    use crate::test_support::lock_env;

    use super::{Sandbox, SandboxConfig};

    #[test]
    fn sandbox_create_with_progress_uses_creation_progress_tuple_signature() {
        let _guard = lock_env();
        let home = tempdir().unwrap();
        let previous =
            ["MSB_HOME", "MSB_CONFIG_PATH", "MSB_BACKEND"].map(|name| (name, env::var_os(name)));
        unsafe {
            env::set_var("MSB_HOME", home.path());
            env::set_var(
                "MSB_CONFIG_PATH",
                home.path().join("missing-dir/config.json"),
            );
            env::set_var("MSB_BACKEND", "invalid");
        }

        Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let mut config = SandboxConfig::default();
                config.spec.name = "progress-signature".into();

                let (mut attached_progress, attached_task) =
                    Sandbox::create_with_progress(config.clone()).unwrap();
                assert!(attached_progress.recv().await.is_none());
                assert!(attached_task.await.unwrap().is_err());

                let (mut detached_progress, detached_task) =
                    Sandbox::create_detached_with_progress(config).unwrap();
                assert!(detached_progress.recv().await.is_none());
                assert!(detached_task.await.unwrap().is_err());
            });

        for (name, value) in previous {
            unsafe {
                match value {
                    Some(value) => env::set_var(name, value),
                    None => env::remove_var(name),
                }
            }
        }
    }
}
