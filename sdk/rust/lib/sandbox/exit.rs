//! Read the outcome retained by a stopped local runtime.

use chrono::{DateTime, Utc};
use sea_orm::{ColumnTrait, QueryFilter};

use super::{SandboxHandle, SandboxStatus};
use crate::backend::LocalBackend;
use crate::db::entity::{run, sandbox};
use crate::error::Operation;
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Persisted outcome of the latest run of a terminal local sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxRunExit {
    /// Runtime execution identifier in the local catalog.
    pub run_id: i32,
    /// Process exit code, when recorded.
    pub exit_code: Option<i32>,
    /// Terminating signal, when recorded.
    pub signal: Option<i32>,
    /// Runtime-recorded termination reason; absence is not an idle timeout.
    pub reason: Option<SandboxTerminationReason>,
    /// Runtime-recorded completion time, when available.
    pub terminated_at: Option<DateTime<Utc>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SandboxHandle {
    /// Read the latest retained exit for this exact local sandbox identity.
    ///
    /// Returns `None` while nonterminal or when the latest run has no terminal
    /// record. Never returns an older exit after a newer run has started. Local
    /// ephemeral cleanup deletes this information; callers needing it must
    /// retain the sandbox until they have consumed the result. Cloud backends
    /// return a typed unsupported error. This method does not update the catalog.
    pub async fn terminal_exit(&self) -> MicrosandboxResult<Option<SandboxRunExit>> {
        let local = self
            .backend
            .as_local()
            .ok_or_else(|| MicrosandboxError::local_only(Operation::SandboxHandleTerminalExit))?;
        let identity = self
            .local()
            .ok_or_else(|| MicrosandboxError::local_only(Operation::SandboxHandleTerminalExit))?;

        // Serialize with SDK start/remove so a new execution cannot race the
        // terminal-state and latest-run reads below.
        let _transition =
            LocalBackend::acquire_sandbox_transition_guard(&local.config().run_dir(), self.name())
                .await?;

        let db = local.db().await?;
        let current = microsandbox_db::catalog::sandbox_query(db.read())
            .await?
            .filter(sandbox::Column::Name.eq(self.name()))
            .one(db.read())
            .await?
            .ok_or_else(|| MicrosandboxError::SandboxNotFound(self.name().into()))?;

        if current.id != identity.db_id {
            return Err(MicrosandboxError::SandboxReplaced {
                name: self.name().into(),
                expected: identity.db_id.to_string(),
                actual: current.id.to_string(),
            });
        }

        if !matches!(
            current.status,
            SandboxStatus::Stopped | SandboxStatus::Crashed
        ) {
            return Ok(None);
        }

        let Some(run) = LocalBackend::load_latest_run(db.read(), current.id).await? else {
            return Ok(None);
        };

        if run.status != run::RunStatus::Terminated {
            return Ok(None);
        }

        Ok(Some(SandboxRunExit {
            run_id: run.id,
            exit_code: run.exit_code,
            signal: run.exit_signal,
            reason: run.termination_reason,
            terminated_at: run.terminated_at.map(|time| time.and_utc()),
        }))
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use sea_orm::{ActiveModelTrait, EntityTrait, Set};

    use super::*;
    use crate::backend::SandboxBackend;
    use crate::sandbox::SandboxConfig;

    #[cfg(unix)]
    #[tokio::test]
    #[ignore = "requires a local VM runtime and registry access"]
    async fn live_idle_timeout_retains_exit_until_explicit_cleanup() {
        use crate::Sandbox;
        use crate::backend::with_backend;
        use std::time::Duration;

        let home = tempfile::tempdir_in("/tmp").unwrap();
        let backend = crate::test_support::local_backend_builder(home.path())
            .build()
            .await
            .unwrap();
        // Install the released runtime into the isolated test home. No runtime
        // source changes or global installation are involved in this check.
        crate::setup::install_runtime(backend.config(), Default::default())
            .await
            .unwrap();
        with_backend(backend, async {
            let builder = Sandbox::builder("retained-idle")
                .image("alpine:3.20")
                .cpus(1)
                .memory(256)
                .ephemeral(false)
                .idle_timeout(5)
                .max_duration(60);
            // Released runtimes may not support HTTP denial responses.
            #[cfg(feature = "net")]
            let builder = builder.network(|network| network.http(|http| http.deny_response(false)));
            let sandbox = builder.create_detached().await.unwrap();
            let handle = Sandbox::get(sandbox.name()).await.unwrap();
            let result = tokio::time::timeout(Duration::from_secs(45), async {
                loop {
                    match handle.terminal_exit().await {
                        Ok(Some(exit)) => break Ok(exit),
                        Ok(None) => {}
                        Err(error) => break Err(error),
                    }
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
            })
            .await;
            let cleanup = handle.destroy().await;
            cleanup.expect("remove live test sandbox");
            let exit = result
                .expect("runtime idle timeout must stop the VM")
                .expect("read retained runtime exit");
            assert_eq!(exit.reason, Some(SandboxTerminationReason::IdleTimeout));
            assert_eq!(exit.exit_code, Some(0));
            assert!(exit.terminated_at.is_some());
            assert!(matches!(
                Sandbox::get("retained-idle").await,
                Err(MicrosandboxError::SandboxNotFound(_))
            ));
        })
        .await;
    }

    #[tokio::test]
    async fn retained_exit_is_current_and_bound_to_the_sandbox_identity() {
        let home = tempfile::tempdir().unwrap();
        let backend = Arc::new(
            crate::test_support::local_backend_builder(home.path())
                .build()
                .await
                .unwrap(),
        );
        let db = backend.db().await.unwrap();

        let mut config = SandboxConfig::default();
        config.spec.name = "retained-exit".into();
        config.spec.lifecycle.ephemeral = false;

        let record = sandbox::ActiveModel {
            name: Set(config.spec.name.clone()),
            config: Set(serde_json::to_string(&config).unwrap()),
            status: Set(SandboxStatus::Stopped),
            ephemeral: Set(false),
            ..Default::default()
        }
        .insert(db.write())
        .await
        .unwrap();

        let handle = backend.get(backend.clone(), "retained-exit").await.unwrap();
        assert_eq!(handle.terminal_exit().await.unwrap(), None);

        let ended = chrono::Utc::now().naive_utc();
        let first = run::ActiveModel {
            sandbox_id: Set(record.id),
            status: Set(run::RunStatus::Terminated),
            exit_code: Set(Some(0)),
            termination_reason: Set(Some(SandboxTerminationReason::IdleTimeout)),
            terminated_at: Set(Some(ended)),
            ..Default::default()
        }
        .insert(db.write())
        .await
        .unwrap();
        assert_eq!(
            handle.terminal_exit().await.unwrap(),
            Some(SandboxRunExit {
                run_id: first.id,
                exit_code: Some(0),
                signal: None,
                reason: Some(SandboxTerminationReason::IdleTimeout),
                terminated_at: Some(ended.and_utc()),
            })
        );

        // A newer execution must hide the old idle-timeout result, even if
        // the sandbox row has not yet transitioned out of Stopped.
        let next = run::ActiveModel {
            sandbox_id: Set(record.id),
            status: Set(run::RunStatus::Running),
            ..Default::default()
        }
        .insert(db.write())
        .await
        .unwrap();
        assert_eq!(handle.terminal_exit().await.unwrap(), None);

        let mut next: run::ActiveModel = next.into();
        next.status = Set(run::RunStatus::Terminated);
        next.exit_code = Set(Some(17));
        next.termination_reason = Set(Some(SandboxTerminationReason::Failed));
        next.update(db.write()).await.unwrap();

        let result = handle.terminal_exit().await.unwrap().unwrap();
        assert_eq!(result.exit_code, Some(17));
        assert_eq!(result.reason, Some(SandboxTerminationReason::Failed));

        let mut active: sandbox::ActiveModel = record.clone().into();
        active.status = Set(SandboxStatus::Starting);
        active.update(db.write()).await.unwrap();
        assert_eq!(handle.terminal_exit().await.unwrap(), None);

        sandbox::Entity::delete_by_id(record.id)
            .exec(db.write())
            .await
            .unwrap();
        assert!(matches!(
            handle.terminal_exit().await,
            Err(MicrosandboxError::SandboxNotFound(_))
        ));

        sandbox::ActiveModel {
            id: Set(record.id + 10),
            name: Set(config.spec.name.clone()),
            config: Set(serde_json::to_string(&config).unwrap()),
            status: Set(SandboxStatus::Stopped),
            ephemeral: Set(false),
            ..Default::default()
        }
        .insert(db.write())
        .await
        .unwrap();
        assert!(matches!(
            handle.terminal_exit().await,
            Err(MicrosandboxError::SandboxReplaced { .. })
        ));
    }
}

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use crate::db::entity::run::TerminationReason as SandboxTerminationReason;
