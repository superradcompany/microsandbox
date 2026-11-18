//! Admission of a fresh local run after Linux has reused the catalog PID.

use super::{LocalContext, RecordedRuntime, sandbox_entity};
use crate::MicrosandboxResult;
use crate::sandbox::{SandboxStatus, load_sandbox_record};
use microsandbox_db::pool::DbPools;

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl LocalContext {
    pub(super) async fn start_endpoint_is_live(&self, name: &str) -> MicrosandboxResult<bool> {
        Ok(
            microsandbox_runtime::ipc::SandboxSocketPaths::in_sandboxes_dir(
                &self.config().run_dir(),
                &self.sandboxes_dir(),
                name,
            )
            .may_be_live()
            .await?,
        )
    }

    /// The caller owns the transition guard and has validated the sandbox identity.
    pub(super) async fn recover_recycled_start(
        &self,
        pools: &DbPools,
        model: sandbox_entity::Model,
    ) -> MicrosandboxResult<sandbox_entity::Model> {
        if !matches!(
            model.status,
            SandboxStatus::Starting | SandboxStatus::Running | SandboxStatus::Draining
        ) {
            return Ok(model);
        }
        let run_dir = self.config().run_dir();
        let Some(_guard) =
            microsandbox_runtime::ipc::try_acquire_lifecycle_guard(&run_dir, &model.name)?
        else {
            return Ok(model);
        };
        let Some(run) = Self::load_active_run(pools.read(), model.id).await? else {
            return Ok(model);
        };
        let lifecycle = microsandbox_runtime::ipc::lifecycle_lock_path(&run_dir, &model.name);
        if !matches!(
            Self::recorded_runtime(Some(&run), &lifecycle),
            RecordedRuntime::Recycled
        ) || self.start_endpoint_is_live(&model.name).await?
        {
            return Ok(model);
        }
        // Retire the old generation only after both ownership guards and the
        // legacy endpoint check agree. Unknown identities keep blocking start.
        let (status, reason) = Self::stale_runtime_terminal_state(model.status);
        Self::mark_sandbox_runtime_stale(pools.write(), model.id, Some(run.id), status, reason)
            .await?;
        load_sandbox_record(pools.read(), &model.name).await
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use sea_orm::{EntityTrait, Set};
    use std::{
        process::{Command, Stdio},
        sync::Arc,
    };

    use super::*;
    use crate::db::entity::run;
    use crate::runtime::SpawnMode;
    use crate::sandbox::SandboxBuilder;

    #[derive(Clone, Copy, PartialEq)]
    enum Operation {
        StartActive,
        StartTerminal,
        Replace,
    }

    // Exercise the real launch and disk handoff against a private catalog. The
    // short-lived fixture child remains ours throughout, including on failure.
    async fn launch_after_reuse(op: Operation) {
        let home = tempfile::tempdir().unwrap();
        let backend = Arc::new(
            crate::test_support::local_backend_builder(home.path())
                .build()
                .unwrap(),
        );
        // Hosted CI supplies the candidate runtime separately from this private catalog.
        // Direct runs can also provide the two individual runtime path overrides.
        if let Some(directory) = std::env::var_os("MSB_TEST_RUNTIME_DIR") {
            crate::setup::install_runtime(
                backend.config(),
                crate::setup::InstallOptions {
                    source: crate::setup::InstallSource::Directory(directory.into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        }
        let name = "pid-reuse";
        let builder = || {
            SandboxBuilder::new(name)
                .image("alpine")
                .cpus(1)
                .memory(256)
        };
        let first = backend
            .create_sandbox(backend.clone(), builder(), SpawnMode::Attached, None)
            .await
            .unwrap();
        let id = first.local_state().unwrap().db_id;
        first.stop_and_wait().await.unwrap();
        drop(first);

        let mut child = scopeguard::guard(
            Command::new("cat").stdin(Stdio::piped()).spawn().unwrap(),
            |mut child| {
                drop(child.stdin.take());
                let _ = child.wait();
            },
        );
        let pools = backend.db().await.unwrap();
        // The process was born after the recorded generation. Keep both alive
        // during the assertion, without depending on kernel PID allocation order.
        let active = op != Operation::StartTerminal;
        let old = run::Entity::insert(run::ActiveModel {
            sandbox_id: Set(id),
            pid: Set(Some(child.id() as i32)),
            started_at: Set(Some(
                (chrono::Utc::now() - chrono::TimeDelta::hours(1)).naive_utc(),
            )),
            status: Set(if active {
                run::RunStatus::Running
            } else {
                run::RunStatus::Terminated
            }),
            ..Default::default()
        })
        .exec(pools.write())
        .await
        .unwrap()
        .last_insert_id;
        if active {
            LocalContext::update_sandbox_status(pools.write(), id, SandboxStatus::Running)
                .await
                .unwrap();
        }

        let next = match op {
            Operation::Replace => {
                backend
                    .create_sandbox(
                        backend.clone(),
                        builder().replace(),
                        SpawnMode::Attached,
                        None,
                    )
                    .await
            }
            _ => {
                backend
                    .start_sandbox(backend.clone(), name, Some(id), SpawnMode::Attached)
                    .await
            }
        }
        .unwrap();
        assert!(child.try_wait().unwrap().is_none());
        let next_id = next.local_state().unwrap().db_id;
        if op == Operation::Replace {
            assert_ne!(id, next_id);
        } else {
            assert_eq!(id, next_id);
            assert_eq!(
                run::Entity::find_by_id(old)
                    .one(pools.read())
                    .await
                    .unwrap()
                    .unwrap()
                    .status,
                run::RunStatus::Terminated
            );
        }
        assert_eq!(
            next.shell("printf ready").await.unwrap().stdout().unwrap(),
            "ready"
        );
        next.stop_and_wait().await.unwrap();
        assert!(child.try_wait().unwrap().is_none());
    }

    #[tokio::test]
    #[ignore = "requires Linux KVM and the matching runtime"]
    async fn fresh_start_after_pid_reuse_with_active_row() {
        launch_after_reuse(Operation::StartActive).await
    }

    #[tokio::test]
    #[ignore = "requires Linux KVM and the matching runtime"]
    async fn fresh_start_after_pid_reuse_with_terminal_row() {
        launch_after_reuse(Operation::StartTerminal).await
    }

    #[tokio::test]
    #[ignore = "requires Linux KVM and the matching runtime"]
    async fn replace_after_pid_reuse() {
        launch_after_reuse(Operation::Replace).await
    }
}
