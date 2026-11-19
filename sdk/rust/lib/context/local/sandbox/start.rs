//! Real-VM admission after an exact recorded process identity no longer exists.

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::{
        process::{Command, Stdio},
        sync::Arc,
    };

    use sea_orm::{EntityTrait, Set};

    use super::super::LocalContext;
    use crate::db::entity::run;
    use crate::runtime::SpawnMode;
    use crate::sandbox::SandboxBuilder;
    use crate::sandbox::SandboxStatus;

    #[derive(Clone, Copy, PartialEq)]
    enum Operation {
        StartActive,
        StartTerminal,
        Replace,
        EnsureRunning,
        Shell,
    }

    // Exercise the real launch and disk handoff against a private catalog. The
    // short-lived fixture child remains ours throughout, including on failure.
    async fn launch_after_reuse(op: Operation) {
        let home = tempfile::tempdir_in("/tmp").unwrap();
        let backend = Arc::new(
            crate::test_support::local_backend_builder(home.path())
                .build()
                .unwrap(),
        );
        // CI supplies the built runtime pair; private catalogs do not inherit its install.
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
                .image("mirror.gcr.io/library/alpine")
                .cpus(1)
                .memory(256)
        };
        let first = backend
            .create_sandbox(backend.clone(), builder(), SpawnMode::Attached, None)
            .await
            .unwrap();
        let id = first.local_state().unwrap().db_id;
        first.stop().await.unwrap();

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

        let old_run = run::Entity::find_by_id(old)
            .one(pools.read())
            .await
            .unwrap()
            .unwrap();
        super::super::process_record::tests::model_reused_pid(&backend, &old_run).await;

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
            Operation::EnsureRunning | Operation::Shell => {
                let sandbox = crate::Sandbox::ctx(backend.as_ref())
                    .get(name)
                    .await
                    .unwrap();
                if op == Operation::EnsureRunning {
                    sandbox.ensure_running().await.unwrap();
                } else {
                    assert_eq!(
                        sandbox
                            .shell("printf ready")
                            .await
                            .unwrap()
                            .stdout()
                            .unwrap(),
                        "ready"
                    );
                }
                Ok(sandbox)
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
        // A retained receiver from the old run cannot clean up the new generation.
        drop(first);
        assert_eq!(
            next.shell("printf ready").await.unwrap().stdout().unwrap(),
            "ready"
        );
        next.stop().await.unwrap();
        let finished = LocalContext::load_latest_run(pools.read(), next_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            finished.pid, None,
            "completed VM must retire its PID with the identity"
        );
        assert!(matches!(
            super::super::process_record::ProcessRecord::load(pools.read(), &finished)
                .await
                .unwrap(),
            super::super::process_record::LoadedProcessRecord::Missing { .. }
        ));
        assert!(child.try_wait().unwrap().is_none());
    }

    #[tokio::test]
    #[ignore = "requires a local VM runtime"]
    async fn fresh_start_after_pid_reuse_with_active_row() {
        launch_after_reuse(Operation::StartActive).await
    }

    #[tokio::test]
    #[ignore = "requires a local VM runtime"]
    async fn fresh_start_after_pid_reuse_with_terminal_row() {
        launch_after_reuse(Operation::StartTerminal).await
    }

    #[tokio::test]
    #[ignore = "requires a local VM runtime"]
    async fn replace_after_pid_reuse() {
        launch_after_reuse(Operation::Replace).await
    }
    #[tokio::test]
    #[ignore = "requires a local VM runtime"]
    async fn ensure_running_after_pid_reuse() {
        launch_after_reuse(Operation::EnsureRunning).await;
    }

    #[tokio::test]
    #[ignore = "requires a local VM runtime"]
    async fn shell_after_pid_reuse() {
        launch_after_reuse(Operation::Shell).await;
    }
}
