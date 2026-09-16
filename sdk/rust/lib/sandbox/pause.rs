//! Resident pause/resume through the existing host control endpoint.

use microsandbox_runtime::control::ControlRequest;

use crate::backend::sandbox::SandboxIdentity;
use crate::backend::{Backend, LocalBackend};
use crate::error::Operation;
use crate::{MicrosandboxError, MicrosandboxResult};

use super::{Sandbox, SandboxHandle, SandboxPauseState, modify};

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Sandbox {
    /// Internal CLI lookup for an immediately following authoritative control mutation.
    ///
    /// Keep database/runtime reconciliation, but skip the pause observation used by ordinary
    /// `get`/`list`: that observation is already stale by the time the mutation executes.
    #[doc(hidden)]
    pub async fn get_for_control(name: &str) -> MicrosandboxResult<SandboxHandle> {
        let backend = crate::backend::default_backend();
        if let Some(local) = backend.as_local() {
            let (model, pid) = match local.try_control_handle_state(name).await? {
                Some(target) => target,
                None => local.sandbox_handle_state(name, None).await?,
            };
            return Ok(SandboxHandle::from_local_model(backend, model, pid));
        }
        backend.sandboxes().get(backend.clone(), name).await
    }

    /// Suspend this resident VM without creating a snapshot or releasing RAM.
    pub async fn pause(&self) -> MicrosandboxResult<()> {
        lifecycle(
            self.name(),
            self.identity(),
            self.backend().as_ref(),
            ControlRequest::Pause,
        )
        .await
        .map(|_| ())
    }

    /// Resume the same VM and processes, correcting wall clock before thawing workloads.
    pub async fn resume(&self) -> MicrosandboxResult<()> {
        lifecycle(
            self.name(),
            self.identity(),
            self.backend().as_ref(),
            ControlRequest::Resume,
        )
        .await
        .map(|_| ())
    }

    /// Inspect the host-confirmed pause state without contacting the suspended guest.
    pub async fn pause_state(&self) -> MicrosandboxResult<SandboxPauseState> {
        lifecycle(
            self.name(),
            self.identity(),
            self.backend().as_ref(),
            ControlRequest::PauseState,
        )
        .await
    }
}

impl SandboxHandle {
    /// Suspend an existing resident sandbox without connecting to its guest.
    pub async fn pause(&self) -> MicrosandboxResult<()> {
        lifecycle(
            self.name(),
            self.identity(),
            self.backend.as_ref(),
            ControlRequest::Pause,
        )
        .await
        .map(|_| ())
    }

    /// Resume an existing user-paused sandbox through host control.
    pub async fn resume(&self) -> MicrosandboxResult<()> {
        lifecycle(
            self.name(),
            self.identity(),
            self.backend.as_ref(),
            ControlRequest::Resume,
        )
        .await
        .map(|_| ())
    }

    /// Inspect resident suspension without opening an agent connection.
    pub async fn pause_state(&self) -> MicrosandboxResult<SandboxPauseState> {
        lifecycle(
            self.name(),
            self.identity(),
            self.backend.as_ref(),
            ControlRequest::PauseState,
        )
        .await
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Overlay resident suspension on database lifecycle without persisting a stale pause on crash.
pub(crate) async fn projected_status(
    local: &LocalBackend,
    name: &str,
    status: super::SandboxStatus,
) -> super::SandboxStatus {
    if status != super::SandboxStatus::Running {
        return status;
    }
    // Old runtimes have no pause endpoint. Bound observation so a busy or unavailable host
    // never makes ordinary list/get wait for an entire checkpoint operation.
    let request = modify::control_request_for(local, name, "{\"op\":\"pause_state\"}\n".into());
    match tokio::time::timeout(std::time::Duration::from_millis(250), request).await {
        Ok(Ok(response))
            if response
                .pause
                .as_ref()
                .is_some_and(|state| state.paused || state.recovery_required) =>
        {
            super::SandboxStatus::Paused
        }
        _ => status,
    }
}

async fn lifecycle(
    name: &str,
    identity: SandboxIdentity,
    backend: &dyn Backend,
    request: ControlRequest,
) -> MicrosandboxResult<SandboxPauseState> {
    let operation = if matches!(request, ControlRequest::Resume) {
        Operation::SandboxResume
    } else {
        Operation::SandboxPause
    };
    let local = backend
        .as_local()
        .ok_or_else(|| MicrosandboxError::local_only(operation))?;
    let SandboxIdentity::Local(expected_id) = identity else {
        return Err(MicrosandboxError::local_only(operation));
    };
    let _transition =
        LocalBackend::acquire_sandbox_transition_guard(&local.config().run_dir(), name).await?;
    let run = local.control_run_identity(name, expected_id).await?;
    // The mutation itself is authoritative. Unknown operations fail on older runtimes, and
    // successful replies must carry pause state; neither case can silently become a no-op.
    let line = format!("{}\n", serde_json::to_string(&request)?);
    let response = modify::control_request_for_run(local, name, run, line).await?;
    let state = response
        .pause
        .ok_or_else(|| MicrosandboxError::Runtime("control response omitted pause state".into()))?;
    // An acknowledgement must confirm the requested transition, not just contain some
    // observation. State inspection itself must still be able to report recovery required.
    let expected = match request {
        ControlRequest::Pause => Some(true),
        ControlRequest::Resume => Some(false),
        _ => None,
    };
    if expected.is_some_and(|paused| state.paused != paused || state.recovery_required) {
        return Err(MicrosandboxError::Runtime(
            "control response did not confirm the requested pause transition".into(),
        ));
    }
    Ok(state)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, unix))]
mod tests {
    use std::sync::Arc;

    use sea_orm::{EntityTrait, Set};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    use super::*;
    use crate::backend::with_backend;

    async fn seed_run(local: &LocalBackend, name: &str) -> i32 {
        use crate::db::entity::{run, sandbox};
        let db = local.db().await.unwrap();
        let id = sandbox::Entity::insert(sandbox::ActiveModel {
            name: Set(name.into()),
            config: Set("{}".into()),
            status: Set(super::super::SandboxStatus::Running),
            ephemeral: Set(false),
            ..Default::default()
        })
        .exec(db.write())
        .await
        .unwrap()
        .last_insert_id;
        run::Entity::insert(run::ActiveModel {
            sandbox_id: Set(id),
            pid: Set(Some(std::process::id() as i32)),
            status: Set(run::RunStatus::Running),
            ..Default::default()
        })
        .exec(db.write())
        .await
        .unwrap();
        id
    }

    #[tokio::test]
    async fn pause_observation_uses_bound_backend_outside_its_ambient_scope() {
        // macOS's per-user TMPDIR may already consume most of the Unix socket path limit.
        let ambient_home = tempfile::tempdir_in("/tmp").unwrap();
        let bound_home = tempfile::tempdir_in("/tmp").unwrap();
        let ambient: Arc<dyn Backend> = Arc::new(
            LocalBackend::builder()
                .home(ambient_home.path())
                .build()
                .await
                .unwrap(),
        );
        let bound = LocalBackend::builder()
            .home(bound_home.path())
            .build()
            .await
            .unwrap();
        let id = seed_run(&bound, "same-name").await;
        let agent =
            crate::runtime::sandbox_agent_socket_path_candidates_for(&bound, "same-name").remove(0);
        let path = microsandbox_runtime::control::control_socket_path_for(&agent);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let listener = tokio::net::UnixListener::bind(path).unwrap();
        let server = tokio::spawn(async move {
            // Each observation is one exchange; it needs no capabilities preflight.
            for _ in 0..2 {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = BufReader::new(stream);
                let mut line = String::new();
                stream.read_line(&mut line).await.unwrap();
                assert_eq!(line, "{\"op\":\"pause_state\"}\n");
                let response = "{\"ok\":true,\"pause\":{\"paused\":true,\"recovery_required\":false,\"capture_unavailable\":null}}\n";
                stream
                    .get_mut()
                    .write_all(response.as_bytes())
                    .await
                    .unwrap();
            }
        });
        with_backend(ambient, async {
            assert_eq!(
                projected_status(&bound, "same-name", super::super::SandboxStatus::Running).await,
                super::super::SandboxStatus::Paused
            );
            assert!(
                lifecycle(
                    "same-name",
                    SandboxIdentity::Local(id),
                    &bound,
                    ControlRequest::PauseState
                )
                .await
                .unwrap()
                .paused
            );
        })
        .await;
        server.await.unwrap();
    }

    #[tokio::test]
    async fn lifecycle_sends_one_mutation_and_requires_an_authoritative_reply() {
        for (operation, response, accepted) in [
            (
                "pause",
                "{\"ok\":true,\"pause\":{\"paused\":true,\"recovery_required\":false}}\n",
                true,
            ),
            (
                "resume",
                "{\"ok\":true,\"pause\":{\"paused\":false,\"recovery_required\":false}}\n",
                true,
            ),
            // Old runtime unknown-operation errors and unsupported current kernels must fail.
            (
                "pause",
                "{\"ok\":false,\"error\":\"unknown variant pause\"}\n",
                false,
            ),
            (
                "resume",
                "{\"ok\":false,\"error\":\"pause/resume unavailable\"}\n",
                false,
            ),
            ("resume", "{\"ok\":true}\n", false),
            (
                "pause",
                "{\"ok\":true,\"pause\":{\"paused\":false,\"recovery_required\":false}}\n",
                false,
            ),
            (
                "resume",
                "{\"ok\":true,\"pause\":{\"paused\":true,\"recovery_required\":false}}\n",
                false,
            ),
            (
                "pause",
                "{\"ok\":true,\"pause\":{\"paused\":true,\"recovery_required\":true}}\n",
                false,
            ),
        ] {
            let home = tempfile::tempdir_in("/tmp").unwrap();
            let backend = LocalBackend::builder()
                .home(home.path())
                .build()
                .await
                .unwrap();
            let id = seed_run(&backend, "source").await;
            let agent =
                crate::runtime::sandbox_agent_socket_path_candidates_for(&backend, "source")
                    .remove(0);
            let path = microsandbox_runtime::control::control_socket_path_for(&agent);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            let listener = tokio::net::UnixListener::bind(path).unwrap();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = BufReader::new(stream);
                let mut line = String::new();
                stream.read_line(&mut line).await.unwrap();
                assert_eq!(line, format!("{{\"op\":\"{operation}\"}}\n"));
                stream
                    .get_mut()
                    .write_all(response.as_bytes())
                    .await
                    .unwrap();
            });
            let request = if operation == "pause" {
                ControlRequest::Pause
            } else {
                ControlRequest::Resume
            };
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                lifecycle("source", SandboxIdentity::Local(id), &backend, request),
            )
            .await
            .unwrap();
            assert_eq!(result.is_ok(), accepted, "{operation}: {response}");
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn stale_receiver_refuses_pause_resume_and_branch_before_control_connect() {
        use crate::db::entity::sandbox;
        let home = tempfile::tempdir_in("/tmp").unwrap();
        let backend = Arc::new(
            LocalBackend::builder()
                .home(home.path())
                .build()
                .await
                .unwrap(),
        );
        let old_id = seed_run(&backend, "reused").await;
        let model = sandbox::Entity::find_by_id(old_id)
            .one(backend.db().await.unwrap().read())
            .await
            .unwrap()
            .unwrap();
        let stale = SandboxHandle::from_local_model(
            backend.clone(),
            model,
            Some(std::process::id() as i32),
        );
        let (client_io, mut server_io) = tokio::io::duplex(4096);
        let handshake = tokio::spawn(async move {
            use microsandbox_protocol::{
                codec,
                core::Ready,
                message::{Message, MessageType},
            };
            server_io.write_all(&1u32.to_be_bytes()).await.unwrap();
            server_io.write_all(&1024u32.to_be_bytes()).await.unwrap();
            codec::write_message(
                &mut server_io,
                &Message::with_payload(MessageType::Ready, 0, &Ready::default()).unwrap(),
            )
            .await
            .unwrap();
        });
        let client = crate::agent::AgentClient::connect_stream_with_timeout(
            client_io,
            std::time::Duration::from_secs(1),
        )
        .await
        .unwrap();
        handshake.await.unwrap();
        let mut config = super::super::SandboxConfig::default();
        config.spec.name = "reused".into();
        let live = Sandbox::from_local(
            backend.clone(),
            crate::backend::SandboxLocalState {
                db_id: old_id,
                handle: None,
                client: Arc::new(client),
            },
            config,
        );
        sandbox::Entity::delete_by_id(old_id)
            .exec(backend.db().await.unwrap().write())
            .await
            .unwrap();
        let replacement_id = seed_run(&backend, "reused").await;
        assert_ne!(old_id, replacement_id);
        for result in [
            stale.pause().await,
            stale.resume().await,
            stale.pause_state().await.map(|_| ()),
        ] {
            assert!(matches!(
                result,
                Err(MicrosandboxError::SandboxReplaced { .. })
            ));
        }
        assert!(matches!(
            stale.branch("child").branch().await,
            Err(MicrosandboxError::SandboxReplaced { .. })
        ));
        for result in [
            live.pause().await,
            live.resume().await,
            live.pause_state().await.map(|_| ()),
        ] {
            assert!(matches!(
                result,
                Err(MicrosandboxError::SandboxReplaced { .. })
            ));
        }
        assert!(matches!(
            live.branch("child").branch().await,
            Err(MicrosandboxError::SandboxReplaced { .. })
        ));
        assert!(!backend.sandboxes_dir().join("child").exists());
    }

    #[tokio::test]
    async fn control_peer_mismatch_sends_no_mutation() {
        let home = tempfile::tempdir_in("/tmp").unwrap();
        let backend = LocalBackend::builder()
            .home(home.path())
            .build()
            .await
            .unwrap();
        let agent =
            crate::runtime::sandbox_agent_socket_path_candidates_for(&backend, "source").remove(0);
        let path = microsandbox_runtime::control::control_socket_path_for(&agent);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let listener = tokio::net::UnixListener::bind(path).unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut line = String::new();
            assert_eq!(
                BufReader::new(stream).read_line(&mut line).await.unwrap(),
                0
            );
        });
        let result = modify::control_request_for_run(
            &backend,
            "source",
            super::super::identity::SandboxRunIdentity {
                sandbox_id: 1,
                run_id: 1,
                pid: std::process::id() as i32 + 1,
            },
            "{\"op\":\"pause\"}\n".into(),
        )
        .await;
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("control endpoint belongs to pid")
        );
        server.await.unwrap();
    }
}
