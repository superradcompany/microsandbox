//! OCI lifecycle orchestration backed by Microsandbox.

use std::path::PathBuf;

use anyhow::{Result, anyhow, bail};
use chrono::Utc;
use microsandbox::sandbox::{Sandbox, SandboxStatus};
use microsandbox_runtime::oci::{
    OciBundle, OciOperation, OciState, OciStateStore, OciStatus, next_status,
    sandbox_name_for_container,
};

use crate::console::open_console_bridge;
use crate::options::{CreateOptions, DeleteOptions, ExecOptions, KillOptions};
use crate::process::{
    HostSignalForwarder, load_process, parse_signal, start_process_stream, wait_for_process_exit,
    write_exec_pid_file,
};
use crate::requests::{
    OCI_SIGNAL_REQUEST, OCI_START_REQUEST, ensure_vmm_process_alive, publish_signal_request,
    publish_start_request, read_init_session_id, stop_sandbox_for_delete, wait_for_init_exit,
    wait_for_init_session_id,
};
use crate::sandbox::{
    create_sandbox_for_bundle, requires_fresh_network_namespace, resolve_created_sandbox_host_pid,
    sandbox_host_pid_from_handle,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Host-side OCI runtime implementation backed by Microsandbox.
#[derive(Debug, Clone)]
pub struct MicrosandboxOciRuntime {
    store: OciStateStore,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl MicrosandboxOciRuntime {
    /// Create an OCI runtime wrapper using the supplied `--root` directory.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            store: OciStateStore::new(root),
        }
    }

    /// Create the Microsandbox-backed OCI container environment.
    pub async fn create(&self, options: CreateOptions) -> Result<()> {
        let bundle = OciBundle::load(&options.bundle)?;
        if bundle
            .process()
            .is_some_and(|process| process.terminal() == Some(true))
            && options.console.is_none()
        {
            bail!("terminal process requires an OCI console socket");
        }
        let _lock = crate::lock::acquire(&self.store, &options.id).await?;
        let mut state = self.store.create_created(&options.id, &bundle)?;

        let state_dir = self.store.container_dir(&options.id)?;
        let result: Result<()> = async {
            let sandbox =
                create_sandbox_for_bundle(&options.id, &bundle, &state_dir, options.console)
                    .await?;
            state.pid = Some(
                resolve_created_sandbox_host_pid(&options.id, &sandbox)
                    .await
                    .ok_or_else(|| anyhow!("container has no VMM host PID"))?,
            );
            self.store.save(&state)?;
            sandbox.detach().await;
            Ok(())
        }
        .await;
        if result.is_err() {
            // Retain state if teardown fails: never hide a potentially live VM.
            stop_sandbox_for_delete(&options.id).await?;
            if let Ok(handle) = Sandbox::get(&sandbox_name_for_container(&options.id)).await {
                handle.remove().await?;
            }
            self.store.delete(&options.id)?;
        }
        result
    }

    /// Record the host process PID Docker/containerd should track for the OCI container.
    pub fn record_host_pid(&self, id: &str, pid: i32) -> Result<()> {
        let mut state = self.store.load(id)?;
        state.pid = Some(pid);
        self.store.save(&state)?;
        Ok(())
    }

    /// Return whether the OCI bundle asks for a fresh network namespace.
    pub fn requires_fresh_network_namespace(&self, id: &str) -> Result<bool> {
        let state = self.store.load(id)?;
        let bundle = OciBundle::load(&state.bundle)?;
        Ok(requires_fresh_network_namespace(&bundle))
    }

    /// Start the configured OCI init process.
    pub async fn start(&self, id: &str) -> Result<()> {
        let _lock = crate::lock::acquire(&self.store, id).await?;
        let mut state = self.store.load(id)?;
        OciOperation::Start.validate(&state)?;

        let host_pid = state
            .pid
            .or(sandbox_host_pid_from_handle(id).await)
            .ok_or_else(|| anyhow!("container `{id}` has no Microsandbox host PID"))?;
        ensure_vmm_process_alive(id, host_pid)?;

        let start_request = self.store.container_dir(id)?.join(OCI_START_REQUEST);
        publish_start_request(&start_request)?;
        let session_id = match wait_for_init_session_id(&self.store, id, host_pid).await {
            Ok(session_id) => session_id,
            Err(error) => {
                let _ = std::fs::remove_file(start_request);
                return Err(error);
            }
        };

        state.mark_running(host_pid, None, Some(session_id), Utc::now());
        self.store.save(&state)?;
        Ok(())
    }

    /// Wait for the OCI init process and its VMM to exit, returning the init exit code.
    pub async fn wait(&self, id: &str) -> Result<i32> {
        let state = self.store.load(id)?;
        if state.status != microsandbox_runtime::oci::OciStatus::Running {
            bail!(
                "cannot wait for container `{id}` while it is {:?}",
                state.status
            );
        }

        let exit_code = wait_for_init_exit(&self.store, id).await?;
        if let Ok(handle) = Sandbox::get(&sandbox_name_for_container(id)).await {
            handle.wait_until_stopped().await?;
        }

        let mut state = self.store.load(id)?;
        state.mark_stopped(Some(exit_code), Utc::now());
        self.store.save(&state)?;
        Ok(exit_code)
    }

    /// Run an additional OCI process in a running container.
    pub async fn exec(&self, options: ExecOptions) -> Result<i32> {
        self.exec_with_console(options, None).await
    }

    /// Run an additional OCI process attached to an OCI console socket bridge.
    pub async fn exec_console(&self, options: ExecOptions, console_slave: PathBuf) -> Result<i32> {
        self.exec_with_console(options, Some(console_slave)).await
    }

    /// Send a signal to the OCI init process inside the guest.
    pub async fn kill(&self, options: KillOptions) -> Result<()> {
        if options.all {
            bail!("kill --all is not implemented");
        }
        let _lock = crate::lock::acquire(&self.store, &options.id).await?;
        let signal = parse_signal(&options.signal)?;
        let state = if signal == 0 || signal == libc::SIGKILL {
            self.store.load(&options.id)?
        } else {
            self.state(&options.id).await?
        };
        OciOperation::Kill.validate(&state)?;
        let pid = state
            .pid
            .ok_or_else(|| anyhow!("container has no VMM host PID"))?;
        ensure_vmm_process_alive(&options.id, pid)?;
        if signal == 0 {
            return Ok(());
        }
        let mut state = state;
        if signal == libc::SIGKILL {
            stop_sandbox_for_delete(&options.id).await?;
            state.mark_stopped(Some(128 + signal), Utc::now());
            self.store.save(&state)?;
            return Ok(());
        }
        if state
            .microsandbox
            .as_ref()
            .and_then(|msb| msb.init_exec_session_id)
            .is_none()
            && let Ok(session_id) = read_init_session_id(&self.store, &options.id)
            && let Some(msb) = state.microsandbox.as_mut()
        {
            msb.init_exec_session_id = Some(session_id);
        }
        if state
            .microsandbox
            .as_ref()
            .and_then(|msb| msb.init_exec_session_id)
            .is_none()
        {
            stop_sandbox_for_delete(&options.id).await?;
            state.mark_stopped(Some(128 + signal), Utc::now());
            self.store.save(&state)?;
            return Ok(());
        }
        publish_signal_request(
            &self
                .store
                .container_dir(&options.id)?
                .join(OCI_SIGNAL_REQUEST),
            signal,
        )?;
        Ok(())
    }

    /// Delete OCI and Microsandbox state.
    pub async fn delete(&self, options: DeleteOptions) -> Result<()> {
        let _lock = crate::lock::acquire(&self.store, &options.id).await?;
        let mut state = if options.force {
            self.store.load(&options.id)?
        } else {
            self.state(&options.id).await?
        };
        if options.force {
            stop_sandbox_for_delete(&options.id).await?;
            state.mark_stopped(None, Utc::now());
            self.store.save(&state)?;
        } else {
            OciOperation::Delete.validate(&state)?;
        }

        if let Ok(handle) = Sandbox::get(&sandbox_name_for_container(&options.id)).await {
            let refreshed = handle.refresh().await.unwrap_or(handle);
            if !matches!(
                refreshed.status_snapshot(),
                SandboxStatus::Stopped | SandboxStatus::Crashed
            ) {
                bail!(
                    "cannot delete running Microsandbox sandbox `{}`",
                    refreshed.name()
                );
            }
            refreshed.remove().await?;
        }

        self.store.delete(&options.id)?;
        Ok(())
    }

    /// Return OCI state, refreshing terminal status from Microsandbox when possible.
    pub async fn state(&self, id: &str) -> Result<OciState> {
        let mut state = self.store.load(id)?;
        if state
            .pid
            .is_some_and(|pid| ensure_vmm_process_alive(id, pid).is_err())
        {
            state.mark_stopped(None, Utc::now());
            return Ok(state);
        }
        if let Ok(handle) = Sandbox::get(&sandbox_name_for_container(id)).await {
            if let Some(local) = handle.local()
                && state.pid.is_none()
            {
                state.pid = local.pid;
            }
            if matches!(
                handle.status_snapshot(),
                SandboxStatus::Stopped | SandboxStatus::Crashed
            ) && !state.status.is_terminal()
            {
                state.mark_stopped(None, Utc::now());
            }
            if matches!(state.status, OciStatus::Running | OciStatus::Paused) {
                let pause = match handle.pause_state().await {
                    Ok(pause) => pause,
                    Err(_)
                        if state
                            .pid
                            .is_some_and(|pid| ensure_vmm_process_alive(id, pid).is_err()) =>
                    {
                        state.mark_stopped(None, Utc::now());
                        return Ok(state);
                    }
                    Err(error) => return Err(error.into()),
                };
                state.status = if pause.paused || pause.recovery_required {
                    OciStatus::Paused
                } else {
                    OciStatus::Running
                };
            }
        }
        if state
            .pid
            .is_some_and(|pid| ensure_vmm_process_alive(id, pid).is_err())
            && !state.status.is_terminal()
        {
            state.mark_stopped(None, Utc::now());
        }
        Ok(state)
    }

    /// Suspend the resident VM through its host control endpoint.
    pub async fn pause(&self, id: &str) -> Result<()> {
        self.change_pause_state(id, OciOperation::Pause, async {
            Sandbox::get_for_control(&sandbox_name_for_container(id))
                .await?
                .pause()
                .await?;
            Ok(())
        })
        .await
    }

    /// Resume the same VM and guest processes through host control.
    pub async fn resume(&self, id: &str) -> Result<()> {
        self.change_pause_state(id, OciOperation::Resume, async {
            Sandbox::get_for_control(&sandbox_name_for_container(id))
                .await?
                .resume()
                .await?;
            Ok(())
        })
        .await
    }

    async fn change_pause_state(
        &self,
        id: &str,
        operation: OciOperation,
        request: impl std::future::Future<Output = Result<()>>,
    ) -> Result<()> {
        let _lock = crate::lock::acquire(&self.store, id).await?;
        let mut state = self.store.load(id)?;
        let status = next_status(operation, &state)?;
        // The SDK checks the VMM acknowledgement before we persist the transition.
        request.await?;
        state.status = status;
        self.store.save(&state)?;
        Ok(())
    }

    async fn exec_with_console(
        &self,
        options: ExecOptions,
        console_slave: Option<PathBuf>,
    ) -> Result<i32> {
        let state = self.state(&options.id).await?;
        OciOperation::Exec.validate(&state)?;
        let mut host_signals = HostSignalForwarder::new()?;

        let process = load_process(&options.process)?;
        let bundle = OciBundle::load(&state.bundle)?;
        let sandbox = crate::process::connect_sandbox(&options.id).await?;
        let (started, mut handle) =
            match start_process_stream(&sandbox, &process, &bundle.rootfs_path()).await {
                Ok(started) => started,
                Err(error) => {
                    sandbox.detach().await;
                    return Err(error);
                }
            };
        let result = async {
            write_exec_pid_file(options.pid_file.as_deref(), &started)?;

            let console = console_slave
                .as_deref()
                .map(open_console_bridge)
                .transpose()?;
            let exit_code = wait_for_process_exit(
                &options.id,
                &mut handle,
                console.as_ref(),
                &mut host_signals,
            )
            .await?;
            Ok(exit_code)
        }
        .await;
        sandbox.detach().await;
        result
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use microsandbox_runtime::oci::MicrosandboxState;

    use super::*;

    fn runtime_with_state(root: &std::path::Path, status: OciStatus) -> MicrosandboxOciRuntime {
        let runtime = MicrosandboxOciRuntime::new(root);
        let mut state = OciState::created(
            "pause-test",
            "1.2.0",
            "/bundle",
            BTreeMap::new(),
            MicrosandboxState::new("oci-pause-test", root, "/rootfs", Utc::now()),
        );
        state.status = status;
        state.pid = Some(1234);
        std::fs::create_dir_all(runtime.store.container_dir(&state.id).unwrap()).unwrap();
        runtime.store.save(&state).unwrap();
        runtime
    }

    #[tokio::test]
    async fn dead_vmm_query_reports_stopped_without_overwriting_persisted_state() {
        let root = tempfile::tempdir().unwrap();
        let runtime = runtime_with_state(root.path(), OciStatus::Running);
        let mut state = runtime.store.load("pause-test").unwrap();
        state.pid = Some(i32::MAX);
        runtime.store.save(&state).unwrap();
        assert_eq!(
            runtime.state("pause-test").await.unwrap().status,
            OciStatus::Stopped
        );
        assert_eq!(runtime.store.load("pause-test").unwrap(), state);
    }

    #[tokio::test]
    async fn invalid_bundle_does_not_create_state() {
        let root = tempfile::tempdir().unwrap();
        let bundle = tempfile::tempdir().unwrap();
        std::fs::create_dir(bundle.path().join("rootfs")).unwrap();
        std::fs::write(
            bundle.path().join("config.json"),
            r#"{
            "ociVersion":"1.2.0","root":{"path":"rootfs"},
            "process":{"args":["/hello"],"cwd":"relative","user":{"uid":0,"gid":0}}
        }"#,
        )
        .unwrap();
        let runtime = MicrosandboxOciRuntime::new(root.path());
        let error = runtime
            .create(CreateOptions {
                id: "rejected".into(),
                bundle: bundle.path().into(),
                console: None,
            })
            .await
            .unwrap_err();
        assert!(error.to_string().contains("cwd"));
        assert!(!root.path().join("rejected").exists());
    }

    #[test]
    fn bundle_loading_accepts_pending_docker_controls() {
        let bundle = tempfile::tempdir().unwrap();
        std::fs::create_dir(bundle.path().join("rootfs")).unwrap();
        std::fs::write(
            bundle.path().join("config.json"),
            r#"{
                "ociVersion":"1.2.0","root":{"path":"rootfs","readonly":true},
                "process":{"args":["/hello"],"cwd":"/","user":{"uid":0,"gid":0},
                    "noNewPrivileges":true,"capabilities":{}},
                "linux":{"namespaces":[{"type":"network"}],
                    "resources":{"memory":{"limit":268435456}}},
                "mounts":[{"destination":"/tmp","type":"tmpfs","source":"tmpfs"}]
            }"#,
        )
        .unwrap();
        // Parsing these fields preserves compatibility; it does not enforce them.
        OciBundle::load(bundle.path()).unwrap();
    }

    #[tokio::test]
    async fn signal_zero_preserves_created_container_and_queues_nothing() {
        let root = tempfile::tempdir().unwrap();
        let runtime = runtime_with_state(root.path(), OciStatus::Created);
        let mut state = runtime.store.load("pause-test").unwrap();
        state.pid = Some(std::process::id() as i32);
        runtime.store.save(&state).unwrap();
        runtime
            .kill(KillOptions {
                id: "pause-test".into(),
                signal: "0".into(),
                all: false,
            })
            .await
            .unwrap();
        assert_eq!(runtime.store.load("pause-test").unwrap(), state);
        assert!(
            !runtime
                .store
                .container_dir("pause-test")
                .unwrap()
                .join(OCI_SIGNAL_REQUEST)
                .exists()
        );
    }

    #[tokio::test]
    async fn pause_resume_persist_only_after_acknowledgement() {
        let root = tempfile::tempdir().unwrap();
        let runtime = runtime_with_state(root.path(), OciStatus::Running);
        for (operation, before, after) in [
            (OciOperation::Pause, OciStatus::Running, OciStatus::Paused),
            (OciOperation::Resume, OciStatus::Paused, OciStatus::Running),
        ] {
            runtime
                .change_pause_state("pause-test", operation, async {
                    assert_eq!(runtime.store.load("pause-test")?.status, before);
                    Ok(())
                })
                .await
                .unwrap();
            let state = runtime.store.load("pause-test").unwrap();
            assert_eq!(state.status, after);
            assert_eq!(state.pid, Some(1234));
        }
    }

    #[tokio::test]
    async fn rejected_host_requests_preserve_state() {
        for (operation, status) in [
            (OciOperation::Pause, OciStatus::Running),
            (OciOperation::Resume, OciStatus::Paused),
        ] {
            let root = tempfile::tempdir().unwrap();
            let runtime = runtime_with_state(root.path(), status);
            let before = runtime.store.load("pause-test").unwrap();
            let error = runtime
                .change_pause_state("pause-test", operation, async {
                    bail!("VMM rejected transition")
                })
                .await
                .unwrap_err();
            assert!(error.to_string().contains("VMM rejected"));
            assert_eq!(runtime.store.load("pause-test").unwrap(), before);
        }
    }

    #[tokio::test]
    async fn invalid_transitions_do_not_contact_vmm() {
        for (operation, status) in [
            (OciOperation::Pause, OciStatus::Created),
            (OciOperation::Pause, OciStatus::Paused),
            (OciOperation::Resume, OciStatus::Running),
            (OciOperation::Resume, OciStatus::Stopped),
        ] {
            let root = tempfile::tempdir().unwrap();
            let runtime = runtime_with_state(root.path(), status);
            assert!(
                runtime
                    .change_pause_state("pause-test", operation, async {
                        panic!("invalid transition must not contact VMM")
                    })
                    .await
                    .is_err()
            );
            assert_eq!(runtime.store.load("pause-test").unwrap().status, status);
        }
    }
}
