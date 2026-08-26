//! OCI lifecycle orchestration backed by Microsandbox.

use std::path::PathBuf;

use anyhow::{Result, anyhow, bail};
use chrono::Utc;
use microsandbox::sandbox::{Sandbox, SandboxStatus};
use microsandbox_runtime::oci::{
    OciBundle, OciOperation, OciState, OciStateStore, next_status, sandbox_name_for_container,
};

use crate::console::open_console_bridge;
use crate::options::{CreateOptions, DeleteOptions, ExecOptions, KillOptions};
use crate::process::{
    HostSignalForwarder, load_process, parse_signal, start_process_stream, wait_for_process_exit,
    write_exec_pid_file,
};
use crate::requests::{
    OCI_SIGNAL_REQUEST, OCI_START_REQUEST, ensure_vmm_process_alive, publish_signal_request,
    publish_start_request, read_init_session_id, signal_init_process_if_known,
    stop_sandbox_for_delete, wait_for_init_exit, wait_for_init_session_id,
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
        let mut state = self.store.create_created(&options.id, &bundle)?;

        let state_dir = self.store.container_dir(&options.id)?;
        let sandbox =
            create_sandbox_for_bundle(&options.id, &bundle, &state_dir, options.console).await?;
        if let Some(pid) = resolve_created_sandbox_host_pid(&options.id, &sandbox).await {
            state.pid = Some(pid);
        }
        self.store.save(&state)?;

        sandbox.detach().await;
        Ok(())
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
        let state = self.store.load(&options.id)?;
        OciOperation::Kill.validate(&state)?;

        let signal = parse_signal(&options.signal)?;
        let mut state = state;
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
        let mut state = self.store.load(&options.id)?;
        if options.force && !state.status.is_terminal() {
            signal_init_process_if_known(&options.id, &state, libc::SIGKILL).await?;
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
                self.store.save(&state)?;
            }
        }
        Ok(state)
    }

    /// Pause the OCI container if Microsandbox has a matching backend state.
    pub async fn pause(&self, id: &str) -> Result<()> {
        let state = self.store.load(id)?;
        let _ = next_status(OciOperation::Pause, &state)?;
        bail!("pause is not implemented by runmsb yet")
    }

    /// Resume the OCI container if Microsandbox has a matching backend state.
    pub async fn resume(&self, id: &str) -> Result<()> {
        let state = self.store.load(id)?;
        let _ = next_status(OciOperation::Resume, &state)?;
        bail!("resume is not implemented by runmsb yet")
    }

    async fn exec_with_console(
        &self,
        options: ExecOptions,
        console_slave: Option<PathBuf>,
    ) -> Result<i32> {
        let state = self.store.load(&options.id)?;
        OciOperation::Exec.validate(&state)?;
        let mut host_signals = HostSignalForwarder::new()?;

        let process = load_process(&options.process)?;
        let bundle = OciBundle::load(&state.bundle)?;
        let sandbox = crate::process::connect_sandbox(&options.id).await?;
        let (started, mut handle) =
            start_process_stream(&sandbox, &process, &bundle.rootfs_path()).await?;
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
        sandbox.detach().await;
        Ok(exit_code)
    }
}
