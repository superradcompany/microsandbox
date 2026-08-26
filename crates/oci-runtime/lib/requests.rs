//! Host-side start and signal requests consumed by the persistent VMM process.

use std::fs;
use std::io::ErrorKind;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use microsandbox::sandbox::{Sandbox, SandboxStatus};
use microsandbox_protocol::exec::ExecSignal;
use microsandbox_protocol::message::MessageType;
use microsandbox_runtime::oci::{OciState, OciStateStore, sandbox_name_for_container};
use nix::errno::Errno;
use nix::sys::signal::kill;
use nix::unistd::Pid;

use crate::process::connect_sandbox;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

pub(crate) const OCI_START_REQUEST: &str = "start.request";
pub(crate) const OCI_INIT_SESSION: &str = "init.session";
pub(crate) const OCI_SIGNAL_REQUEST: &str = "init.signal";

const OCI_INIT_SESSION_ERROR: &str = "init.session.error";
const OCI_INIT_SESSION_EXIT: &str = "init.session.exit";
const OCI_START_TIMEOUT: Duration = Duration::from_secs(30);

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) async fn signal_init_process(id: &str, state: &OciState, signal: i32) -> Result<()> {
    let session_id = state
        .microsandbox
        .as_ref()
        .and_then(|msb| msb.init_exec_session_id)
        .ok_or_else(|| anyhow!("container `{id}` has no OCI init exec session to signal"))?;
    let sandbox = connect_sandbox(id).await?;
    let payload = ExecSignal { signal };

    sandbox
        .client_arc()
        .send(session_id, MessageType::ExecSignal, &payload)
        .await
        .with_context(|| {
            format!("send signal {signal} to OCI init exec session {session_id} for `{id}`")
        })?;
    sandbox.detach().await;
    Ok(())
}

pub(crate) async fn signal_init_process_if_known(
    id: &str,
    state: &OciState,
    signal: i32,
) -> Result<()> {
    if state
        .microsandbox
        .as_ref()
        .and_then(|msb| msb.init_exec_session_id)
        .is_none()
    {
        return Ok(());
    }

    if let Err(error) = signal_init_process(id, state, signal).await {
        tracing::warn!(
            container_id = id,
            signal,
            error = %error,
            "failed to signal OCI init process during force delete; continuing with sandbox cleanup"
        );
    }
    Ok(())
}

pub(crate) fn publish_start_request(path: &Path) -> Result<()> {
    fs::write(path, b"start").with_context(|| {
        format!(
            "publish OCI start request for VMM supervisor `{}`",
            path.display()
        )
    })
}

pub(crate) fn publish_signal_request(path: &Path, signal: i32) -> Result<()> {
    let temporary = path.with_extension(format!("signal.{}", std::process::id()));
    fs::write(&temporary, signal.to_string())
        .with_context(|| format!("write OCI init signal request `{}`", temporary.display()))?;
    fs::rename(&temporary, path)
        .with_context(|| format!("publish OCI init signal request `{}`", path.display()))
}

pub(crate) async fn wait_for_init_session_id(
    store: &OciStateStore,
    id: &str,
    host_pid: i32,
) -> Result<u32> {
    let deadline = tokio::time::Instant::now() + OCI_START_TIMEOUT;
    loop {
        if let Some(error) = read_init_session_error(store, id)? {
            bail!("VMM supervisor failed to start OCI init for `{id}`: {error}");
        }
        match read_init_session_id(store, id) {
            Ok(session_id) => return Ok(session_id),
            Err(error) if tokio::time::Instant::now() >= deadline => {
                let state_dir = store.container_dir(id)?;
                let entries = state_dir_entries(&state_dir);
                return Err(error)
                    .with_context(|| {
                        format!("timed out waiting for VMM supervisor to start OCI init for `{id}`")
                    })
                    .with_context(|| {
                        format!(
                            "OCI state directory `{}` contains: {entries}",
                            state_dir.display()
                        )
                    });
            }
            Err(_) => {
                ensure_vmm_process_alive(id, host_pid)?;
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    }
}

pub(crate) fn ensure_vmm_process_alive(id: &str, host_pid: i32) -> Result<()> {
    if host_pid <= 0 {
        bail!("container `{id}` has invalid Microsandbox VMM host PID {host_pid}");
    }

    match kill(Pid::from_raw(host_pid), None) {
        Ok(()) | Err(Errno::EPERM) => Ok(()),
        Err(Errno::ESRCH) => {
            bail!("Microsandbox VMM process {host_pid} for `{id}` exited before OCI init started")
        }
        Err(error) => Err(error).with_context(|| {
            format!("check Microsandbox VMM process {host_pid} for `{id}` during OCI start")
        }),
    }
}

pub(crate) fn read_init_session_id(store: &OciStateStore, id: &str) -> Result<u32> {
    let path = store.container_dir(id)?.join(OCI_INIT_SESSION);
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("read OCI init session id `{}`", path.display()))?;
    raw.trim()
        .parse::<u32>()
        .with_context(|| format!("parse OCI init session id `{}`", path.display()))
}

pub(crate) async fn wait_for_init_exit(store: &OciStateStore, id: &str) -> Result<i32> {
    let path = store.container_dir(id)?.join(OCI_INIT_SESSION_EXIT);
    loop {
        match fs::read_to_string(&path) {
            Ok(raw) => {
                return raw
                    .trim()
                    .parse::<i32>()
                    .with_context(|| format!("parse OCI init exit status `{}`", path.display()));
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("read OCI init exit status `{}`", path.display()));
            }
        }

        if let Ok(handle) = Sandbox::get(&sandbox_name_for_container(id)).await {
            let refreshed = handle.refresh().await.unwrap_or(handle);
            if matches!(
                refreshed.status_snapshot(),
                SandboxStatus::Stopped | SandboxStatus::Crashed
            ) {
                bail!(
                    "Microsandbox VMM for `{id}` stopped without publishing OCI init exit status"
                );
            }
        }

        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

pub(crate) async fn stop_sandbox_for_delete(id: &str) -> Result<()> {
    let name = sandbox_name_for_container(id);
    let Ok(handle) = Sandbox::get(&name).await else {
        return Ok(());
    };
    let refreshed = handle.refresh().await.unwrap_or(handle);
    if matches!(
        refreshed.status_snapshot(),
        SandboxStatus::Stopped | SandboxStatus::Crashed
    ) {
        return Ok(());
    }

    refreshed
        .stop()
        .await
        .with_context(|| format!("stop Microsandbox sandbox `{name}` during force delete"))
}

fn read_init_session_error(store: &OciStateStore, id: &str) -> Result<Option<String>> {
    let path = store.container_dir(id)?.join(OCI_INIT_SESSION_ERROR);
    match fs::read_to_string(&path) {
        Ok(raw) => Ok(Some(raw.trim().to_string())),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => {
            Err(error).with_context(|| format!("read OCI init startup error `{}`", path.display()))
        }
    }
}

fn state_dir_entries(path: &Path) -> String {
    let Ok(entries) = fs::read_dir(path) else {
        return "<unreadable>".into();
    };

    let mut names = entries
        .filter_map(|entry| {
            entry
                .ok()
                .and_then(|entry| entry.file_name().into_string().ok())
        })
        .collect::<Vec<_>>();
    names.sort();

    if names.is_empty() {
        "<empty>".into()
    } else {
        names.join(", ")
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vmm_liveness_accepts_current_process_and_rejects_missing_process() {
        ensure_vmm_process_alive("container", std::process::id() as i32)
            .expect("current process is alive");

        let error = ensure_vmm_process_alive("container", i32::MAX)
            .expect_err("maximum PID should not exist");
        assert!(error.to_string().contains("exited before OCI init started"));
    }

    #[tokio::test]
    async fn wait_for_init_session_fails_immediately_when_vmm_exits() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = OciStateStore::new(temp.path());
        let state_dir = store.container_dir("container").expect("state dir");
        std::fs::create_dir_all(&state_dir).expect("create state dir");

        let started = tokio::time::Instant::now();
        let error = wait_for_init_session_id(&store, "container", i32::MAX)
            .await
            .expect_err("dead VMM should fail startup");

        assert!(error.to_string().contains("exited before OCI init started"));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[tokio::test]
    async fn wait_for_init_exit_returns_published_status() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = OciStateStore::new(temp.path());
        let state_dir = store.container_dir("container").expect("state dir");
        std::fs::create_dir_all(&state_dir).expect("create state dir");
        std::fs::write(state_dir.join(OCI_INIT_SESSION_EXIT), "143\n").expect("write exit status");

        assert_eq!(
            wait_for_init_exit(&store, "container")
                .await
                .expect("wait for exit"),
            143
        );
    }
}
