//! Host-side OCI init monitor helpers.

use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use microsandbox_oci_runtime::MicrosandboxOciRuntime;
use microsandbox_runtime::oci::OciStatus;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) async fn spawn_create_monitor(
    root: &Path,
    id: &str,
    console_slave: Option<&PathBuf>,
    isolate_network_namespace: bool,
) -> Result<i32> {
    let exe = std::env::current_exe().context("resolve current runtime executable")?;
    let mut command = tokio::process::Command::new(exe);
    command
        .arg("--root")
        .arg(root)
        .arg("monitor")
        .arg("--wait-start");
    if let Some(console_slave) = console_slave {
        command.arg("--console-slave").arg(console_slave);
    }
    command.arg(id).stdin(Stdio::null());
    if console_slave.is_some() {
        let log = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(monitor_log_path(root, id))
            .with_context(|| format!("open OCI init monitor log for `{id}`"))?;
        let log_for_stdout = log.try_clone().context("clone OCI init monitor log")?;
        command
            .stdout(Stdio::from(log_for_stdout))
            .stderr(Stdio::from(log));
    } else {
        command.stdout(Stdio::inherit()).stderr(Stdio::inherit());
    }

    unsafe {
        command.pre_exec(move || {
            if isolate_network_namespace && libc::unshare(libc::CLONE_NEWNET) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let child = command
        .spawn()
        .with_context(|| format!("spawn OCI init monitor for `{id}`"))?;
    let pid = child
        .id()
        .ok_or_else(|| anyhow::anyhow!("OCI init monitor for `{id}` has no host PID"))?;
    let pid = i32::try_from(pid).context("OCI init monitor host PID does not fit pid-file")?;

    Ok(pid)
}

pub(crate) async fn request_monitor_start(
    runtime: &MicrosandboxOciRuntime,
    root: &Path,
    id: &str,
) -> Result<()> {
    fs::write(start_request_path(root, id), b"start")
        .with_context(|| format!("write OCI start request for `{id}`"))?;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        if matches!(
            runtime.state(id).await.map(|state| state.status),
            Ok(OciStatus::Running)
        ) {
            return Ok(());
        }

        if matches!(
            runtime.state(id).await.map(|state| state.status),
            Ok(OciStatus::Stopped)
        ) {
            return Ok(());
        }

        if tokio::time::Instant::now() >= deadline {
            let monitor_log = monitor_log_excerpt(root, id);
            match monitor_log {
                Some(monitor_log) => bail!(
                    "timed out waiting for OCI init monitor for `{id}`; monitor log: {monitor_log}"
                ),
                None => bail!("timed out waiting for OCI init monitor for `{id}`"),
            }
        }

        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

pub(crate) async fn wait_for_start_request(
    runtime: &MicrosandboxOciRuntime,
    root: &Path,
    id: &str,
) -> Result<bool> {
    let path = start_request_path(root, id);
    loop {
        if path.exists() {
            return Ok(true);
        }
        if runtime.state(id).await.is_err() {
            return Ok(false);
        }

        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn start_request_path(root: &Path, id: &str) -> PathBuf {
    root.join(id).join("start.request")
}

fn monitor_log_path(root: &Path, id: &str) -> PathBuf {
    root.join(id).join("monitor.log")
}

fn monitor_log_excerpt(root: &Path, id: &str) -> Option<String> {
    const MAX_MONITOR_LOG_BYTES: usize = 8 * 1024;

    let path = monitor_log_path(root, id);
    let bytes = fs::read(path).ok()?;
    let bytes = if bytes.len() > MAX_MONITOR_LOG_BYTES {
        &bytes[bytes.len() - MAX_MONITOR_LOG_BYTES..]
    } else {
        &bytes
    };
    let log = String::from_utf8_lossy(bytes).trim().to_string();
    (!log.is_empty()).then_some(log)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn monitor_log_excerpt_returns_trimmed_tail() {
        let temp = tempfile::tempdir().expect("tempdir");
        let id = "abc123";
        fs::create_dir_all(temp.path().join(id)).expect("state dir");
        let prefix = "x".repeat(9 * 1024);
        fs::write(
            monitor_log_path(temp.path(), id),
            format!("{prefix}real monitor error\n"),
        )
        .expect("monitor log");

        let excerpt = monitor_log_excerpt(temp.path(), id).expect("excerpt");

        assert!(excerpt.len() <= 8 * 1024 + "real monitor error".len());
        assert!(excerpt.ends_with("real monitor error"));
    }
}
