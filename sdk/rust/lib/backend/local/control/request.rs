//! Request transport over a local sandbox's runtime control endpoint.

use std::sync::Arc;

use microsandbox_control_client::CompactDisks;

use super::ControlSession;
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Retain the protocol session only when it matches an earlier identity-bearing selection.
pub(crate) async fn control_session_for_run(
    local: &crate::backend::LocalBackend,
    name: &str,
    run: crate::sandbox::identity::SandboxRunIdentity,
) -> MicrosandboxResult<ControlSession> {
    let session = local.control_session(name).await?.ok_or_else(|| {
        MicrosandboxError::Runtime("runtime control endpoint is unavailable".into())
    })?;
    if !session.matches_run(run) {
        return Err(MicrosandboxError::ControlClient(Arc::new(
            microsandbox_control_client::ControlClientError::RuntimeChanged,
        )));
    }
    Ok(session)
}

/// Bind the command to the selected process before sending any bytes on a reusable endpoint.
#[cfg(all(test, unix))]
pub(crate) async fn control_request_for_run(
    local: &crate::backend::LocalBackend,
    name: &str,
    run: crate::sandbox::identity::SandboxRunIdentity,
    request: String,
) -> MicrosandboxResult<microsandbox_runtime::control::ControlResponse> {
    control_request_for_run_with_memory(local, name, run, request, None).await
}

/// Optional descriptor travels with the first request byte on the already authenticated socket.
#[cfg(any(target_os = "linux", all(test, unix)))]
pub(crate) async fn control_request_for_run_with_memory(
    local: &crate::backend::LocalBackend,
    name: &str,
    run: crate::sandbox::identity::SandboxRunIdentity,
    request: String,
    _memory: Option<&std::fs::File>,
) -> MicrosandboxResult<microsandbox_runtime::control::ControlResponse> {
    let candidates = crate::runtime::sandbox_agent_socket_path_candidates_for(local, name)
        .into_iter()
        .map(|path| microsandbox_runtime::control::control_socket_path_for(&path));
    #[cfg(unix)]
    let stream = connect_control_socket(candidates).await?;
    let peer_pid = control_peer_pid(&stream)?;
    if peer_pid != run.pid {
        return Err(MicrosandboxError::Runtime(format!(
            "sandbox {name:?} control endpoint belongs to pid {peer_pid}, expected {}",
            run.pid
        )));
    }
    local.validate_control_run(name, run).await?;
    #[cfg(target_os = "linux")]
    let request = if let Some(memory) = _memory {
        use std::os::fd::AsRawFd;
        let first = *request
            .as_bytes()
            .first()
            .ok_or_else(|| MicrosandboxError::Runtime("empty control request".into()))?;
        loop {
            stream.writable().await?;
            match stream.try_io(tokio::io::Interest::WRITABLE, || {
                microsandbox_runtime::memory_handoff::send_first(stream.as_raw_fd(), memory, first)
            }) {
                Ok(()) => break,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(error) => return Err(error.into()),
            }
        }
        request[1..].to_owned()
    } else {
        request
    };
    let response = control_request_over_stream(stream, &request).await?;
    if !response.ok {
        return Err(MicrosandboxError::Runtime(format!(
            "runtime control refused: {}",
            response.error.unwrap_or_else(|| "unknown error".into())
        )));
    }
    Ok(response)
}

#[cfg(target_os = "linux")]
fn control_peer_pid(stream: &tokio::net::UnixStream) -> std::io::Result<i32> {
    stream.peer_cred()?.pid().ok_or_else(|| {
        std::io::Error::other("control endpoint did not report its process identity")
    })
}

#[cfg(all(test, target_os = "macos"))]
fn control_peer_pid(stream: &tokio::net::UnixStream) -> std::io::Result<i32> {
    use std::os::fd::AsRawFd;
    let mut pid: libc::pid_t = 0;
    let mut size = std::mem::size_of_val(&pid) as libc::socklen_t;
    // LOCAL_PEERPID identifies the server attached to this connected socket, not a later
    // process that reuses its filesystem pathname. getpeereid alone exposes only UID/GID.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&mut pid as *mut libc::pid_t).cast(),
            &mut size,
        )
    };
    if result == -1 {
        return Err(std::io::Error::last_os_error());
    }
    if size as usize != std::mem::size_of_val(&pid) || pid <= 0 {
        return Err(std::io::Error::other(
            "invalid control endpoint process identity",
        ));
    }
    Ok(pid)
}

#[cfg(all(test, unix, not(any(target_os = "linux", target_os = "macos"))))]
fn control_peer_pid(_stream: &tokio::net::UnixStream) -> std::io::Result<i32> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "control endpoint process verification is unsupported on this platform",
    ))
}

#[cfg(any(target_os = "linux", all(test, unix)))]
async fn connect_control_socket(
    candidates: impl IntoIterator<Item = std::path::PathBuf>,
) -> std::io::Result<tokio::net::UnixStream> {
    let mut last_error = None;
    for path in candidates {
        if !path.exists() {
            continue;
        }
        match tokio::net::UnixStream::connect(&path).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }

    Err(last_error.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no runtime control endpoint exists",
        )
    }))
}

/// Send and receive one control exchange over an already-connected transport.
#[cfg(any(target_os = "linux", all(test, unix)))]
async fn control_request_over_stream<S>(
    mut stream: S,
    request: &str,
) -> MicrosandboxResult<microsandbox_runtime::control::ControlResponse>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| crate::MicrosandboxError::Runtime(format!("control request failed: {e}")))?;

    let mut line = String::new();
    BufReader::new(stream)
        .read_line(&mut line)
        .await
        .map_err(|e| crate::MicrosandboxError::Runtime(format!("control response failed: {e}")))?;
    let response: microsandbox_runtime::control::ControlResponse =
        serde_json::from_str(line.trim())?;
    Ok(response)
}

/// Capability-gated disk maintenance over the existing control endpoint.
pub(crate) async fn control_disk_compact(
    local: &crate::backend::LocalBackend,
    name: &str,
    target: microsandbox_types::DiskCompactionTarget,
    layers: Option<usize>,
    dry_run: bool,
) -> MicrosandboxResult<crate::sandbox::DiskCompactionResult> {
    // Discovery and mutation must use the same retained backend as the selected sandbox.
    // An ambient backend may contain a different sandbox with this exact name.
    let session = local.control_session(name).await?.ok_or_else(|| {
        crate::MicrosandboxError::Runtime("runtime control endpoint is unavailable".into())
    })?;
    let capabilities = session.capabilities();
    if !capabilities.disk_compact_owned {
        return Err(crate::MicrosandboxError::Runtime(
            "this running sandbox does not support disk compaction; restart with the updated runtime".into(),
        ));
    }
    session
        .request(&CompactDisks(microsandbox_protocol::control::DiskCompact {
            target,
            layers: layers.map(|value| value as u64),
            dry_run,
        }))
        .await
        .map_err(crate::MicrosandboxError::ControlClient)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[tokio::test]
    async fn compaction_uses_selected_backend_for_discovery_and_mutation() {
        use microsandbox_types::DiskCompactionTarget;
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let first_home = tempfile::tempdir_in("/tmp").unwrap();
        let second_home = tempfile::tempdir_in("/tmp").unwrap();
        let first = crate::test_support::local_backend_builder(first_home.path())
            .build()
            .await
            .unwrap();
        let second = crate::test_support::local_backend_builder(second_home.path())
            .build()
            .await
            .unwrap();
        crate::test_support::seed_control_run(&first, "worker").await;
        crate::test_support::seed_control_run(&second, "worker").await;
        let mut servers = Vec::new();
        for (local, marker, target) in [
            (&first, 1, DiskCompactionTarget::All),
            (
                &second,
                2,
                DiskCompactionTarget::Disk {
                    guest_path: "/data".into(),
                },
            ),
        ] {
            let agent =
                crate::runtime::sandbox_agent_socket_path_candidates_for(local, "worker").remove(0);
            let path = microsandbox_runtime::control::control_socket_path_for(&agent);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            let listener = tokio::net::UnixListener::bind(path).unwrap();
            servers.push(tokio::spawn(async move {
                for request_index in 0..2 {
                    let (stream, _) = listener.accept().await.unwrap();
                    let mut stream = BufReader::new(stream);
                    let mut line = String::new();
                    stream.read_line(&mut line).await.unwrap();
                    let request: serde_json::Value = serde_json::from_str(&line).unwrap();
                    let response = if request_index == 0 {
                        assert_eq!(request["op"], "capabilities");
                        serde_json::json!({"ok": true, "capabilities": {
                            "disk_compact_owned": true, "cpu_resize": false,
                            "memory_resize": false, "secrets_update": false
                        }})
                    } else {
                        assert_eq!(request["op"], "disk_compact");
                        assert_eq!(request["target"], serde_json::to_value(target.clone()).unwrap());
                        assert_eq!(request["layers"], 999);
                        assert_eq!(request["dry_run"], true);
                        serde_json::json!({"ok": true, "compaction": microsandbox_types::DiskCompactionResult {
                            dry_run: true, total_us: marker, ..Default::default()
                        }})
                    };
                    stream.get_mut().write_all(format!("{response}\n").as_bytes()).await.unwrap();
                }
            }));
        }
        for (local, marker, target) in [
            (&first, 1, DiskCompactionTarget::All),
            (
                &second,
                2,
                DiskCompactionTarget::Disk {
                    guest_path: "/data".into(),
                },
            ),
        ] {
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                control_disk_compact(local, "worker", target, Some(999), true),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(result.total_us, marker);
        }
        for server in servers {
            server.await.unwrap();
        }
    }
}
