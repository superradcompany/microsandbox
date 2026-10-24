//! Authenticated raw control requests, including Linux memory-descriptor transfer.

#[cfg(any(target_os = "linux", all(test, unix)))]
use microsandbox_runtime::control::ControlResponse;
#[cfg(any(target_os = "linux", all(test, unix)))]
use tokio::io::{AsyncRead, AsyncWrite};

use crate::backend::LocalBackend;
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl LocalBackend {
    /// Bind the command to the selected process before sending any bytes on a reusable endpoint.
    #[cfg(all(test, unix))]
    pub(crate) async fn control_request_for_run(
        &self,
        name: &str,
        run: crate::sandbox::identity::SandboxRunIdentity,
        request: String,
    ) -> MicrosandboxResult<ControlResponse> {
        self.control_request_for_run_with_memory(name, run, request, None)
            .await
    }

    /// Optional descriptor travels with the first request byte on the already authenticated socket.
    #[cfg(any(target_os = "linux", all(test, unix)))]
    pub(crate) async fn control_request_for_run_with_memory(
        &self,
        name: &str,
        run: crate::sandbox::identity::SandboxRunIdentity,
        request: String,
        _memory: Option<&std::fs::File>,
    ) -> MicrosandboxResult<ControlResponse> {
        let candidates = crate::runtime::sandbox_agent_socket_path_candidates_for(self, name)
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
        self.validate_control_run(name, run).await?;
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
                    microsandbox_runtime::memory_handoff::send_first(
                        stream.as_raw_fd(),
                        memory,
                        first,
                    )
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
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

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
) -> MicrosandboxResult<ControlResponse>
where
    S: AsyncRead + AsyncWrite + Unpin,
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
    let response: ControlResponse = serde_json::from_str(line.trim())?;
    Ok(response)
}
