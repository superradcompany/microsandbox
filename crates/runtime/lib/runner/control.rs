//! Host-side runtime control socket.
//!
//! Live VM mutations that are host/VMM-owned (memory resize through
//! virtio-mem, CPU online targets, and secret reconfiguration in the host
//! network layer) cannot go through agentd: the guest is untrusted and the
//! knobs live host-side. The sandbox process serves them instead next to the
//! agent endpoint — a unix socket on unix hosts, a named pipe on Windows.
//! Existing one-line JSON clients remain supported. New callers may use a
//! versioned request envelope carrying boot identity, revision fencing, and
//! request correlation; both paths enter one runtime-owned executor.
//!
//! Secret requests may carry raw secret values (rotation needs the new
//! material), so request lines are never logged and [`SecretValue`] redacts
//! itself in `Debug` output; errors carry secret names only.

#[cfg(unix)]
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

use crate::control::*;

mod executor;
pub use executor::RuntimeControlExecutor;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Everything the control listener can reach: the VMM control handle plus the
/// host network secrets layer when this build carries one.
#[derive(Clone)]
pub struct ControlContext {
    /// Single authority for reads and mutations.
    pub executor: std::sync::Arc<RuntimeControlExecutor>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Spawn the control listener thread. Non-fatal on failure by design: the
/// caller logs and continues, and the SDK treats a missing socket as "no live
/// control capability".
#[cfg(unix)]
pub fn spawn_control_listener(
    socket_path: PathBuf,
    context: ControlContext,
) -> std::io::Result<()> {
    let _ = std::fs::remove_file(&socket_path);
    let listener = std::os::unix::net::UnixListener::bind(&socket_path)?;

    std::thread::Builder::new()
        .name("msb-control".to_string())
        .spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(mut stream) => {
                        if let Err(e) = serve_connection(&mut stream, &context) {
                            tracing::debug!("control: connection error: {e}");
                        }
                    }
                    Err(e) => {
                        tracing::warn!("control: accept failed, stopping listener: {e}");
                        break;
                    }
                }
            }
        })?;

    Ok(())
}

#[cfg(unix)]
fn serve_connection(
    stream: &mut std::os::unix::net::UnixStream,
    context: &ControlContext,
) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let Some((first, memory)) = crate::memory_handoff::receive_first(stream.as_raw_fd())?
        else {
            return Ok(());
        };
        let mut rest = String::new();
        BufReader::new(&mut *stream).read_line(&mut rest)?;
        let line = format!("{}{rest}", char::from(first));
        stream.write_all(&respond_with_memory(line.trim(), context, memory))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let mut line = String::new();
        BufReader::new(&mut *stream).read_line(&mut line)?;
        stream.write_all(&respond_to_line(line.trim(), context))
    }
}

/// Serve the Windows named-pipe listener. One pipe instance exists at a time;
/// each connection is one request/response exchange, after which the instance
/// is recreated. Zero-byte connections are tolerated because `Path::exists()`
/// probes from the SDK open and immediately close the pipe.
#[cfg(windows)]
pub fn spawn_control_listener(pipe_name: PathBuf, context: ControlContext) -> std::io::Result<()> {
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::net::windows::named_pipe::{PipeMode, ServerOptions};

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()?;

    std::thread::Builder::new()
        .name("msb-control".to_string())
        .spawn(move || {
            runtime.block_on(async move {
                let mut first_pipe_instance = true;
                loop {
                    let mut options = ServerOptions::new();
                    options.pipe_mode(PipeMode::Byte);
                    if first_pipe_instance {
                        options.first_pipe_instance(true);
                    }
                    let server = match options.create(&pipe_name) {
                        Ok(server) => server,
                        Err(e) => {
                            tracing::warn!("control: pipe create failed, stopping listener: {e}");
                            break;
                        }
                    };
                    first_pipe_instance = false;

                    if let Err(e) = server.connect().await {
                        tracing::debug!("control: pipe connect error: {e}");
                        continue;
                    }

                    let mut reader = BufReader::new(server);
                    let mut line = String::new();
                    match reader.read_line(&mut line).await {
                        Ok(0) => continue, // existence probe: opened and closed
                        Ok(_) => {}
                        Err(e) => {
                            tracing::debug!("control: connection error: {e}");
                            continue;
                        }
                    }

                    // Checkpoint capture and other host mutations are intentionally synchronous
                    // under one executor lock. Run them outside the current-thread pipe reactor,
                    // matching the dedicated blocking listener used on Unix and allowing capture
                    // code to drive the separate VM runtime without nesting Tokio runtimes.
                    let request = line.trim().to_owned();
                    let request_context = context.clone();
                    let payload = match tokio::task::spawn_blocking(move || {
                        respond_to_line(&request, &request_context)
                    })
                    .await
                    {
                        Ok(payload) => payload,
                        Err(error) => {
                            tracing::error!(%error, "control: request executor failed");
                            continue;
                        }
                    };
                    let server = reader.into_inner();
                    if let Err(e) = write_windows_control_response(server, &payload).await {
                        tracing::debug!("control: response write error: {e}");
                        continue;
                    }
                }
            });
        })?;

    Ok(())
}

/// Write one Windows control response and close the connected pipe instance.
///
/// `NamedPipeServer::disconnect` discards unread pipe data, so calling it immediately after an
/// asynchronous flush can erase a fast response before the client consumes it. Dropping the
/// connected handle preserves the written bytes while the listener creates a fresh instance.
#[cfg(windows)]
async fn write_windows_control_response(
    mut server: tokio::net::windows::named_pipe::NamedPipeServer,
    payload: &[u8],
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;

    server.write_all(payload).await?;
    server.flush().await
}

/// Parse one request line and produce the newline-terminated JSON reply.
#[cfg(not(target_os = "linux"))]
fn respond_to_line(line: &str, context: &ControlContext) -> Vec<u8> {
    respond_with_memory(line, context, None)
}

fn respond_with_memory(
    line: &str,
    context: &ControlContext,
    memory: Option<std::fs::File>,
) -> Vec<u8> {
    let value = serde_json::from_str::<serde_json::Value>(line);
    let mut payload = match value {
        Ok(value) if value.get("protocol_version").is_some() => {
            match serde_json::from_value::<ControlEnvelope>(value) {
                Ok(envelope)
                    if memory.is_none()
                        && !matches!(
                            envelope.command,
                            ControlRequest::BranchCreateMemfd { .. }
                        ) =>
                {
                    serde_json::to_vec(&context.executor.execute(envelope))
                }
                Ok(_) => serde_json::to_vec(&ControlResponse {
                    ok: false,
                    error: Some("descriptor handoff requires a one-shot branch request".into()),
                    ..Default::default()
                }),
                Err(error) => serde_json::to_vec(&ControlResponse {
                    ok: false,
                    error_code: Some("invalid_envelope".into()),
                    error: Some(format!("invalid control envelope: {error}")),
                    ..Default::default()
                }),
            }
        }
        Ok(value) => match serde_json::from_value::<ControlRequest>(value) {
            Ok(mut request) => match attach_branch_memory(&mut request, memory) {
                Ok(()) => serde_json::to_vec(&context.executor.execute_legacy(request)),
                Err(error) => serde_json::to_vec(&ControlResponse {
                    ok: false,
                    error: Some(error.to_string()),
                    ..Default::default()
                }),
            },
            Err(error) => serde_json::to_vec(&ControlResponse {
                ok: false,
                error_code: Some("invalid_request".into()),
                error: Some(format!("invalid control request: {error}")),
                ..Default::default()
            }),
        },
        Err(error) => serde_json::to_vec(&ControlResponse {
            ok: false,
            error_code: Some("invalid_json".into()),
            error: Some(format!("invalid control request: {error}")),
            ..Default::default()
        }),
    }
    .unwrap_or_default();
    payload.push(b'\n');
    payload
}

fn attach_branch_memory(
    request: &mut ControlRequest,
    memory: Option<std::fs::File>,
) -> std::io::Result<()> {
    match (request, memory) {
        (ControlRequest::BranchCreateMemfd { backing, .. }, Some(file)) => {
            #[cfg(target_os = "linux")]
            {
                crate::memory_handoff::validate_empty(&file)?;
                *backing = Some(std::sync::Arc::new(file));
                Ok(())
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (backing, file);
                Err(std::io::Error::other("memory descriptors require Linux"))
            }
        }
        (ControlRequest::BranchCreateMemfd { .. }, None) => {
            Err(std::io::Error::other("missing branch memory descriptor"))
        }
        (_, Some(_)) => Err(std::io::Error::other("unexpected control descriptor")),
        (_, None) => Ok(()),
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_operation_rejects_missing_transport_ownership() {
        let mut request: ControlRequest = serde_json::from_str(r#"{"op":"branch_create_memfd","branch_id":"branch_test","child_name":"child","memory_cache_dir":"/cache"}"#).unwrap();
        assert!(attach_branch_memory(&mut request, None).is_err());
        let old: ControlCapabilities = serde_json::from_str(r#"{"cpu_resize":false,"memory_resize":false,"secrets_update":false,"branch_create":true}"#).unwrap();
        assert!(!old.branch_memfd);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn immediate_windows_control_response_survives_server_close() {
        use std::time::Duration;

        use tokio::io::{AsyncBufReadExt, BufReader};
        use tokio::net::windows::named_pipe::{ClientOptions, PipeMode, ServerOptions};

        let pipe_name = format!(r"\\.\pipe\msb-control-response-test-{}", std::process::id());
        let server = ServerOptions::new()
            .first_pipe_instance(true)
            .pipe_mode(PipeMode::Byte)
            .create(&pipe_name)
            .unwrap();
        let client = ClientOptions::new().open(&pipe_name).unwrap();

        let writer = tokio::spawn(async move {
            server.connect().await.unwrap();
            write_windows_control_response(server, b"{\"ok\":false}\n")
                .await
                .unwrap();
        });
        let mut line = String::new();
        tokio::time::timeout(
            Duration::from_secs(1),
            BufReader::new(client).read_line(&mut line),
        )
        .await
        .unwrap()
        .unwrap();
        writer.await.unwrap();

        assert_eq!(line, "{\"ok\":false}\n");
    }

    #[test]
    fn secret_value_debug_is_redacted() {
        let request = ControlRequest::SecretsUpdate {
            changes: vec![SecretLiveChange::Rotate {
                name: "API_KEY".into(),
                value: SecretValue("sentinel-secret-value".into()),
            }],
        };

        let debug = format!("{request:?}");
        assert!(!debug.contains("sentinel-secret-value"));
        assert!(debug.contains("[redacted]"));
        assert!(debug.contains("API_KEY"));
    }

    #[test]
    fn secrets_update_round_trips_through_json() {
        let request = ControlRequest::SecretsUpdate {
            changes: vec![
                SecretLiveChange::Rotate {
                    name: "API_KEY".into(),
                    value: SecretValue("new-material".into()),
                },
                SecretLiveChange::Remove {
                    name: "OLD_KEY".into(),
                },
                SecretLiveChange::SetAllowedHosts {
                    name: "API_KEY".into(),
                    hosts: vec!["api.example.com".into(), "*".into()],
                },
            ],
        };

        let json = serde_json::to_string(&request).unwrap();
        let parsed: ControlRequest = serde_json::from_str(&json).unwrap();
        let ControlRequest::SecretsUpdate { changes } = parsed else {
            panic!("expected secrets_update");
        };
        assert_eq!(changes.len(), 3);
        let SecretLiveChange::Rotate { name, value } = &changes[0] else {
            panic!("expected rotate");
        };
        assert_eq!(name, "API_KEY");
        assert_eq!(value.0, "new-material");
    }

    #[test]
    fn checkpoint_request_round_trips_through_json() {
        let request = ControlRequest::CheckpointCreate {
            record_integrity: false,
            checkpoint_id: "checkpoint_0123456789abcdef".into(),
            intent: CheckpointCaptureIntent::FullSnapshot,
        };

        let json = serde_json::to_string(&request).unwrap();
        let parsed: ControlRequest = serde_json::from_str(&json).unwrap();

        assert!(matches!(
            parsed,
            ControlRequest::CheckpointCreate {
                checkpoint_id,
                intent: CheckpointCaptureIntent::FullSnapshot,
                record_integrity: false,
            } if checkpoint_id == "checkpoint_0123456789abcdef"
        ));
    }

    #[test]
    fn disk_only_capture_has_a_distinct_wire_operation() {
        let request = ControlRequest::DiskCheckpointCreate {
            checkpoint_id: "disk_test".into(),
        };
        let json = serde_json::to_string(&request).unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&json).unwrap()["op"],
            "disk_checkpoint_create"
        );
        assert!(
            matches!(serde_json::from_str::<ControlRequest>(&json).unwrap(), ControlRequest::DiskCheckpointCreate { checkpoint_id } if checkpoint_id == "disk_test")
        );
        // An older runtime's capability response cannot accidentally opt into this operation.
        let old: ControlCapabilities = serde_json::from_str(r#"{"cpu_resize":false,"memory_resize":false,"secrets_update":false,"checkpoint_create":true}"#).unwrap();
        assert!(!old.disk_checkpoint_create);
    }

    #[test]
    fn capabilities_response_serializes_flags() {
        let response = ControlResponse {
            ok: true,
            capabilities: Some(ControlCapabilities {
                optional_disk_integrity: true,
                branch_create: true,
                branch_memfd: false,
                pause_resume: true,
                root_disk_grow: true,
                disk_compact: true,
                disk_compact_owned: true,
                cpu_resize: true,
                memory_resize: false,
                secrets_update: true,
                checkpoint_create: true,
                disk_checkpoint_create: true,
            }),
            ..Default::default()
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"secrets_update\":true"));
        assert!(json.contains("\"memory_resize\":false"));

        let parsed: ControlResponse = serde_json::from_str(&json).unwrap();
        assert!(parsed.capabilities.unwrap().secrets_update);
    }

    #[test]
    fn legacy_responses_without_capabilities_still_parse() {
        let parsed: ControlResponse = serde_json::from_str(r#"{"ok":true}"#).unwrap();
        assert!(parsed.ok);
        assert!(parsed.capabilities.is_none());
    }
}
