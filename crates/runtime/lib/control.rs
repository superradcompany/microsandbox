//! Host-side runtime control socket.
//!
//! Live VM mutations that are host/VMM-owned (memory resize through
//! virtio-mem, CPU online targets, and secret reconfiguration in the host
//! network layer) cannot go through agentd: the guest is untrusted and the
//! knobs live host-side. The sandbox process serves them instead next to the
//! agent endpoint — a unix socket on unix hosts, a named pipe on Windows.
//! The protocol is deliberately tiny: one JSON request line in, one JSON
//! response line out, per connection.
//!
//! Secret requests may carry raw secret values (rotation needs the new
//! material), so request lines are never logged and [`SecretValue`] redacts
//! itself in `Debug` output; errors carry secret names only.

#[cfg(unix)]
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Extension of the per-sandbox control socket, derived from the agent
/// socket path (`<sandbox>.sock` becomes `<sandbox>.control.sock`).
pub const CONTROL_SOCKET_EXTENSION: &str = "control.sock";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A control request from the SDK.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ControlRequest {
    /// Report which live-control operations this sandbox process supports.
    Capabilities,

    /// Ask the guest to converge on this much total usable memory.
    MemoryTarget {
        /// Desired total memory in MiB.
        total_mib: u64,
    },

    /// Report the current memory sizing without changing anything.
    MemoryState,

    /// Ask the guest to converge on this many online CPUs; the VMM enforces
    /// the ceiling immediately regardless of guest cooperation.
    CpuTarget {
        /// Desired online CPU count.
        online: u32,
    },

    /// Report the current CPU sizing without changing anything.
    CpuState,

    /// Apply live secret changes to the host network/secrets layer.
    /// Values never reach agentd or the guest; the placeholders the guest
    /// already holds keep working against the updated host-side state.
    SecretsUpdate {
        /// Ordered changes to apply. The first failure aborts the batch.
        changes: Vec<SecretLiveChange>,
    },
}

/// One live secret change carried by [`ControlRequest::SecretsUpdate`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "change", rename_all = "snake_case")]
pub enum SecretLiveChange {
    /// Replace the host-side value of an existing secret.
    Rotate {
        /// Secret identity (the guest environment variable name).
        name: String,
        /// New secret material. Redacted in `Debug`; never logged.
        value: SecretValue,
    },

    /// Stop resolving and injecting a secret for future connections.
    Remove {
        /// Secret identity (the guest environment variable name).
        name: String,
    },

    /// Replace the allowed-host patterns of an existing secret.
    SetAllowedHosts {
        /// Secret identity (the guest environment variable name).
        name: String,
        /// Host patterns (`host`, `*.host`, or `*`).
        hosts: Vec<String>,
    },
}

/// Raw secret material in transit over the control socket. Wrapped so any
/// `Debug`-formatted request or error path shows `[redacted]` instead of the
/// value, and zeroized on drop so the plaintext does not linger in freed
/// memory after the rotation batch is applied.
#[derive(Clone, Serialize, Deserialize, zeroize::ZeroizeOnDrop)]
#[serde(transparent)]
pub struct SecretValue(pub String);

/// The reply to any control request.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ControlResponse {
    /// Whether the request was accepted.
    pub ok: bool,

    /// Failure detail when `ok` is false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// Memory sizing, present for memory requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<MemoryControlState>,

    /// CPU sizing, present for CPU requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu: Option<CpuControlState>,

    /// Supported operations, present for capability requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<ControlCapabilities>,
}

/// Live-control operations supported by this sandbox process, carried in
/// [`ControlResponse`]. Runtimes that predate this op only served the socket
/// when they could resize, so the SDK treats a missing reply as
/// resize-capable and secrets-incapable.
#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
pub struct ControlCapabilities {
    /// Live CPU online/offline targets are available.
    pub cpu_resize: bool,

    /// Live memory targets through virtio-mem are available.
    pub memory_resize: bool,

    /// Live secret rotation, removal, and allowed-host updates are available.
    pub secrets_update: bool,
}

/// Memory sizing carried in [`ControlResponse`], all in MiB.
#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
pub struct MemoryControlState {
    /// Memory the VM booted with.
    pub boot_mib: u64,

    /// Total memory the host asked the guest to converge on.
    pub target_mib: u64,

    /// Total memory currently usable by the guest.
    pub current_mib: u64,

    /// Boot-time ceiling for live growth.
    pub max_mib: u64,
}

/// CPU sizing carried in [`ControlResponse`].
#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
pub struct CpuControlState {
    /// CPUs possible in this boot.
    pub possible: u32,

    /// Online count the host asked the guest to converge on.
    pub requested_online: u32,

    /// Online count the guest driver last reported.
    pub actual_online: u32,

    /// Online count the VMM currently enforces.
    pub enforced: u32,
}

/// Everything the control listener can reach: the VMM control handle plus the
/// host network secrets layer when this build carries one.
pub struct ControlContext {
    /// Live VM resource control handle.
    pub vm: msb_krun::VmControl,

    /// Live secrets view of the sandbox's network stack, when networking is
    /// enabled and the sandbox booted with secrets.
    #[cfg(feature = "net")]
    pub secrets: Option<microsandbox_network::secrets::handle::SecretsHandle>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ControlContext {
    fn secrets_update_supported(&self) -> bool {
        #[cfg(feature = "net")]
        {
            self.secrets.is_some()
        }
        #[cfg(not(feature = "net"))]
        {
            false
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl std::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[redacted]")
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// The control socket path that belongs to the given agent socket path.
pub fn control_socket_path_for(agent_sock: &std::path::Path) -> PathBuf {
    agent_sock.with_extension(CONTROL_SOCKET_EXTENSION)
}

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
    let mut line = String::new();
    BufReader::new(&mut *stream).read_line(&mut line)?;
    stream.write_all(&respond_to_line(line.trim(), context))
}

/// Serve the Windows named-pipe listener. One pipe instance exists at a time;
/// each connection is one request/response exchange, after which the instance
/// is recreated. Zero-byte connections are tolerated because `Path::exists()`
/// probes from the SDK open and immediately close the pipe.
#[cfg(windows)]
pub fn spawn_control_listener(pipe_name: PathBuf, context: ControlContext) -> std::io::Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
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

                    let payload = respond_to_line(line.trim(), &context);
                    let mut server = reader.into_inner();
                    if let Err(e) = server.write_all(&payload).await {
                        tracing::debug!("control: response write error: {e}");
                        continue;
                    }
                    // Flush before this instance drops, or the client can
                    // lose the unread reply when the handle closes.
                    let _ = server.flush().await;
                    let _ = server.disconnect();
                }
            });
        })?;

    Ok(())
}

/// Parse one request line and produce the newline-terminated JSON reply.
fn respond_to_line(line: &str, context: &ControlContext) -> Vec<u8> {
    let response = match serde_json::from_str::<ControlRequest>(line) {
        Ok(request) => handle_request(request, context),
        Err(e) => ControlResponse {
            ok: false,
            error: Some(format!("invalid control request: {e}")),
            ..Default::default()
        },
    };

    let mut payload = serde_json::to_vec(&response).unwrap_or_default();
    payload.push(b'\n');
    payload
}

fn handle_request(request: ControlRequest, context: &ControlContext) -> ControlResponse {
    let control = &context.vm;
    let memory = |state: Option<msb_krun::VmMemoryState>| match state {
        Some(state) => ControlResponse {
            ok: true,
            memory: Some(MemoryControlState {
                boot_mib: state.boot_mib,
                target_mib: state.target_mib,
                current_mib: state.current_mib,
                max_mib: state.max_mib,
            }),
            ..Default::default()
        },
        None => ControlResponse {
            ok: false,
            error: Some("this VM booted without memory hotplug capacity".to_string()),
            ..Default::default()
        },
    };
    let cpu = |state: Option<msb_krun::VmCpuState>| match state {
        Some(state) => ControlResponse {
            ok: true,
            cpu: Some(CpuControlState {
                possible: state.possible,
                requested_online: state.requested_online,
                actual_online: state.actual_online,
                enforced: state.enforced,
            }),
            ..Default::default()
        },
        None => ControlResponse {
            ok: false,
            error: Some("this VM booted without CPU capacity".to_string()),
            ..Default::default()
        },
    };

    match request {
        ControlRequest::Capabilities => ControlResponse {
            ok: true,
            capabilities: Some(ControlCapabilities {
                cpu_resize: control.cpu_resize_supported(),
                memory_resize: control.memory_resize_supported(),
                secrets_update: context.secrets_update_supported(),
            }),
            ..Default::default()
        },
        ControlRequest::MemoryTarget { total_mib } => {
            if control.set_memory_target_mib(total_mib).is_none() {
                return memory(None);
            }
            memory(control.memory_state())
        }
        ControlRequest::MemoryState => memory(control.memory_state()),
        ControlRequest::CpuTarget { online } => {
            if control.set_cpu_target(online).is_none() {
                return cpu(None);
            }
            cpu(control.cpu_state())
        }
        ControlRequest::CpuState => cpu(control.cpu_state()),
        ControlRequest::SecretsUpdate { changes } => handle_secrets_update(context, changes),
    }
}

#[cfg(feature = "net")]
fn handle_secrets_update(
    context: &ControlContext,
    changes: Vec<SecretLiveChange>,
) -> ControlResponse {
    let Some(secrets) = &context.secrets else {
        return ControlResponse {
            ok: false,
            error: Some(
                "live secret reconfiguration is not available for this sandbox".to_string(),
            ),
            ..Default::default()
        };
    };

    for change in changes {
        let result = match change {
            // `value` owns its plaintext and zeroizes on drop; clone the inner
            // string into the rotation call (the wrapper cannot be moved out of
            // a `Drop` type) and let the original wipe itself at arm's end.
            SecretLiveChange::Rotate { name, value } => {
                secrets.rotate_value(&name, value.0.clone())
            }
            SecretLiveChange::Remove { name } => {
                secrets.remove(&name);
                Ok(())
            }
            SecretLiveChange::SetAllowedHosts { name, hosts } => {
                secrets.set_allowed_hosts(&name, &hosts)
            }
        };
        if let Err(e) = result {
            // SecretsUpdateError carries secret names only, never values.
            return ControlResponse {
                ok: false,
                error: Some(e.to_string()),
                ..Default::default()
            };
        }
    }

    ControlResponse {
        ok: true,
        ..Default::default()
    }
}

#[cfg(not(feature = "net"))]
fn handle_secrets_update(
    _context: &ControlContext,
    _changes: Vec<SecretLiveChange>,
) -> ControlResponse {
    ControlResponse {
        ok: false,
        error: Some("this runtime was built without network support".to_string()),
        ..Default::default()
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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
    fn capabilities_response_serializes_flags() {
        let response = ControlResponse {
            ok: true,
            capabilities: Some(ControlCapabilities {
                cpu_resize: true,
                memory_resize: false,
                secrets_update: true,
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
