//! Host-side runtime control listener and VM mutation handlers.

#[cfg(unix)]
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

use crate::control::{
    ControlCapabilities, ControlRequest, ControlResponse, CpuControlState, MemoryControlState,
    SecretLiveChange,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

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
                        Ok(0) => continue,
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
                    // Flush before this instance drops, or the client can lose
                    // the unread reply when the handle closes.
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
