//! Host-side runtime control socket.
//!
//! Live VM mutations that are host/VMM-owned (currently memory resize through
//! virtio-mem) cannot go through agentd: the guest is untrusted and the knob
//! lives in the VMM. The sandbox process serves them instead on a unix socket
//! next to the agent socket. The protocol is deliberately tiny: one JSON
//! request line in, one JSON response line out, per connection.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// File name of the control socket, created next to the agent socket.
pub const CONTROL_SOCKET_NAME: &str = "control.sock";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A control request from the SDK.
#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ControlRequest {
    /// Ask the guest to converge on this much total usable memory.
    MemoryTarget {
        /// Desired total memory in MiB.
        total_mib: u64,
    },

    /// Report the current memory sizing without changing anything.
    MemoryState,
}

/// The reply to any control request.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ControlResponse {
    /// Whether the request was accepted.
    pub ok: bool,

    /// Failure detail when `ok` is false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// Memory the VM booted with, in MiB.
    pub boot_mib: u64,

    /// Total memory the host asked the guest to converge on, in MiB.
    pub target_mib: u64,

    /// Total memory currently usable by the guest, in MiB.
    pub current_mib: u64,

    /// Boot-time ceiling for live growth, in MiB.
    pub max_mib: u64,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Spawn the control listener thread. Non-fatal on failure by design: the
/// caller logs and continues, and the SDK treats a missing socket as "no live
/// memory resize capability".
#[cfg(unix)]
pub fn spawn_control_listener(
    socket_path: PathBuf,
    control: msb_krun::VmControl,
) -> std::io::Result<()> {
    let _ = std::fs::remove_file(&socket_path);
    let listener = std::os::unix::net::UnixListener::bind(&socket_path)?;

    std::thread::Builder::new()
        .name("msb-control".to_string())
        .spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(mut stream) => {
                        if let Err(e) = serve_connection(&mut stream, &control) {
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
    control: &msb_krun::VmControl,
) -> std::io::Result<()> {
    let mut line = String::new();
    BufReader::new(&mut *stream).read_line(&mut line)?;

    let response = match serde_json::from_str::<ControlRequest>(line.trim()) {
        Ok(request) => handle_request(request, control),
        Err(e) => ControlResponse {
            ok: false,
            error: Some(format!("invalid control request: {e}")),
            ..Default::default()
        },
    };

    let mut payload = serde_json::to_vec(&response).unwrap_or_default();
    payload.push(b'\n');
    stream.write_all(&payload)
}

#[cfg(unix)]
fn handle_request(request: ControlRequest, control: &msb_krun::VmControl) -> ControlResponse {
    let respond = |state: Option<msb_krun::VmMemoryState>| match state {
        Some(state) => ControlResponse {
            ok: true,
            error: None,
            boot_mib: state.boot_mib,
            target_mib: state.target_mib,
            current_mib: state.current_mib,
            max_mib: state.max_mib,
        },
        None => ControlResponse {
            ok: false,
            error: Some("this VM booted without memory hotplug capacity".to_string()),
            ..Default::default()
        },
    };

    match request {
        ControlRequest::MemoryTarget { total_mib } => {
            if control.set_memory_target_mib(total_mib).is_none() {
                return respond(None);
            }
            respond(control.memory_state())
        }
        ControlRequest::MemoryState => respond(control.memory_state()),
    }
}
