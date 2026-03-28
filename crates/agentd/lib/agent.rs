//! Main agent loop: serial I/O, session management, heartbeat.

use std::{collections::HashMap, fs::OpenOptions, os::fd::AsRawFd};

use chrono::Utc;
use tokio::{
    io::unix::AsyncFd,
    sync::mpsc,
    time::{Duration, interval},
};

use microsandbox_protocol::{
    codec::{MAX_FRAME_SIZE, encode_to_buf, try_decode_from_buf},
    core::Ready,
    exec::{
        ExecExited, ExecRequest, ExecResize, ExecSignal, ExecStarted, ExecStderr, ExecStdin,
        ExecStdout,
    },
    fs::{FsData, FsRequest},
    message::{Message, MessageType},
};

use crate::{
    error::{AgentdError, AgentdResult},
    fs::FsWriteSession,
    heartbeat::{heartbeat_dir_exists, write_heartbeat},
    serial::{AGENT_PORT_NAME, find_serial_port},
    session::{ExecSession, SessionOutput},
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Heartbeat interval in seconds.
///
/// Keep this short so small idle timeouts (for example `--idle-timeout 1`)
/// can be enforced without multi-second scheduling drift.
const HEARTBEAT_INTERVAL_SECS: u64 = 1;

/// Read buffer size for the serial port.
const SERIAL_READ_BUF_SIZE: usize = 64 * 1024;

/// Maximum allowed input buffer size (frame size limit + 4 bytes for length prefix).
const MAX_INPUT_BUF_SIZE: usize = MAX_FRAME_SIZE as usize + 4;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Runs the main agent loop.
///
/// Discovers the virtio serial port, sends `core.ready` with boot timing data,
/// then enters the main select loop handling serial I/O, process output, and heartbeat.
///
/// - `boot_time_ns`: `CLOCK_BOOTTIME` at `main()` start (kernel boot duration).
/// - `init_time_ns`: nanoseconds spent in `init::init()`.
pub async fn run(boot_time_ns: u64, init_time_ns: u64) -> AgentdResult<()> {
    // Discover serial port.
    let port_path = find_serial_port(AGENT_PORT_NAME)?;

    // Open the port once with read+write. Virtio-console multiport devices
    // only allow a single open; a second open returns EBUSY.
    let port_file = OpenOptions::new().read(true).write(true).open(&port_path)?;

    // Set non-blocking for async I/O.
    let port_fd = port_file.as_raw_fd();
    set_nonblocking(port_fd)?;

    // A single AsyncFd tracks both readable and writable readiness.
    let async_port = AsyncFd::new(port_file)?;

    // Buffer for serial reads.
    let mut read_buf = vec![0u8; SERIAL_READ_BUF_SIZE];
    let mut serial_in_buf = Vec::new();
    let mut serial_out_buf = Vec::new();

    // Active exec sessions.
    let mut sessions: HashMap<u32, ExecSession> = HashMap::new();

    // Active filesystem write sessions.
    let mut write_sessions: HashMap<u32, FsWriteSession> = HashMap::new();

    // Channel for session output events.
    let (session_tx, mut session_rx) = mpsc::unbounded_channel::<(u32, SessionOutput)>();

    // Heartbeat state.
    let mut last_activity = Utc::now();
    let mut heartbeat_timer = interval(Duration::from_secs(HEARTBEAT_INTERVAL_SECS));

    // Send core.ready with boot timing data.
    let ready_time_ns = crate::clock::boottime_ns();
    let ready_msg = Message::with_payload(
        MessageType::Ready,
        0,
        &Ready {
            boot_time_ns,
            init_time_ns,
            ready_time_ns,
        },
    )
    .map_err(|e| AgentdError::ExecSession(format!("encode ready: {e}")))?;
    encode_to_buf(&ready_msg, &mut serial_out_buf)
        .map_err(|e| AgentdError::ExecSession(format!("encode ready frame: {e}")))?;
    flush_write_buf(&async_port, &mut serial_out_buf).await?;

    // Main loop.
    'agent: loop {
        tokio::select! {
            // Read from serial port.
            result = async_port.readable() => {
                let Ok(mut guard) = result else {
                    break;
                };

                loop {
                    match guard.try_io(|inner| read_from_fd(inner.get_ref().as_raw_fd(), &mut read_buf)) {
                        Ok(Ok(0)) => {
                            // EOF on serial — host disconnected.
                            break 'agent;
                        }
                        Ok(Ok(n)) => {
                            serial_in_buf.extend_from_slice(&read_buf[..n]);
                            last_activity = Utc::now();

                            // Guard against unbounded buffer growth.
                            if serial_in_buf.len() > MAX_INPUT_BUF_SIZE {
                                return Err(AgentdError::ExecSession(
                                    "serial input buffer exceeded maximum size".into(),
                                ));
                            }

                            // Try to parse complete messages.
                            while let Some(msg) = try_decode_from_buf(&mut serial_in_buf)
                                .map_err(|e| AgentdError::ExecSession(format!("decode: {e}")))?
                            {
                                handle_message(
                                    msg,
                                    &mut sessions,
                                    &mut write_sessions,
                                    &session_tx,
                                    &mut serial_out_buf,
                                ).await?;
                            }

                            // Flush any outgoing messages.
                            if !serial_out_buf.is_empty() {
                                flush_write_buf(&async_port, &mut serial_out_buf).await?;
                            }
                        }
                        Ok(Err(e)) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Ok(Err(e)) => return Err(e.into()),
                        Err(_would_block) => break,
                    }
                }
            }

            // Receive output events from session reader tasks.
            Some((id, output)) = session_rx.recv() => {
                match output {
                    SessionOutput::Stdout(data) => {
                        let msg = Message::with_payload(MessageType::ExecStdout, id, &ExecStdout { data })
                            .map_err(|e| AgentdError::ExecSession(format!("encode stdout: {e}")))?;
                        encode_to_buf(&msg, &mut serial_out_buf)
                            .map_err(|e| AgentdError::ExecSession(format!("encode stdout frame: {e}")))?;
                    }
                    SessionOutput::Stderr(data) => {
                        let msg = Message::with_payload(MessageType::ExecStderr, id, &ExecStderr { data })
                            .map_err(|e| AgentdError::ExecSession(format!("encode stderr: {e}")))?;
                        encode_to_buf(&msg, &mut serial_out_buf)
                            .map_err(|e| AgentdError::ExecSession(format!("encode stderr frame: {e}")))?;
                    }
                    SessionOutput::Exited(code) => {
                        let msg = Message::with_payload(MessageType::ExecExited, id, &ExecExited { code })
                            .map_err(|e| AgentdError::ExecSession(format!("encode exited: {e}")))?;
                        encode_to_buf(&msg, &mut serial_out_buf)
                            .map_err(|e| AgentdError::ExecSession(format!("encode exited frame: {e}")))?;
                        sessions.remove(&id);
                    }
                    SessionOutput::Raw(frame_bytes) => {
                        // Pre-encoded frame — write directly to output buffer.
                        serial_out_buf.extend_from_slice(&frame_bytes);
                    }
                }

                if !serial_out_buf.is_empty() {
                    flush_write_buf(&async_port, &mut serial_out_buf).await?;
                }
            }

            // Heartbeat tick.
            _ = heartbeat_timer.tick() => {
                if heartbeat_dir_exists() {
                    let _ = write_heartbeat(
                        sessions.len() as u32,
                        last_activity,
                    ).await;
                }
            }
        }
    }

    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Handles a single incoming message from the host.
async fn handle_message(
    msg: Message,
    sessions: &mut HashMap<u32, ExecSession>,
    write_sessions: &mut HashMap<u32, FsWriteSession>,
    session_tx: &mpsc::UnboundedSender<(u32, SessionOutput)>,
    out_buf: &mut Vec<u8>,
) -> AgentdResult<()> {
    match msg.t {
        MessageType::ExecRequest => {
            let mut req: ExecRequest = msg
                .payload()
                .map_err(|e| AgentdError::ExecSession(format!("decode exec request: {e}")))?;
            prepend_scripts_to_path(&mut req);
            match ExecSession::spawn(msg.id, &req, session_tx.clone()) {
                Ok(session) => {
                    let reply = Message::with_payload(
                        MessageType::ExecStarted,
                        msg.id,
                        &ExecStarted { pid: session.pid() },
                    )
                    .map_err(|e| AgentdError::ExecSession(format!("encode started: {e}")))?;
                    encode_to_buf(&reply, out_buf).map_err(|e| {
                        AgentdError::ExecSession(format!("encode started frame: {e}"))
                    })?;
                    sessions.insert(msg.id, session);
                }
                Err(e) => {
                    // Send an immediate exit with code -1 on spawn failure.
                    let reply = Message::with_payload(
                        MessageType::ExecExited,
                        msg.id,
                        &ExecExited { code: -1 },
                    )
                    .map_err(|e| AgentdError::ExecSession(format!("encode exited: {e}")))?;
                    encode_to_buf(&reply, out_buf).map_err(|e| {
                        AgentdError::ExecSession(format!("encode exited frame: {e}"))
                    })?;
                    eprintln!("failed to spawn exec session {}: {e}", msg.id);
                }
            }
        }

        MessageType::ExecStdin => {
            let stdin: ExecStdin = msg
                .payload()
                .map_err(|e| AgentdError::ExecSession(format!("decode stdin: {e}")))?;
            if let Some(session) = sessions.get_mut(&msg.id) {
                if stdin.data.is_empty() {
                    // Empty data signals EOF — close stdin.
                    session.close_stdin();
                } else {
                    let _ = session.write_stdin(&stdin.data).await;
                }
            }
        }

        MessageType::ExecResize => {
            let resize: ExecResize = msg
                .payload()
                .map_err(|e| AgentdError::ExecSession(format!("decode resize: {e}")))?;
            if let Some(session) = sessions.get(&msg.id) {
                let _ = session.resize(resize.rows, resize.cols);
            }
        }

        MessageType::ExecSignal => {
            let signal: ExecSignal = msg
                .payload()
                .map_err(|e| AgentdError::ExecSession(format!("decode signal: {e}")))?;
            if let Some(session) = sessions.get(&msg.id) {
                let _ = session.send_signal(signal.signal);
            }
        }

        MessageType::FsRequest => {
            let req: FsRequest = msg
                .payload()
                .map_err(|e| AgentdError::ExecSession(format!("decode fs request: {e}")))?;
            match crate::fs::handle_fs_request(msg.id, req, out_buf, session_tx).await {
                Ok(Some(ws)) => {
                    write_sessions.insert(msg.id, ws);
                }
                Ok(None) => {}
                Err(e) => {
                    eprintln!("fs request error for {}: {e}", msg.id);
                }
            }
        }

        MessageType::FsData => {
            let data: FsData = msg
                .payload()
                .map_err(|e| AgentdError::ExecSession(format!("decode fs data: {e}")))?;
            if let Some(session) = write_sessions.get_mut(&msg.id) {
                match crate::fs::handle_fs_data(msg.id, data, session, out_buf).await {
                    Ok(true) => {
                        // Session complete — remove it.
                        write_sessions.remove(&msg.id);
                    }
                    Ok(false) => {}
                    Err(e) => {
                        eprintln!("fs data error for {}: {e}", msg.id);
                        write_sessions.remove(&msg.id);
                    }
                }
            } else {
                // No write session for this ID — send error response.
                let resp = microsandbox_protocol::fs::FsResponse {
                    ok: false,
                    error: Some(format!("unknown write session: {}", msg.id)),
                    data: None,
                };
                let reply = Message::with_payload(MessageType::FsResponse, msg.id, &resp)
                    .map_err(|e| AgentdError::ExecSession(format!("encode fs error: {e}")))?;
                encode_to_buf(&reply, out_buf)
                    .map_err(|e| AgentdError::ExecSession(format!("encode fs error frame: {e}")))?;
            }
        }

        MessageType::Shutdown => {
            // Graceful shutdown — signal all sessions, then ask the guest
            // kernel to power off so block-root filesystems can shut down
            // cleanly instead of leaving ext4 journal recovery pending.
            for (_, session) in sessions.drain() {
                let _ = session.send_signal(15); // SIGTERM
            }
            write_sessions.clear();

            request_guest_poweroff()?;
            return Err(AgentdError::Shutdown);
        }

        _ => {
            // Ignore unknown or unexpected message types.
        }
    }

    Ok(())
}

/// Prepends `/.msb/scripts` to PATH in the exec request's environment.
///
/// If the request already has a PATH entry, prepends to it. Otherwise
/// inherits from agentd's environment and prepends.
/// Default PATH for the guest when no PATH is inherited.
const DEFAULT_GUEST_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

fn prepend_scripts_to_path(req: &mut microsandbox_protocol::exec::ExecRequest) {
    let scripts = microsandbox_protocol::SCRIPTS_PATH;

    // Check if the request already specifies PATH.
    if let Some(entry) = req.env.iter_mut().find(|e| e.starts_with("PATH=")) {
        let existing = &entry["PATH=".len()..];
        *entry = format!("PATH={scripts}:{existing}");
    } else {
        // Inherit from agentd's process environment, falling back to a
        // sensible default since PID 1 in a minimal guest may not have PATH.
        let inherited = std::env::var("PATH").unwrap_or_else(|_| DEFAULT_GUEST_PATH.to_string());
        req.env.push(format!("PATH={scripts}:{inherited}"));
    }
}

/// Sets a file descriptor to non-blocking mode.
fn set_nonblocking(fd: i32) -> AgentdResult<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let ret = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

/// Reads from a raw fd (non-blocking).
fn read_from_fd(fd: i32, buf: &mut [u8]) -> std::io::Result<usize> {
    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    if n < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

/// Flushes the write buffer to the async fd.
async fn flush_write_buf(fd: &AsyncFd<std::fs::File>, buf: &mut Vec<u8>) -> AgentdResult<()> {
    while !buf.is_empty() {
        let mut guard = fd.writable().await?;
        match guard.try_io(|inner| write_to_fd(inner.get_ref().as_raw_fd(), buf)) {
            Ok(Ok(n)) => {
                buf.drain(..n);
            }
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Ok(Err(e)) => return Err(e.into()),
            Err(_would_block) => continue,
        }
    }
    Ok(())
}

/// Writes to a raw fd (non-blocking).
fn write_to_fd(fd: i32, buf: &[u8]) -> std::io::Result<usize> {
    let n = unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
    if n < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

#[cfg(target_os = "linux")]
fn request_guest_poweroff() -> AgentdResult<()> {
    unsafe {
        libc::sync();
    }

    let _ = remount_root_readonly();

    unsafe {
        libc::sync();
    }

    let ret = unsafe { libc::reboot(libc::RB_POWER_OFF) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn request_guest_poweroff() -> AgentdResult<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn remount_root_readonly() -> AgentdResult<()> {
    let target = std::ffi::CString::new("/").expect("static path contains no NUL");
    let ret = unsafe {
        libc::mount(
            std::ptr::null(),
            target.as_ptr(),
            std::ptr::null(),
            (libc::MS_REMOUNT | libc::MS_RDONLY) as libc::c_ulong,
            std::ptr::null(),
        )
    };

    if ret != 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    Ok(())
}
