//! Main agent loop: serial I/O, session management, heartbeat.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::time::Instant;
use std::{env, ptr};

use chrono::Utc;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tokio::time::{self, Duration};

use microsandbox_protocol::HANDOFF_POWEROFF_TIMEOUT;
use microsandbox_protocol::codec::{self, MAX_FRAME_SIZE};
use microsandbox_protocol::core::{
    ClockSync, InitAck, InitResolved, Ready, RelayClientDisconnected, ResolvedUser,
};
use microsandbox_protocol::exec::{
    ExecExited, ExecFailed, ExecFailureKind, ExecRequest, ExecResize, ExecSignal, ExecStarted,
    ExecStderr, ExecStdin, ExecStdinError, ExecStdout,
};
use microsandbox_protocol::fs::{FsData, FsRequest};
use microsandbox_protocol::message::{Message, MessageType};

use crate::config::AgentdConfig;
use crate::error::{AgentdError, AgentdResult};
use crate::fs::{FsReadSession, FsState, FsStreamSession, FsWriteSession};
use crate::serial::AGENT_PORT_NAME;
use crate::session::{ExecSession, SessionOutput, resolve_default_user};
use crate::{clock, fs, heartbeat, serial};

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

/// Maximum time to wait for the host to acknowledge the init context.
const INIT_ACK_TIMEOUT_SECS: u64 = 60;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Default)]
struct AgentState {
    sessions: HashMap<u32, ExecSession>,
    write_sessions: HashMap<u32, FsWriteSession>,
    read_sessions: HashMap<u32, FsReadSession>,
    fs: FsState,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Runs the main agent loop.
///
/// Reuses the already-open virtio serial port, sends `core.ready` with boot timing data,
/// then enters the main select loop handling serial I/O, process output, and heartbeat.
///
/// - `boot_time_ns`: `CLOCK_BOOTTIME` at `main()` start (kernel boot duration).
/// - `init_time_ns`: nanoseconds spent in `init::init()`.
pub async fn run(
    boot_time_ns: u64,
    init_time_ns: u64,
    config: &AgentdConfig,
    port_file: File,
) -> AgentdResult<()> {
    // Set non-blocking for async I/O. Early boot handshakes use the same fd
    // in blocking mode before it is moved into the async loop.
    let port_fd = port_file.as_raw_fd();
    set_nonblocking(port_fd)?;

    // A single AsyncFd tracks both readable and writable readiness.
    let async_port = AsyncFd::new(port_file)?;

    // Buffer for serial reads.
    let mut read_buf = vec![0u8; SERIAL_READ_BUF_SIZE];
    let mut serial_in_buf = Vec::new();
    let mut serial_out_buf = Vec::new();

    let mut state = AgentState::default();

    // Channel for session output events.
    let (session_tx, mut session_rx) = mpsc::unbounded_channel::<(u32, SessionOutput)>();

    // Heartbeat state.
    let mut last_activity = Utc::now();
    let mut heartbeat_timer = time::interval(Duration::from_secs(HEARTBEAT_INTERVAL_SECS));

    // Send core.ready with boot timing data.
    let ready_time_ns = clock::boottime_ns();
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
    codec::encode_to_buf(&ready_msg, &mut serial_out_buf)
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

                            // Guard against unbounded buffer growth.
                            if serial_in_buf.len() > MAX_INPUT_BUF_SIZE {
                                return Err(AgentdError::ExecSession(
                                    "serial input buffer exceeded maximum size".into(),
                                ));
                            }

                            // Try to parse complete messages.
                            while let Some(msg) = codec::try_decode_from_buf(&mut serial_in_buf)
                                .map_err(|e| AgentdError::ExecSession(format!("decode: {e}")))?
                            {
                                if message_refreshes_idle_timer(&msg.t) {
                                    last_activity = Utc::now();
                                }

                                handle_message(
                                    msg,
                                    &mut state,
                                    &session_tx,
                                    &mut serial_out_buf,
                                    config,
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
                        codec::encode_to_buf(&msg, &mut serial_out_buf)
                            .map_err(|e| AgentdError::ExecSession(format!("encode stdout frame: {e}")))?;
                    }
                    SessionOutput::Stderr(data) => {
                        let msg = Message::with_payload(MessageType::ExecStderr, id, &ExecStderr { data })
                            .map_err(|e| AgentdError::ExecSession(format!("encode stderr: {e}")))?;
                        codec::encode_to_buf(&msg, &mut serial_out_buf)
                            .map_err(|e| AgentdError::ExecSession(format!("encode stderr frame: {e}")))?;
                    }
                    SessionOutput::Exited(code) => {
                        let msg = Message::with_payload(MessageType::ExecExited, id, &ExecExited { code })
                            .map_err(|e| AgentdError::ExecSession(format!("encode exited: {e}")))?;
                        codec::encode_to_buf(&msg, &mut serial_out_buf)
                            .map_err(|e| AgentdError::ExecSession(format!("encode exited frame: {e}")))?;
                        state.sessions.remove(&id);
                    }
                    SessionOutput::Raw(frame_bytes) => {
                        remove_completed_fs_read(&frame_bytes, &mut state.read_sessions);
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
                if heartbeat::heartbeat_dir_exists() {
                    let _ = heartbeat::write_heartbeat(
                        state.sessions.len() as u32,
                        last_activity,
                    ).await;
                }
            }
        }
    }

    Ok(())
}

/// Opens the agent virtio-serial port once for early boot handshakes and the agent loop.
pub fn open_serial_port() -> AgentdResult<File> {
    // Discover serial port.
    let port_path = serial::find_serial_port(AGENT_PORT_NAME)?;

    // Open the port once with read+write. Virtio-console multiport devices
    // only allow a single open; a second open returns EBUSY.
    Ok(OpenOptions::new().read(true).write(true).open(&port_path)?)
}

/// Reports init-time guest context to the host and waits for an acknowledgement.
pub fn report_init_context(port_file: &File, default_user: Option<&str>) -> AgentdResult<()> {
    let (uid, gid) = resolve_default_user(default_user)?;
    let deadline = init_ack_deadline();
    let fd = port_file.as_raw_fd();
    set_nonblocking(fd)?;

    let msg = Message::with_payload(
        MessageType::InitResolved,
        0,
        &InitResolved {
            default_user: ResolvedUser { uid, gid },
        },
    )
    .map_err(|e| AgentdError::ExecSession(format!("encode init context: {e}")))?;

    let mut out = Vec::new();
    codec::encode_to_buf(&msg, &mut out)
        .map_err(|e| AgentdError::ExecSession(format!("encode init context frame: {e}")))?;
    write_all_to_fd(fd, &out, deadline)?;
    wait_for_init_ack(fd, deadline)
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Handles a single incoming message from the host.
async fn handle_message(
    msg: Message,
    state: &mut AgentState,
    session_tx: &mpsc::UnboundedSender<(u32, SessionOutput)>,
    out_buf: &mut Vec<u8>,
    config: &AgentdConfig,
) -> AgentdResult<()> {
    match msg.t {
        MessageType::ExecRequest => {
            let mut req: ExecRequest = msg
                .payload()
                .map_err(|e| AgentdError::ExecSession(format!("decode exec request: {e}")))?;
            prepend_scripts_to_path(&mut req);
            match ExecSession::spawn(msg.id, &req, session_tx.clone(), config.user.as_deref()) {
                Ok(session) => {
                    let reply = Message::with_payload(
                        MessageType::ExecStarted,
                        msg.id,
                        &ExecStarted { pid: session.pid() },
                    )
                    .map_err(|e| AgentdError::ExecSession(format!("encode started: {e}")))?;
                    codec::encode_to_buf(&reply, out_buf).map_err(|e| {
                        AgentdError::ExecSession(format!("encode started frame: {e}"))
                    })?;
                    state.sessions.insert(msg.id, session);
                }
                Err(e) => {
                    // Send a typed `ExecFailed` so the host can render a
                    // useful message + hint. `ExecSpawnFailed` already
                    // carries the structured payload; other error
                    // variants (free-form `ExecSession(_)` etc.) get
                    // wrapped as `Other` with the message preserved.
                    let payload = match &e {
                        AgentdError::ExecSpawnFailed(p) => p.clone(),
                        other => ExecFailed {
                            kind: ExecFailureKind::Other,
                            errno: None,
                            errno_name: None,
                            message: other.to_string(),
                            stage: None,
                        },
                    };
                    let reply = Message::with_payload(MessageType::ExecFailed, msg.id, &payload)
                        .map_err(|e| AgentdError::ExecSession(format!("encode failed: {e}")))?;
                    codec::encode_to_buf(&reply, out_buf).map_err(|e| {
                        AgentdError::ExecSession(format!("encode failed frame: {e}"))
                    })?;
                    eprintln!("failed to spawn exec session {}: {e}", msg.id);
                }
            }
        }

        MessageType::ExecStdin => {
            let stdin: ExecStdin = msg
                .payload()
                .map_err(|e| AgentdError::ExecSession(format!("decode stdin: {e}")))?;
            if let Some(session) = state.sessions.get_mut(&msg.id) {
                if stdin.data.is_empty() {
                    // Empty data signals EOF — close stdin.
                    session.close_stdin();
                } else if let Err(e) = session.write_stdin(&stdin.data).await {
                    let payload = stdin_error_payload(&e);
                    eprintln!("stdin write error on session {}: {e}", msg.id);
                    let reply =
                        Message::with_payload(MessageType::ExecStdinError, msg.id, &payload)
                            .map_err(|e| {
                                AgentdError::ExecSession(format!("encode stdin error: {e}"))
                            })?;
                    codec::encode_to_buf(&reply, out_buf).map_err(|e| {
                        AgentdError::ExecSession(format!("encode stdin error frame: {e}"))
                    })?;
                }
            }
        }

        MessageType::ExecResize => {
            let resize: ExecResize = msg
                .payload()
                .map_err(|e| AgentdError::ExecSession(format!("decode resize: {e}")))?;
            if let Some(session) = state.sessions.get(&msg.id) {
                let _ = session.resize(resize.rows, resize.cols);
            }
        }

        MessageType::ExecSignal => {
            let signal: ExecSignal = msg
                .payload()
                .map_err(|e| AgentdError::ExecSession(format!("decode signal: {e}")))?;
            if let Some(session) = state.sessions.get(&msg.id) {
                let _ = session.send_signal(signal.signal);
            }
        }

        MessageType::FsRequest => {
            let req: FsRequest = msg
                .payload()
                .map_err(|e| AgentdError::ExecSession(format!("decode fs request: {e}")))?;
            match fs::handle_fs_request(msg.id, req, &mut state.fs, out_buf, session_tx).await {
                Ok(Some(FsStreamSession::Read(rs))) => {
                    state.read_sessions.insert(msg.id, rs);
                }
                Ok(Some(FsStreamSession::Write(ws))) => {
                    state.write_sessions.insert(msg.id, ws);
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
            if let Some(session) = state.write_sessions.get_mut(&msg.id) {
                match fs::handle_fs_data(msg.id, data, session, out_buf).await {
                    Ok(true) => {
                        // Session complete — remove it.
                        state.write_sessions.remove(&msg.id);
                    }
                    Ok(false) => {}
                    Err(e) => {
                        eprintln!("fs data error for {}: {e}", msg.id);
                        state.write_sessions.remove(&msg.id);
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
                codec::encode_to_buf(&reply, out_buf)
                    .map_err(|e| AgentdError::ExecSession(format!("encode fs error frame: {e}")))?;
            }
        }

        MessageType::RelayClientDisconnected => {
            let disconnected: RelayClientDisconnected = msg
                .payload()
                .map_err(|e| AgentdError::ExecSession(format!("decode relay disconnect: {e}")))?;
            state
                .fs
                .close_owner_range(disconnected.id_start, disconnected.id_end_exclusive);
            abort_read_sessions_in_owner_range(
                &mut state.read_sessions,
                disconnected.id_start,
                disconnected.id_end_exclusive,
            );
            state.write_sessions.retain(|_, session| {
                let owner_id = session.owner_id();
                owner_id < disconnected.id_start || owner_id >= disconnected.id_end_exclusive
            });
        }

        MessageType::ClockSync => {
            let sync: ClockSync = msg
                .payload()
                .map_err(|e| AgentdError::ExecSession(format!("decode clock sync: {e}")))?;
            if let Err(e) = clock::sync_realtime_unix_nanos(sync.unix_time_nanos) {
                eprintln!("clock: failed to sync realtime clock: {e}");
            }
        }

        MessageType::Shutdown => {
            // Graceful shutdown — signal all sessions, then ask the guest
            // kernel to power off so block-root filesystems can shut down
            // cleanly instead of leaving ext4 journal recovery pending.
            for (_, session) in state.sessions.drain() {
                let _ = session.send_signal(15); // SIGTERM
            }
            state.write_sessions.clear();
            state.fs.clear();

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

/// Returns whether a host message should refresh the sandbox idle timer.
///
/// Maintenance traffic such as clock synchronization must not count as user
/// activity, otherwise periodic host tasks would keep an idle sandbox alive.
fn message_refreshes_idle_timer(t: &MessageType) -> bool {
    !matches!(t, MessageType::ClockSync)
}

fn remove_completed_fs_read(frame_bytes: &[u8], read_sessions: &mut HashMap<u32, FsReadSession>) {
    let mut buf = frame_bytes.to_vec();
    let Ok(Some(msg)) = codec::try_decode_from_buf(&mut buf) else {
        return;
    };
    if msg.t == MessageType::FsResponse {
        read_sessions.remove(&msg.id);
    }
}

fn abort_read_sessions_in_owner_range(
    read_sessions: &mut HashMap<u32, FsReadSession>,
    id_start: u32,
    id_end_exclusive: u32,
) {
    let mut retained = HashMap::new();
    for (id, session) in read_sessions.drain() {
        let owner_id = session.owner_id();
        if owner_id >= id_start && owner_id < id_end_exclusive {
            session.abort();
        } else {
            retained.insert(id, session);
        }
    }
    *read_sessions = retained;
}

/// Build an `ExecStdinError` payload from a failed `write_stdin` result.
fn stdin_error_payload(err: &AgentdError) -> ExecStdinError {
    let io_err = match err {
        AgentdError::Io(e) => Some(e),
        _ => None,
    };
    let errno = io_err.and_then(|e| e.raw_os_error());
    ExecStdinError {
        errno,
        errno_name: errno.and_then(errno_name),
        message: err.to_string(),
    }
}

/// Map common errno values to their standard names. Returns `None` for
/// codes we don't recognize; callers fall back to the numeric `errno`.
fn errno_name(code: i32) -> Option<String> {
    let name = match code {
        libc::EPIPE => "EPIPE",
        libc::EBADF => "EBADF",
        libc::EINVAL => "EINVAL",
        libc::EIO => "EIO",
        libc::ENOSPC => "ENOSPC",
        libc::EFBIG => "EFBIG",
        _ => return None,
    };
    Some(name.to_string())
}

fn prepend_scripts_to_path(req: &mut microsandbox_protocol::exec::ExecRequest) {
    let scripts = microsandbox_protocol::SCRIPTS_PATH;

    // Check if the request already specifies PATH.
    if let Some(entry) = req.env.iter_mut().find(|e| e.starts_with("PATH=")) {
        let existing = &entry["PATH=".len()..];
        *entry = format!("PATH={scripts}:{existing}");
    } else {
        // Inherit from agentd's process environment, falling back to a
        // sensible default since PID 1 in a minimal guest may not have PATH.
        let inherited = env::var("PATH").unwrap_or_else(|_| DEFAULT_GUEST_PATH.to_string());
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

fn init_ack_deadline() -> Instant {
    Instant::now() + std::time::Duration::from_secs(INIT_ACK_TIMEOUT_SECS)
}

fn init_ack_timeout() -> AgentdError {
    AgentdError::ExecSession("timed out waiting for init ack".into())
}

fn wait_for_init_ack(fd: i32, deadline: Instant) -> AgentdResult<()> {
    let mut serial_in_buf = Vec::new();
    let mut read_buf = [0u8; 4096];

    loop {
        if let Some(msg) = codec::try_decode_from_buf(&mut serial_in_buf)
            .map_err(|e| AgentdError::ExecSession(format!("decode init ack: {e}")))?
        {
            if msg.t == MessageType::InitAck {
                let _: InitAck = msg.payload().map_err(|e| {
                    AgentdError::ExecSession(format!("decode init ack payload: {e}"))
                })?;
                return Ok(());
            }

            return Err(AgentdError::ExecSession(format!(
                "expected core.init.ack, got {}",
                msg.t.as_str()
            )));
        }

        if serial_in_buf.len() > MAX_INPUT_BUF_SIZE {
            return Err(AgentdError::ExecSession(
                "serial input buffer exceeded maximum size while waiting for init ack".into(),
            ));
        }

        if !poll_fd_until(fd, libc::POLLIN, deadline)? {
            return Err(init_ack_timeout());
        }

        let n = match read_from_fd(fd, &mut read_buf) {
            Ok(n) => n,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                ) =>
            {
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        if n == 0 {
            return Err(AgentdError::ExecSession(
                "serial port closed while waiting for init ack".into(),
            ));
        }
        serial_in_buf.extend_from_slice(&read_buf[..n]);
    }
}

fn poll_fd_until(fd: i32, events: i16, deadline: Instant) -> AgentdResult<bool> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(false);
        }

        let timeout_ms = remaining.as_millis().min(i32::MAX as u128) as i32;
        let timeout_ms = if timeout_ms == 0 { 1 } else { timeout_ms };
        let mut pfd = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        let ret = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if ret > 0 {
            return Ok(true);
        }
        if ret == 0 {
            return Ok(false);
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return Err(err.into());
    }
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

fn write_all_to_fd(fd: i32, mut buf: &[u8], deadline: Instant) -> AgentdResult<()> {
    while !buf.is_empty() {
        match write_to_fd(fd, buf) {
            Ok(0) => return Err(std::io::Error::from(std::io::ErrorKind::WriteZero).into()),
            Ok(n) => buf = &buf[n..],
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if !poll_fd_until(fd, libc::POLLOUT, deadline)? {
                    return Err(init_ack_timeout());
                }
            }
            Err(e) => return Err(e.into()),
        }
    }

    Ok(())
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

fn request_guest_poweroff() -> AgentdResult<()> {
    unsafe {
        libc::sync();
    }

    if crate::handoff::is_pid_1() {
        // PID 1 mode (no handoff): remount root RO and reboot.
        let _ = remount_root_readonly();
        unsafe {
            libc::sync();
        }
        let ret = unsafe { libc::reboot(libc::RB_POWER_OFF) };
        if ret != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        return Ok(());
    }

    // Handoff mode: ask the new init (PID 1) to shut down.
    // SIGRTMIN+4 is systemd's poweroff signal; sysvinit-derived inits
    // typically default-handle it as a clean exit. Either way, PID 1
    // exiting causes the kernel to panic the guest, which the VMM
    // observes as a clean shutdown.
    if crate::handoff::signal_init_shutdown().is_ok() {
        std::thread::sleep(HANDOFF_POWEROFF_TIMEOUT);
    }

    // SIGTERM fallback for inits that didn't act on SIGRTMIN+4. If
    // both are ignored, we return Ok and let the host's outer
    // VMM-process kill be the backstop — the VM still dies, just
    // less gracefully.
    let _ = crate::handoff::signal_init_term();
    Ok(())
}

fn remount_root_readonly() -> AgentdResult<()> {
    let target = std::ffi::CString::new("/").expect("static path contains no NUL");
    let ret = unsafe {
        libc::mount(
            ptr::null(),
            target.as_ptr(),
            ptr::null(),
            (libc::MS_REMOUNT | libc::MS_RDONLY) as libc::c_ulong,
            ptr::null(),
        )
    };

    if ret != 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    Ok(())
}
