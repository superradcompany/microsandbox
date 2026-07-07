//! Main agent loop: serial I/O, session management, heartbeat.

use std::collections::HashMap;
use std::env;
use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use chrono::Utc;
use tokio::io::unix::AsyncFd;
use tokio::sync::{mpsc, watch};
use tokio::time::{self, Duration};

use microsandbox_protocol::HANDOFF_POWEROFF_TIMEOUT;
use microsandbox_protocol::codec::{self, MAX_FRAME_SIZE};
use microsandbox_protocol::core::{
    ClockSync, CoreError, CoreErrorKind, InitAck, InitResolved, Ping, Pong, Ready,
    RelayClientDisconnected, ResolvedUser, Touch, Touched,
};
use microsandbox_protocol::exec::{
    ExecExited, ExecFailed, ExecFailureKind, ExecRequest, ExecResize, ExecSignal, ExecStarted,
    ExecStderr, ExecStdin, ExecStdinError, ExecStdout,
};
use microsandbox_protocol::fs::{FsData, FsRequest};
use microsandbox_protocol::heartbeat::{ActivityCounters, Heartbeat};
use microsandbox_protocol::message::{Message, MessageType};
use microsandbox_protocol::tcp::{TcpClose, TcpConnect, TcpData, TcpEof, TcpFailed};

use crate::config::AgentdConfig;
use crate::error::{AgentdError, AgentdResult};
use crate::fs::{FsReadSession, FsState, FsStreamSession, FsWriteSession};
use crate::serial::AGENT_PORT_NAME;
use crate::session::{
    ExecSession, RawActivity, RawSessionCompletion, SessionOutput, resolve_default_user,
};
use crate::tcp::TcpSession;
use crate::{clock, fs, handoff, heartbeat, serial};

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
    tcp_sessions: HashMap<u32, TcpSession>,
    fs: FsState,
}

struct ActivityTracker {
    activity_seq: u64,
    counters: ActivityCounters,
}

#[derive(Clone)]
struct HeartbeatSnapshot {
    activity_seq: u64,
    active_exec_sessions: u32,
    active_fs_streams: u32,
    active_tcp_streams: u32,
    counters: ActivityCounters,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ActivityTracker {
    fn new() -> Self {
        Self {
            activity_seq: 0,
            counters: ActivityCounters::default(),
        }
    }

    fn record_host_message(&mut self) {
        self.touch();
        self.counters.host_messages = self.counters.host_messages.saturating_add(1);
    }

    fn record_guest_message(&mut self) {
        self.touch();
        self.counters.guest_messages = self.counters.guest_messages.saturating_add(1);
    }

    fn add_exec_output_bytes(&mut self, len: usize) {
        self.counters.exec_output_bytes =
            self.counters.exec_output_bytes.saturating_add(len as u64);
    }

    fn add_fs_bytes(&mut self, len: usize) {
        self.counters.fs_bytes = self.counters.fs_bytes.saturating_add(len as u64);
    }

    fn add_tcp_bytes(&mut self, len: usize) {
        self.counters.tcp_bytes = self.counters.tcp_bytes.saturating_add(len as u64);
    }

    fn touch(&mut self) {
        self.activity_seq = self.activity_seq.saturating_add(1);
    }
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

    // Heartbeat/activity state.
    let mut activity = ActivityTracker::new();
    let (heartbeat_tx, heartbeat_rx) = watch::channel(heartbeat_snapshot(&state, &activity));
    // The liveness pulse runs on a dedicated OS thread, NOT a Tokio task. On the
    // single-threaded agent runtime a flood of exec output can monopolize the
    // executor and starve a heartbeat *task*, freezing the pulse even though the
    // agent is alive — which makes the host wrongly declare it unresponsive and
    // kill the sandbox. A plain OS thread is scheduled by the guest kernel
    // independently of the async runtime, so the pulse keeps ticking under load.
    let heartbeat_shutdown = Arc::new(AtomicBool::new(false));
    let heartbeat_thread = spawn_heartbeat_thread(heartbeat_rx, Arc::clone(&heartbeat_shutdown));

    // Send core.ready with boot timing data.
    let ready_time_ns = clock::boottime_ns();
    let ready_msg = Message::with_payload(
        MessageType::Ready,
        0,
        &Ready {
            boot_time_ns,
            init_time_ns,
            ready_time_ns,
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
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
                            if !handoff::is_pid_1() {
                                guard.clear_ready();
                                drop(guard);
                                time::sleep(Duration::from_millis(100)).await;
                                break;
                            }
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

                            // Try to parse complete frames. Recoverable
                            // message-level failures are reported on the same
                            // correlation ID with `core.error`; unrecoverable
                            // frame-level failures still close the agent loop.
                            while let Some(frame) = codec::try_decode_raw_from_buf(&mut serial_in_buf)
                                .map_err(|e| AgentdError::ExecSession(format!("decode frame: {e}")))?
                            {
                                let id = frame.id;
                                let msg = match codec::raw_frame_to_message(frame) {
                                    Ok(msg) => msg,
                                    Err(e) => {
                                        return Err(AgentdError::ExecSession(format!(
                                            "decode message for id {id}: {e}"
                                        )));
                                    }
                                };

                                if msg.flags != msg.t.flags() {
                                    let out_before = serial_out_buf.len();
                                    encode_core_error_if_supported(
                                        &msg,
                                        msg.id,
                                        CoreErrorKind::InvalidFlags,
                                        format!(
                                            "invalid flags for {}: got {}, expected {}",
                                            msg.t.as_str(),
                                            msg.flags,
                                            msg.t.flags()
                                        ),
                                        Some(msg.t.as_str().to_string()),
                                        &mut serial_out_buf,
                                    )?;
                                    record_encoded_guest_messages(
                                        &serial_out_buf,
                                        out_before,
                                        &mut activity,
                                    );
                                    publish_heartbeat_snapshot(&heartbeat_tx, &state, &activity);
                                    continue;
                                }

                                if message_refreshes_idle_timer(&msg.t) {
                                    activity.record_host_message();
                                    publish_heartbeat_snapshot(&heartbeat_tx, &state, &activity);
                                }

                                let out_before = serial_out_buf.len();
                                handle_message(
                                    msg,
                                    &mut state,
                                    &mut activity,
                                    &session_tx,
                                    &mut serial_out_buf,
                                    config,
                                ).await?;
                                record_encoded_guest_messages(
                                    &serial_out_buf,
                                    out_before,
                                    &mut activity,
                                );
                                publish_heartbeat_snapshot(&heartbeat_tx, &state, &activity);
                            }

                            // Flush any outgoing messages.
                            if !serial_out_buf.is_empty() {
                                flush_write_buf(&async_port, &mut serial_out_buf).await?;
                            }
                        }
                        Ok(Err(e)) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Ok(Err(_)) if !handoff::is_pid_1() => {
                            guard.clear_ready();
                            drop(guard);
                            time::sleep(Duration::from_millis(100)).await;
                            break;
                        }
                        Ok(Err(e)) => return Err(e.into()),
                        Err(_would_block) => break,
                    }
                }
            }

            // Receive output events from session reader tasks.
            Some((id, output)) = session_rx.recv() => {
                match output {
                    SessionOutput::Stdout(data) => {
                        let len = data.len();
                        let msg = Message::with_payload(MessageType::ExecStdout, id, &ExecStdout { data })
                            .map_err(|e| AgentdError::ExecSession(format!("encode stdout: {e}")))?;
                        codec::encode_to_buf(&msg, &mut serial_out_buf)
                            .map_err(|e| AgentdError::ExecSession(format!("encode stdout frame: {e}")))?;
                        activity.record_guest_message();
                        activity.add_exec_output_bytes(len);
                    }
                    SessionOutput::Stderr(data) => {
                        let len = data.len();
                        let msg = Message::with_payload(MessageType::ExecStderr, id, &ExecStderr { data })
                            .map_err(|e| AgentdError::ExecSession(format!("encode stderr: {e}")))?;
                        codec::encode_to_buf(&msg, &mut serial_out_buf)
                            .map_err(|e| AgentdError::ExecSession(format!("encode stderr frame: {e}")))?;
                        activity.record_guest_message();
                        activity.add_exec_output_bytes(len);
                    }
                    SessionOutput::Exited(code) => {
                        let msg = Message::with_payload(MessageType::ExecExited, id, &ExecExited { code })
                            .map_err(|e| AgentdError::ExecSession(format!("encode exited: {e}")))?;
                        codec::encode_to_buf(&msg, &mut serial_out_buf)
                            .map_err(|e| AgentdError::ExecSession(format!("encode exited frame: {e}")))?;
                        state.sessions.remove(&id);
                        activity.record_guest_message();
                    }
                    SessionOutput::Raw(output) => {
                        apply_raw_activity(output.activity, &mut activity);
                        complete_raw_session(
                            id,
                            output.completion,
                            &mut state.read_sessions,
                            &mut state.tcp_sessions,
                        );
                        // Pre-encoded frame — write directly to output buffer.
                        serial_out_buf.extend_from_slice(&output.frame);
                    }
                }
                publish_heartbeat_snapshot(&heartbeat_tx, &state, &activity);

                if !serial_out_buf.is_empty() {
                    flush_write_buf(&async_port, &mut serial_out_buf).await?;
                }
            }
        }
    }

    heartbeat_shutdown.store(true, Ordering::Relaxed);
    let _ = heartbeat_thread.join();

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
    activity: &mut ActivityTracker,
    session_tx: &mpsc::UnboundedSender<(u32, SessionOutput)>,
    out_buf: &mut Vec<u8>,
    config: &AgentdConfig,
) -> AgentdResult<()> {
    match msg.t {
        MessageType::Ping => {
            let Some(_) = decode_payload_or_core_error::<Ping>(&msg, out_buf)? else {
                return Ok(());
            };
            let reply = Message::with_payload(MessageType::Pong, msg.id, &Pong {})
                .map_err(|e| AgentdError::ExecSession(format!("encode pong: {e}")))?;
            codec::encode_to_buf(&reply, out_buf)
                .map_err(|e| AgentdError::ExecSession(format!("encode pong frame: {e}")))?;
        }

        MessageType::Touch => {
            let Some(_) = decode_payload_or_core_error::<Touch>(&msg, out_buf)? else {
                return Ok(());
            };
            activity.record_host_message();
            let reply = Message::with_payload(
                MessageType::Touched,
                msg.id,
                &Touched {
                    activity_seq: activity.activity_seq,
                },
            )
            .map_err(|e| AgentdError::ExecSession(format!("encode touched: {e}")))?;
            codec::encode_to_buf(&reply, out_buf)
                .map_err(|e| AgentdError::ExecSession(format!("encode touched frame: {e}")))?;
        }

        MessageType::ExecRequest => {
            let Some(mut req) = decode_payload_or_core_error::<ExecRequest>(&msg, out_buf)? else {
                return Ok(());
            };
            prepend_scripts_to_path(&mut req);
            match ExecSession::spawn(
                msg.id,
                &req,
                session_tx.clone(),
                config.user.as_deref(),
                config.security_profile,
            ) {
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
            let Some(stdin) = decode_payload_or_core_error::<ExecStdin>(&msg, out_buf)? else {
                return Ok(());
            };
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
            let Some(resize) = decode_payload_or_core_error::<ExecResize>(&msg, out_buf)? else {
                return Ok(());
            };
            if let Some(session) = state.sessions.get(&msg.id) {
                let _ = session.resize(resize.rows, resize.cols);
            }
        }

        MessageType::ExecSignal => {
            let Some(signal) = decode_payload_or_core_error::<ExecSignal>(&msg, out_buf)? else {
                return Ok(());
            };
            if let Some(session) = state.sessions.get(&msg.id) {
                let _ = session.send_signal(signal.signal);
            }
        }

        MessageType::FsRequest => {
            let Some(req) = decode_payload_or_core_error::<FsRequest>(&msg, out_buf)? else {
                return Ok(());
            };
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
            let Some(data) = decode_payload_or_core_error::<FsData>(&msg, out_buf)? else {
                return Ok(());
            };
            let len = data.data.len();
            if let Some(session) = state.write_sessions.get_mut(&msg.id) {
                match fs::handle_fs_data(msg.id, data, session, out_buf).await {
                    Ok(true) => {
                        // Session complete — remove it.
                        state.write_sessions.remove(&msg.id);
                    }
                    Ok(false) => {
                        activity.add_fs_bytes(len);
                    }
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

        MessageType::TcpConnect => {
            let Some(req) = decode_payload_or_core_error::<TcpConnect>(&msg, out_buf)? else {
                return Ok(());
            };
            // The connect runs inside the session task; the agent loop never
            // blocks on it. Success or failure arrives later as a tcp frame.
            let session = TcpSession::open(msg.id, req, session_tx);
            state.tcp_sessions.insert(msg.id, session);
        }

        MessageType::TcpData => {
            let Some(data) = decode_payload_or_core_error::<TcpData>(&msg, out_buf)? else {
                return Ok(());
            };
            let len = data.data.len();
            if let Some(session) = state.tcp_sessions.get(&msg.id) {
                if let Err(e) = session.write_data(data.data).await {
                    state.tcp_sessions.remove(&msg.id);
                    encode_tcp_failed(msg.id, e, out_buf)?;
                } else {
                    activity.add_tcp_bytes(len);
                }
            } else {
                encode_tcp_failed(msg.id, format!("unknown TCP session: {}", msg.id), out_buf)?;
            }
        }

        MessageType::TcpEof => {
            let Some(_) = decode_payload_or_core_error::<TcpEof>(&msg, out_buf)? else {
                return Ok(());
            };
            if let Some(session) = state.tcp_sessions.get(&msg.id)
                && let Err(e) = session.close_write().await
            {
                state.tcp_sessions.remove(&msg.id);
                encode_tcp_failed(msg.id, e, out_buf)?;
            }
        }

        MessageType::TcpClose => {
            let Some(_) = decode_payload_or_core_error::<TcpClose>(&msg, out_buf)? else {
                return Ok(());
            };
            if let Some(session) = state.tcp_sessions.remove(&msg.id) {
                session.close();
            }
        }

        MessageType::RelayClientDisconnected => {
            let Some(disconnected) =
                decode_payload_or_core_error::<RelayClientDisconnected>(&msg, out_buf)?
            else {
                return Ok(());
            };
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
            close_tcp_sessions_in_owner_range(
                &mut state.tcp_sessions,
                disconnected.id_start,
                disconnected.id_end_exclusive,
            );
        }

        MessageType::ClockSync => {
            let Some(sync) = decode_payload_or_core_error::<ClockSync>(&msg, out_buf)? else {
                return Ok(());
            };
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
            for (_, session) in state.tcp_sessions.drain() {
                session.close();
            }
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
/// Maintenance traffic such as clock synchronization and reachability checks
/// must not count as user activity, otherwise periodic host tasks would keep an
/// idle sandbox alive. `core.touch` is excluded here too because it refreshes
/// idleness explicitly in its handler, after its payload has been validated.
fn message_refreshes_idle_timer(t: &MessageType) -> bool {
    !matches!(
        t,
        MessageType::ClockSync | MessageType::Ping | MessageType::Touch
    )
}

/// Returns whether an agent reply should refresh the sandbox idle timer.
///
/// Most guest output still represents useful sandbox activity. Maintenance
/// replies to `core.ping` and `core.touch` are excluded so `ping` is a pure
/// health check and `touch` advances activity exactly once. `core.error` is
/// also excluded because valid work already records activity on the incoming
/// request, while malformed maintenance traffic should not become a keepalive.
fn guest_message_refreshes_idle_timer(t: &MessageType) -> bool {
    !matches!(
        t,
        MessageType::Pong | MessageType::Touched | MessageType::CoreError
    )
}

/// Spawns the heartbeat pulse on a dedicated OS thread.
///
/// This thread is intentionally outside the Tokio runtime: it reads the latest
/// [`HeartbeatSnapshot`] (a lock-free `watch` borrow) and writes the heartbeat
/// file with blocking `std::fs` once per [`HEARTBEAT_INTERVAL_SECS`]. Because it
/// is an ordinary kernel-scheduled thread, a CPU-bound or I/O-saturated async
/// runtime cannot delay the pulse — which is exactly the starvation that made
/// the host kill busy-but-healthy sandboxes. The sleep is chunked so the thread
/// observes the shutdown flag promptly when the agent loop exits.
fn spawn_heartbeat_thread(
    snapshot_rx: watch::Receiver<HeartbeatSnapshot>,
    shutdown: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("agentd-heartbeat".to_string())
        .spawn(move || {
            let mut heartbeat_seq = 0u64;
            let mut last_activity_seq = snapshot_rx.borrow().activity_seq;
            let mut last_activity = Utc::now();

            let interval = Duration::from_secs(HEARTBEAT_INTERVAL_SECS);
            let step = Duration::from_millis(100);

            while !shutdown.load(Ordering::Relaxed) {
                let mut slept = Duration::ZERO;
                while slept < interval {
                    if shutdown.load(Ordering::Relaxed) {
                        return;
                    }
                    std::thread::sleep(step);
                    slept += step;
                }

                if !heartbeat::heartbeat_dir_exists() {
                    continue;
                }

                heartbeat_seq = heartbeat_seq.saturating_add(1);
                let snapshot = snapshot_rx.borrow().clone();
                let timestamp = Utc::now();
                if snapshot.activity_seq != last_activity_seq {
                    last_activity_seq = snapshot.activity_seq;
                    last_activity = timestamp;
                }
                let heartbeat = Heartbeat {
                    heartbeat_seq,
                    activity_seq: snapshot.activity_seq,
                    timestamp,
                    last_activity,
                    active_exec_sessions: snapshot.active_exec_sessions,
                    active_fs_streams: snapshot.active_fs_streams,
                    active_tcp_streams: snapshot.active_tcp_streams,
                    activity_counters: snapshot.counters,
                };
                let _ = heartbeat::write_heartbeat(&heartbeat);
            }
        })
        .expect("failed to spawn agentd heartbeat thread")
}

fn heartbeat_snapshot(state: &AgentState, activity: &ActivityTracker) -> HeartbeatSnapshot {
    HeartbeatSnapshot {
        activity_seq: activity.activity_seq,
        active_exec_sessions: state.sessions.len() as u32,
        active_fs_streams: state
            .read_sessions
            .len()
            .saturating_add(state.write_sessions.len()) as u32,
        active_tcp_streams: state.tcp_sessions.len() as u32,
        counters: activity.counters,
    }
}

fn publish_heartbeat_snapshot(
    heartbeat_tx: &watch::Sender<HeartbeatSnapshot>,
    state: &AgentState,
    activity: &ActivityTracker,
) {
    let _ = heartbeat_tx.send(heartbeat_snapshot(state, activity));
}

fn record_encoded_guest_messages(out_buf: &[u8], start: usize, activity: &mut ActivityTracker) {
    let mut offset = start;
    while offset + 4 <= out_buf.len() {
        let frame_len = u32::from_be_bytes([
            out_buf[offset],
            out_buf[offset + 1],
            out_buf[offset + 2],
            out_buf[offset + 3],
        ]) as usize;
        let total = 4usize.saturating_add(frame_len);
        if offset.saturating_add(total) > out_buf.len() {
            break;
        }

        if encoded_guest_message_refreshes_idle_timer(out_buf, offset, frame_len) {
            activity.record_guest_message();
        }
        offset += total;
    }
}

fn encoded_guest_message_refreshes_idle_timer(
    out_buf: &[u8],
    offset: usize,
    frame_len: usize,
) -> bool {
    if frame_len < microsandbox_protocol::message::FRAME_HEADER_SIZE {
        return true;
    }

    let id_start = offset + 4;
    let flags_index = id_start + 4;
    let body_start = flags_index + 1;
    let body_end = offset + 4 + frame_len;
    if body_end > out_buf.len() || body_start > body_end {
        return true;
    }

    let id = u32::from_be_bytes([
        out_buf[id_start],
        out_buf[id_start + 1],
        out_buf[id_start + 2],
        out_buf[id_start + 3],
    ]);
    let frame = codec::RawFrame {
        id,
        flags: out_buf[flags_index],
        body: out_buf[body_start..body_end].to_vec(),
    };

    codec::raw_frame_to_message(frame)
        .map(|msg| guest_message_refreshes_idle_timer(&msg.t))
        .unwrap_or(true)
}

fn apply_raw_activity(raw: RawActivity, activity: &mut ActivityTracker) {
    if raw.guest_message {
        activity.record_guest_message();
    }
    if raw.fs_bytes > 0 {
        activity.add_fs_bytes(raw.fs_bytes);
    }
    if raw.tcp_bytes > 0 {
        activity.add_tcp_bytes(raw.tcp_bytes);
    }
}

fn complete_raw_session(
    id: u32,
    completion: Option<RawSessionCompletion>,
    read_sessions: &mut HashMap<u32, FsReadSession>,
    tcp_sessions: &mut HashMap<u32, TcpSession>,
) {
    match completion {
        Some(RawSessionCompletion::FsRead) => {
            read_sessions.remove(&id);
        }
        Some(RawSessionCompletion::Tcp) => {
            tcp_sessions.remove(&id);
        }
        None => {}
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

fn close_tcp_sessions_in_owner_range(
    tcp_sessions: &mut HashMap<u32, TcpSession>,
    id_start: u32,
    id_end_exclusive: u32,
) {
    let mut retained = HashMap::new();
    for (id, session) in tcp_sessions.drain() {
        let owner_id = session.owner_id();
        if owner_id >= id_start && owner_id < id_end_exclusive {
            session.close();
        } else {
            retained.insert(id, session);
        }
    }
    *tcp_sessions = retained;
}

fn encode_tcp_failed(id: u32, error: String, out_buf: &mut Vec<u8>) -> AgentdResult<()> {
    let reply = Message::with_payload(MessageType::TcpFailed, id, &TcpFailed { error })
        .map_err(|e| AgentdError::ExecSession(format!("encode tcp failed: {e}")))?;
    codec::encode_to_buf(&reply, out_buf)
        .map_err(|e| AgentdError::ExecSession(format!("encode tcp failed frame: {e}")))?;
    Ok(())
}

fn encode_core_error_if_supported(
    source: &Message,
    id: u32,
    kind: CoreErrorKind,
    message: String,
    offending_type: Option<String>,
    out_buf: &mut Vec<u8>,
) -> AgentdResult<()> {
    if !MessageType::CoreError.is_available_at(source.v) {
        return Err(AgentdError::ExecSession(format!(
            "cannot send core.error to protocol generation {}",
            source.v
        )));
    }

    encode_core_error(id, kind, message, offending_type, out_buf)
}

fn encode_core_error(
    id: u32,
    kind: CoreErrorKind,
    message: String,
    offending_type: Option<String>,
    out_buf: &mut Vec<u8>,
) -> AgentdResult<()> {
    let reply = Message::with_payload(
        MessageType::CoreError,
        id,
        &CoreError {
            kind,
            message,
            offending_type,
        },
    )
    .map_err(|e| AgentdError::ExecSession(format!("encode core error: {e}")))?;
    codec::encode_to_buf(&reply, out_buf)
        .map_err(|e| AgentdError::ExecSession(format!("encode core error frame: {e}")))?;
    Ok(())
}

fn decode_payload_or_core_error<T>(msg: &Message, out_buf: &mut Vec<u8>) -> AgentdResult<Option<T>>
where
    T: serde::de::DeserializeOwned,
{
    match msg.payload::<T>() {
        Ok(payload) => Ok(Some(payload)),
        Err(error) => {
            encode_core_error_if_supported(
                msg,
                msg.id,
                CoreErrorKind::InvalidPayload,
                format!("decode payload for {}: {error}", msg.t.as_str()),
                Some(msg.t.as_str().to_string()),
                out_buf,
            )?;
            Ok(None)
        }
    }
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
    if crate::handoff::is_pid_1() {
        // PID 1 mode (no handoff): tear down filesystems so block-backed
        // mounts reach a clean terminal state, then power the kernel off.
        crate::teardown::teardown_filesystems(true);
        let ret = unsafe { libc::reboot(libc::RB_POWER_OFF) };
        if ret != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        return Ok(());
    }

    unsafe {
        libc::sync();
    }

    // Handoff mode: ask the new init (PID 1) to shut down.
    // SIGRTMIN+4 is systemd's poweroff signal; sysvinit-derived inits
    // typically default-handle it as a clean exit. Either way, PID 1
    // exiting causes the kernel to panic the guest, which the VMM
    // observes as a clean shutdown.
    if crate::handoff::signal_init_shutdown().is_ok() {
        std::thread::sleep(HANDOFF_POWEROFF_TIMEOUT);
    }

    // Reaching this point means the init ignored the poweroff request, so
    // the guest is going down hard (SIGTERM fallback, then the host's
    // VMM-process kill as backstop). Force filesystems toward a clean
    // terminal state first — without the process sweep, since the foreign
    // init's services are not ours to kill.
    crate::teardown::teardown_filesystems(false);

    let _ = crate::handoff::signal_init_term();
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_encoded_guest_messages_counts_only_appended_frames() {
        let mut out_buf = Vec::new();
        let existing =
            Message::with_payload(MessageType::ExecStarted, 1, &ExecStarted { pid: 123 }).unwrap();
        codec::encode_to_buf(&existing, &mut out_buf).unwrap();
        let start = out_buf.len();

        let appended =
            Message::with_payload(MessageType::ExecStarted, 2, &ExecStarted { pid: 456 }).unwrap();
        codec::encode_to_buf(&appended, &mut out_buf).unwrap();

        let mut activity = ActivityTracker::new();
        record_encoded_guest_messages(&out_buf, start, &mut activity);

        assert_eq!(activity.activity_seq, 1);
        assert_eq!(activity.counters.guest_messages, 1);
    }

    #[test]
    fn apply_raw_activity_updates_guest_and_byte_counters() {
        let mut activity = ActivityTracker::new();

        apply_raw_activity(RawActivity::fs_bytes(42), &mut activity);
        apply_raw_activity(RawActivity::tcp_bytes(7), &mut activity);

        assert_eq!(activity.activity_seq, 2);
        assert_eq!(activity.counters.guest_messages, 2);
        assert_eq!(activity.counters.fs_bytes, 42);
        assert_eq!(activity.counters.tcp_bytes, 7);
    }

    #[test]
    fn maintenance_messages_do_not_implicitly_refresh_idle_timer() {
        assert!(!message_refreshes_idle_timer(&MessageType::ClockSync));
        assert!(!message_refreshes_idle_timer(&MessageType::Ping));
        assert!(!message_refreshes_idle_timer(&MessageType::Touch));
        assert!(message_refreshes_idle_timer(&MessageType::ExecRequest));
    }

    #[test]
    fn maintenance_replies_do_not_refresh_idle_timer() {
        assert!(!guest_message_refreshes_idle_timer(&MessageType::Pong));
        assert!(!guest_message_refreshes_idle_timer(&MessageType::Touched));
        assert!(!guest_message_refreshes_idle_timer(&MessageType::CoreError));
        assert!(guest_message_refreshes_idle_timer(&MessageType::ExecStdout));
    }

    #[test]
    fn record_encoded_guest_messages_ignores_pong_and_touched() {
        let mut out_buf = Vec::new();
        let pong = Message::with_payload(MessageType::Pong, 1, &Pong {}).unwrap();
        codec::encode_to_buf(&pong, &mut out_buf).unwrap();

        let touched =
            Message::with_payload(MessageType::Touched, 2, &Touched { activity_seq: 42 }).unwrap();
        codec::encode_to_buf(&touched, &mut out_buf).unwrap();

        let mut activity = ActivityTracker::new();
        record_encoded_guest_messages(&out_buf, 0, &mut activity);

        assert_eq!(activity.activity_seq, 0);
        assert_eq!(activity.counters.guest_messages, 0);
    }
}
