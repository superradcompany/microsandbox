//! Interactive attach types for terminal bridging with sandboxes.

use std::{collections::VecDeque, sync::Arc};

use microsandbox_protocol::{
    exec::{
        ExecExited, ExecFailed, ExecOutputAck, ExecStarted, ExecStderr, ExecStdin, ExecStdinAck,
        ExecStdinError, ExecStdout,
    },
    message::{Message, MessageType},
};
use microsandbox_types::EnvVar;
use tokio_util::task::AbortOnDropHandle;

use crate::{MicrosandboxError, MicrosandboxResult, agent::AgentClient};

use super::exec::{InputWindow, Rlimit};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

#[cfg(unix)]
const LEGACY_TERMINAL_READ_SIZE: usize = 1024;

/// Allow large pastes while bounding memory if the guest never reads stdin.
const MAX_TERMINAL_INPUT_BACKLOG: usize = 64 * 1024 * 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Options for attaching to a sandbox with an interactive session.
///
/// The host terminal is set to raw mode for the duration of the attach session.
/// The guest process runs in a PTY, enabling terminal features (colors, line
/// editing, Ctrl+C → SIGINT).
#[derive(Debug, Clone, Default)]
pub struct AttachOptions {
    /// Arguments.
    pub(crate) args: Vec<String>,

    /// Environment variables (merged with sandbox env).
    pub(crate) env: Vec<EnvVar>,

    /// Working directory (default: sandbox's workdir).
    pub(crate) cwd: Option<String>,

    /// Guest user override for the attached command.
    pub(crate) user: Option<String>,

    /// Detach key sequence (default: `"ctrl-]"`).
    ///
    /// Uses Docker-style syntax: `"ctrl-<char>"` for control keys,
    /// comma-separated for multi-key sequences (e.g., `"ctrl-p,ctrl-q"`).
    pub(crate) detach_keys: Option<String>,

    /// Resource limits.
    pub(crate) rlimits: Vec<Rlimit>,
}

/// Builder for `AttachOptions`.
#[derive(Default)]
pub struct AttachOptionsBuilder {
    options: AttachOptions,
}

/// Parsed detach key sequence.
///
/// Matches raw stdin bytes against the configured detach sequence.
pub(crate) struct DetachKeys {
    /// The byte sequence that triggers detach.
    sequence: Vec<u8>,
}

/// Tracks execution flow control shared by Unix and Windows terminal bridges.
///
/// The terminal loops own platform-specific I/O; this state handles agent
/// messages and records output only after the terminal accepts it.
struct AttachProtocol {
    /// Guest-advertised stdin capacity, absent when connected to a legacy agent.
    input_window: Option<Arc<InputWindow>>,
    /// Cumulative output consumed by the terminal, absent for legacy agents.
    output_ack: Option<ExecOutputAck>,
    #[cfg(unix)]
    /// Read size supported by the guest, or the legacy 1 KiB size.
    terminal_read_size: usize,
}

/// A terminal-relevant event decoded from the agent stream.
///
/// Missing exit and failure payloads retain the terminal bridge's existing
/// behavior: return exit code -1 when no valid payload is available.
enum AttachMessage {
    Ignored,
    Output(Vec<u8>),
    StdinError(String),
    Exited(Option<i32>),
    Failed(Option<ExecFailed>),
}

/// Queues terminal input while one write waits for guest stdin credit.
struct TerminalInput {
    queued: VecDeque<Vec<u8>>,
    queued_bytes: usize,
    pending_write: Option<AbortOnDropHandle<MicrosandboxResult<()>>>,
    closed: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl AttachOptionsBuilder {
    /// Prepend arguments resolved by a higher-level execution helper.
    pub(crate) fn prepend_args(mut self, args: impl IntoIterator<Item = String>) -> Self {
        self.options.args.splice(0..0, args);
        self
    }

    /// Append a command-line argument to the attached command.
    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.options.args.push(arg.into());
        self
    }

    /// Append multiple command-line arguments.
    pub fn args(mut self, args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.options.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Override the working directory for the attached session.
    pub fn cwd(mut self, cwd: impl Into<String>) -> Self {
        self.options.cwd = Some(cwd.into());
        self
    }

    /// Override the guest user for the attached session.
    pub fn user(mut self, user: impl Into<String>) -> Self {
        self.options.user = Some(user.into());
        self
    }

    /// Set an environment variable for the attached session. Merged on
    /// top of sandbox-level env vars.
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.options.env.push(EnvVar::new(key, value));
        self
    }

    /// Set multiple environment variables for the attached session.
    pub fn envs(
        mut self,
        vars: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
    ) -> Self {
        self.options
            .env
            .extend(vars.into_iter().map(|(key, value)| EnvVar::new(key, value)));
        self
    }

    /// Key sequence to detach from the session without stopping it.
    /// Uses Docker-style syntax: `"ctrl-]"` (default), `"ctrl-p,ctrl-q"`,
    /// or a single character like `"q"`.
    pub fn detach_keys(mut self, keys: impl Into<String>) -> Self {
        self.options.detach_keys = Some(keys.into());
        self
    }

    /// Set a resource limit (soft = hard).
    pub fn rlimit(mut self, resource: super::exec::RlimitResource, limit: u64) -> Self {
        self.options.rlimits.push(Rlimit {
            resource,
            soft: limit,
            hard: limit,
        });
        self
    }

    /// Set a resource limit with different soft/hard values.
    pub fn rlimit_range(
        mut self,
        resource: super::exec::RlimitResource,
        soft: u64,
        hard: u64,
    ) -> Self {
        self.options.rlimits.push(Rlimit {
            resource,
            soft,
            hard,
        });
        self
    }

    /// Finalize the options. Called automatically when using the closure form.
    ///
    /// Returns an error if any rlimit entry has `soft > hard`.
    pub fn build(self) -> MicrosandboxResult<AttachOptions> {
        super::exec::validate_rlimits(&self.options.rlimits)?;
        Ok(self.options)
    }
}

impl DetachKeys {
    /// Default detach key: Ctrl+] (0x1D).
    const DEFAULT: u8 = 0x1d;

    /// Parse a detach key specification string.
    ///
    /// Supports Docker-style syntax:
    /// - `"ctrl-]"` → `[0x1D]`
    /// - `"ctrl-a"` → `[0x01]`
    /// - `"ctrl-p,ctrl-q"` → `[0x10, 0x11]`
    pub fn parse(spec: &str) -> MicrosandboxResult<Self> {
        let mut sequence = Vec::new();
        for part in spec.split(',') {
            let part = part.trim();
            if let Some(ch) = part.strip_prefix("ctrl-") {
                let byte = match ch {
                    "]" => 0x1d,
                    "[" => 0x1b,
                    "\\" => 0x1c,
                    "^" => 0x1e,
                    "_" => 0x1f,
                    "@" => 0x00,
                    c if c.len() == 1 => {
                        let b = c.as_bytes()[0];
                        if b.is_ascii_lowercase() {
                            b - b'a' + 1
                        } else if b.is_ascii_uppercase() {
                            b - b'A' + 1
                        } else {
                            return Err(crate::MicrosandboxError::InvalidConfig(format!(
                                "invalid detach key: {part}"
                            )));
                        }
                    }
                    _ => {
                        return Err(crate::MicrosandboxError::InvalidConfig(format!(
                            "invalid detach key: {part}"
                        )));
                    }
                };
                sequence.push(byte);
            } else if part.len() == 1 {
                sequence.push(part.as_bytes()[0]);
            } else {
                return Err(crate::MicrosandboxError::InvalidConfig(format!(
                    "invalid detach key: {part}"
                )));
            }
        }

        if sequence.is_empty() {
            sequence.push(Self::DEFAULT);
        }

        Ok(Self { sequence })
    }

    /// Create the default detach keys (Ctrl+]).
    pub fn default_keys() -> Self {
        Self {
            sequence: vec![Self::DEFAULT],
        }
    }

    /// Returns the detach key sequence bytes.
    pub fn sequence(&self) -> &[u8] {
        &self.sequence
    }
}

impl AttachProtocol {
    /// Enable flow control only when the agent advertises its limits and ack support.
    fn new(client: &AgentClient) -> MicrosandboxResult<Self> {
        let exec_limits = client.ready()?.exec_limits;
        if let Some(limits) = exec_limits {
            limits
                .validate()
                .map_err(|error| MicrosandboxError::Runtime(error.into()))?;
        }

        // Older agents have no execution windows and must not receive acknowledgements.
        let flow_control_limits =
            exec_limits.filter(|_| client.supports(MessageType::ExecOutputAck));
        let input_window = flow_control_limits
            .map(|limits| InputWindow::new(limits.input_limit, limits.stdin_chunk_size as usize));
        let output_ack = flow_control_limits.map(|_| ExecOutputAck::default());
        #[cfg(unix)]
        let terminal_read_size = flow_control_limits.map_or(LEGACY_TERMINAL_READ_SIZE, |limits| {
            limits.stdin_chunk_size as usize
        });

        Ok(Self {
            input_window,
            output_ack,
            #[cfg(unix)]
            terminal_read_size,
        })
    }

    fn input_window(&self) -> Option<Arc<InputWindow>> {
        self.input_window.clone()
    }

    #[cfg(unix)]
    fn terminal_read_size(&self) -> usize {
        self.terminal_read_size
    }

    /// Update flow-control state before handing terminal output or exit to the caller.
    fn handle_message(&mut self, msg: Message) -> MicrosandboxResult<AttachMessage> {
        match msg.t {
            MessageType::ExecStarted => {
                let _ = msg.payload::<ExecStarted>()?;
                if let Some(window) = &self.input_window {
                    window.mark_started();
                }
                Ok(AttachMessage::Ignored)
            }
            MessageType::ExecStdinAck => {
                if let Some(window) = &self.input_window {
                    let ack = msg.payload::<ExecStdinAck>()?;
                    if !window.acknowledge(ack.consumed) {
                        return Err(MicrosandboxError::Runtime(
                            "invalid execution stdin acknowledgement".into(),
                        ));
                    }
                }
                Ok(AttachMessage::Ignored)
            }
            MessageType::ExecStdinError => {
                self.close();
                let error = msg.payload::<ExecStdinError>()?;
                Ok(AttachMessage::StdinError(error.message))
            }
            MessageType::ExecStdout => {
                let out = msg.payload::<ExecStdout>()?;
                Ok(AttachMessage::Output(out.data))
            }
            MessageType::ExecStderr => {
                let out = msg.payload::<ExecStderr>()?;
                Ok(AttachMessage::Output(out.data))
            }
            MessageType::ExecExited => Ok(AttachMessage::Exited(
                msg.payload::<ExecExited>().ok().map(|exited| exited.code),
            )),
            MessageType::ExecFailed => Ok(AttachMessage::Failed(msg.payload::<ExecFailed>().ok())),
            _ => Ok(AttachMessage::Ignored),
        }
    }

    /// Charge an output chunk after a successful terminal write.
    ///
    /// `ExecOutputAck::consume` also accounts for the protocol's per-chunk overhead.
    fn output_written(&mut self, bytes: usize) -> MicrosandboxResult<bool> {
        let Some(ack) = &mut self.output_ack else {
            return Ok(false);
        };

        ack.consume(bytes).ok_or_else(|| {
            MicrosandboxError::Runtime("execution output counter overflow".into())
        })?;
        Ok(true)
    }

    /// Release guest output credit after the platform has accepted the batch.
    async fn acknowledge_output(&self, client: &AgentClient, id: u32) -> MicrosandboxResult<()> {
        if let Some(ack) = &self.output_ack {
            client.send(id, MessageType::ExecOutputAck, ack).await?;
        }
        Ok(())
    }

    fn close(&self) {
        if let Some(window) = &self.input_window {
            window.close();
        }
    }
}

impl TerminalInput {
    fn new() -> Self {
        Self {
            queued: VecDeque::new(),
            queued_bytes: 0,
            pending_write: None,
            closed: false,
        }
    }

    /// Preserve input order while continuing to read detach keys from the terminal.
    fn push(
        &mut self,
        client: &Arc<AgentClient>,
        id: u32,
        window: Option<Arc<InputWindow>>,
        data: Vec<u8>,
    ) -> MicrosandboxResult<()> {
        // Keep reading for detach keys after the guest closes stdin, without sending more data.
        if self.closed {
            return Ok(());
        }

        if self.pending_write.is_none() {
            self.pending_write = Some(spawn_stdin_write(Arc::clone(client), id, window, data));
            return Ok(());
        }

        let queued_bytes = self.queued_bytes.checked_add(data.len()).ok_or_else(|| {
            MicrosandboxError::Terminal("terminal input backlog size overflow".into())
        })?;
        if queued_bytes > MAX_TERMINAL_INPUT_BACKLOG {
            return Err(MicrosandboxError::Terminal(
                "terminal input backlog exceeded 64 MiB while guest stdin was blocked".into(),
            ));
        }

        self.queued_bytes = queued_bytes;
        self.queued.push_back(data);
        Ok(())
    }

    /// Start the next queued write after the previous one completes.
    fn write_completed(
        &mut self,
        client: &Arc<AgentClient>,
        id: u32,
        window: Option<Arc<InputWindow>>,
    ) {
        self.pending_write = None;

        if let Some(data) = self.queued.pop_front() {
            self.queued_bytes -= data.len();
            self.pending_write = Some(spawn_stdin_write(Arc::clone(client), id, window, data));
        }
    }

    /// Stop pending and queued input without ending the attached execution.
    /// Returns whether stdin was open, so the terminal reports the failure once.
    fn close(&mut self) -> bool {
        if self.closed {
            return false;
        }

        self.closed = true;
        self.pending_write = None;
        self.queued.clear();
        self.queued_bytes = 0;
        true
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn input_contains_detach_sequence(
    data: &[u8],
    detach_seq: &[u8],
    match_pos: &mut usize,
) -> bool {
    if detach_seq.is_empty() {
        return false;
    }

    for &byte in data {
        if byte == detach_seq[*match_pos] {
            *match_pos += 1;
            if *match_pos == detach_seq.len() {
                return true;
            }
        } else {
            *match_pos = 0;
            if byte == detach_seq[0] {
                *match_pos = 1;
            }
        }
    }

    false
}

/// Keep receiving agent messages while stdin waits for guest start or credit.
fn spawn_stdin_write(
    client: Arc<AgentClient>,
    id: u32,
    window: Option<Arc<InputWindow>>,
    data: Vec<u8>,
) -> AbortOnDropHandle<MicrosandboxResult<()>> {
    AbortOnDropHandle::new(tokio::spawn(async move {
        if let Some(window) = window {
            window.wait_started().await?;
            window.send(&client, id, data).await
        } else {
            client
                .send(id, MessageType::ExecStdin, &ExecStdin { data })
                .await?;
            Ok(())
        }
    }))
}

//--------------------------------------------------------------------------------------------------
// Module: agent (backend-agnostic ops driven over an agent connection)
//--------------------------------------------------------------------------------------------------

#[cfg(unix)]
pub(crate) mod agent {
    //! Local attach impl: bridges the host TTY to a PTY exec session in the
    //! named sandbox. Owns the host terminal's raw mode for the duration.

    use std::os::fd::AsRawFd;
    use std::sync::Arc;

    use microsandbox_protocol::{
        exec::{ExecFailed, ExecResize},
        message::MessageType,
    };
    use tokio::io::{AsyncWriteExt, unix::AsyncFd};

    use crate::{
        MicrosandboxError, MicrosandboxResult,
        sandbox::{
            AttachOptionsBuilder, SandboxConfig, build_exec_request,
            open_nonblocking_terminal_input, read_from_fd, terminal_path_for_fd,
        },
    };

    use super::{
        AttachMessage, AttachProtocol, DetachKeys, TerminalInput, input_contains_detach_sequence,
    };

    pub(crate) async fn attach(
        backend: &dyn crate::backend::Backend,
        name: &str,
        config: &SandboxConfig,
        cmd: String,
        opts_builder: AttachOptionsBuilder,
    ) -> MicrosandboxResult<i32> {
        let opts = opts_builder.build()?;

        let client = Arc::new(super::super::fs::agent::connect_agent(backend, name).await?);

        let detach_keys = match &opts.detach_keys {
            Some(spec) => DetachKeys::parse(spec)?,
            None => DetachKeys::default_keys(),
        };

        let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));

        let req = build_exec_request(
            config,
            cmd,
            opts.args,
            opts.cwd,
            opts.user,
            &opts.env,
            &opts.rlimits,
            true,
            rows,
            cols,
        );

        let mut protocol = AttachProtocol::new(&client)?;
        let (id, mut rx) = client.stream(MessageType::ExecRequest, &req).await?;

        crossterm::terminal::enable_raw_mode()
            .map_err(|e| crate::MicrosandboxError::Terminal(e.to_string()))?;
        let _raw_guard = scopeguard::guard((), |_| {
            let _ = crossterm::terminal::disable_raw_mode();
        });

        let tty_input_path = terminal_path_for_fd(std::io::stdin().as_raw_fd())
            .map_err(|e| crate::MicrosandboxError::Terminal(format!("resolve tty path: {e}")))?;
        let tty_input = open_nonblocking_terminal_input(&tty_input_path)
            .map_err(|e| crate::MicrosandboxError::Terminal(format!("open tty input: {e}")))?;
        // SAFETY: The owned terminal file keeps its non-blocking descriptor open and unchanged.
        let stdin_async = unsafe { AsyncFd::register(tty_input) }
            .map_err(|e| crate::MicrosandboxError::Terminal(format!("async tty input: {e}")))?;

        let mut input_buf = vec![0u8; protocol.terminal_read_size()];
        let mut stdout = tokio::io::stdout();
        let mut sigwinch =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
                .map_err(|e| crate::MicrosandboxError::Runtime(format!("sigwinch: {e}")))?;

        let mut exit_code: i32 = -1;
        let mut match_pos = 0usize;
        let detach_seq = detach_keys.sequence();
        let mut spawn_failure: Option<ExecFailed> = None;
        let mut terminal_input = TerminalInput::new();

        loop {
            tokio::select! {
                result = stdin_async.readable() => {
                    let mut guard = match result {
                        Ok(g) => g,
                        Err(_) => break,
                    };

                    match guard.try_io(|inner| {
                        read_from_fd(inner.get_ref().as_raw_fd(), &mut input_buf)
                    }) {
                        Ok(Ok(0)) => break,
                        Ok(Ok(n)) => {
                            let data = &input_buf[..n];

                            if input_contains_detach_sequence(data, detach_seq, &mut match_pos) {
                                break;
                            }

                            terminal_input.push(&client, id, protocol.input_window(), data.to_vec())?;
                        }
                        Ok(Err(e)) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Ok(Err(_)) => break,
                        Err(_would_block) => continue,
                    }
                }

                result = async { terminal_input.pending_write.as_mut().unwrap().await }, if terminal_input.pending_write.is_some() => {
                    result.map_err(|error| MicrosandboxError::Runtime(format!("terminal input task failed: {error}")))??;
                    terminal_input.write_completed(&client, id, protocol.input_window());
                }

                msg = rx.recv() => {
                    let Some(msg) = msg else {
                        return Err(MicrosandboxError::Runtime(
                            "agent connection closed during terminal attach".into(),
                        ));
                    };

                    let mut should_break = false;
                    let mut output_written = false;
                    let mut msg = msg;

                    loop {
                        match protocol.handle_message(msg)? {
                            AttachMessage::Ignored => {}
                            AttachMessage::Output(data) => {
                                stdout.write_all(&data).await?;
                                output_written |= protocol.output_written(data.len())?;
                            }
                            AttachMessage::StdinError(message) => {
                                if terminal_input.close() {
                                    stdout.write_all(format!("\r\nGuest stdin closed: {message}\r\n").as_bytes()).await?;
                                }
                            }
                            AttachMessage::Exited(code) => {
                                if let Some(code) = code {
                                    exit_code = code;
                                }
                                should_break = true;
                            }
                            AttachMessage::Failed(failure) => {
                                spawn_failure = failure;
                                should_break = true;
                            }
                        }

                        if should_break {
                            break;
                        }
                        msg = match rx.try_recv() {
                            Ok(next) => next,
                            Err(_) => break,
                        };
                    }

                    stdout.flush().await?;
                    // A terminal message means the guest no longer needs output credit.
                    if output_written && !should_break {
                        protocol.acknowledge_output(&client, id).await?;
                    }

                    if should_break {
                        break;
                    }
                }

                _ = sigwinch.recv() => {
                    if let Ok((new_cols, new_rows)) = crossterm::terminal::size() {
                        let payload = ExecResize { rows: new_rows, cols: new_cols };
                        let _ = client.send(id, MessageType::ExecResize, &payload).await;
                    }
                }
            }
        }

        protocol.close();

        if let Some(failure) = spawn_failure {
            return Err(crate::MicrosandboxError::ExecFailed(failure));
        }

        Ok(exit_code)
    }
}

#[cfg(windows)]
pub(crate) mod agent {
    use std::sync::Arc;

    use microsandbox_protocol::{exec::ExecResize, message::MessageType};

    use crate::backend::Backend;
    use crate::{
        MicrosandboxError, MicrosandboxResult,
        sandbox::{
            AttachOptionsBuilder, SandboxConfig, build_exec_request,
            terminal::{
                WindowsTerminalEvent, WindowsTerminalEventPump, WindowsTerminalGuard,
                current_terminal_size,
            },
        },
    };

    use super::{
        AttachMessage, AttachProtocol, DetachKeys, TerminalInput, input_contains_detach_sequence,
    };

    pub(crate) async fn attach(
        backend: &dyn Backend,
        name: &str,
        config: &SandboxConfig,
        cmd: String,
        opts_builder: AttachOptionsBuilder,
    ) -> MicrosandboxResult<i32> {
        let opts = opts_builder.build()?;

        let client = Arc::new(super::super::fs::agent::connect_agent(backend, name).await?);

        let detach_keys = match &opts.detach_keys {
            Some(spec) => DetachKeys::parse(spec)?,
            None => DetachKeys::default_keys(),
        };

        let (cols, rows) = current_terminal_size().unwrap_or((80, 24));

        let req = build_exec_request(
            config,
            cmd,
            opts.args,
            opts.cwd,
            opts.user,
            &opts.env,
            &opts.rlimits,
            true,
            rows,
            cols,
        );
        let mut protocol = AttachProtocol::new(&client)?;
        let (id, mut rx) = client.stream(MessageType::ExecRequest, &req).await?;

        let mut terminal_guard = WindowsTerminalGuard::enter()?;
        let mut terminal_events = WindowsTerminalEventPump::spawn_for_guard(&terminal_guard)?;
        let mut exit_code: i32 = -1;
        let mut spawn_failure: Option<microsandbox_protocol::exec::ExecFailed> = None;
        let detach_seq = detach_keys.sequence();
        let mut match_pos = 0usize;
        let mut terminal_input = TerminalInput::new();

        loop {
            tokio::select! {
                Some(event) = terminal_events.recv() => {
                    match event {
                        WindowsTerminalEvent::Input(data) => {
                            if input_contains_detach_sequence(&data, detach_seq, &mut match_pos) {
                                break;
                            }

                            terminal_input.push(&client, id, protocol.input_window(), data)?;
                        }
                        WindowsTerminalEvent::Resize { cols, rows } => {
                            let payload = ExecResize { rows, cols };
                            let _ = client.send(id, MessageType::ExecResize, &payload).await;
                        }
                        WindowsTerminalEvent::Error(error) => {
                            return Err(MicrosandboxError::Terminal(error));
                        }
                    }
                }

                result = async { terminal_input.pending_write.as_mut().unwrap().await }, if terminal_input.pending_write.is_some() => {
                    result.map_err(|error| MicrosandboxError::Runtime(format!("terminal input task failed: {error}")))??;
                    terminal_input.write_completed(&client, id, protocol.input_window());
                }

                msg = rx.recv() => {
                    let Some(msg) = msg else {
                        return Err(MicrosandboxError::Runtime(
                            "agent connection closed during terminal attach".into(),
                        ));
                    };

                    let mut should_break = false;
                    let mut output_written = false;
                    let mut msg = msg;

                    loop {
                        match protocol.handle_message(msg)? {
                            AttachMessage::Ignored => {}
                            AttachMessage::Output(data) => {
                                terminal_guard.write_output(&data)?;
                                output_written |= protocol.output_written(data.len())?;
                            }
                            AttachMessage::StdinError(message) => {
                                if terminal_input.close() {
                                    terminal_guard.write_output(format!("\r\nGuest stdin closed: {message}\r\n").as_bytes())?;
                                }
                            }
                            AttachMessage::Exited(code) => {
                                if let Some(code) = code {
                                    exit_code = code;
                                }
                                should_break = true;
                            }
                            AttachMessage::Failed(failure) => {
                                spawn_failure = failure;
                                should_break = true;
                            }
                        }

                        if should_break {
                            break;
                        }
                        msg = match rx.try_recv() {
                            Ok(next) => next,
                            Err(_) => break,
                        };
                    }

                    if output_written && !should_break {
                        protocol.acknowledge_output(&client, id).await?;
                    }

                    if should_break {
                        break;
                    }
                }
            }
        }

        protocol.close();
        if let Some(failure) = spawn_failure {
            return Err(MicrosandboxError::ExecFailed(failure));
        }

        terminal_guard.finish_output()?;

        Ok(exit_code)
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use microsandbox_protocol::exec::EXEC_OUTPUT_EVENT_OVERHEAD;
    use tokio::time::timeout;

    use super::*;

    #[test]
    fn stderr_output_consumes_guest_credit() {
        let mut protocol = AttachProtocol {
            input_window: None,
            output_ack: Some(ExecOutputAck::default()),
            #[cfg(unix)]
            terminal_read_size: LEGACY_TERMINAL_READ_SIZE,
        };
        let message = Message::with_payload(
            MessageType::ExecStderr,
            1,
            &ExecStderr {
                data: b"error".to_vec(),
            },
        )
        .expect("encode stderr");

        let AttachMessage::Output(data) = protocol.handle_message(message).expect("decode stderr")
        else {
            panic!("stderr was not forwarded to the terminal");
        };
        assert_eq!(data, b"error");
        assert!(protocol.output_written(data.len()).expect("credit stderr"));
        assert_eq!(
            protocol.output_ack.expect("output window").consumed,
            data.len() as u64 + u64::from(EXEC_OUTPUT_EVENT_OVERHEAD)
        );
    }

    #[tokio::test]
    async fn stdin_error_closes_input_but_keeps_output_available() {
        let window = InputWindow::new(64, 16);
        let mut protocol = AttachProtocol {
            input_window: Some(Arc::clone(&window)),
            output_ack: Some(ExecOutputAck::default()),
            #[cfg(unix)]
            terminal_read_size: LEGACY_TERMINAL_READ_SIZE,
        };
        let error = Message::with_payload(
            MessageType::ExecStdinError,
            1,
            &ExecStdinError {
                errno: None,
                errno_name: None,
                message: "broken pipe".into(),
            },
        )
        .expect("encode stdin error");

        let AttachMessage::StdinError(message) =
            protocol.handle_message(error).expect("handle stdin error")
        else {
            panic!("stdin error was not reported");
        };
        assert_eq!(message, "broken pipe");
        assert!(
            timeout(Duration::from_secs(1), window.wait_started())
                .await
                .expect("closed input window did not wake")
                .is_err()
        );

        let output = Message::with_payload(
            MessageType::ExecStdout,
            1,
            &ExecStdout {
                data: b"still running".to_vec(),
            },
        )
        .expect("encode stdout");
        assert!(matches!(
            protocol.handle_message(output).expect("handle later output"),
            AttachMessage::Output(data) if data == b"still running"
        ));
    }

    #[test]
    fn test_detach_keys_default() {
        let keys = DetachKeys::default_keys();
        assert_eq!(keys.sequence(), &[0x1d]);
    }

    #[test]
    fn test_detach_keys_ctrl_bracket() {
        let keys = DetachKeys::parse("ctrl-]").unwrap();
        assert_eq!(keys.sequence(), &[0x1d]);
    }

    #[test]
    fn test_detach_keys_ctrl_letter() {
        let keys = DetachKeys::parse("ctrl-a").unwrap();
        assert_eq!(keys.sequence(), &[0x01]);

        let keys = DetachKeys::parse("ctrl-z").unwrap();
        assert_eq!(keys.sequence(), &[0x1a]);
    }

    #[test]
    fn test_detach_keys_multi_sequence() {
        let keys = DetachKeys::parse("ctrl-p,ctrl-q").unwrap();
        assert_eq!(keys.sequence(), &[0x10, 0x11]);
    }

    #[test]
    #[allow(clippy::byte_char_slices)] // intentional: comparing to a single-byte slice
    fn test_detach_keys_single_char() {
        let keys = DetachKeys::parse("q").unwrap();
        assert_eq!(keys.sequence(), b"q");
    }

    #[test]
    fn test_detach_keys_invalid() {
        assert!(DetachKeys::parse("ctrl-").is_err());
        assert!(DetachKeys::parse("ctrl-ab").is_err());
    }

    #[test]
    fn test_input_contains_detach_sequence_across_chunks() {
        let keys = DetachKeys::parse("ctrl-p,ctrl-q").unwrap();
        let mut match_pos = 0;

        assert!(!input_contains_detach_sequence(
            &[0x10],
            keys.sequence(),
            &mut match_pos
        ));
        assert_eq!(match_pos, 1);

        assert!(input_contains_detach_sequence(
            &[0x11],
            keys.sequence(),
            &mut match_pos
        ));
    }

    #[test]
    fn test_input_contains_detach_sequence_restarts_partial_match() {
        let keys = DetachKeys::parse("ctrl-p,ctrl-q").unwrap();
        let mut match_pos = 0;

        assert!(!input_contains_detach_sequence(
            &[0x10, 0x10],
            keys.sequence(),
            &mut match_pos
        ));
        assert_eq!(match_pos, 1);
    }
}
