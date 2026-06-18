//! Execution types for running commands inside sandboxes.

use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use microsandbox_protocol::{
    exec::{ExecResize, ExecSignal, ExecStdin},
    message::MessageType,
};
use tokio::sync::mpsc;

use crate::{MicrosandboxResult, agent::AgentClient};
use microsandbox_types::EnvVar;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Options for command execution (everything except the command itself).
#[derive(Debug, Clone, Default)]
pub struct ExecOptions {
    /// Arguments.
    pub args: Vec<String>,

    /// Working directory (overrides sandbox default).
    pub cwd: Option<String>,

    /// Guest user override for this command.
    pub user: Option<String>,

    /// Environment variables (merged with sandbox env).
    pub env: Vec<EnvVar>,

    /// Execution timeout. On expiry, SIGKILL is sent.
    pub timeout: Option<Duration>,

    /// Stdin mode.
    pub stdin: StdinMode,

    /// Allocate a PTY (pseudo-terminal).
    pub tty: bool,

    /// Resource limits applied before exec via `setrlimit()`.
    pub rlimits: Vec<Rlimit>,
}

/// Builder for [`ExecOptions`].
#[derive(Default)]
pub struct ExecOptionsBuilder {
    options: ExecOptions,
}

/// How stdin is provided to the command.
#[derive(Debug, Clone, Default)]
pub enum StdinMode {
    /// No stdin (`/dev/null`).
    #[default]
    Null,

    /// Pipe stdin via [`ExecSink`].
    Pipe,

    /// Provide fixed bytes as stdin.
    Bytes(Vec<u8>),
}

/// Output of a completed command execution.
#[derive(Debug)]
pub struct ExecOutput {
    /// Exit status.
    status: ExitStatus,

    /// Captured stdout.
    stdout: Bytes,

    /// Captured stderr.
    stderr: Bytes,
}

/// Process exit status.
#[derive(Debug, Clone, Copy)]
pub struct ExitStatus {
    /// Exit code.
    pub code: i32,

    /// Whether the process exited successfully (code == 0).
    pub success: bool,
}

/// Handle to a streaming exec session.
pub struct ExecHandle {
    /// Correlation ID for this session (protocol-level u32, exposed as String).
    id: u32,

    /// Event receiver.
    events: mpsc::UnboundedReceiver<ExecEvent>,

    /// Stdin sink (only if `StdinMode::Pipe` was used).
    stdin: Option<ExecSink>,

    /// Bridge reference for sending signals/stdin.
    client: Arc<AgentClient>,
}

/// Cloneable control handle for a streaming exec session.
#[derive(Clone)]
pub struct ExecControl {
    /// Correlation ID for this session.
    id: u32,

    /// Bridge reference for sending control messages.
    client: Arc<AgentClient>,
}

/// Events emitted by a streaming exec session.
#[derive(Debug)]
pub enum ExecEvent {
    /// Process started.
    Started {
        /// Guest PID.
        pid: u32,
    },

    /// Stdout data.
    Stdout(Bytes),

    /// Stderr data.
    Stderr(Bytes),

    /// Process exited.
    Exited {
        /// Exit code.
        code: i32,
    },

    /// Process failed to spawn (binary not found, permission
    /// denied, etc.). Distinct from `Exited` — `Failed` means the
    /// user code never ran. Terminal: no further events follow.
    Failed(microsandbox_protocol::exec::ExecFailed),

    /// A stdin write to the child failed (e.g. broken pipe). Non-terminal:
    /// the session keeps running and may still emit further output and
    /// an `Exited` event.
    StdinError(microsandbox_protocol::exec::ExecStdinError),
}

/// Sink for writing to a running process's stdin.
pub struct ExecSink {
    id: u32,
    client: Arc<AgentClient>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ExecOptionsBuilder {
    /// Append a command-line argument (e.g., `"-la"` or `"/tmp"`).
    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.options.args.push(arg.into());
        self
    }

    /// Append multiple command-line arguments.
    pub fn args(mut self, args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.options.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Override the working directory for this command (overrides the
    /// sandbox default set via the builder's `workdir` method).
    pub fn cwd(mut self, cwd: impl Into<String>) -> Self {
        self.options.cwd = Some(cwd.into());
        self
    }

    /// Override the guest user for this command.
    pub fn user(mut self, user: impl Into<String>) -> Self {
        self.options.user = Some(user.into());
        self
    }

    /// Set an environment variable for this command. Merged on top of
    /// the sandbox-level env vars.
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.options.env.push(EnvVar::new(key, value));
        self
    }

    /// Set multiple environment variables for this command.
    pub fn envs(
        mut self,
        vars: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
    ) -> Self {
        self.options
            .env
            .extend(vars.into_iter().map(|(key, value)| EnvVar::new(key, value)));
        self
    }

    /// Kill the process with SIGKILL if it hasn't exited within this duration.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.options.timeout = Some(timeout);
        self
    }

    /// Set stdin mode to null (`/dev/null`).
    pub fn stdin_null(mut self) -> Self {
        self.options.stdin = StdinMode::Null;
        self
    }

    /// Set stdin mode to pipe (use `ExecHandle::stdin()`).
    pub fn stdin_pipe(mut self) -> Self {
        self.options.stdin = StdinMode::Pipe;
        self
    }

    /// Set stdin to fixed bytes.
    pub fn stdin_bytes(mut self, data: impl Into<Vec<u8>>) -> Self {
        self.options.stdin = StdinMode::Bytes(data.into());
        self
    }

    /// Allocate a pseudo-terminal. Enable for interactive programs (shells,
    /// editors, `top`); disable for scripts and batch jobs (default: false).
    pub fn tty(mut self, enabled: bool) -> Self {
        self.options.tty = enabled;
        self
    }

    /// Set a resource limit (soft = hard).
    pub fn rlimit(mut self, resource: RlimitResource, limit: u64) -> Self {
        self.options.rlimits.push(Rlimit {
            resource,
            soft: limit,
            hard: limit,
        });
        self
    }

    /// Set a resource limit with different soft/hard values.
    pub fn rlimit_range(mut self, resource: RlimitResource, soft: u64, hard: u64) -> Self {
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
    pub fn build(self) -> MicrosandboxResult<ExecOptions> {
        validate_rlimits(&self.options.rlimits)?;
        Ok(self.options)
    }
}

/// Validates that every rlimit has `soft <= hard`.
pub(crate) fn validate_rlimits(rlimits: &[Rlimit]) -> MicrosandboxResult<()> {
    for rlimit in rlimits {
        if rlimit.soft > rlimit.hard {
            return Err(crate::MicrosandboxError::InvalidConfig(format!(
                "rlimit {}: soft ({}) must not exceed hard ({})",
                rlimit.resource.as_str(),
                rlimit.soft,
                rlimit.hard
            )));
        }
    }
    Ok(())
}

impl ExecOutput {
    /// Create output from raw parts.
    pub(crate) fn from_parts(status: ExitStatus, stdout: Bytes, stderr: Bytes) -> Self {
        Self {
            status,
            stdout,
            stderr,
        }
    }

    /// Exit code and success flag of the completed process.
    pub fn status(&self) -> ExitStatus {
        self.status
    }

    /// Get stdout as a UTF-8 string.
    pub fn stdout(&self) -> Result<String, std::string::FromUtf8Error> {
        String::from_utf8(self.stdout.to_vec())
    }

    /// Get stderr as a UTF-8 string.
    pub fn stderr(&self) -> Result<String, std::string::FromUtf8Error> {
        String::from_utf8(self.stderr.to_vec())
    }

    /// Get stdout as raw bytes.
    pub fn stdout_bytes(&self) -> &Bytes {
        &self.stdout
    }

    /// Get stderr as raw bytes.
    pub fn stderr_bytes(&self) -> &Bytes {
        &self.stderr
    }
}

impl ExecHandle {
    /// Create a new exec handle.
    pub(crate) fn new(
        id: u32,
        events: mpsc::UnboundedReceiver<ExecEvent>,
        stdin: Option<ExecSink>,
        client: Arc<AgentClient>,
    ) -> Self {
        Self {
            id,
            events,
            stdin,
            client,
        }
    }

    /// Get the execution session ID.
    pub fn id(&self) -> String {
        self.id.to_string()
    }

    /// Get a cloneable control handle for this session.
    pub fn control(&self) -> ExecControl {
        ExecControl {
            id: self.id,
            client: Arc::clone(&self.client),
        }
    }

    /// Consume this handle into separately owned control, stdin, and event parts.
    #[cfg(feature = "ssh")]
    pub(crate) fn into_parts(
        self,
    ) -> (
        ExecControl,
        Option<ExecSink>,
        mpsc::UnboundedReceiver<ExecEvent>,
    ) {
        (
            ExecControl {
                id: self.id,
                client: Arc::clone(&self.client),
            },
            self.stdin,
            self.events,
        )
    }

    /// Receive the next exec event.
    ///
    /// Returns `None` when the session has ended.
    pub async fn recv(&mut self) -> Option<ExecEvent> {
        self.events.recv().await
    }

    /// Take the stdin sink (if `StdinMode::Pipe` was used).
    ///
    /// Returns `None` if stdin was not piped or was already taken.
    pub fn take_stdin(&mut self) -> Option<ExecSink> {
        self.stdin.take()
    }

    /// Wait for the command to complete and return the exit status.
    pub async fn wait(&mut self) -> MicrosandboxResult<ExitStatus> {
        while let Some(event) = self.events.recv().await {
            match event {
                ExecEvent::Exited { code } => {
                    return Ok(ExitStatus {
                        code,
                        success: code == 0,
                    });
                }
                ExecEvent::Failed(payload) => {
                    return Err(crate::MicrosandboxError::ExecFailed(payload));
                }
                _ => {}
            }
        }

        Err(crate::MicrosandboxError::Runtime(
            "exec session ended without exit event".into(),
        ))
    }

    /// Wait for completion and collect all stdout/stderr.
    pub async fn collect(&mut self) -> MicrosandboxResult<ExecOutput> {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit_code: Option<i32> = None;

        while let Some(event) = self.events.recv().await {
            match event {
                ExecEvent::Started { pid: _ } => {}
                ExecEvent::Stdout(data) => {
                    stdout.extend_from_slice(&data);
                }
                ExecEvent::Stderr(data) => {
                    stderr.extend_from_slice(&data);
                }
                ExecEvent::Exited { code } => {
                    exit_code = Some(code);
                    break;
                }
                ExecEvent::Failed(payload) => {
                    return Err(crate::MicrosandboxError::ExecFailed(payload));
                }
                ExecEvent::StdinError(_) => {}
            }
        }

        let code = exit_code.ok_or_else(|| {
            crate::MicrosandboxError::Runtime("exec session ended without exit event".into())
        })?;

        Ok(ExecOutput {
            status: ExitStatus {
                code,
                success: code == 0,
            },
            stdout: Bytes::from(stdout),
            stderr: Bytes::from(stderr),
        })
    }

    /// Send a Unix signal (e.g., `libc::SIGTERM`, `libc::SIGINT`) to the
    /// running process inside the guest.
    pub async fn signal(&self, signal: i32) -> MicrosandboxResult<()> {
        self.control().signal(signal).await
    }

    /// Send SIGKILL to the running process.
    pub async fn kill(&self) -> MicrosandboxResult<()> {
        self.control().kill().await
    }

    /// Resize the PTY for this session.
    pub async fn resize(&self, rows: u16, cols: u16) -> MicrosandboxResult<()> {
        self.control().resize(rows, cols).await
    }
}

impl ExecControl {
    /// Get the execution session ID.
    pub fn id(&self) -> String {
        self.id.to_string()
    }

    /// Send a Unix signal (e.g., `libc::SIGTERM`, `libc::SIGINT`) to the
    /// running process inside the guest.
    pub async fn signal(&self, signal: i32) -> MicrosandboxResult<()> {
        let payload = ExecSignal { signal };
        self.client
            .send(self.id, MessageType::ExecSignal, &payload)
            .await?;
        Ok(())
    }

    /// Send SIGKILL to the running process.
    pub async fn kill(&self) -> MicrosandboxResult<()> {
        self.signal(9).await
    }

    /// Resize the PTY for this session.
    pub async fn resize(&self, rows: u16, cols: u16) -> MicrosandboxResult<()> {
        let payload = ExecResize { rows, cols };
        self.client
            .send(self.id, MessageType::ExecResize, &payload)
            .await?;
        Ok(())
    }
}

impl ExecSink {
    /// Create a new stdin sink.
    pub(crate) fn new(id: u32, client: Arc<AgentClient>) -> Self {
        Self { id, client }
    }

    /// Write data to the process's stdin.
    pub async fn write(&self, data: impl AsRef<[u8]>) -> MicrosandboxResult<()> {
        let payload = ExecStdin {
            data: data.as_ref().to_vec(),
        };
        self.client
            .send(self.id, MessageType::ExecStdin, &payload)
            .await?;
        Ok(())
    }

    /// Close stdin (sends EOF to the process).
    pub async fn close(&self) -> MicrosandboxResult<()> {
        let payload = ExecStdin { data: Vec::new() };
        self.client
            .send(self.id, MessageType::ExecStdin, &payload)
            .await?;
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Module: local (free fn impls called by LocalBackend's SandboxBackend impl)
//--------------------------------------------------------------------------------------------------

pub(crate) mod local {
    //! Local exec dispatch keyed by `(sandbox_name, cmd, opts)`.
    //!
    //! Opens a fresh agent UDS each call (option A in the parity plan).

    use std::sync::Arc;

    use bytes::Bytes;
    use microsandbox_protocol::{
        exec::{ExecExited, ExecStarted, ExecStderr, ExecStdin, ExecStdout},
        message::{Message, MessageType},
    };
    use tokio::sync::mpsc;

    use crate::{
        MicrosandboxError, MicrosandboxResult,
        backend::LocalBackend,
        sandbox::{SandboxConfig, build_exec_request},
    };

    use super::{ExecEvent, ExecHandle, ExecOptions, ExecOutput, ExecSink, ExitStatus, StdinMode};

    pub(crate) async fn exec_stream(
        local: &LocalBackend,
        name: &str,
        config: &SandboxConfig,
        cmd: String,
        opts: ExecOptions,
    ) -> MicrosandboxResult<ExecHandle> {
        exec_stream_with_pty_size(local, name, config, cmd, opts, 24, 80).await
    }

    pub(crate) async fn exec_stream_with_pty_size(
        local: &LocalBackend,
        name: &str,
        config: &SandboxConfig,
        cmd: String,
        opts: ExecOptions,
        rows: u16,
        cols: u16,
    ) -> MicrosandboxResult<ExecHandle> {
        let client = Arc::new(super::super::fs::local::connect_agent(local, name).await?);
        let ExecOptions {
            args,
            cwd,
            user,
            env,
            rlimits,
            tty,
            stdin: stdin_mode,
            timeout: _,
        } = opts;

        tracing::debug!(
            sandbox = %name,
            cmd = %cmd,
            args = ?args,
            cwd = ?cwd,
            tty,
            "exec_stream"
        );

        let req = build_exec_request(
            config, cmd, args, cwd, user, &env, &rlimits, tty, rows, cols,
        );
        let (id, rx) = client.stream(MessageType::ExecRequest, &req).await?;

        let stdin = match &stdin_mode {
            StdinMode::Pipe => Some(ExecSink::new(id, Arc::clone(&client))),
            _ => None,
        };

        if let StdinMode::Bytes(ref data) = stdin_mode {
            let data = data.clone();
            let bridge = Arc::clone(&client);
            tokio::spawn(async move {
                let payload = ExecStdin { data };
                let _ = bridge.send(id, MessageType::ExecStdin, &payload).await;
                let close = ExecStdin { data: Vec::new() };
                let _ = bridge.send(id, MessageType::ExecStdin, &close).await;
            });
        }

        let (event_tx, event_rx) = mpsc::unbounded_channel();
        tokio::spawn(event_mapper_task(rx, event_tx));

        Ok(ExecHandle::new(id, event_rx, stdin, client))
    }

    pub(crate) async fn exec(
        local: &LocalBackend,
        name: &str,
        config: &SandboxConfig,
        cmd: String,
        opts: ExecOptions,
    ) -> MicrosandboxResult<ExecOutput> {
        let timeout_duration = opts.timeout;
        let mut handle = exec_stream(local, name, config, cmd, opts).await?;

        match timeout_duration {
            Some(duration) => match tokio::time::timeout(duration, handle.collect()).await {
                Ok(result) => result,
                Err(_) => {
                    let _ = handle.kill().await;
                    let _ =
                        tokio::time::timeout(std::time::Duration::from_secs(5), handle.collect())
                            .await;
                    Err(MicrosandboxError::ExecTimeout(duration))
                }
            },
            None => handle.collect().await,
        }
    }

    /// Background task that converts raw protocol messages into [`ExecEvent`]s.
    async fn event_mapper_task(
        mut rx: mpsc::Receiver<Message>,
        tx: mpsc::UnboundedSender<ExecEvent>,
    ) {
        while let Some(msg) = rx.recv().await {
            let event = match msg.t {
                MessageType::ExecStarted => match msg.payload::<ExecStarted>() {
                    Ok(started) => ExecEvent::Started { pid: started.pid },
                    Err(_) => continue,
                },
                MessageType::ExecStdout => match msg.payload::<ExecStdout>() {
                    Ok(out) => ExecEvent::Stdout(Bytes::from(out.data)),
                    Err(_) => continue,
                },
                MessageType::ExecStderr => match msg.payload::<ExecStderr>() {
                    Ok(err) => ExecEvent::Stderr(Bytes::from(err.data)),
                    Err(_) => continue,
                },
                MessageType::ExecExited => {
                    if let Ok(exited) = msg.payload::<ExecExited>() {
                        let _ = tx.send(ExecEvent::Exited { code: exited.code });
                    }
                    break;
                }
                MessageType::ExecFailed => {
                    if let Ok(failed) = msg.payload::<microsandbox_protocol::exec::ExecFailed>() {
                        let _ = tx.send(ExecEvent::Failed(failed));
                    }
                    break;
                }
                MessageType::ExecStdinError => {
                    match msg.payload::<microsandbox_protocol::exec::ExecStdinError>() {
                        Ok(payload) => ExecEvent::StdinError(payload),
                        Err(_) => continue,
                    }
                }
                _ => continue,
            };
            if tx.send(event).is_err() {
                break;
            }
        }
    }

    // Re-export so backend trait impl can also use ExitStatus for typing.
    #[allow(dead_code)]
    pub(crate) fn _exit_status(code: i32) -> ExitStatus {
        ExitStatus {
            code,
            success: code == 0,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use microsandbox_types::{Rlimit, RlimitResource};
