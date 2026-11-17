//! Execution types for running commands inside sandboxes.

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use microsandbox_protocol::{
    exec::{ExecFailed, ExecResize, ExecSignal, ExecStdin},
    message::MessageType,
};

use microsandbox_types::EnvVar;

use crate::{MicrosandboxResult, agent::AgentClient};

use super::io::{self, EventReceiver, InputWindow};

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
///
/// Output buffering defaults to 1 MiB shared by stdout and stderr. Supported guests
/// wait on a full buffer until output is consumed. Older guests warn and retain
/// unlimited buffering. Collecting output is not size-limited.
pub struct ExecHandle {
    /// Correlation ID for this session (protocol-level u32, exposed as String).
    id: u32,

    /// Event receiver; reading acknowledges consumed output to the guest.
    events: EventReceiver,

    /// Stdin sink (only if `StdinMode::Pipe` was used).
    stdin: Option<ExecSink>,

    /// Bridge reference for sending signals/stdin.
    client: Arc<AgentClient>,

    /// Client-owned deadline state, shared with the independent event pump.
    timeout: Option<Arc<StreamTimeout>>,
}

struct StreamTimeout {
    /// Requested timeout, measured from request dispatch.
    duration: Duration,
    /// Whether the deadline elapsed, independently of application output reads.
    expired: AtomicBool,
    /// Failure to deliver timeout termination, reported to the output consumer.
    failure: Mutex<Option<String>>,
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
    Failed(ExecFailed),

    /// A stdin write to the child failed (e.g. broken pipe). Non-terminal:
    /// the session keeps running and may still emit further output and
    /// an `Exited` event.
    StdinError(microsandbox_protocol::exec::ExecStdinError),
}

/// Sink for writing to a running process's stdin.
pub struct ExecSink {
    id: u32,
    client: Arc<AgentClient>,
    /// Guest-advertised stdin allowance; absent for legacy buffering.
    window: Option<Arc<io::InputWindow>>,
    /// Serializes writes and EOF; true once EOF is committed to the transport queue.
    write_lock: tokio::sync::Mutex<bool>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ExecOptionsBuilder {
    /// Prepend arguments resolved by a higher-level execution helper.
    pub(crate) fn prepend_args(mut self, args: impl IntoIterator<Item = String>) -> Self {
        self.options.args.splice(0..0, args);
        self
    }

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
    fn new(
        id: u32,
        events: EventReceiver,
        stdin: Option<ExecSink>,
        client: Arc<AgentClient>,
        timeout: Option<Arc<StreamTimeout>>,
    ) -> Self {
        Self {
            id,
            events,
            stdin,
            client,
            timeout,
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
    pub(crate) fn into_parts(self) -> (ExecControl, Option<ExecSink>, EventReceiver) {
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
    /// Returns `None` when the session has ended. A configured timeout is enforced even
    /// while no events are polled. This raw event API reports the actual exit event;
    /// [`Self::wait`] and [`Self::collect`] report `ExecTimeout` after a timed-out exit.
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
    ///
    /// Returns `ExecTimeout` after the process exits following its configured deadline.
    /// Cancelling this wait does not cancel the deadline. Failure to deliver termination
    /// is reported separately, without claiming that the process exited.
    pub async fn wait(&mut self) -> MicrosandboxResult<ExitStatus> {
        while let Some(event) = self.events.recv().await {
            match event {
                ExecEvent::Exited { code } => {
                    self.check_timeout()?;
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

        Err(self.incomplete_error())
    }

    /// Wait for completion and collect all stdout/stderr.
    ///
    /// Uses the same timeout and termination-confirmation behavior as [`Self::wait`].
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
                    self.check_timeout()?;
                    exit_code = Some(code);
                    break;
                }
                ExecEvent::Failed(payload) => {
                    return Err(crate::MicrosandboxError::ExecFailed(payload));
                }
                ExecEvent::StdinError(_) => {}
            }
        }

        let code = exit_code.ok_or_else(|| self.incomplete_error())?;

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

    fn check_timeout(&self) -> MicrosandboxResult<()> {
        if let Some(timeout) = &self.timeout
            && timeout.expired.load(Ordering::Acquire)
        {
            return Err(crate::MicrosandboxError::ExecTimeout(timeout.duration));
        }
        Ok(())
    }

    fn incomplete_error(&self) -> crate::MicrosandboxError {
        let failure = self
            .timeout
            .as_ref()
            .and_then(|timeout| timeout.failure.lock().unwrap().clone());
        crate::MicrosandboxError::Runtime(
            failure.unwrap_or_else(|| "exec session ended without exit event".into()),
        )
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
    fn new(id: u32, client: Arc<AgentClient>, window: Option<Arc<InputWindow>>) -> Self {
        Self {
            id,
            client,
            window,
            write_lock: tokio::sync::Mutex::new(false),
        }
    }

    /// Write data to the process's stdin, waiting until all bytes have been sent.
    /// Empty data is a no-op, never EOF. Call [`close`](Self::close) when done writing; in pipe
    /// mode it sends EOF.
    /// A cancelled write may have queued a prefix that is still delivered.
    pub async fn write(&self, data: impl AsRef<[u8]>) -> MicrosandboxResult<()> {
        let data = data.as_ref();
        if data.is_empty() {
            return Ok(());
        }

        // Serialize chunks so concurrent writes and EOF keep their original operation order.
        let closed = self.write_lock.lock().await;
        if *closed {
            return Err(crate::MicrosandboxError::Runtime(
                "execution stdin closed".into(),
            ));
        }
        if let Some(window) = &self.window {
            window.wait_started().await?;
        }

        if let Some(window) = &self.window {
            window.send(&self.client, self.id, data).await?;
            return Ok(());
        }

        self.client
            .send(
                self.id,
                MessageType::ExecStdin,
                &ExecStdin {
                    data: data.to_vec(),
                },
            )
            .await?;
        Ok(())
    }

    /// Close stdin (sends EOF to the process).
    /// Waits for any current write to finish. Cancel a blocked write first if the process
    /// is not consuming input; any prefix already sent may still arrive before EOF.
    pub async fn close(&self) -> MicrosandboxResult<()> {
        let mut closed = self.write_lock.lock().await;
        if *closed {
            return Ok(());
        }
        if let Some(window) = &self.window {
            window.wait_started().await?;
        }

        // An empty frame is the protocol's EOF marker.
        self.client
            .send_and_commit(
                self.id,
                MessageType::ExecStdin,
                &ExecStdin { data: Vec::new() },
                || *closed = true,
            )
            .await?;
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Module: agent (backend-agnostic ops driven over an agent connection)
//--------------------------------------------------------------------------------------------------

pub(crate) mod agent {
    //! Local exec dispatch keyed by `(sandbox_name, cmd, opts)`.
    //!
    //! Opens a fresh agent UDS each call (option A in the parity plan).

    use std::{
        sync::{Arc, Weak},
        time::Duration,
    };

    use bytes::Bytes;
    use microsandbox_protocol::{
        exec::{
            EXEC_OUTPUT_EVENT_OVERHEAD, ExecExited, ExecFailed, ExecFailureKind, ExecSignal,
            ExecStarted, ExecStderr, ExecStdinAck, ExecStdout,
        },
        message::{Message, MessageType},
    };
    use tokio::{
        sync::{mpsc, watch},
        time::Instant,
    };

    use crate::{
        MicrosandboxError, MicrosandboxResult,
        agent::AgentClient,
        sandbox::{SandboxConfig, build_exec_request, fs::agent::connect_agent},
    };

    use super::{
        ExecEvent, ExecHandle, ExecOptions, ExecOutput, ExecSink, ExitStatus, StdinMode,
        StreamTimeout,
        io::{self, EventReceiver},
    };

    pub(crate) async fn exec_stream(
        backend: &dyn crate::backend::Backend,
        name: &str,
        config: &SandboxConfig,
        cmd: String,
        opts: ExecOptions,
    ) -> MicrosandboxResult<ExecHandle> {
        exec_stream_with_pty_size(backend, name, config, cmd, opts, 24, 80).await
    }

    pub(crate) async fn exec_stream_with_pty_size(
        backend: &dyn crate::backend::Backend,
        name: &str,
        config: &SandboxConfig,
        cmd: String,
        opts: ExecOptions,
        rows: u16,
        cols: u16,
    ) -> MicrosandboxResult<ExecHandle> {
        let client = Arc::new(connect_agent(backend, name).await?);
        let policy = client.ready()?.exec_limits;

        if let Some(policy) = policy {
            policy
                .validate()
                .map_err(|error| MicrosandboxError::Runtime(error.into()))?;
        }

        let controlled = policy.is_some() && client.supports(MessageType::ExecOutputAck);
        if !controlled {
            tracing::warn!(
                sandbox = %name,
                "guest does not support exec output backpressure; \
                retaining legacy unbounded buffering"
            );
        }

        let ExecOptions {
            args,
            cwd,
            user,
            env,
            rlimits,
            tty,
            stdin: stdin_mode,
            timeout,
        } = opts;

        // Validate before dispatch. Count execution time from request dispatch, but never
        // signal a pre-start correlation: older agents also require ExecStarted first.
        let deadline = timeout
            .map(|duration| {
                Instant::now().checked_add(duration).ok_or_else(|| {
                    MicrosandboxError::InvalidConfig(
                        "execution timeout exceeds the supported duration range".into(),
                    )
                })
            })
            .transpose()?;
        let timeout = timeout.map(|duration| {
            Arc::new(StreamTimeout {
                duration,
                expired: super::AtomicBool::new(false),
                failure: super::Mutex::new(None),
            })
        });

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
        let input_window = policy.filter(|_| controlled).map(|policy| {
            io::InputWindow::new(policy.input_limit, policy.stdin_chunk_size as usize)
        });
        let (id, rx) = client.stream(MessageType::ExecRequest, &req).await?;

        let stdin = match &stdin_mode {
            StdinMode::Pipe => Some(ExecSink::new(id, Arc::clone(&client), input_window.clone())),
            _ => None,
        };

        let finite_input = match stdin_mode {
            // A pipe with no caller-owned writer still needs an explicit guest EOF.
            // PTYs have no independent stdin half; retain their existing terminal semantics.
            StdinMode::Null if !tty => Some(Vec::new()),
            StdinMode::Bytes(data) => Some(data),
            _ => None,
        };
        if let Some(data) = finite_input {
            let sink = ExecSink::new(id, Arc::clone(&client), input_window.clone());
            tokio::spawn(async move {
                if !data.is_empty() {
                    let _ = sink.write(data).await;
                }
                let _ = sink.close().await;
            });
        }

        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let (event_rx, acknowledgements) = EventReceiver::new(event_rx, controlled);
        tokio::spawn(event_mapper_task(
            rx,
            event_tx,
            deadline.zip(timeout.clone()),
            Arc::downgrade(&client),
            id,
            acknowledgements,
            input_window,
        ));

        Ok(ExecHandle::new(id, event_rx, stdin, client, timeout))
    }

    pub(crate) async fn exec(
        backend: &dyn crate::backend::Backend,
        name: &str,
        config: &SandboxConfig,
        cmd: String,
        mut opts: ExecOptions,
    ) -> MicrosandboxResult<ExecOutput> {
        // Buffered exec keeps its existing deadline and error contract. Do not start a
        // second timer in its underlying streaming session.
        let timeout_duration = opts.timeout.take();
        let mut handle = exec_stream(backend, name, config, cmd, opts).await?;

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
        timeout: Option<(Instant, Arc<StreamTimeout>)>,
        client: Weak<AgentClient>,
        id: u32,
        acknowledgements: Option<io::OutputAcknowledgements>,
        input_window: Option<Arc<io::InputWindow>>,
    ) {
        let policy = client
            .upgrade()
            .and_then(|client| client.ready().ok())
            .and_then(|ready| ready.exec_limits);

        let mut output_sent = 0_u64;
        let discarded = acknowledgements
            .as_ref()
            .map(|acknowledgements| acknowledgements.consumed.clone());
        let acknowledgement_client = client.clone();
        let acknowledgement = async move {
            match acknowledgements {
                Some(acknowledgements) => {
                    acknowledgements
                        .run(|acknowledgement| {
                            let client = acknowledgement_client.clone();
                            async move {
                                let client = client.upgrade().ok_or("exec connection closed")?;
                                client
                                    .send(id, MessageType::ExecOutputAck, &acknowledgement)
                                    .await
                                    .map_err(|error| error.to_string())
                            }
                        })
                        .await
                }
                None => std::future::pending().await,
            }
        };

        let worker = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(acknowledgement));
        let acknowledgement = async move { worker.await.map_err(|error| error.to_string())? };
        tokio::pin!(acknowledgement);

        let (started_tx, started_rx) = watch::channel(false);
        let monitor = async {
            let Some((deadline, state)) = &timeout else {
                return std::future::pending::<Result<(), String>>().await;
            };
            enforce_deadline(*deadline, started_rx, state, async {
                let client = client
                    .upgrade()
                    .ok_or("exec connection closed before timeout termination")?;
                client
                    .send(id, MessageType::ExecSignal, &ExecSignal { signal: 9 })
                    .await
                    .map_err(|error| error.to_string())
            })
            .await
        };
        let mut monitor = Some(Box::pin(monitor));
        let mut reader_closed = false;
        loop {
            let msg = tokio::select! {
                // Preserve completion while a retained stdin/control handle owns the connection.
                _ = tx.closed(), if !reader_closed => {
                    reader_closed = true;
                    continue;
                },

                result = &mut acknowledgement => {
                    if let Err(error) = result
                        && !tx.is_closed()
                    {
                        tracing::warn!(%error, "exec output acknowledgement delivery failed");
                    }
                    break;
                }

                result = async { monitor.as_mut().expect("active deadline").await }, if monitor.is_some() => {
                    monitor = None;

                    if let Err(error) = result {
                        let diagnostic = format!("exec timeout termination failed; process exit is unconfirmed: {error}");
                        if let Some((_, state)) = &timeout {
                            *state.failure.lock().unwrap() = Some(diagnostic.clone());
                        }
                        tracing::warn!(%diagnostic);
                        break;
                    }
                    continue;
                }
                msg = rx.recv() => match msg { Some(msg) => msg, None => break },
            };

            let event = match msg.t {
                MessageType::ExecStdinAck => {
                    if let Some(window) = &input_window {
                        match msg.payload::<ExecStdinAck>() {
                            Ok(acknowledgement) if window.acknowledge(acknowledgement.consumed) => {
                            }
                            _ => {
                                tracing::warn!("invalid execution stdin acknowledgement");
                                if let Some(client) = client.upgrade() {
                                    client.abort().await;
                                }
                                break;
                            }
                        }
                    }

                    continue;
                }
                MessageType::ExecStarted => match msg.payload::<ExecStarted>() {
                    Ok(started) => {
                        started_tx.send_replace(true);
                        if let Some(window) = &input_window {
                            window.mark_started();
                        }

                        ExecEvent::Started { pid: started.pid }
                    }
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
                    if let Ok(failed) = msg.payload::<ExecFailed>() {
                        let _ = tx.send(ExecEvent::Failed(failed));
                    }
                    break;
                }
                MessageType::ExecStdinError => {
                    if let Some(window) = &input_window {
                        window.close();
                    }
                    match msg.payload::<microsandbox_protocol::exec::ExecStdinError>() {
                        Ok(payload) => ExecEvent::StdinError(payload),
                        Err(_) => continue,
                    }
                }
                _ => continue,
            };

            if let (Some(policy), Some(consumed)) = (policy, discarded.as_ref())
                && let ExecEvent::Stdout(data) | ExecEvent::Stderr(data) = &event
            {
                let sent = output_sent
                    .checked_add(data.len() as u64 + u64::from(EXEC_OUTPUT_EVENT_OVERHEAD));
                if data.len() > policy.output_chunk_size as usize
                    || sent.is_none_or(|sent| {
                        sent.saturating_sub(consumed.borrow().consumed)
                            > u64::from(policy.output_limit)
                    })
                {
                    let _ = tx.send(ExecEvent::Failed(ExecFailed {
                        kind: ExecFailureKind::Other,
                        errno: None,
                        errno_name: None,
                        message: "guest output exceeds the advertised execution policy".into(),
                        stage: Some("protocol".into()),
                    }));

                    if let Some(client) = client.upgrade() {
                        client.abort().await;
                    }

                    break;
                }
                output_sent = sent.unwrap();
            }

            if let Err(error) = tx.send(event)
                && let Some(consumed) = &discarded
            {
                io::consume(consumed, &error.0);
            }
        }

        if let Some(window) = input_window {
            window.close();
        }
    }

    async fn enforce_deadline(
        deadline: Instant,
        mut started: watch::Receiver<bool>,
        state: &StreamTimeout,
        signal: impl std::future::Future<Output = Result<(), String>>,
    ) -> Result<(), String> {
        tokio::time::sleep_until(deadline).await;
        started
            .wait_for(|started| *started)
            .await
            .map_err(|_| "exec ended before startup acknowledgement")?;
        state.expired.store(true, super::Ordering::Release);
        // Older transports may block a signal behind input. Bound delivery instead of
        // hanging the caller or falsely claiming that the guest has exited.
        tokio::time::timeout(Duration::from_secs(5), signal)
            .await
            .map_err(|_| "signal delivery did not complete within five seconds".to_owned())?
    }

    // Re-export so backend trait impl can also use ExitStatus for typing.
    #[allow(dead_code)]
    pub(crate) fn _exit_status(code: i32) -> ExitStatus {
        ExitStatus {
            code,
            success: code == 0,
        }
    }

    //--------------------------------------------------------------------------------------------------
    // Tests
    //--------------------------------------------------------------------------------------------------

    #[cfg(test)]
    mod tests {
        use std::sync::Mutex;
        use std::sync::atomic::{AtomicBool, Ordering};

        use super::*;
        use microsandbox_protocol::{codec, core::Ready, message::PROTOCOL_VERSION};

        const TEST_INPUT_LIMIT: u32 = 64 * 1024;

        async fn flow_test_client() -> (Arc<AgentClient>, tokio::io::DuplexStream) {
            flow_test_client_with_version(PROTOCOL_VERSION).await
        }

        async fn flow_test_client_with_version(
            version: u8,
        ) -> (Arc<AgentClient>, tokio::io::DuplexStream) {
            use tokio::io::AsyncWriteExt;

            let (host, mut peer) = tokio::io::duplex(1024);
            let connect = AgentClient::connect_stream_with_timeout(host, Duration::from_secs(3));
            let handshake = async {
                peer.write_all(&1u32.to_be_bytes()).await.unwrap();
                peer.write_all(&1024u32.to_be_bytes()).await.unwrap();
                let mut ready =
                    Message::with_payload(MessageType::Ready, 0, &Ready::default()).unwrap();
                ready.v = version;
                codec::write_message(&mut peer, &ready).await.unwrap();
                peer
            };
            let (client, peer) = tokio::join!(connect, handshake);
            (Arc::new(client.unwrap()), peer)
        }

        #[tokio::test]
        async fn stdin_allowance_preserves_control_progress_and_eof_order() {
            use microsandbox_protocol::{
                codec,
                exec::{ExecOutputAck, ExecStdin},
            };
            for chunk_size in [1024, 16384, 65536] {
                let (client, mut peer) = flow_test_client().await;
                let window = super::super::io::InputWindow::new(TEST_INPUT_LIMIT, chunk_size);
                window.mark_started();
                let sink = ExecSink::new(77, client.clone(), Some(window.clone()));
                let total = 2 * TEST_INPUT_LIMIT as usize + 3;
                let writer = async {
                    sink.write(vec![7; total]).await.unwrap();
                    sink.close().await.unwrap();
                };
                let reader = async {
                    let mut received = 0;
                    let allowance = TEST_INPUT_LIMIT as usize;
                    while received < allowance {
                        let msg = codec::read_message(&mut peer).await.unwrap();
                        assert_eq!(msg.t, MessageType::ExecStdin);
                        let data = msg.payload::<ExecStdin>().unwrap().data;
                        assert!(!data.is_empty());
                        assert!(data.len() <= chunk_size);
                        assert!(data.iter().all(|byte| *byte == 7));
                        received += data.len();
                    }
                    assert_eq!(received, allowance);
                    assert!(
                        tokio::time::timeout(
                            Duration::from_millis(20),
                            codec::read_message(&mut peer)
                        )
                        .await
                        .is_err(),
                        "stdin must wait until the guest acknowledges consumed bytes"
                    );

                    // Control traffic must pass while stdin is waiting for guest acknowledgement.
                    let (sent, message) = tokio::join!(
                        client.send(
                            77,
                            MessageType::ExecOutputAck,
                            &ExecOutputAck { consumed: 256 }
                        ),
                        codec::read_message(&mut peer),
                    );
                    sent.unwrap();
                    assert_eq!(message.unwrap().t, MessageType::ExecOutputAck);
                    assert!(window.acknowledge(received as u64));

                    loop {
                        let msg = codec::read_message(&mut peer).await.unwrap();
                        assert_eq!(msg.t, MessageType::ExecStdin);
                        let data = msg.payload::<ExecStdin>().unwrap().data;
                        if data.is_empty() {
                            break;
                        }
                        assert!(data.iter().all(|byte| *byte == 7));
                        received += data.len();
                        assert!(window.acknowledge(received as u64));
                    }
                    assert_eq!(received, total, "EOF must follow every byte");
                };
                tokio::time::timeout(Duration::from_secs(10), async {
                    tokio::join!(writer, reader);
                })
                .await
                .unwrap();
            }
        }

        #[tokio::test]
        async fn empty_stdin_write_does_not_send_eof() {
            use microsandbox_protocol::exec::ExecStdin;

            for controlled in [false, true] {
                let (client, mut peer) = flow_test_client().await;
                let window = controlled.then(|| {
                    let window = super::super::io::InputWindow::new(TEST_INPUT_LIMIT, 16384);
                    window.mark_started();
                    window
                });
                let sink = ExecSink::new(77, client, window);

                sink.write(b"aaaaa").await.unwrap();
                sink.write(b"").await.unwrap();
                sink.write(b"bbbbb").await.unwrap();
                sink.close().await.unwrap();

                let mut frames = Vec::new();
                for _ in 0..3 {
                    let msg = codec::read_message(&mut peer).await.unwrap();
                    assert_eq!(msg.id, 77);
                    frames.push(msg.payload::<ExecStdin>().unwrap().data);
                }
                assert_eq!(frames, [b"aaaaa".to_vec(), b"bbbbb".to_vec(), Vec::new()]);

                sink.write(b"").await.unwrap();
                assert!(sink.write(b"after EOF").await.is_err());
                sink.close().await.unwrap();
                assert!(
                    tokio::time::timeout(Duration::from_millis(20), codec::read_message(&mut peer))
                        .await
                        .is_err(),
                    "only the first close may send EOF"
                );
            }
        }

        #[tokio::test]
        async fn closing_stdin_wakes_waiting_writes() {
            use microsandbox_protocol::{codec, exec::ExecStdin};
            for started in [false, true] {
                let (client, mut peer) = flow_test_client().await;
                let window = super::super::io::InputWindow::new(TEST_INPUT_LIMIT, 16 * 1024);
                if started {
                    window.mark_started();
                }
                let sink = ExecSink::new(77, client, Some(window.clone()));
                let writer = async {
                    assert!(sink.write(vec![1; 256 * 1024]).await.is_err());
                };
                let reader = async {
                    for _ in 0..if started { 4 } else { 0 } {
                        let msg = codec::read_message(&mut peer).await.unwrap();
                        assert!(!msg.payload::<ExecStdin>().unwrap().data.is_empty());
                    }
                    window.close();
                };
                tokio::time::timeout(Duration::from_secs(3), async {
                    tokio::join!(writer, reader);
                })
                .await
                .expect("closed stdin must wake queued and in-flight writes");
            }
        }

        #[tokio::test]
        async fn cancelling_admitted_eof_keeps_stdin_closed() {
            use microsandbox_protocol::exec::ExecStdin;
            use std::future::{Future, poll_fn};
            use std::task::Poll;

            for controlled in [false, true] {
                let (client, mut peer) = flow_test_client().await;
                let window = controlled.then(|| {
                    let window = super::super::io::InputWindow::new(TEST_INPUT_LIMIT, 16384);
                    window.mark_started();
                    window
                });
                let sink = ExecSink::new(77, client.clone(), window);
                let mut close = Box::pin(sink.close());
                // Queue EOF without yielding to the socket writer, then cancel its caller while
                // the accepted frame still waits for physical delivery.
                poll_fn(|cx| {
                    assert!(close.as_mut().poll(cx).is_pending());
                    Poll::Ready(())
                })
                .await;
                drop(close);

                let mut write = Box::pin(sink.write(b"after EOF"));
                poll_fn(|cx| {
                    assert!(
                        matches!(write.as_mut().poll(cx), Poll::Ready(Err(_))),
                        "an admitted EOF must reject subsequent writes even if close was cancelled"
                    );
                    Poll::Ready(())
                })
                .await;
                sink.close().await.unwrap();
                let eof = codec::read_message(&mut peer).await.unwrap();
                assert_eq!(eof.id, 77);
                assert!(eof.payload::<ExecStdin>().unwrap().data.is_empty());
            }
        }

        #[tokio::test]
        async fn cancelled_stdin_respects_transport_admission() {
            use microsandbox_protocol::exec::ExecStdin;
            use std::future::{Future, poll_fn};
            use std::task::Poll;

            for limit in [16 * 1024, 32 * 1024, TEST_INPUT_LIMIT] {
                let (client, mut peer) = flow_test_client().await;
                let window = super::super::io::InputWindow::new(limit, 16 * 1024);
                let filler = ExecStdin {
                    data: vec![1; 4096],
                };
                let mut pending: Vec<_> = (100..132)
                    .map(|id| Box::pin(client.send(id, MessageType::ExecStdin, &filler)))
                    .collect();
                // Fill the real bounded writer queue while the peer does not read.
                poll_fn(|cx| {
                    for send in &mut pending {
                        assert!(send.as_mut().poll(cx).is_pending());
                    }
                    Poll::Ready(())
                })
                .await;

                for _ in 0..4 {
                    let mut write = Box::pin(window.send(&client, 77, vec![2; 16 * 1024]));
                    poll_fn(|cx| {
                        assert!(write.as_mut().poll(cx).is_pending());
                        Poll::Ready(())
                    })
                    .await;
                    drop(write);
                }
                drop(pending);

                let receive = async {
                    let mut bytes = 0;
                    while bytes < limit as usize {
                        let msg = codec::read_message(&mut peer).await.unwrap();
                        if msg.id == 77 {
                            let data = msg.payload::<ExecStdin>().unwrap().data;
                            assert!(data.iter().all(|byte| *byte == 3));
                            bytes += data.len();
                        }
                    }
                    assert_eq!(bytes, limit as usize);
                };
                tokio::time::timeout(Duration::from_secs(3), async {
                    tokio::join!(
                        async {
                            window
                                .send(&client, 77, vec![3; limit as usize])
                                .await
                                .unwrap();
                        },
                        receive
                    );
                })
                .await
                .expect("cancelled writes must not consume capacity");

                let mut blocked = Box::pin(window.send(&client, 77, vec![5; 16 * 1024]));
                poll_fn(|cx| {
                    assert!(blocked.as_mut().poll(cx).is_pending());
                    Poll::Ready(())
                })
                .await;
                assert!(
                    tokio::time::timeout(
                        Duration::from_millis(20),
                        codec::read_message(&mut peer),
                    )
                    .await
                    .is_err(),
                    "a full configured input window must not admit another chunk",
                );
                drop(blocked);

                assert!(window.acknowledge(u64::from(limit)));
                let mut write = Box::pin(window.send(&client, 77, vec![4; 16 * 1024]));
                poll_fn(|cx| {
                    assert!(write.as_mut().poll(cx).is_pending());
                    Poll::Ready(())
                })
                .await;
                // The frame is admitted, but the peer has not read it yet. Cancelling
                // must keep its charge and allow the eventual acknowledgement.
                drop(write);
                let msg =
                    tokio::time::timeout(Duration::from_secs(3), codec::read_message(&mut peer))
                        .await
                        .unwrap()
                        .unwrap();
                assert_eq!(msg.id, 77);
                assert_eq!(msg.payload::<ExecStdin>().unwrap().data, vec![4; 16 * 1024]);
                assert!(window.acknowledge(u64::from(limit) + 16 * 1024));
            }
        }

        #[tokio::test(start_paused = true)]
        async fn dropped_reader_preserves_timeout_and_output_flow() {
            use microsandbox_protocol::exec::{
                EXEC_OUTPUT_EVENT_OVERHEAD, ExecOutputAck, ExecRequest,
            };

            for controlled in [false, true] {
                let (client, mut peer) = flow_test_client().await;
                let request: ExecRequest = serde_json::from_value(
                    serde_json::json!({"cmd":"cat", "output_limit":controlled.then_some(65536)}),
                )
                .unwrap();
                let ((id, rx), _) = tokio::join!(
                    async {
                        client
                            .stream(MessageType::ExecRequest, &request)
                            .await
                            .unwrap()
                    },
                    async {
                        codec::read_message(&mut peer).await.unwrap();
                    }
                );
                let (tx, events) = mpsc::unbounded_channel();
                let (events, acknowledgements) =
                    super::super::io::EventReceiver::new(events, controlled);
                let pump = tokio::spawn(event_mapper_task(
                    rx,
                    tx,
                    Some((Instant::now() + Duration::from_secs(10), Arc::new(state()))),
                    Arc::downgrade(&client),
                    id,
                    acknowledgements,
                    None,
                ));
                let handle = ExecHandle::new(id, events, None, client, None);
                let control = handle.control();

                let started =
                    Message::with_payload(MessageType::ExecStarted, id, &ExecStarted { pid: 123 })
                        .unwrap();
                codec::write_message(&mut peer, &started).await.unwrap();

                let output = Message::with_payload(
                    MessageType::ExecStdout,
                    id,
                    &ExecStdout {
                        data: vec![1; 4096],
                    },
                )
                .unwrap();
                codec::write_message(&mut peer, &output).await.unwrap();
                drop(handle);

                tokio::time::timeout(Duration::from_secs(20), async {
                    if controlled {
                        for chunks in 1..=2 {
                            let expected = chunks * (4096 + u64::from(EXEC_OUTPUT_EVENT_OVERHEAD));
                            let msg = codec::read_message(&mut peer).await.unwrap();
                            assert_eq!(msg.t, MessageType::ExecOutputAck);
                            assert_eq!(msg.payload::<ExecOutputAck>().unwrap().consumed, expected);
                            if chunks == 1 {
                                codec::write_message(&mut peer, &output).await.unwrap();
                            }
                        }
                    }
                    tokio::time::advance(Duration::from_secs(10)).await;
                    let signal = codec::read_message(&mut peer).await.unwrap();
                    assert_eq!(signal.t, MessageType::ExecSignal);
                    assert_eq!(signal.payload::<ExecSignal>().unwrap().signal, 9);
                    let exited =
                        Message::with_payload(MessageType::ExecExited, id, &ExecExited { code: 0 })
                            .unwrap();
                    codec::write_message(&mut peer, &exited).await.unwrap();
                    pump.await.unwrap();
                })
                .await
                .expect("retained control handle must not strand the producer");
                drop(control);
            }
        }

        fn state() -> StreamTimeout {
            StreamTimeout {
                duration: Duration::from_secs(1),
                expired: AtomicBool::new(false),
                failure: Mutex::new(None),
            }
        }

        #[tokio::test(start_paused = true)]
        async fn stream_deadline_waits_for_start_and_fires_once() {
            let state = state();
            let (started, receiver) = watch::channel(false);
            let signalled = AtomicBool::new(false);
            let deadline = enforce_deadline(Instant::now(), receiver, &state, async {
                assert!(!signalled.swap(true, Ordering::SeqCst));
                Ok(())
            });
            tokio::pin!(deadline);
            assert!(
                tokio::time::timeout(Duration::from_secs(10), &mut deadline)
                    .await
                    .is_err()
            );
            assert!(!state.expired.load(Ordering::Acquire));
            assert!(!signalled.load(Ordering::SeqCst));
            started.send_replace(true);
            deadline.await.unwrap();
            assert!(state.expired.load(Ordering::Acquire));
            assert!(signalled.load(Ordering::SeqCst));
        }

        #[tokio::test(start_paused = true)]
        async fn stream_deadline_cancelled_before_expiry_does_not_signal() {
            let state = state();
            let (_started, receiver) = watch::channel(true);
            let signalled = AtomicBool::new(false);
            {
                let deadline = enforce_deadline(
                    Instant::now() + Duration::from_secs(2),
                    receiver,
                    &state,
                    async {
                        signalled.store(true, Ordering::SeqCst);
                        Ok(())
                    },
                );
                tokio::pin!(deadline);
                assert!(
                    tokio::time::timeout(Duration::from_secs(1), &mut deadline)
                        .await
                        .is_err()
                );
            }
            tokio::time::advance(Duration::from_secs(10)).await;
            assert!(!state.expired.load(Ordering::Acquire));
            assert!(!signalled.load(Ordering::SeqCst));
        }

        #[tokio::test(start_paused = true)]
        async fn stream_deadline_bounds_and_reports_signal_failure() {
            let state = state();
            let (_started, receiver) = watch::channel(true);
            assert_eq!(
                enforce_deadline(Instant::now(), receiver.clone(), &state, async {
                    Err("delivery_unconfirmed".into())
                })
                .await
                .unwrap_err(),
                "delivery_unconfirmed"
            );
            let before = Instant::now();
            let error = enforce_deadline(before, receiver, &state, std::future::pending())
                .await
                .unwrap_err();
            assert!(error.contains("five seconds"));
            assert_eq!(Instant::now() - before, Duration::from_secs(5));
        }

        #[tokio::test(start_paused = true)]
        async fn stream_pump_exit_cancels_deadline_without_late_signal() {
            let state = Arc::new(state());
            let (tx, rx) = mpsc::channel(2);
            let (events_tx, mut events) = mpsc::unbounded_channel();
            tx.send(
                Message::with_payload(MessageType::ExecStarted, 1, &ExecStarted { pid: 123 })
                    .unwrap(),
            )
            .await
            .unwrap();
            tx.send(
                Message::with_payload(MessageType::ExecExited, 1, &ExecExited { code: 0 }).unwrap(),
            )
            .await
            .unwrap();
            event_mapper_task(
                rx,
                events_tx,
                Some((Instant::now() + Duration::from_secs(1), state.clone())),
                Weak::new(),
                1,
                None,
                None,
            )
            .await;
            assert!(matches!(
                events.recv().await,
                Some(ExecEvent::Started { pid: 123 })
            ));
            assert!(matches!(
                events.recv().await,
                Some(ExecEvent::Exited { code: 0 })
            ));
            tokio::time::advance(Duration::from_secs(2)).await;
            assert!(!state.expired.load(Ordering::Acquire));
        }

        #[tokio::test(start_paused = true)]
        async fn stream_pump_reports_unconfirmed_termination_without_fake_exit() {
            let state = Arc::new(state());
            let (tx, rx) = mpsc::channel(1);
            let (events_tx, mut events) = mpsc::unbounded_channel();
            tx.send(
                Message::with_payload(MessageType::ExecStarted, 1, &ExecStarted { pid: 123 })
                    .unwrap(),
            )
            .await
            .unwrap();
            event_mapper_task(
                rx,
                events_tx,
                Some((Instant::now(), state.clone())),
                Weak::new(),
                1,
                None,
                None,
            )
            .await;
            assert!(matches!(
                events.recv().await,
                Some(ExecEvent::Started { .. })
            ));
            assert!(events.recv().await.is_none());
            assert!(
                state
                    .failure
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .contains("process exit is unconfirmed")
            );
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use microsandbox_types::{Rlimit, RlimitResource};
