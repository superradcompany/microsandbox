//! Execution types for running commands inside sandboxes.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use microsandbox_protocol::exec::{ExecSignal, ExecStdin};
use microsandbox_protocol::message::{Message, MessageType};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::MicrosandboxResult;
use crate::agent::AgentBridge;

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

    /// Environment variables (merged with sandbox env).
    pub env: Vec<(String, String)>,

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
pub struct ExecOutput {
    /// Exit status.
    pub status: ExitStatus,

    /// Captured stdout.
    pub stdout: Bytes,

    /// Captured stderr.
    pub stderr: Bytes,
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
    /// Correlation ID for this session.
    pub(crate) id: u32,

    /// Event receiver.
    events: mpsc::UnboundedReceiver<ExecEvent>,

    /// Stdin sink (only if `StdinMode::Pipe` was used).
    stdin: Option<ExecSink>,

    /// Bridge reference for sending signals/stdin.
    bridge: Arc<AgentBridge>,
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
}

/// Sink for writing to a running process's stdin.
pub struct ExecSink {
    id: u32,
    bridge: Arc<AgentBridge>,
}

/// A POSIX resource limit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rlimit {
    /// Resource type.
    pub resource: RlimitResource,

    /// Soft limit (can be raised up to hard limit by the process).
    pub soft: u64,

    /// Hard limit (ceiling, requires privileges to raise).
    pub hard: u64,
}

/// POSIX resource limit identifiers (maps to `RLIMIT_*` constants).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RlimitResource {
    /// Max CPU time in seconds (`RLIMIT_CPU`).
    Cpu,
    /// Max file size in bytes (`RLIMIT_FSIZE`).
    Fsize,
    /// Max data segment size (`RLIMIT_DATA`).
    Data,
    /// Max stack size (`RLIMIT_STACK`).
    Stack,
    /// Max core file size (`RLIMIT_CORE`).
    Core,
    /// Max resident set size (`RLIMIT_RSS`).
    Rss,
    /// Max number of processes (`RLIMIT_NPROC`).
    Nproc,
    /// Max open file descriptors (`RLIMIT_NOFILE`).
    Nofile,
    /// Max locked memory (`RLIMIT_MEMLOCK`).
    Memlock,
    /// Max address space size (`RLIMIT_AS`).
    As,
    /// Max file locks (`RLIMIT_LOCKS`).
    Locks,
    /// Max pending signals (`RLIMIT_SIGPENDING`).
    Sigpending,
    /// Max bytes in POSIX message queues (`RLIMIT_MSGQUEUE`).
    Msgqueue,
    /// Max nice priority (`RLIMIT_NICE`).
    Nice,
    /// Max real-time priority (`RLIMIT_RTPRIO`).
    Rtprio,
    /// Max real-time timeout (`RLIMIT_RTTIME`).
    Rttime,
}

/// Trait for types that can be converted to [`ExecOptions`].
///
/// Enables ergonomic calling patterns:
/// - `sandbox.exec("ls", ["-la"])` — args array
/// - `sandbox.exec("python", |e| e.args(["-c", "print('hi')"]))` — closure
/// - `sandbox.exec("cat", ())` — no options
/// - `sandbox.exec("my-app", options)` — pre-built ExecOptions
pub trait IntoExecOptions {
    /// Convert into exec options.
    fn into_exec_options(self) -> ExecOptions;
}


//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ExecOptionsBuilder {
    /// Add a single argument.
    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.options.args.push(arg.into());
        self
    }

    /// Add multiple arguments.
    pub fn args(mut self, args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.options.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Set the working directory.
    pub fn cwd(mut self, cwd: impl Into<String>) -> Self {
        self.options.cwd = Some(cwd.into());
        self
    }

    /// Add an environment variable.
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.options.env.push((key.into(), value.into()));
        self
    }

    /// Add multiple environment variables.
    pub fn envs(
        mut self,
        vars: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
    ) -> Self {
        self.options
            .env
            .extend(vars.into_iter().map(|(k, v)| (k.into(), v.into())));
        self
    }

    /// Set execution timeout.
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

    /// Allocate a PTY.
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

    /// Build the options.
    pub fn build(self) -> ExecOptions {
        self.options
    }
}

impl ExecHandle {
    /// Create a new exec handle.
    pub(crate) fn new(
        id: u32,
        events: mpsc::UnboundedReceiver<ExecEvent>,
        stdin: Option<ExecSink>,
        bridge: Arc<AgentBridge>,
    ) -> Self {
        Self {
            id,
            events,
            stdin,
            bridge,
        }
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
            if let ExecEvent::Exited { code } = event {
                return Ok(ExitStatus {
                    code,
                    success: code == 0,
                });
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
        let mut exit_code = -1;

        while let Some(event) = self.events.recv().await {
            match event {
                ExecEvent::Stdout(data) => stdout.extend_from_slice(&data),
                ExecEvent::Stderr(data) => stderr.extend_from_slice(&data),
                ExecEvent::Exited { code } => {
                    exit_code = code;
                    break;
                }
                ExecEvent::Started { .. } => {}
            }
        }

        Ok(ExecOutput {
            status: ExitStatus {
                code: exit_code,
                success: exit_code == 0,
            },
            stdout: Bytes::from(stdout),
            stderr: Bytes::from(stderr),
        })
    }

    /// Send a signal to the running process.
    pub async fn signal(&self, signal: i32) -> MicrosandboxResult<()> {
        let payload = ExecSignal { signal };
        let msg = Message::with_payload(MessageType::ExecSignal, self.id, &payload)?;
        self.bridge.send(&msg).await
    }

    /// Send SIGKILL to the running process.
    pub async fn kill(&self) -> MicrosandboxResult<()> {
        self.signal(9).await
    }
}

impl ExecSink {
    /// Create a new stdin sink.
    pub(crate) fn new(id: u32, bridge: Arc<AgentBridge>) -> Self {
        Self { id, bridge }
    }

    /// Write data to the process's stdin.
    pub async fn write(&self, data: impl AsRef<[u8]>) -> MicrosandboxResult<()> {
        let payload = ExecStdin {
            data: data.as_ref().to_vec(),
        };
        let msg = Message::with_payload(MessageType::ExecStdin, self.id, &payload)?;
        self.bridge.send(&msg).await
    }

    /// Close stdin (sends EOF to the process).
    pub async fn close(&self) -> MicrosandboxResult<()> {
        let payload = ExecStdin { data: Vec::new() };
        let msg = Message::with_payload(MessageType::ExecStdin, self.id, &payload)?;
        self.bridge.send(&msg).await
    }
}

impl RlimitResource {
    /// Returns the lowercase string representation used in the protocol.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Fsize => "fsize",
            Self::Data => "data",
            Self::Stack => "stack",
            Self::Core => "core",
            Self::Rss => "rss",
            Self::Nproc => "nproc",
            Self::Nofile => "nofile",
            Self::Memlock => "memlock",
            Self::As => "as",
            Self::Locks => "locks",
            Self::Sigpending => "sigpending",
            Self::Msgqueue => "msgqueue",
            Self::Nice => "nice",
            Self::Rtprio => "rtprio",
            Self::Rttime => "rttime",
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for ExecOptionsBuilder {
    fn default() -> Self {
        Self {
            options: ExecOptions::default(),
        }
    }
}

/// No options: `sandbox.exec("cat", ())`
impl IntoExecOptions for () {
    fn into_exec_options(self) -> ExecOptions {
        ExecOptions::default()
    }
}

/// Closure pattern: `sandbox.exec("python", |e| e.args(["-c", "print('hi')"]))`
impl<F> IntoExecOptions for F
where
    F: FnOnce(ExecOptionsBuilder) -> ExecOptionsBuilder,
{
    fn into_exec_options(self) -> ExecOptions {
        self(ExecOptionsBuilder::default()).build()
    }
}

/// Direct options: `sandbox.exec("my-app", options)`
impl IntoExecOptions for ExecOptions {
    fn into_exec_options(self) -> ExecOptions {
        self
    }
}

/// Args array: `sandbox.exec("ls", ["-la", "/tmp"])`
impl<const N: usize> IntoExecOptions for [&str; N] {
    fn into_exec_options(self) -> ExecOptions {
        ExecOptions {
            args: self.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }
}

/// String to `RlimitResource` conversion.
///
/// Accepts: `"nofile"`, `"as"`, `"nproc"`, `"cpu"`, etc. (case-insensitive).
impl TryFrom<&str> for RlimitResource {
    type Error = String;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s.to_lowercase().as_str() {
            "cpu" => Ok(Self::Cpu),
            "fsize" => Ok(Self::Fsize),
            "data" => Ok(Self::Data),
            "stack" => Ok(Self::Stack),
            "core" => Ok(Self::Core),
            "rss" => Ok(Self::Rss),
            "nproc" => Ok(Self::Nproc),
            "nofile" => Ok(Self::Nofile),
            "memlock" => Ok(Self::Memlock),
            "as" => Ok(Self::As),
            "locks" => Ok(Self::Locks),
            "sigpending" => Ok(Self::Sigpending),
            "msgqueue" => Ok(Self::Msgqueue),
            "nice" => Ok(Self::Nice),
            "rtprio" => Ok(Self::Rtprio),
            "rttime" => Ok(Self::Rttime),
            _ => Err(format!("unknown rlimit resource: {s}")),
        }
    }
}

