//! Exec-related protocol message payloads.

use std::str::FromStr;

use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Window charge for each output chunk, bounding even very small writes.
pub use microsandbox_types::EXEC_OUTPUT_EVENT_OVERHEAD;

/// Runtime-owned execution policy advertised in Ready.
pub use microsandbox_types::ExecLimits;

/// Maximum encoded execution acknowledgement, signal or resize envelope.
pub const MAX_EXEC_CONTROL_BYTES: usize = 4096;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Request to execute a command in the guest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecRequest {
    /// The command to execute (program path).
    pub cmd: String,

    /// Arguments to the command.
    #[serde(default)]
    pub args: Vec<String>,

    /// Environment variables as key=value pairs.
    #[serde(default)]
    pub env: Vec<String>,

    /// Working directory for the command.
    #[serde(default)]
    pub cwd: Option<String>,

    /// Optional guest user override for the command.
    #[serde(default)]
    pub user: Option<String>,

    /// Whether to allocate a PTY for the command.
    #[serde(default)]
    pub tty: bool,

    /// Initial terminal rows (only used when `tty` is true).
    #[serde(default = "default_rows")]
    pub rows: u16,

    /// Initial terminal columns (only used when `tty` is true).
    #[serde(default = "default_cols")]
    pub cols: u16,

    /// POSIX resource limits to apply to the spawned process via `setrlimit()`.
    #[serde(default)]
    pub rlimits: Vec<ExecRlimit>,

    /// Whether `env` lists every sandbox default environment variable the
    /// command should see; agentd then removes boot defaults whose keys `env`
    /// omits.
    ///
    /// Secret placeholders, the variables agentd sets itself (TLS bundle paths,
    /// `HOME`) and `PATH` with its scripts directory are kept. Only agents that
    /// advertise [`Ready::replace_default_env_version`](crate::core::Ready::replace_default_env_version)
    /// honour it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub replace_default_env: bool,
}

/// A POSIX resource limit to apply to a spawned process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecRlimit {
    /// Resource name (lowercase): "nofile", "nproc", "as", "cpu", etc.
    pub resource: String,

    /// Soft limit (can be raised up to hard limit by the process).
    pub soft: u64,

    /// Hard limit (ceiling, requires privileges to raise).
    pub hard: u64,
}

/// Confirmation that a command has been started.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecStarted {
    /// The PID of the spawned process.
    pub pid: u32,
}

/// Stdin data sent to a running command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecStdin {
    /// The raw input data.
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

/// Notification that an `ExecStdin` write to the child's stdin failed.
/// The most common cause is the child closing its read end (EPIPE);
/// the session is otherwise alive and may still produce output and an
/// exit code, so this is delivered as a non-terminal event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecStdinError {
    /// `errno` from the underlying write, if available.
    #[serde(default)]
    pub errno: Option<i32>,

    /// Standard errno name like `"EPIPE"`, populated when `errno` is.
    #[serde(default)]
    pub errno_name: Option<String>,

    /// Human-readable description from agentd.
    pub message: String,
}

/// Stdout data from a running command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecStdout {
    /// The raw output data.
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

/// Stderr data from a running command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecStderr {
    /// The raw error output data.
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

/// Notification that a command has exited.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecExited {
    /// The exit code of the process.
    pub code: i32,
}

/// Notification that a command failed to start (the user's program
/// never got to run). Distinct from `ExecExited`, which means the
/// process ran and reported an exit code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecFailed {
    /// Coarse classification used by the CLI/SDK to pick hints.
    pub kind: ExecFailureKind,

    /// `errno` if the underlying failure was a syscall.
    #[serde(default)]
    pub errno: Option<i32>,

    /// Standard errno name like `"ENOENT"`. Easier to grep than the
    /// raw number; populated by the agentd classifier.
    #[serde(default)]
    pub errno_name: Option<String>,

    /// Human-readable description from agentd. Always populated.
    pub message: String,

    /// Which step failed when the kind alone isn't enough — e.g.
    /// `"execvp"`, `"setrlimit(RLIMIT_NOFILE)"`, `"posix_openpt"`.
    #[serde(default)]
    pub stage: Option<String>,
}

/// Coarse classification of an `ExecFailed` cause. The CLI's
/// stage-to-hint mapper keys off this; the SDK exposes it directly
/// for programmatic consumers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecFailureKind {
    /// Binary not found on PATH or at the explicit path. ENOENT on
    /// the binary path itself (not on the cwd — see `BadCwd`).
    NotFound,

    /// Binary found but not executable: EACCES or EPERM on file.
    PermissionDenied,

    /// File exists but the kernel can't run it: bad ELF, missing
    /// interpreter for a shebang script, wrong architecture, etc.
    /// ENOEXEC.
    NotExecutable,

    /// Working directory unusable: doesn't exist (ENOENT on cwd),
    /// not a directory (ENOTDIR), or no permission to chdir.
    BadCwd,

    /// Argument or env list too large (E2BIG), too many symlinks
    /// resolving the path (ELOOP), path too long (ENAMETOOLONG),
    /// or invalid bytes in argv (e.g. interior NUL — EINVAL).
    BadArgs,

    /// Resource limit prevented the spawn: rejected `setrlimit`
    /// (EPERM/EINVAL), per-process fork limit (EAGAIN with NPROC),
    /// fd table exhaustion (EMFILE/ENFILE).
    ResourceLimit,

    /// User/group setup failed: requested user doesn't exist in the
    /// sandbox, or `setuid`/`setgid` rejected (EPERM).
    UserSetupFailed,

    /// Memory pressure: kernel couldn't allocate (ENOMEM, or EAGAIN
    /// on fork without an explicit rlimit cause).
    OutOfMemory,

    /// PTY allocation or attachment failed (pty mode only).
    PtySetupFailed,

    /// Anything else: `errno` is carried verbatim, `message` and
    /// `stage` describe the specifics.
    Other,
}

/// Request to resize the PTY of a running command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecResize {
    /// New number of rows.
    pub rows: u16,

    /// New number of columns.
    pub cols: u16,
}

/// Request to send a signal to a running command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecSignal {
    /// The signal number to send (e.g. 15 for SIGTERM).
    pub signal: i32,
}

/// Acknowledges cumulative bytes written into the child's stdin pipe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecStdinAck {
    /// Bytes written to the child's stdin since this execution started.
    pub consumed: u64,
}

/// Acknowledges cumulative output consumed by the SDK, including per-chunk overhead.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExecOutputAck {
    /// Payload bytes plus per-chunk overhead consumed since this exec started.
    pub consumed: u64,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ExecOutputAck {
    /// Record one consumed output chunk, including its per-chunk overhead.
    ///
    /// Returns `None` on counter overflow without changing the acknowledgement.
    pub fn consume(&mut self, payload_bytes: usize) -> Option<()> {
        let charge = u64::try_from(payload_bytes)
            .ok()?
            .checked_add(u64::from(EXEC_OUTPUT_EVENT_OVERHEAD))?;

        self.consumed = self.consumed.checked_add(charge)?;

        Some(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn default_rows() -> u16 {
    24
}

fn default_cols() -> u16 {
    80
}

impl FromStr for ExecRlimit {
    type Err = String;

    fn from_str(spec: &str) -> Result<Self, Self::Err> {
        let (resource, limit) = spec
            .split_once('=')
            .ok_or_else(|| "rlimit must be in format RESOURCE=LIMIT".to_string())?;

        let mut parts = limit.split(':');
        let soft = parts
            .next()
            .ok_or_else(|| "missing soft limit".to_string())?
            .parse::<u64>()
            .map_err(|err| format!("invalid soft limit: {err}"))?;
        let hard = match parts.next() {
            Some(value) => value
                .parse::<u64>()
                .map_err(|err| format!("invalid hard limit: {err}"))?,
            None => soft,
        };

        if parts.next().is_some() {
            return Err("too many ':' separators".into());
        }

        if soft > hard {
            return Err("soft limit cannot exceed hard limit".into());
        }

        Ok(Self {
            resource: resource.to_ascii_lowercase(),
            soft,
            hard,
        })
    }
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::{ExecRequest, ExecRlimit};

    /// `ExecRequest` as agents before `replace_default_env` decode it.
    #[derive(Debug, Serialize, Deserialize)]
    struct LegacyExecRequest {
        cmd: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        env: Vec<String>,
        #[serde(default)]
        cwd: Option<String>,
        #[serde(default)]
        user: Option<String>,
        #[serde(default)]
        tty: bool,
        rows: u16,
        cols: u16,
        #[serde(default)]
        rlimits: Vec<ExecRlimit>,
    }

    fn request(replace_default_env: bool) -> ExecRequest {
        ExecRequest {
            cmd: "/bin/sh".into(),
            args: vec!["-c".into(), "env".into()],
            env: vec!["MODE=prod".into()],
            cwd: Some("/app".into()),
            user: None,
            tty: false,
            rows: 24,
            cols: 80,
            rlimits: Vec::new(),
            replace_default_env,
        }
    }

    fn cbor(value: &impl Serialize) -> Vec<u8> {
        let mut bytes = Vec::new();
        ciborium::into_writer(value, &mut bytes).unwrap();
        bytes
    }

    #[test]
    fn exec_request_without_replace_default_env_is_byte_compatible() {
        let current = request(false);
        let legacy = LegacyExecRequest {
            cmd: current.cmd.clone(),
            args: current.args.clone(),
            env: current.env.clone(),
            cwd: current.cwd.clone(),
            user: None,
            tty: false,
            rows: 24,
            cols: 80,
            rlimits: Vec::new(),
        };

        assert_eq!(cbor(&current), cbor(&legacy));
        let decoded: ExecRequest = ciborium::from_reader(cbor(&legacy).as_slice()).unwrap();
        assert!(!decoded.replace_default_env);
    }

    #[test]
    fn older_agents_decode_and_ignore_replace_default_env() {
        let bytes = cbor(&request(true));

        let legacy: LegacyExecRequest = ciborium::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(legacy.env, vec!["MODE=prod"]);
        assert_eq!(legacy.cwd.as_deref(), Some("/app"));
        let decoded: ExecRequest = ciborium::from_reader(bytes.as_slice()).unwrap();
        assert!(decoded.replace_default_env);
    }

    #[test]
    fn test_exec_rlimit_from_str_uses_soft_for_hard_when_omitted() {
        assert_eq!(
            "NOFILE=65535".parse::<ExecRlimit>().unwrap(),
            ExecRlimit {
                resource: "nofile".to_string(),
                soft: 65_535,
                hard: 65_535,
            }
        );
    }

    #[test]
    fn test_exec_rlimit_from_str_parses_soft_and_hard() {
        assert_eq!(
            "nofile=4096:65535".parse::<ExecRlimit>().unwrap(),
            ExecRlimit {
                resource: "nofile".to_string(),
                soft: 4_096,
                hard: 65_535,
            }
        );
    }

    #[test]
    fn test_exec_rlimit_from_str_rejects_soft_above_hard() {
        let err = "nofile=65535:4096".parse::<ExecRlimit>().unwrap_err();
        assert_eq!(err, "soft limit cannot exceed hard limit");
    }
}

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use microsandbox_types::RlimitResource;
