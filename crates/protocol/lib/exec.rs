//! Exec-related protocol message payloads.

use std::str::FromStr;

use serde::{Deserialize, Serialize};

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
}

/// POSIX resource limit identifiers (maps to `RLIMIT_*` constants).
///
/// This is the canonical set of resource names understood by the protocol;
/// both the host-side builders and the guest-side parser agree on it.
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

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn default_rows() -> u16 {
    24
}

fn default_cols() -> u16 {
    80
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RlimitResource {
    /// Returns the lowercase string representation used on the wire.
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

/// Case-insensitive string to [`RlimitResource`] conversion.
impl TryFrom<&str> for RlimitResource {
    type Error = String;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s.to_ascii_lowercase().as_str() {
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
    use super::ExecRlimit;

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
