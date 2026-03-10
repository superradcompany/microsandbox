//! Interactive attach types for terminal bridging with sandboxes.

use crate::MicrosandboxResult;

use super::exec::Rlimit;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Configuration for attaching to a sandbox with an interactive session.
///
/// The host terminal is set to raw mode for the duration of the attach session.
/// The guest process runs in a PTY, enabling terminal features (colors, line
/// editing, Ctrl+C → SIGINT).
#[derive(Debug, Clone, Default)]
pub struct AttachConfig {
    /// Command to run (default: sandbox's configured shell).
    pub cmd: Option<String>,

    /// Arguments.
    pub args: Vec<String>,

    /// Environment variables (merged with sandbox env).
    pub env: Vec<(String, String)>,

    /// Working directory (default: sandbox's workdir).
    pub cwd: Option<String>,

    /// Detach key sequence (default: `"ctrl-]"`).
    ///
    /// Uses Docker-style syntax: `"ctrl-<char>"` for control keys,
    /// comma-separated for multi-key sequences (e.g., `"ctrl-p,ctrl-q"`).
    pub detach_keys: Option<String>,

    /// Resource limits.
    pub rlimits: Vec<Rlimit>,
}

/// Builder for [`AttachConfig`].
pub struct AttachBuilder {
    config: AttachConfig,
}

/// Trait for types that can be converted to [`AttachConfig`].
///
/// Enables ergonomic calling patterns:
/// - `sandbox.attach(())` — default shell
/// - `sandbox.attach("bash")` — specific command
/// - `sandbox.attach(|a| a.cmd("zsh").env("TERM", "xterm"))` — closure
/// - `sandbox.attach(config)` — pre-built AttachConfig
pub trait IntoAttachConfig {
    /// Convert into attach configuration.
    fn into_attach_config(self) -> AttachConfig;
}

/// Parsed detach key sequence.
///
/// Matches raw stdin bytes against the configured detach sequence.
pub(crate) struct DetachKeys {
    /// The byte sequence that triggers detach.
    sequence: Vec<u8>,
}

/// Information about an active session (stub — deferred).
///
/// Session listing and reconnection require protocol extensions
/// (`core.sessions.list`, `core.session.attach`) that are not yet implemented.
pub struct SessionInfo {
    /// Unique session ID.
    pub id: String,

    /// Command being executed.
    pub cmd: String,

    /// When the session was started.
    pub started_at: chrono::DateTime<chrono::Utc>,

    /// Whether session has TTY.
    pub tty: bool,

    /// Process ID in guest.
    pub pid: Option<u32>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl AttachBuilder {
    /// Set the command to run.
    pub fn cmd(mut self, cmd: impl Into<String>) -> Self {
        self.config.cmd = Some(cmd.into());
        self
    }

    /// Add a single argument.
    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.config.args.push(arg.into());
        self
    }

    /// Add multiple arguments.
    pub fn args(mut self, args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.config.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Set the working directory.
    pub fn cwd(mut self, cwd: impl Into<String>) -> Self {
        self.config.cwd = Some(cwd.into());
        self
    }

    /// Add an environment variable.
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.config.env.push((key.into(), value.into()));
        self
    }

    /// Add multiple environment variables.
    pub fn envs(
        mut self,
        vars: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
    ) -> Self {
        self.config
            .env
            .extend(vars.into_iter().map(|(k, v)| (k.into(), v.into())));
        self
    }

    /// Set the detach key sequence.
    pub fn detach_keys(mut self, keys: impl Into<String>) -> Self {
        self.config.detach_keys = Some(keys.into());
        self
    }

    /// Set a resource limit (soft = hard).
    pub fn rlimit(mut self, resource: super::exec::RlimitResource, limit: u64) -> Self {
        self.config.rlimits.push(Rlimit {
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
        self.config.rlimits.push(Rlimit {
            resource,
            soft,
            hard,
        });
        self
    }

    /// Build the configuration.
    pub fn build(self) -> AttachConfig {
        self.config
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

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for AttachBuilder {
    fn default() -> Self {
        Self {
            config: AttachConfig::default(),
        }
    }
}

/// Unit type for default shell: `sandbox.attach(())`
impl IntoAttachConfig for () {
    fn into_attach_config(self) -> AttachConfig {
        AttachConfig::default()
    }
}

/// Closure pattern: `sandbox.attach(|a| a.cmd("zsh").env("TERM", "xterm"))`
impl<F> IntoAttachConfig for F
where
    F: FnOnce(AttachBuilder) -> AttachBuilder,
{
    fn into_attach_config(self) -> AttachConfig {
        self(AttachBuilder::default()).build()
    }
}

/// Direct config: `sandbox.attach(config)`
impl IntoAttachConfig for AttachConfig {
    fn into_attach_config(self) -> AttachConfig {
        self
    }
}

/// Simple string for command: `sandbox.attach("bash")`
impl IntoAttachConfig for &str {
    fn into_attach_config(self) -> AttachConfig {
        AttachConfig {
            cmd: Some(self.to_string()),
            ..Default::default()
        }
    }
}

/// String for command: `sandbox.attach(String::from("bash"))`
impl IntoAttachConfig for String {
    fn into_attach_config(self) -> AttachConfig {
        AttachConfig {
            cmd: Some(self),
            ..Default::default()
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_detach_keys_single_char() {
        let keys = DetachKeys::parse("q").unwrap();
        assert_eq!(keys.sequence(), &[b'q']);
    }

    #[test]
    fn test_detach_keys_invalid() {
        assert!(DetachKeys::parse("ctrl-").is_err());
        assert!(DetachKeys::parse("ctrl-ab").is_err());
    }
}
