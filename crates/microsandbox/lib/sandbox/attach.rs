//! Interactive attach types for terminal bridging with sandboxes.

use crate::MicrosandboxResult;

use super::exec::Rlimit;

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

/// Builder for [`AttachOptions`].
#[derive(Default)]
pub struct AttachOptionsBuilder {
    options: AttachOptions,
}

/// Trait for types that can be converted to an optional command string.
///
/// Enables ergonomic `cmd` patterns:
/// - `sandbox.attach((), ())` — default shell
/// - `sandbox.attach("bash", ())` — specific command
pub trait IntoAttachCmd {
    /// Convert into an optional command string.
    fn into_attach_cmd(self) -> Option<String>;
}

/// Trait for types that can be converted to [`AttachOptions`].
///
/// Enables ergonomic `opts` patterns:
/// - `sandbox.attach("bash", ())` — no options
/// - `sandbox.attach("zsh", |a| a.env("TERM", "xterm"))` — closure
/// - `sandbox.attach("bash", options)` — pre-built AttachOptions
pub trait IntoAttachOptions {
    /// Convert into attach options.
    fn into_attach_options(self) -> AttachOptions;
}

/// Parsed detach key sequence.
///
/// Matches raw stdin bytes against the configured detach sequence.
pub(crate) struct DetachKeys {
    /// The byte sequence that triggers detach.
    sequence: Vec<u8>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl AttachOptionsBuilder {
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

    /// Set an environment variable for the attached session. Merged on
    /// top of sandbox-level env vars.
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.options.env.push((key.into(), value.into()));
        self
    }

    /// Set multiple environment variables for the attached session.
    pub fn envs(
        mut self,
        vars: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
    ) -> Self {
        self.options
            .env
            .extend(vars.into_iter().map(|(k, v)| (k.into(), v.into())));
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
    pub fn build(self) -> AttachOptions {
        self.options
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

/// Unit type for default shell: `sandbox.attach((), ())`
impl IntoAttachCmd for () {
    fn into_attach_cmd(self) -> Option<String> {
        None
    }
}

/// String for specific command: `sandbox.attach("bash", ())`
impl IntoAttachCmd for &str {
    fn into_attach_cmd(self) -> Option<String> {
        Some(self.to_string())
    }
}

/// Owned string for specific command: `sandbox.attach(String::from("bash"), ())`
impl IntoAttachCmd for String {
    fn into_attach_cmd(self) -> Option<String> {
        Some(self)
    }
}

/// No options: `sandbox.attach("bash", ())`
impl IntoAttachOptions for () {
    fn into_attach_options(self) -> AttachOptions {
        AttachOptions::default()
    }
}

/// Closure pattern: `sandbox.attach("zsh", |a| a.env("TERM", "xterm"))`
impl<F> IntoAttachOptions for F
where
    F: FnOnce(AttachOptionsBuilder) -> AttachOptionsBuilder,
{
    fn into_attach_options(self) -> AttachOptions {
        self(AttachOptionsBuilder::default()).build()
    }
}

/// Direct options: `sandbox.attach("bash", options)`
impl IntoAttachOptions for AttachOptions {
    fn into_attach_options(self) -> AttachOptions {
        self
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
