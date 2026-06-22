//! Interactive attach types for terminal bridging with sandboxes.

use microsandbox_types::EnvVar;

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

//--------------------------------------------------------------------------------------------------
// Module: local (free fn impls called by LocalBackend's SandboxBackend impl)
//--------------------------------------------------------------------------------------------------

pub(crate) mod local {
    //! Local attach impl: bridges the host TTY to a PTY exec session in the
    //! named sandbox. Owns the host terminal's raw mode for the duration.

    use std::os::fd::AsRawFd;
    use std::sync::Arc;

    use microsandbox_protocol::{
        exec::{ExecExited, ExecResize, ExecStdin, ExecStdout},
        message::MessageType,
    };
    use tokio::io::{AsyncWriteExt, unix::AsyncFd};

    use crate::{
        MicrosandboxResult,
        backend::LocalBackend,
        sandbox::{
            AttachOptionsBuilder, SandboxConfig, build_exec_request,
            open_nonblocking_terminal_input, read_from_fd, terminal_path_for_fd,
        },
    };

    use super::DetachKeys;

    pub(crate) async fn attach(
        local: &LocalBackend,
        name: &str,
        config: &SandboxConfig,
        cmd: String,
        opts_builder: AttachOptionsBuilder,
    ) -> MicrosandboxResult<i32> {
        let opts = opts_builder.build()?;

        let client = Arc::new(super::super::fs::local::connect_agent(local, name).await?);

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
        let stdin_async = AsyncFd::new(tty_input)
            .map_err(|e| crate::MicrosandboxError::Terminal(format!("async tty input: {e}")))?;

        let mut stdout = tokio::io::stdout();
        let mut sigwinch =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
                .map_err(|e| crate::MicrosandboxError::Runtime(format!("sigwinch: {e}")))?;

        let mut exit_code: i32 = -1;
        let mut spawn_failure: Option<microsandbox_protocol::exec::ExecFailed> = None;
        let detach_seq = detach_keys.sequence();
        let mut match_pos = 0usize;

        loop {
            tokio::select! {
                result = stdin_async.readable() => {
                    let mut guard = match result {
                        Ok(g) => g,
                        Err(_) => break,
                    };

                    let mut input_buf = [0u8; 1024];
                    match guard.try_io(|inner| {
                        read_from_fd(inner.get_ref().as_raw_fd(), &mut input_buf)
                    }) {
                        Ok(Ok(0)) => break,
                        Ok(Ok(n)) => {
                            let data = &input_buf[..n];

                            let mut detached = false;
                            for &b in data {
                                if b == detach_seq[match_pos] {
                                    match_pos += 1;
                                    if match_pos == detach_seq.len() {
                                        detached = true;
                                        break;
                                    }
                                } else {
                                    match_pos = 0;
                                    if b == detach_seq[0] {
                                        match_pos = 1;
                                    }
                                }
                            }

                            if detached {
                                break;
                            }

                            let payload = ExecStdin { data: data.to_vec() };
                            let _ = client.send(id, MessageType::ExecStdin, &payload).await;
                        }
                        Ok(Err(e)) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Ok(Err(_)) => break,
                        Err(_would_block) => continue,
                    }
                }

                Some(msg) = rx.recv() => {
                    let mut should_break = false;

                    match msg.t {
                        MessageType::ExecStdout => {
                            if let Ok(out) = msg.payload::<ExecStdout>() {
                                let _ = stdout.write_all(&out.data).await;
                            }
                        }
                        MessageType::ExecExited => {
                            if let Ok(exited) = msg.payload::<ExecExited>() {
                                exit_code = exited.code;
                            }
                            should_break = true;
                        }
                        MessageType::ExecFailed => {
                            if let Ok(failed) =
                                msg.payload::<microsandbox_protocol::exec::ExecFailed>()
                            {
                                spawn_failure = Some(failed);
                            }
                            should_break = true;
                        }
                        _ => {}
                    }

                    if !should_break {
                        while let Ok(next) = rx.try_recv() {
                            match next.t {
                                MessageType::ExecStdout => {
                                    if let Ok(out) = next.payload::<ExecStdout>() {
                                        let _ = stdout.write_all(&out.data).await;
                                    }
                                }
                                MessageType::ExecExited => {
                                    if let Ok(exited) = next.payload::<ExecExited>() {
                                        exit_code = exited.code;
                                    }
                                    should_break = true;
                                    break;
                                }
                                MessageType::ExecFailed => {
                                    if let Ok(failed) = next
                                        .payload::<microsandbox_protocol::exec::ExecFailed>()
                                    {
                                        spawn_failure = Some(failed);
                                    }
                                    should_break = true;
                                    break;
                                }
                                _ => {}
                            }
                        }
                    }

                    let _ = stdout.flush().await;

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

        if let Some(failure) = spawn_failure {
            return Err(crate::MicrosandboxError::ExecFailed(failure));
        }
        Ok(exit_code)
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
}
