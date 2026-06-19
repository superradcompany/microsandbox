//! Guest init-handoff types for the sandbox boot path.
//!
//! When [`HandoffInit`] is set on a [`super::SandboxConfig`], agentd
//! finishes its setup, forks, and the parent execve's into the
//! configured init binary — typically `systemd`, but any init works.
//! agentd continues as a normal process, serving host requests over
//! virtio-serial.
//!
//! Users construct this via the builder methods on
//! [`super::SandboxBuilder`]:
//!
//! ```ignore
//! Sandbox::builder("dev")
//!     .image("debian:bookworm")
//!     .init("/lib/systemd/systemd")
//!     .build().await?;
//!
//! Sandbox::builder("dev")
//!     .image("debian:bookworm")
//!     .init_with("/lib/systemd/systemd", |i| {
//!         i.args(["--unit=multi-user.target"])
//!          .env("container", "microsandbox")
//!     })
//!     .build().await?;
//! ```

use std::path::Path;

use microsandbox_protocol::HANDOFF_INIT_AUTO;

use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Builder for the `args` + `env` portion of [`HandoffInit`].
///
/// The cmd is supplied positionally to
/// [`super::SandboxBuilder::init_with`], not stored in this builder —
/// matching how [`super::ExecOptionsBuilder`] omits the command name.
#[derive(Default)]
pub struct InitOptionsBuilder {
    args: Vec<String>,
    env: Vec<(String, String)>,
}

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use microsandbox_types::HandoffInit;

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl InitOptionsBuilder {
    /// Append a single argv entry.
    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Append multiple argv entries.
    pub fn args(mut self, args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Set an env var for the init process. Repeatable; later entries
    /// with the same key shadow earlier ones inside the guest.
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    /// Set multiple env vars at once.
    pub fn envs(
        mut self,
        vars: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
    ) -> Self {
        self.env
            .extend(vars.into_iter().map(|(k, v)| (k.into(), v.into())));
        self
    }

    /// Finalise into `(args, env)`. Called by the SandboxBuilder shim.
    pub(crate) fn build(self) -> (Vec<String>, Vec<(String, String)>) {
        (self.args, self.env)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Validation
//--------------------------------------------------------------------------------------------------

/// Validate a populated [`HandoffInit`] before it's persisted into
/// [`super::SandboxConfig`] or serialised onto MSB_HANDOFF_INIT* env
/// vars.
///
/// Constraints (each violation produces an `InvalidConfig` error):
/// - `cmd` must be valid UTF-8 (the host→guest transport is
///   `String`-only and `PathBuf` JSON serde drops non-UTF-8 bytes).
/// - `cmd` must be either an absolute path or the literal sentinel
///   [`HANDOFF_INIT_AUTO`] (which agentd resolves at boot time).
/// - `cmd` must not contain a NUL byte (CString incompatibility).
/// - Each argv entry must be free of `\0` (CString terminator).
/// - Each env key must be non-empty and free of `=` and `\0`
///   (POSIX disallows `=` in keys).
/// - Each env value must be free of `\0`.
pub(crate) fn validate(spec: &HandoffInit) -> MicrosandboxResult<()> {
    validate_cmd(&spec.cmd)?;
    for (i, arg) in spec.args.iter().enumerate() {
        validate_arg(i, arg)?;
    }
    for (k, v) in &spec.env {
        validate_env_pair(k, v)?;
    }
    Ok(())
}

fn validate_cmd(cmd: &Path) -> MicrosandboxResult<()> {
    let s = cmd.to_str().ok_or_else(|| {
        MicrosandboxError::InvalidConfig(format!(
            "init cmd path must be valid UTF-8: {}",
            cmd.display()
        ))
    })?;
    if s.contains('\0') {
        return Err(MicrosandboxError::InvalidConfig(format!(
            "init cmd path must not contain a NUL byte: {s:?}"
        )));
    }
    // The sentinel `auto` is resolved guest-side; everything else must
    // be an absolute path so the eventual `execve` knows where to look.
    if s != HANDOFF_INIT_AUTO && !cmd.is_absolute() {
        return Err(MicrosandboxError::InvalidConfig(format!(
            "init cmd must be an absolute path or `{HANDOFF_INIT_AUTO}`, got: {s:?}"
        )));
    }
    Ok(())
}

fn validate_arg(index: usize, arg: &str) -> MicrosandboxResult<()> {
    if arg.contains('\0') {
        return Err(MicrosandboxError::InvalidConfig(format!(
            "init arg #{index} must not contain a NUL byte"
        )));
    }
    Ok(())
}

fn validate_env_pair(key: &str, value: &str) -> MicrosandboxResult<()> {
    if key.is_empty() {
        return Err(MicrosandboxError::InvalidConfig(
            "init env key must not be empty".into(),
        ));
    }
    if key.contains('=') {
        return Err(MicrosandboxError::InvalidConfig(format!(
            "init env key {key:?} must not contain '='"
        )));
    }
    if key.contains('\0') {
        return Err(MicrosandboxError::InvalidConfig(format!(
            "init env key {key:?} must not contain NUL"
        )));
    }
    if value.contains('\0') {
        return Err(MicrosandboxError::InvalidConfig(format!(
            "init env value for {key:?} must not contain NUL"
        )));
    }
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn ok(cmd: &str, args: &[&str], env: &[(&str, &str)]) -> HandoffInit {
        HandoffInit {
            cmd: PathBuf::from(cmd),
            args: args.iter().map(|s| s.to_string()).collect(),
            env: env
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    #[test]
    fn validate_accepts_well_formed() {
        let spec = ok(
            "/lib/systemd/systemd",
            &["--unit=multi-user.target"],
            &[("LANG", "C.UTF-8"), ("PATH", "/usr/bin:/bin")],
        );
        assert!(validate(&spec).is_ok());
    }

    #[test]
    fn validate_accepts_unit_separator_in_arg() {
        let spec = ok("/sbin/init", &["foo\x1fbar"], &[]);
        assert!(validate(&spec).is_ok());
    }

    #[test]
    fn validate_rejects_equals_in_env_key() {
        let spec = ok("/sbin/init", &[], &[("BAD=KEY", "value")]);
        let err = validate(&spec).unwrap_err();
        assert!(format!("{err}").contains("must not contain '='"));
    }

    #[test]
    fn validate_rejects_empty_env_key() {
        let spec = ok("/sbin/init", &[], &[("", "value")]);
        let err = validate(&spec).unwrap_err();
        assert!(format!("{err}").contains("must not be empty"));
    }

    #[test]
    fn validate_accepts_unit_separator_in_env_value() {
        let spec = ok("/sbin/init", &[], &[("KEY", "v\x1fbad")]);
        assert!(validate(&spec).is_ok());
    }

    #[test]
    fn validate_rejects_nul_in_arg() {
        let spec = ok("/sbin/init", &["foo\0bar"], &[]);
        let err = validate(&spec).unwrap_err();
        assert!(format!("{err}").contains("NUL"));
    }

    #[test]
    fn validate_accepts_auto_sentinel() {
        let spec = ok("auto", &[], &[]);
        assert!(validate(&spec).is_ok());
    }

    #[test]
    fn validate_rejects_relative_cmd_path() {
        let spec = ok("sbin/init", &[], &[]);
        let err = validate(&spec).unwrap_err();
        assert!(format!("{err}").contains("absolute path or `auto`"));
    }

    #[cfg(unix)]
    #[test]
    fn validate_rejects_non_utf8_cmd() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let mut spec = ok("/sbin/init", &[], &[]);
        spec.cmd = PathBuf::from(OsStr::from_bytes(b"/\xff/init"));
        let err = validate(&spec).unwrap_err();
        assert!(format!("{err}").contains("valid UTF-8"));
    }
}
