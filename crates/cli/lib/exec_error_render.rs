//! Render `ExecFailed` payloads as styled error blocks.
//!
//! Mirrors `boot_error_render` for spawn-time exec failures. The
//! runtime's relay produces a typed `ExecFailed` (see
//! `crates/protocol/lib/exec.rs`) whenever a user-program spawn
//! fails inside the guest — binary not found, permission denied,
//! bad cwd, etc. The CLI walks its `anyhow::Error::chain()` for
//! `MicrosandboxError::ExecFailed`, reaches this module, and emits
//! the bold-red `error:` block per `design/cli/output-style.md`.
//!
//! The on-disk `ExecFailed` schema carries `kind`, `errno`,
//! `errno_name`, `message`, and optional `stage`. Stage and errno
//! aren't repeated in the rendered output (the message + kind are
//! enough for users); they're available via the SDK / `--json` if
//! anyone needs them programmatically.

use microsandbox_protocol::exec::{ExecFailed, ExecFailureKind};

use crate::ui::{self, ErrorLine};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Render an `ExecFailed` payload for a named command.
///
/// `cmd` is the command the user attempted to run (used in the
/// header). The rendering follows the boot-error pattern:
/// `error:` header in bold red, white cause line tagged with the
/// stage, then dim-cyan hint lines.
pub fn render(cmd: &str, err: &ExecFailed) {
    let header = format!("failed to exec {:?}", cmd);
    let stage_label = stage_label(err.kind);

    let cause = match err.errno_name.as_deref() {
        Some(name) => format!("{stage_label}: {} ({name})", err.message),
        None => match err.errno {
            Some(no) => format!("{stage_label}: {} (errno {no})", err.message),
            None => format!("{stage_label}: {}", err.message),
        },
    };

    let hint = stage_hint(cmd, err);

    let mut lines: Vec<ErrorLine<'_>> = Vec::with_capacity(2);
    lines.push(ErrorLine::Cause(&cause));
    if let Some(ref h) = hint {
        lines.push(ErrorLine::Hint(h));
    }

    ui::error_with_lines(&header, &lines);
}

/// Map a kind to the cause-line prefix.
fn stage_label(kind: ExecFailureKind) -> &'static str {
    match kind {
        ExecFailureKind::NotFound => "not found",
        ExecFailureKind::PermissionDenied => "permission denied",
        ExecFailureKind::NotExecutable => "not executable",
        ExecFailureKind::BadCwd => "bad cwd",
        ExecFailureKind::BadArgs => "bad args",
        ExecFailureKind::ResourceLimit => "resource limit",
        ExecFailureKind::UserSetupFailed => "user setup",
        ExecFailureKind::OutOfMemory => "out of memory",
        ExecFailureKind::PtySetupFailed => "pty setup",
        ExecFailureKind::Other => "exec",
    }
}

/// Map `(kind, cmd)` to a single actionable hint, when one exists.
fn stage_hint(cmd: &str, err: &ExecFailed) -> Option<String> {
    match err.kind {
        ExecFailureKind::NotFound => Some(format!(
            "is `{cmd}` on PATH inside the sandbox? Try `msb exec ... -- which {cmd}`"
        )),
        ExecFailureKind::PermissionDenied => Some(format!(
            "check the binary's permissions — `chmod +x {cmd}` may be needed"
        )),
        ExecFailureKind::NotExecutable => Some(
            "the file isn't a runnable program — wrong architecture, missing shebang \
             interpreter, or corrupted ELF"
                .into(),
        ),
        ExecFailureKind::BadCwd => Some(
            "the working directory doesn't exist or isn't accessible — \
             create it inside the sandbox first"
                .into(),
        ),
        ExecFailureKind::BadArgs => Some(
            "argument list is invalid: too long (E2BIG), too many symlinks, \
             or contains null bytes"
                .into(),
        ),
        ExecFailureKind::ResourceLimit => Some(
            "the sandbox hit a resource limit (fd table, process count). \
             Raise `--rlimit` or stop other processes"
                .into(),
        ),
        ExecFailureKind::UserSetupFailed => Some(
            "the requested user/group could not be applied — check that the user \
             exists in the sandbox's `/etc/passwd`"
                .into(),
        ),
        ExecFailureKind::OutOfMemory => {
            Some("the sandbox is memory-constrained — try a larger `--memory`".into())
        }
        ExecFailureKind::PtySetupFailed => {
            Some("pty allocation failed; try `--no-tty` or pipe stdin (`< /dev/null`)".into())
        }
        ExecFailureKind::Other => None,
    }
}

/// POSIX-style exit code to use when a command fails to spawn.
///
/// `127` for "command not found", `126` for "found but not
/// executable", `1` otherwise. Matches shell convention so scripts
/// that branch on the exit code keep working.
pub fn exit_code_for(kind: ExecFailureKind) -> i32 {
    match kind {
        ExecFailureKind::NotFound => 127,
        ExecFailureKind::PermissionDenied | ExecFailureKind::NotExecutable => 126,
        _ => 1,
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn err(kind: ExecFailureKind) -> ExecFailed {
        ExecFailed {
            kind,
            errno: Some(2),
            errno_name: Some("ENOENT".into()),
            message: "x".into(),
            stage: None,
        }
    }

    #[test]
    fn exit_codes() {
        assert_eq!(exit_code_for(ExecFailureKind::NotFound), 127);
        assert_eq!(exit_code_for(ExecFailureKind::PermissionDenied), 126);
        assert_eq!(exit_code_for(ExecFailureKind::NotExecutable), 126);
        assert_eq!(exit_code_for(ExecFailureKind::Other), 1);
        assert_eq!(exit_code_for(ExecFailureKind::OutOfMemory), 1);
    }

    #[test]
    fn every_kind_has_a_label() {
        for kind in [
            ExecFailureKind::NotFound,
            ExecFailureKind::PermissionDenied,
            ExecFailureKind::NotExecutable,
            ExecFailureKind::BadCwd,
            ExecFailureKind::BadArgs,
            ExecFailureKind::ResourceLimit,
            ExecFailureKind::UserSetupFailed,
            ExecFailureKind::OutOfMemory,
            ExecFailureKind::PtySetupFailed,
            ExecFailureKind::Other,
        ] {
            let label = stage_label(kind);
            assert!(!label.is_empty(), "label missing for {kind:?}");
        }
    }

    #[test]
    fn other_kind_has_no_hint() {
        assert!(stage_hint("foo", &err(ExecFailureKind::Other)).is_none());
    }

    #[test]
    fn not_found_hint_mentions_path() {
        let h = stage_hint("nonexistent", &err(ExecFailureKind::NotFound)).unwrap();
        assert!(h.contains("PATH"));
        assert!(h.contains("nonexistent"));
    }
}
