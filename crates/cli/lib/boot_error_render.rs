//! Render structured boot-stage failure records as styled error blocks.
//!
//! The runtime writes a `boot-error.json` next to the sandbox's logs
//! whenever the sandbox process dies before the agent relay becomes
//! available (see `microsandbox_runtime::boot_error`). The CLI reads
//! that record via `MicrosandboxError::BootStart` and renders it here,
//! following `design/cli/output-style.md` Error Messages: a bold-red
//! `error:` header, a white cause line tagged with the stage, and any
//! number of dim-cyan hint lines mapped from the stage + errno.

use microsandbox_protocol::core::InitFailureReason;
use microsandbox_runtime::boot_error::{BootError, BootErrorStage};

use crate::ui::{self, ErrorLine};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Render a boot-error record for a named sandbox.
///
/// Output layout:
/// ```text
/// error: failed to start "<name>"
///   → <stage>: <message>
///   → <hint, if any>
///   → run `msb logs --source system <name>` for full diagnostics
/// ```
pub fn render(name: &str, err: &BootError) {
    let header = format!("failed to start {:?}", name);
    let stage = stage_label(err.stage);
    let cause = format!("{}: {}", stage, err.message);

    let hint_text = stage_hint(err);
    let log_pointer = format!("run `msb logs --source system {name}` for full diagnostics");

    let mut lines: Vec<ErrorLine<'_>> = Vec::with_capacity(3);
    lines.push(ErrorLine::Cause(&cause));
    if let Some(ref h) = hint_text {
        lines.push(ErrorLine::Hint(h));
    }
    lines.push(ErrorLine::Hint(&log_pointer));

    ui::error_with_lines(&header, &lines);
}

/// Lowercase short label for the stage, used as the cause-line prefix.
fn stage_label(stage: BootErrorStage) -> &'static str {
    match stage {
        BootErrorStage::Mount => "mount",
        BootErrorStage::BuildVm => "build_vm",
        BootErrorStage::Config => "config",
        BootErrorStage::Network => "network",
        BootErrorStage::Image => "image",
        BootErrorStage::Other => "other",
    }
}

/// Map a typed guest failure or stage and errno to an actionable hint
/// when one is known. Returns `None` if no specific hint applies — the
/// `error_with_lines` rendering will then show only the cause line and
/// the always-on log pointer.
fn stage_hint(err: &BootError) -> Option<String> {
    match (err.reason, err.stage, err.errno) {
        (Some(InitFailureReason::UserNotFound), _, _) => Some(
            "user selects an existing account; remove the user \
            override to use the image default, or create that account \
            in the image"
                .into(),
        ),
        (Some(InitFailureReason::GroupNotFound), _, _) => Some(
            "the requested group must exist in the image; correct the group \
            override or create that group in the image"
                .into(),
        ),

        // Mount + ENOENT → host path doesn't exist.
        (_, BootErrorStage::Mount, Some(2)) => Some(extract_mount_hint(&err.message)),

        // Mount + EACCES → permissions on host path.
        (_, BootErrorStage::Mount, Some(13)) => {
            Some("the host path is not readable by msb (check permissions)".into())
        }

        // Image + ENOENT → image not pulled / rootfs missing.
        (_, BootErrorStage::Image, Some(2)) => {
            Some("rootfs not found — try `msb pull <image>` first".into())
        }

        // Network + EADDRINUSE → port collision.
        (_, BootErrorStage::Network, Some(48)) | (_, BootErrorStage::Network, Some(98)) => Some(
            "a port is already bound — try a different host port or stop the other process".into(),
        ),

        _ => None,
    }
}

/// For mount ENOENT, try to extract the host path from the message so
/// the hint can name it explicitly. The runtime emits messages of the
/// form `mount <tag>: No such file or directory (os error 2)` — the
/// tag does not contain the host path, so we emit a generic hint when
/// we cannot recover one.
fn extract_mount_hint(_message: &str) -> String {
    // Future: parse the host path from the volume spec at higher levels
    // and pass it through. For now, a clear generic message is enough.
    "the host path for one of the mounts does not exist".into()
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_hints_use_typed_reasons_not_diagnostic_wording() {
        for (reason, expected_hint) in [
            (
                serde_json::json!("user_not_found"),
                Some("user selects an existing account"),
            ),
            (
                serde_json::json!("group_not_found"),
                Some("the requested group must exist"),
            ),
            (serde_json::json!("a_future_reason"), None),
            (serde_json::Value::Null, None),
        ] {
            for message in [
                "new diagnostic wording",
                "guest initialization failed: guest user not found: iggy",
            ] {
                let mut record = serde_json::json!({
                    "t": "2026-10-02T00:00:00Z",
                    "stage": "other",
                    "errno": null,
                    "message": message,
                });
                if !reason.is_null() {
                    record["reason"] = reason.clone();
                }
                let error: BootError = serde_json::from_value(record).unwrap();
                let hint = stage_hint(&error);
                match expected_hint {
                    Some(expected) => assert!(hint.unwrap().starts_with(expected)),
                    None => assert!(hint.is_none()),
                }
            }
        }
    }

    #[test]
    fn mount_enoent_has_hint() {
        let err = BootError {
            t: "2026-04-30T20:32:59.690Z".into(),
            stage: BootErrorStage::Mount,
            reason: None,
            errno: Some(2),
            message: "mount foo: No such file or directory (os error 2)".into(),
        };
        assert!(stage_hint(&err).is_some());
    }

    #[test]
    fn other_with_no_errno_has_no_hint() {
        let err = BootError {
            t: "2026-04-30T20:32:59.690Z".into(),
            stage: BootErrorStage::Other,
            reason: None,
            errno: None,
            message: "weird".into(),
        };
        assert!(stage_hint(&err).is_none());
    }

    #[test]
    fn network_eaddrinuse_macos_and_linux() {
        let err = BootError {
            t: "x".into(),
            stage: BootErrorStage::Network,
            reason: None,
            errno: Some(48), // macOS EADDRINUSE
            message: "bind: in use".into(),
        };
        assert!(stage_hint(&err).is_some());

        let err2 = BootError {
            t: "x".into(),
            stage: BootErrorStage::Network,
            reason: None,
            errno: Some(98), // linux EADDRINUSE
            message: "bind: in use".into(),
        };
        assert!(stage_hint(&err2).is_some());
    }
}
