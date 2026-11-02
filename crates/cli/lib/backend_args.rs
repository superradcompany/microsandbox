//! Invocation-scoped backend selection for the CLI.

use clap::Args;
use microsandbox::{BackendKind, config::BackendContext};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Explicit backend flags, available throughout the command hierarchy.
#[derive(Debug, Default, Clone, Copy, Args)]
pub struct BackendArgs {
    /// Use microsandbox cloud for this invocation.
    #[arg(long, global = true, conflicts_with = "local")]
    pub cloud: bool,

    /// Use the local runtime for this invocation.
    #[arg(long, global = true, conflicts_with = "cloud")]
    pub local: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl BackendArgs {
    /// Return the explicit selection, leaving ambient defaults alone when absent.
    pub fn selected_kind(self) -> Option<BackendKind> {
        if self.cloud {
            Some(BackendKind::Cloud)
        } else if self.local {
            Some(BackendKind::Local)
        } else {
            None
        }
    }

    /// Reject managed selection that would silently route an explicit flag elsewhere.
    /// Credential resolution and backend admission remain owned by the SDK resolver.
    pub fn validate_selection(self) -> anyhow::Result<()> {
        if let Some(requested) = self.selected_kind() {
            let context = BackendContext::load()?;
            if let Some(selected) = context.selected {
                self.validate_kind(selected.kind, requested)?;
            }
        }
        Ok(())
    }

    fn validate_kind(self, selected: BackendKind, requested: BackendKind) -> anyhow::Result<()> {
        anyhow::ensure!(
            selected == requested,
            "--{} conflicts with the managed active profile selecting {}; ask your administrator to change the managed profile",
            requested.as_str(),
            selected.as_str(),
        );
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_flags_reject_opposite_managed_selection() {
        for (flags, requested, other) in [
            (
                BackendArgs {
                    cloud: true,
                    local: false,
                },
                BackendKind::Cloud,
                BackendKind::Local,
            ),
            (
                BackendArgs {
                    cloud: false,
                    local: true,
                },
                BackendKind::Local,
                BackendKind::Cloud,
            ),
        ] {
            assert!(flags.validate_kind(requested, requested).is_ok());
            let error = flags
                .validate_kind(other, requested)
                .unwrap_err()
                .to_string();
            assert!(error.contains("managed active profile"));
            assert!(error.contains(&format!("--{}", requested.as_str())));
        }
    }
}
