//! Explicit recovery of a stopped sandbox's protected storage.

use clap::Args;
use microsandbox::sandbox::{Sandbox, StorageRecoveryOptions, StorageRecoverySelection};

use crate::ui::OutputFormat;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Import or resume stopped sandbox storage without booting a VM.
#[derive(Debug, Args)]
pub struct RecoverStorageArgs {
    /// Sandbox to recover. Inspect it first with `doctor --storage --sandbox NAME`.
    pub name: String,

    /// Select a complete disk view reported by doctor. Repeat for each ambiguous disk.
    #[arg(long, value_name = "DISK_ID=CANDIDATE_ID", value_parser = selection, requires = "accept_selected_view")]
    pub select: Vec<StorageRecoverySelection>,

    /// Acknowledge that the selected view may omit later writes. Originals remain retained.
    #[arg(long, requires = "select")]
    pub accept_selected_view: bool,

    /// macOS: confirm legacy VMs in every home are stopped and prevent new writers until done.
    #[arg(long)]
    pub legacy_writers_stopped: bool,

    /// Output a structured report (json).
    #[arg(long, value_name = "FORMAT", value_enum)]
    pub format: Option<OutputFormat>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Recover only the requested sandbox; related running writers are reported, never stopped.
pub async fn run(args: RecoverStorageArgs) -> anyhow::Result<()> {
    let result = Sandbox::recover_storage(
        &args.name,
        StorageRecoveryOptions {
            selections: args.select,
            accept_selected_view: args.accept_selected_view,
            legacy_writers_stopped: args.legacy_writers_stopped,
        },
    )
    .await?;
    if args.format == Some(OutputFormat::Json) {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!(
            "Storage for '{}' is ready. Original legacy files are retained. Start the sandbox and verify its data before arranging cleanup.",
            result.name
        );
    }
    Ok(())
}

fn selection(value: &str) -> Result<StorageRecoverySelection, String> {
    let (disk_id, candidate_id) = value
        .split_once('=')
        .ok_or("use DISK_ID=CANDIDATE_ID from storage inspection")?;
    if disk_id.is_empty() || candidate_id.is_empty() || value.len() > 512 {
        return Err("use bounded, non-empty disk and candidate IDs from storage inspection".into());
    }
    Ok(StorageRecoverySelection {
        disk_id: disk_id.into(),
        candidate_id: candidate_id.into(),
    })
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Parser)]
    struct Command {
        #[command(flatten)]
        args: RecoverStorageArgs,
    }

    #[test]
    fn explicit_view_selection_requires_acknowledgement() {
        assert!(Command::try_parse_from(["recover-storage", "app"]).is_ok());
        assert!(
            Command::try_parse_from(["recover-storage", "app", "--select", "root=candidate"])
                .is_err()
        );
        assert!(
            Command::try_parse_from(["recover-storage", "app", "--accept-selected-view"]).is_err()
        );
        let parsed = Command::try_parse_from([
            "recover-storage",
            "app",
            "--select",
            "root=candidate",
            "--accept-selected-view",
        ])
        .unwrap();
        assert_eq!(parsed.args.select[0].disk_id, "root");
        for invalid in ["candidate", "=candidate", "root="] {
            assert!(selection(invalid).is_err());
        }
    }

    #[test]
    fn maintenance_confirmation_is_explicit_and_independent_of_view_selection() {
        let default = Command::try_parse_from(["recover-storage", "app"]).unwrap();
        assert!(!default.args.legacy_writers_stopped);
        let maintenance =
            Command::try_parse_from(["recover-storage", "app", "--legacy-writers-stopped"])
                .unwrap();
        assert!(maintenance.args.legacy_writers_stopped);
        assert!(!maintenance.args.accept_selected_view);
        assert!(maintenance.args.select.is_empty());
    }
}
