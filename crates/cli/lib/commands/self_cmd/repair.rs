//! Guided repair of selected local sandboxes, with explicit consent for each blocking VM.

use std::io::{self, IsTerminal};

use anyhow::Context;
use clap::Args;
use microsandbox::sandbox::{Sandbox, StorageRecovery, StorageRecoveryOptions};
use microsandbox::setup::{
    self, StorageDiagnosticReason, StorageDiagnosticStatus, StorageSelection,
};

use super::storage_doctor::{StorageDoctorExit, terminal_text, write_diagnosis};
use crate::ui::OutputFormat;

mod interactive;
mod report;
mod terminal;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Repair selected local sandboxes, retaining the original disk files.
#[derive(Debug, Args)]
pub struct RepairArgs {
    /// Sandbox to repair. In a terminal, omit to select multiple sandboxes.
    #[arg(
        long,
        value_name = "SANDBOX",
        group = "repair_target",
        conflicts_with = "name"
    )]
    pub sandbox: Option<String>,

    /// Positional sandbox name retained for existing scripts.
    #[arg(
        value_name = "SANDBOX",
        hide = true,
        group = "repair_target",
        conflicts_with = "sandbox"
    )]
    pub name: Option<String>,

    /// Print a machine-readable result without interactive prompts.
    #[arg(long, value_enum, requires = "repair_target")]
    pub format: Option<OutputFormat>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RepairArgs {
    fn normalize_target(mut self) -> Self {
        // Normalize before choosing interactive or scripted execution. Both spellings
        // must select the same sandbox and retain the same automation requirements.
        self.name = self.sandbox.take().or(self.name);
        self
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) async fn run(args: RepairArgs) -> anyhow::Result<()> {
    let args = args.normalize_target();
    // JSON and redirected input never supply consent. The terminal flow asks for
    // required shutdown and macOS maintenance confirmations before repairing storage.
    if args.format != Some(OutputFormat::Json)
        && io::stdin().is_terminal()
        && io::stdout().is_terminal()
        && io::stderr().is_terminal()
    {
        return interactive::run(args).await;
    }
    run_scripted(args).await
}

async fn run_scripted(args: RepairArgs) -> anyhow::Result<()> {
    let json = args.format == Some(OutputFormat::Json);
    let name = args
        .name
        .context("provide a sandbox name: msb self repair --sandbox SANDBOX")?;

    // Keep the read-only inventory ahead of backend initialization. A stopped row can
    // precede actual process teardown; the SDK takes locks and checks again before capture.
    let report = setup::diagnose_storage(
        Default::default(),
        StorageSelection::Named(vec![name.clone()]),
    )
    .await?;
    let item = report
        .sandboxes
        .into_iter()
        .next()
        .context("sandbox inspection returned no result")?;
    if item.status == StorageDiagnosticStatus::Ready {
        if json {
            // A no-op removes no originals and returns the same success shape as an import.
            return done(
                StorageRecovery {
                    name,
                    ready: true,
                    originals_retained: true,
                },
                true,
            );
        }
        println!("Storage for '{}' is already ready.", terminal_text(&name));
        return Ok(());
    }
    if item.reason == Some(StorageDiagnosticReason::IncompleteCreation) {
        return blocked(
            &item,
            2,
            json,
            "Finish or recover the interrupted creation before repairing its disks.",
        );
    }
    // A running Windows VM may deny read-only disk opens. Report its verified blocker
    // without attempting a shutdown; only interactive repair can request stop consent.
    if item.status == StorageDiagnosticStatus::Unavailable
        && !(item.running && item.reason == Some(StorageDiagnosticReason::StorageUnavailable))
    {
        return blocked(&item, 3, json, "Repair needs a complete diagnosis.");
    }
    let blockers = setup::storage_repair_blockers(Default::default(), &name).await?;
    if let Some(blocker) = blockers.first() {
        return blocked(
            &item,
            2,
            json,
            &format!(
                "Run 'msb stop {}', then 'msb self repair --sandbox {}'.",
                terminal_text(&blocker.name),
                terminal_text(&name)
            ),
        );
    }
    if item.status == StorageDiagnosticStatus::Unavailable {
        return blocked(&item, 3, json, "Repair needs a complete diagnosis.");
    }
    if item.running {
        return blocked(
            &item,
            2,
            json,
            "Wait for the sandbox to finish stopping, then run repair again.",
        );
    }
    if item.status == StorageDiagnosticStatus::RecoveryRequired {
        return blocked(
            &item,
            2,
            json,
            "Storage needs investigation. Run repair in an interactive terminal without --format json to review a diagnostic report.",
        );
    }
    if cfg!(target_os = "macos") {
        // Never infer cross-home writer safety from this home's inventory or redirected
        // input. The interactive path is the only CLI source of maintenance consent.
        return blocked(
            &item,
            2,
            json,
            "macOS legacy repair requires interactive maintenance confirmation. Run repair in an interactive terminal without --format json after stopping legacy VMs across all homes and excluding new writers until repair finishes.",
        );
    }

    let result = Sandbox::recover_storage(&name, StorageRecoveryOptions::default()).await?;
    done(result, json)
}

fn done(result: StorageRecovery, json: bool) -> anyhow::Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("Storage for '{}' is ready.", terminal_text(&result.name));
    }
    Ok(())
}

fn blocked(
    item: &setup::StorageSandboxDiagnosis,
    code: i32,
    json: bool,
    action: &str,
) -> anyhow::Result<()> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(
                &serde_json::json!({"sandbox": item, "next_step": action})
            )?
        );
    } else {
        write_diagnosis(&mut io::stderr().lock(), item, false)?;
        eprintln!("{action}");
    }
    Err(StorageDoctorExit { code }.into())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Command {
        #[command(flatten)]
        args: RepairArgs,
    }

    #[test]
    fn automation_requires_a_target() {
        for args in [
            vec!["repair"],
            vec!["repair", "api"],
            vec!["repair", "--sandbox", "api"],
            vec!["repair", "api", "--format", "json"],
            vec!["repair", "--sandbox", "api", "--format", "json"],
        ] {
            Command::try_parse_from(args).unwrap();
        }
        for args in [
            vec!["repair", "--format", "json"],
            vec!["repair", "--sandbox"],
            vec!["repair", "--sandbox", "api", "api"],
            vec!["repair", "api", "--sandbox", "other"],
            vec!["repair", "--sandbox", "api", "--sandbox", "api"],
            vec!["repair", "--sandbox", "api", "--all"],
        ] {
            assert!(Command::try_parse_from(args).is_err());
        }
    }

    #[test]
    fn removed_selection_and_confirmation_flags_are_rejected() {
        for target in [vec!["api"], vec!["--sandbox", "api"]] {
            for flag in [
                "--select=root=view-a",
                "--accept-selected-view",
                "--legacy-writers-stopped",
            ] {
                let mut arguments = vec!["repair"];
                arguments.extend_from_slice(&target);
                arguments.push(flag);
                let error = Command::try_parse_from(arguments).err().unwrap();
                assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
            }
        }
    }

    #[test]
    fn sandbox_flag_and_positional_target_use_the_same_repair_path() {
        for target in [vec!["api"], vec!["--sandbox", "api"]] {
            let mut arguments = vec!["repair"];
            arguments.extend(target);
            arguments.extend(["--format", "json"]);
            let args = Command::try_parse_from(arguments)
                .unwrap()
                .args
                .normalize_target();

            assert_eq!(args.name.as_deref(), Some("api"));
            assert!(args.sandbox.is_none());
            assert_eq!(args.format, Some(OutputFormat::Json));
        }

        let args = Command::try_parse_from(["repair"])
            .unwrap()
            .args
            .normalize_target();
        assert!(args.name.is_none(), "bare repair must retain the picker");
    }
}
