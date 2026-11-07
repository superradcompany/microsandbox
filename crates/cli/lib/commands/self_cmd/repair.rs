//! Guided repair of selected local sandboxes, with explicit consent for each blocking VM.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, BufRead, IsTerminal, Read, Write};

use anyhow::{Context, ensure};
use clap::Args;
use microsandbox::sandbox::{
    Sandbox, StorageRecovery, StorageRecoveryOptions, StorageRecoverySelection,
};
use microsandbox::setup::{
    self, StorageDiagnosticReason, StorageDiagnosticStatus, StorageSelection,
};
use microsandbox_runtime::checkpoint::migration::CandidateSummary;

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
    #[arg(value_name = "SANDBOX")]
    pub name: Option<String>,

    /// For automation, select one diagnosed view per disk.
    #[arg(long, value_name = "DISK_ID=CANDIDATE_ID", value_parser = selection, requires_all = ["name", "accept_selected_view"])]
    pub select: Vec<StorageRecoverySelection>,

    /// Accept that these exact disk views may omit later writes.
    #[arg(long, requires = "select")]
    pub accept_selected_view: bool,

    /// On macOS, attest that legacy VMs across all homes are stopped and new writers are excluded.
    #[arg(long, requires = "name")]
    pub legacy_writers_stopped: bool,

    /// Print a machine-readable result without interactive prompts.
    #[arg(long, value_enum, requires = "name")]
    pub format: Option<OutputFormat>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) async fn run(args: RepairArgs) -> anyhow::Result<()> {
    // Keep the existing machine interface and explicit selections stable. The normal
    // terminal flow repairs the validated active state and reports unresolved layouts.
    if args.format != Some(OutputFormat::Json)
        && args.select.is_empty()
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
    let interactive = !json
        && io::stdin().is_terminal()
        && io::stdout().is_terminal()
        && io::stderr().is_terminal();
    let name = args
        .name
        .context("provide a sandbox name: msb self repair SANDBOX")?;

    // Keep the read-only inventory ahead of backend initialization or any stop request.
    // A stopped row can precede actual process teardown; the SDK takes locks and checks again.
    let item = loop {
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
            ensure!(
                args.select.is_empty(),
                "sandbox storage is already ready; an applied view cannot be replaced"
            );
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
        // A running Windows VM may deny even read-only disk opens. Its observed run can
        // still authorize a graceful stop, after which inspection is repeated. Malformed
        // configuration or an incomplete creation never justifies stopping a peer.
        if item.status == StorageDiagnosticStatus::Unavailable
            && !(item.running && item.reason == Some(StorageDiagnosticReason::StorageUnavailable))
        {
            return blocked(&item, 3, json, "Repair needs a complete diagnosis.");
        }
        let blockers = setup::storage_repair_blockers(Default::default(), &name).await?;
        if let Some(blocker) = blockers.first() {
            let explanation = format!(
                "Run 'msb stop {}', then 'msb self repair {}'.",
                terminal_text(&blocker.name),
                terminal_text(&name)
            );
            if !interactive {
                return blocked(&item, 2, json, &explanation);
            }
            let names = blockers
                .iter()
                .map(|entry| terminal_text(&entry.name))
                .collect::<Vec<_>>()
                .join(", ");
            println!("Repair requires these sandboxes to stop: {names}.");
            println!(
                "Stopping a VM can upgrade this home's catalog. Older tools may then refuse to open it."
            );
            if !confirm(&format!(
                "Stop '{}' gracefully?",
                terminal_text(&blocker.name)
            ))? {
                return cancelled();
            }
            // The SDK verifies this observed sandbox and run. Never signal a reported PID.
            Sandbox::stop_storage_repair_blocker(blocker).await?;
            continue;
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
            let Some(inspection) = item
                .inspection
                .as_ref()
                .filter(|report| !report.candidates.is_empty())
            else {
                return blocked(
                    &item,
                    2,
                    json,
                    "Resolve the reported storage problem, then run repair again.",
                );
            };
            // The combined preview has a resource bound. Previously identified explicit
            // choices can still be independently validated as a smaller selected group.
            if !inspection.can_preview() && args.select.is_empty() {
                return blocked(
                    &item,
                    2,
                    json,
                    "These disk views cannot be previewed together. Preserve the originals; only supply --select if you have independently identified the views to recover.",
                );
            }
        }
        break item;
    };
    let needs_choice = item.status == StorageDiagnosticStatus::RecoveryRequired;
    if !needs_choice && !args.select.is_empty() {
        return blocked(
            &item,
            2,
            json,
            "These selections do not apply to this repair. Inspect the sandbox again.",
        );
    }
    if needs_choice && args.select.is_empty() && !interactive {
        return blocked(
            &item,
            2,
            json,
            "Storage needs investigation. Run interactive repair to review a diagnostic report, or supply independently verified --select values and --accept-selected-view.",
        );
    }

    if !args.select.is_empty() {
        let views = &item
            .inspection
            .as_ref()
            .context("disk choices are unavailable")?
            .candidates;
        if !current_choices(views, &args.select) {
            return blocked(
                &item,
                2,
                json,
                "Choose exactly one current view for every disk. Run doctor again to refresh the IDs.",
            );
        }
    }

    let mut maintenance = args.legacy_writers_stopped;
    if cfg!(target_os = "macos") && !maintenance {
        let instruction = "Stop legacy VMs across all homes and keep old tools and other writers away from these disks until repair finishes.";
        if !interactive {
            return blocked(
                &item,
                2,
                json,
                &format!("{instruction} After doing so, pass --legacy-writers-stopped."),
            );
        }
        println!("{instruction}");
        if !confirm("Have you stopped those VMs and excluded new writers?")? {
            return cancelled();
        }
        maintenance = true;
    }
    let options = StorageRecoveryOptions {
        legacy_writers_stopped: maintenance,
        ..Default::default()
    };
    let result = if needs_choice {
        ensure!(
            args.accept_selected_view,
            "explicit choices require --accept-selected-view"
        );
        // Headless callers explicitly identified the views. Capture only their selected
        // group; the SDK rechecks the metadata-bound IDs under lifecycle ownership.
        Sandbox::recover_storage(
            &name,
            StorageRecoveryOptions {
                selections: args.select,
                accept_selected_view: true,
                ..options
            },
        )
        .await?
    } else {
        Sandbox::recover_storage(&name, options).await?
    };
    done(result, json)
}

// Reject stale, incomplete, or duplicate machine choices before allocating any preview.
// The immutable session independently validates these IDs again when it applies them.
fn current_choices(candidates: &[CandidateSummary], choices: &[StorageRecoverySelection]) -> bool {
    let mut disks = BTreeMap::<&str, BTreeSet<&str>>::new();
    for view in candidates {
        disks.entry(&view.disk_id).or_default().insert(&view.id);
    }
    disks.len() == choices.len()
        && choices.iter().all(|choice| {
            disks
                .remove(choice.disk_id.as_str())
                .is_some_and(|views| views.contains(choice.candidate_id.as_str()))
        })
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

fn cancelled() -> anyhow::Result<()> {
    eprintln!("Repair cancelled.");
    Err(StorageDoctorExit { code: 2 }.into())
}

fn selection(value: &str) -> Result<StorageRecoverySelection, String> {
    let (disk, view) = value
        .split_once('=')
        .ok_or("use DISK_ID=CANDIDATE_ID from sandbox diagnosis")?;
    if value.len() > 512 || disk.is_empty() || view.is_empty() {
        return Err("use bounded, non-empty disk and candidate IDs".into());
    }
    Ok(StorageRecoverySelection {
        disk_id: disk.into(),
        candidate_id: view.into(),
    })
}

/// EOF and oversize input must never accept a default choice or advance the wizard.
fn answer(prompt: &str) -> anyhow::Result<String> {
    eprint!("{prompt}");
    io::stderr().flush()?;
    let mut line = String::new();
    let n = io::stdin().lock().take(4097).read_line(&mut line)?;
    ensure!(n <= 4096, "reply exceeds 4096 bytes");
    Ok(line.trim().to_owned())
}

fn confirm(prompt: &str) -> anyhow::Result<bool> {
    Ok(matches!(
        answer(&format!("{prompt} [y/N] "))?
            .to_ascii_lowercase()
            .as_str(),
        "y" | "yes"
    ))
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
    fn explicit_choices_cover_each_role_once_and_cannot_name_another_roles_view() {
        let view = |role: &str, id: &str| CandidateSummary {
            disk_id: role.into(),
            id: id.into(),
            layers: 1,
            virtual_size: 512,
            estimated_bytes: 512,
        };
        let views = [
            view("root", "one"),
            view("root", "two"),
            view("data", "three"),
        ];
        let choices = |input: &[&str]| {
            input
                .iter()
                .map(|s| selection(s).unwrap())
                .collect::<Vec<_>>()
        };
        assert!(current_choices(
            &views,
            &choices(&["data=three", "root=two"])
        ));
        for invalid in [
            vec!["root=two"],
            vec!["root=one", "root=two"],
            vec!["root=three", "data=three"],
            vec!["root=stale", "data=three"],
        ] {
            assert!(!current_choices(&views, &choices(&invalid)));
        }
    }

    #[test]
    fn automation_requires_a_target_and_acknowledgment_for_each_explicit_run() {
        for args in [
            vec!["repair"],
            vec!["repair", "api"],
            vec!["repair", "api", "--format", "json"],
            vec![
                "repair",
                "api",
                "--select",
                "root=view-a",
                "--accept-selected-view",
            ],
        ] {
            Command::try_parse_from(args).unwrap();
        }
        for args in [
            vec!["repair", "--format", "json"],
            vec!["repair", "api", "--select", "root=view-a"],
            vec!["repair", "api", "--accept-selected-view"],
            vec!["repair", "--legacy-writers-stopped"],
        ] {
            assert!(Command::try_parse_from(args).is_err());
        }
    }
}
