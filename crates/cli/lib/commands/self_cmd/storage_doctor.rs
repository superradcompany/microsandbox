//! Explicit storage diagnosis dispatch, separate from host probes and host fixes.

use std::fmt;

use microsandbox::setup::{StorageDiagnosis, StorageDiagnosticStatus, StorageSelection};

use super::DoctorArgs;
use crate::ui::OutputFormat;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A report was printed successfully but requires attention; suppress duplicate generic errors.
#[derive(Debug)]
pub struct StorageDoctorExit {
    /// 2 for migration blockers; 3 for an incomplete per-sandbox inspection.
    pub code: i32,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl fmt::Display for StorageDoctorExit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("storage diagnosis requires attention")
    }
}

impl std::error::Error for StorageDoctorExit {}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Dispatch before host diagnosis: ordinary host checks can create clone-probe files.
pub async fn run_doctor_command(args: DoctorArgs) -> anyhow::Result<()> {
    if !args.storage {
        if !args.sandboxes.is_empty() || args.all_sandboxes || args.format.is_some() {
            anyhow::bail!("storage scope and format require --storage");
        }
        return super::run_doctor(args);
    }
    let selection = storage_selection(&args)?;
    let report = microsandbox::setup::diagnose_storage(Default::default(), selection).await?;
    if args.format == Some(OutputFormat::Json) {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_report(&report);
    }
    let code = report.exit_code();
    if code != 0 {
        return Err(StorageDoctorExit { code }.into());
    }
    Ok(())
}

fn storage_selection(args: &DoctorArgs) -> anyhow::Result<StorageSelection> {
    // Also protect direct library callers that did not pass through clap's argument checks.
    if args.fix || args.yes {
        anyhow::bail!("storage diagnosis cannot be combined with host fixes or confirmation flags");
    }
    match (args.all_sandboxes, args.sandboxes.is_empty()) {
        (true, true) => Ok(StorageSelection::All),
        (false, false) => Ok(StorageSelection::Named(args.sandboxes.clone())),
        _ => anyhow::bail!(
            "storage diagnosis requires --sandbox NAME or --all-sandboxes, exclusively"
        ),
    }
}

fn print_report(report: &StorageDiagnosis) {
    let maintenance = if cfg!(target_os = "macos") {
        " --legacy-writers-stopped"
    } else {
        ""
    };
    println!("storage diagnosis: {}", report.home.display());
    println!(
        "required runtime capability: {}",
        report.required_runtime_capability
    );
    for item in &report.sandboxes {
        let status = serde_json::to_value(item.status).expect("status serializes");
        println!(
            "{}: {}{}",
            item.name,
            status.as_str().unwrap_or("unavailable"),
            if item.running {
                " (running; provisional)"
            } else {
                ""
            }
        );
        if let Some(reason) = item.reason {
            println!(
                "  reason: {}",
                serde_json::to_value(reason)
                    .expect("reason serializes")
                    .as_str()
                    .unwrap_or("unavailable")
            );
        }
        if let Some(inspection) = &item.inspection {
            for reason in &inspection.reasons {
                println!("  {reason}");
            }
            if inspection.estimated_bytes != 0 {
                println!("  estimated capture bytes: {}", inspection.estimated_bytes);
            }
            for candidate in &inspection.candidates {
                println!(
                    "  candidate {}: disk {}, {} layers, {} bytes",
                    candidate.id, candidate.disk_id, candidate.layers, candidate.virtual_size
                );
            }
        }
        if item.running && item.status != StorageDiagnosticStatus::Ready {
            println!(
                "  stop '{}' before migration, then repeat this storage check",
                item.name
            );
        } else {
            match item.status {
                StorageDiagnosticStatus::Eligible => println!(
                    "  next: msb start {} (migrates automatically), or msb recover-storage {} (without booting)",
                    item.name, item.name
                ),
                StorageDiagnosticStatus::MaintenanceRequired => {
                    println!(
                        "  stop legacy VMs across all homes and prevent old-tool launches or writes to this storage until recovery finishes"
                    );
                    println!(
                        "  then: msb recover-storage {} --legacy-writers-stopped",
                        item.name
                    );
                }
                StorageDiagnosticStatus::InProgress => {
                    println!("  resume: msb recover-storage {}{}", item.name, maintenance);
                    if !maintenance.is_empty() {
                        println!(
                            "  first stop legacy VMs across all homes and prevent new writers until recovery finishes"
                        );
                    }
                }
                StorageDiagnosticStatus::RecoveryRequired
                    if item
                        .inspection
                        .as_ref()
                        .is_some_and(|report| !report.candidates.is_empty()) =>
                {
                    println!(
                        "  after choosing a complete view for each affected disk: msb recover-storage {} --select DISK_ID=CANDIDATE_ID --accept-selected-view{}",
                        item.name, maintenance
                    );
                    println!(
                        "  selecting a view can omit later writes; original files remain retained"
                    );
                    if !maintenance.is_empty() {
                        println!(
                            "  first stop legacy VMs across all homes and prevent new writers until recovery finishes"
                        );
                    }
                }
                StorageDiagnosticStatus::RecoveryRequired
                | StorageDiagnosticStatus::Unavailable => {
                    println!(
                        "  preserve the original files and resolve the reported blocker before retrying; do not delete guards or edit journals"
                    );
                }
                StorageDiagnosticStatus::Ready => {}
            }
        }
    }
    println!("No sandbox configuration or disk data was changed.");
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Debug, Parser)]
    struct Command {
        #[command(flatten)]
        doctor: DoctorArgs,
    }

    #[test]
    fn doctor_storage_arguments_require_explicit_nonconflicting_scope() {
        for arguments in [
            vec!["doctor"],
            vec!["doctor", "--fix"],
            vec!["doctor", "--fix", "--yes"],
            vec!["doctor", "--storage", "--sandbox", "app"],
            vec![
                "doctor",
                "--storage",
                "--sandbox",
                "app",
                "--sandbox",
                "worker",
            ],
            vec!["doctor", "--storage", "--all-sandboxes", "--format", "json"],
        ] {
            Command::try_parse_from(&arguments)
                .unwrap_or_else(|error| panic!("{arguments:?}: {error}"));
        }
        for arguments in [
            vec!["doctor", "--storage"],
            vec!["doctor", "--sandbox", "app"],
            vec!["doctor", "--all-sandboxes"],
            vec!["doctor", "--format", "json"],
            vec!["doctor", "--storage", "--all-sandboxes", "--sandbox", "app"],
            vec!["doctor", "--storage", "--all-sandboxes", "--fix"],
            vec!["doctor", "--storage", "--all-sandboxes", "--yes"],
        ] {
            assert!(
                Command::try_parse_from(&arguments).is_err(),
                "accepted {arguments:?}"
            );
        }
    }
}
