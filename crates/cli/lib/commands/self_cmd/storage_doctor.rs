//! Read-only diagnosis of one sandbox, kept separate from host probes and their optional fixes.

use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, Write};

use microsandbox::setup::{
    StorageDiagnosticReason, StorageDiagnosticStatus, StorageSandboxDiagnosis, StorageSelection,
};
use microsandbox_runtime::checkpoint::migration::CandidateSummary;
use microsandbox_utils::format::format_bytes;

use super::DoctorArgs;
use crate::ui::OutputFormat;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A diagnostic was printed and identified something that needs attention.
#[derive(Debug)]
pub struct StorageDoctorExit {
    /// 2 for an actionable blocker; 3 when inspection could not finish.
    pub code: i32,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl fmt::Display for StorageDoctorExit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("sandbox storage needs attention")
    }
}

impl std::error::Error for StorageDoctorExit {}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Dispatch before host probes, which can create filesystem probe files.
pub async fn run_doctor_command(mut args: DoctorArgs) -> anyhow::Result<()> {
    // Resolve the explicit flag before host/storage dispatch, so a named request
    // never falls through to host probes merely because its positional field is empty.
    args.sandbox = args.sandbox_flag.take().or(args.sandbox);
    if args.sandbox.is_none() && !args.all {
        anyhow::ensure!(
            args.format.is_none(),
            "provide --sandbox SANDBOX or --all for JSON output"
        );
        return super::run_doctor(args);
    }
    anyhow::ensure!(
        !args.fix && !args.yes,
        "host setup flags apply only to bare msb doctor"
    );
    let selection = match (args.sandbox, args.all) {
        (Some(name), false) => StorageSelection::Named(vec![name]),
        (None, true) => StorageSelection::All,
        _ => anyhow::bail!("choose --sandbox SANDBOX or --all"),
    };
    let report = microsandbox::setup::diagnose_storage(Default::default(), selection).await?;
    if args.format == Some(OutputFormat::Json) {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        if report.sandboxes.is_empty() {
            println!("There are no local sandboxes to inspect.");
        }
        for item in &report.sandboxes {
            write_diagnosis(&mut io::stdout().lock(), item, true)?;
        }
    }
    match report.exit_code() {
        0 => Ok(()),
        code => Err(StorageDoctorExit { code }.into()),
    }
}

/// Reasons can contain host-supplied paths. Escape controls before using them on a terminal.
pub(super) fn terminal_text(text: &str) -> String {
    text.chars().flat_map(char::escape_debug).collect()
}

pub(super) fn write_diagnosis(
    out: &mut impl Write,
    item: &StorageSandboxDiagnosis,
    show_next_step: bool,
) -> io::Result<()> {
    use StorageDiagnosticStatus::*;
    let name = terminal_text(&item.name);
    let message = match item.status {
        Ready => "storage is ready.",
        Eligible => "storage can be upgraded automatically.",
        MaintenanceRequired => "storage can be upgraded during a maintenance window.",
        InProgress => "a previous storage upgrade needs to finish.",
        RecoveryRequired => "storage needs repair.",
        Unavailable => "storage could not be inspected.",
    };
    writeln!(out, "{name}: {message}")?;
    if let Some(reason) = item.reason {
        let detail = match reason {
            StorageDiagnosticReason::NotFound => {
                "No sandbox with that name exists in this local home."
            }
            StorageDiagnosticReason::InvalidConfiguration => {
                "The saved sandbox configuration could not be read safely."
            }
            StorageDiagnosticReason::IncompleteCreation => {
                "Sandbox creation or restore has not finished."
            }
            StorageDiagnosticReason::StorageUnavailable => {
                "The local storage could not be inspected safely."
            }
        };
        writeln!(out, "{detail}")?;
    }
    if let Some(inspection) = &item.inspection {
        for reason in &inspection.reasons {
            writeln!(out, "{}", terminal_text(reason))?;
        }
        if item.status == RecoveryRequired && inspection.can_preview() {
            for (role, views) in grouped_views(&inspection.candidates) {
                write_views(
                    out,
                    role,
                    item.guest_mounts.get(role).map(String::as_str),
                    &views,
                )?;
            }
        }
        if inspection.estimated_bytes > 0 {
            writeln!(
                out,
                "Estimated space for the selected disks: {}",
                format_bytes(inspection.estimated_bytes)
            )?;
        }
    }
    if !show_next_step {
        return Ok(());
    }
    if item.running && item.status != Ready {
        writeln!(
            out,
            "The sandbox is running or changing state. Run 'msb self repair --sandbox {name}' to check what needs to stop."
        )?;
    } else {
        match item.status {
            Eligible => writeln!(
                out,
                "Run 'msb start {name}' to upgrade and start, or 'msb self repair --sandbox {name}' to upgrade while stopped."
            )?,
            MaintenanceRequired | InProgress | RecoveryRequired => writeln!(
                out,
                "Run 'msb self repair --sandbox {name}' for the next step."
            )?,
            Ready | Unavailable => {}
        }
    }
    Ok(())
}

pub(super) fn grouped_views(
    candidates: &[CandidateSummary],
) -> Vec<(&str, Vec<&CandidateSummary>)> {
    // Root first, then deterministic disk order; alternatives are only comparable within a role.
    let mut groups = BTreeMap::new();
    for view in candidates {
        groups
            .entry((view.disk_id != "root", view.disk_id.as_str()))
            .or_insert_with(Vec::new)
            .push(view);
    }
    groups
        .into_iter()
        .map(|((_, disk), views)| (disk, views))
        .collect()
}

pub(super) fn disk_label(role: &str, mount: Option<&str>) -> String {
    match (role, mount) {
        ("root", _) => "Root disk (/)".into(),
        (_, Some(mount)) => format!("{} ({})", terminal_text(mount), terminal_text(role)),
        _ => format!("Disk {}", terminal_text(role)),
    }
}

pub(super) fn write_views(
    out: &mut impl Write,
    role: &str,
    mount: Option<&str>,
    views: &[&CandidateSummary],
) -> io::Result<()> {
    writeln!(out, "{}:", disk_label(role, mount))?;
    for (i, view) in views.iter().enumerate() {
        writeln!(
            out,
            "  View {}: {} {}, {}",
            i + 1,
            view.layers,
            if view.layers == 1 { "layer" } else { "layers" },
            format_bytes(view.virtual_size)
        )?;
    }
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Debug, Parser)]
    struct Command {
        #[command(flatten)]
        doctor: DoctorArgs,
    }

    #[test]
    fn alternatives_are_displayed_per_guest_mount_without_asking_users_to_compare_hashes() {
        let view = |role: &str, id: &str, layers| CandidateSummary {
            disk_id: role.into(),
            id: id.into(),
            layers,
            virtual_size: 1024,
            estimated_bytes: 1024,
        };
        let candidates = [
            view("data_123", "view-secret-a", 1),
            view("root", "view-secret-b", 1),
            view("root", "view-secret-c", 2),
        ];
        let mut output = Vec::new();
        for (role, views) in grouped_views(&candidates) {
            write_views(
                &mut output,
                role,
                (role == "data_123").then_some("/data"),
                &views,
            )
            .unwrap();
        }
        let output = String::from_utf8(output).unwrap();
        let (root, owned) = output.split_once("/data (data_123):").unwrap();
        assert!(root.starts_with("Root disk (/):") && root.contains("View 2: 2 layers"));
        assert!(owned.contains("View 1: 1 layer") && !owned.contains("View 2"));
        assert!(!output.contains("view-secret-"));
        assert_eq!(terminal_text("path\x1b[2J"), r"path\u{1b}[2J");
    }

    #[test]
    fn sandbox_doctor_is_read_only_and_bare_doctor_keeps_host_fixes() {
        for args in [
            vec!["doctor"],
            vec!["doctor", "--fix", "--yes"],
            vec!["doctor", "api"],
            vec!["doctor", "--sandbox", "api"],
            vec!["doctor", "api", "--format", "json"],
            vec!["doctor", "--sandbox", "api", "--format", "json"],
            vec!["doctor", "--all", "--format", "json"],
            vec!["doctor", "-a", "--format", "json"],
        ] {
            Command::try_parse_from(args).unwrap();
        }
        for args in [
            vec!["doctor", "api", "--fix"],
            vec!["doctor", "api", "--yes"],
            vec!["doctor", "--format", "json"],
            vec!["doctor", "worker", "api"],
            vec!["doctor", "api", "--all"],
            vec!["doctor", "--sandbox", "api", "--all"],
            vec!["doctor", "--sandbox", "api", "--fix"],
            vec!["doctor", "--sandbox", "api", "--yes"],
            vec!["doctor", "--sandbox", "api", "api"],
            vec!["doctor", "api", "--sandbox", "other"],
            vec!["doctor", "--sandbox", "api", "--sandbox", "api"],
            vec!["doctor", "--sandbox"],
            vec!["doctor", "--storage", "--all-sandboxes"],
        ] {
            assert!(Command::try_parse_from(args).is_err());
        }
    }
}
