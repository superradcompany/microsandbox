//! `msb df` and `msb prune` — observe storage and reclaim unused runtime RAM.

use std::fmt::Write as _;
use std::io::{self, IsTerminal, Write};
use std::time::Duration;

use clap::Args;
use console::style;
use microsandbox::storage::{
    MemoryCacheKind, MemoryCacheReport, MemoryCacheState, MemoryPruneOptions, Storage,
    StorageCategoryUsage, StorageItemUsage, StorageUsage,
};
use microsandbox_utils::format::format_bytes;

use crate::ui;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Arguments for aggregate local storage usage.
#[derive(Debug, Args)]
pub struct DfArgs {
    /// Output format (json).
    #[arg(long, value_name = "FORMAT", value_parser = ["json"])]
    pub format: Option<String>,

    /// Include individual objects, backing paths, and retention reasons.
    #[arg(long)]
    pub verbose: bool,
}

/// Arguments for reclaiming published runtime RAM that has no current owner.
#[derive(Debug, Args)]
#[command(
    after_help = "Only unused runtime RAM cache files are removed. Saved snapshots, sandbox disks, volumes, images, and stable lock files are retained."
)]
pub struct PruneArgs {
    /// Only consider backing files older than this age (e.g. 30m, 2h, 7d).
    #[arg(long, value_name = "DURATION", value_parser = parse_age, default_value = "0s")]
    pub older_than: Duration,

    /// Show eligible files without removing them or asking for confirmation.
    #[arg(long)]
    pub dry_run: bool,

    /// Skip the interactive confirmation.
    #[arg(long)]
    pub yes: bool,

    /// Suppress successful human-readable output; errors remain visible.
    #[arg(short, long, conflicts_with = "format")]
    pub quiet: bool,

    /// Output a structured report (json).
    #[arg(long, value_name = "FORMAT", value_parser = ["json"])]
    pub format: Option<String>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Show a point-in-time aggregate storage observation for the selected local backend.
pub async fn run_df(args: DfArgs) -> anyhow::Result<()> {
    let usage = Storage::usage().await?;
    if args.format.as_deref() == Some("json") {
        println!("{}", serde_json::to_string_pretty(&usage)?);
    } else {
        print!("{}", render_usage(&usage, args.verbose));
    }
    Ok(())
}

/// Add the same storage accounting and retention details to per-object inspection.
pub(crate) fn display_item(usage: &StorageItemUsage) {
    ui::detail_header("Storage");
    ui::detail_kv_indent("Logical size", &size_cell(usage.logical_bytes));
    ui::detail_kv_indent("Allocated blocks", &size_cell(usage.allocated_bytes));
    ui::detail_kv_indent("In use", bool_cell(usage.in_use));
    ui::detail_kv_indent("Reclaimable", bool_cell(usage.reclaimable));
    for reason in &usage.reasons {
        println!("  {reason}");
    }
    println!(
        "  Allocated blocks may include shared extents; they are not exclusive physical usage."
    );
}

/// Preview, confirm, and revalidate unused runtime RAM before removal.
pub async fn run_prune(args: PruneArgs) -> anyhow::Result<()> {
    let mut options = MemoryPruneOptions {
        dry_run: true,
        older_than: args.older_than,
        max_entries: None,
        ..Default::default()
    };
    let mut preview = Storage::prune(&options).await?;
    if args.dry_run || has_errors(&preview) {
        return print_prune_report(&args, &preview);
    }

    // Quiet controls output only. It can never authorize deletion in an unattended run.
    require_interactive_or_yes(&args, io::stdin().is_terminal())?;
    if eligible_count(&preview) == 0 {
        preview.dry_run = false;
        return print_prune_report(&args, &preview);
    }

    if !args.yes {
        eprint!("Prune unused runtime memory cache entries? [y/N] ");
        io::stderr().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            if args.format.as_deref() == Some("json") {
                let mut report = serde_json::to_value(&preview)?;
                report["cancelled"] = true.into();
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else if !args.quiet {
                eprintln!("Aborted.");
            }
            return Ok(());
        }
    }

    // The preview is advisory: ownership can change while the user considers the prompt.
    // A fresh complete scan reacquires ownership locks before unlinking every candidate.
    options.dry_run = false;
    let report = Storage::prune(&options).await?;
    print_prune_report(&args, &report)
}

//--------------------------------------------------------------------------------------------------
// Functions: Rendering And Policy
//--------------------------------------------------------------------------------------------------

fn categories(usage: &StorageUsage) -> [(&'static str, &StorageCategoryUsage); 6] {
    [
        ("images", &usage.images),
        ("snapshots", &usage.snapshots),
        ("branch memory", &usage.branch_memory),
        ("snapshot memory", &usage.snapshot_memory),
        ("sandboxes", &usage.sandboxes),
        ("volumes", &usage.volumes),
    ]
}

fn render_usage(usage: &StorageUsage, verbose: bool) -> String {
    let mut table = ui::Table::new(&["TYPE", "COUNT", "IN USE", "LOGICAL SIZE", "RECLAIMABLE"]);
    for (name, category) in categories(usage) {
        table.add_row(vec![
            name.to_string(),
            count_cell(category.count),
            count_cell(category.in_use),
            size_cell(category.logical_bytes),
            size_cell(category.reclaimable_logical_bytes),
        ]);
    }
    let mut output = table.render();
    output.push_str("\nReclaimable shows logical bytes; '-' means unknown.\nPhysical space freed may differ because files can share disk blocks.\n");
    if verbose {
        for note in &usage.notes {
            let _ = writeln!(output, "{note}");
        }
    } else {
        output.push_str("Use --verbose for ownership details and accounting exclusions.\n");
    }
    for (name, category) in categories(usage) {
        if verbose {
            let mut title = name.to_string();
            title[..1].make_ascii_uppercase();
            let _ = writeln!(
                output,
                "\n{}",
                style(format!("{title} ({})", count_cell(category.count))).bold()
            );
            for item in &category.items {
                let _ = writeln!(output, "  {}", item.name);
                let _ = writeln!(output, "    Path:          {}", item.path.display());
                let _ = writeln!(
                    output,
                    "    Logical size:  {}",
                    size_cell(item.logical_bytes)
                );
                let _ = writeln!(
                    output,
                    "    Allocated:     {}",
                    size_cell(item.allocated_bytes)
                );
                let _ = writeln!(output, "    In use:        {}", bool_cell(item.in_use));
                let _ = writeln!(output, "    Reclaimable:   {}", bool_cell(item.reclaimable));
                for reason in &item.reasons {
                    let _ = writeln!(output, "    Reason:        {reason}");
                }
            }
        }
        for note in &category.notes {
            let _ = writeln!(output, "  {name}: {note}");
        }
    }
    output
}

fn print_prune_report(args: &PruneArgs, report: &MemoryCacheReport) -> anyhow::Result<()> {
    let errors = has_errors(report);
    if args.format.as_deref() == Some("json") {
        println!("{}", serde_json::to_string_pretty(report)?);
    } else {
        if !args.quiet {
            let count = if report.dry_run {
                eligible_count(report) as u64
            } else {
                report.files_removed
            };
            if errors {
                ui::warn("runtime memory cache cleanup encountered errors");
            } else if count == 0 {
                eprintln!("Nothing to prune.");
            } else if report.dry_run {
                ui::notice("Would prune", "runtime memory cache");
            } else {
                ui::success("Pruned", "runtime memory cache");
            }
            if count > 0 || errors {
                eprint!("{}", render_prune_summary(report));
            }
        }
        // Failures are always visible, including when quiet suppresses successful output.
        for entry in &report.entries {
            if entry.state == MemoryCacheState::Error || entry.error.is_some() {
                ui::error(&format!(
                    "{}: {}",
                    entry.path.display(),
                    entry
                        .error
                        .as_deref()
                        .unwrap_or("could not establish safe ownership")
                ));
            }
        }
    }
    if errors {
        // JSON already contains the individual errors, and human errors were rendered above.
        return Err(ui::AlreadyRenderedError.into());
    }
    Ok(())
}

fn render_prune_summary(report: &MemoryCacheReport) -> String {
    let selected = if report.dry_run {
        MemoryCacheState::Reclaimable
    } else {
        MemoryCacheState::Removed
    };
    let selected_entries: Vec<_> = report
        .entries
        .iter()
        .filter(|entry| entry.state == selected)
        .collect();
    let branches = selected_entries
        .iter()
        .filter(|entry| entry.kind == MemoryCacheKind::BranchMemory)
        .count();
    let snapshots = selected_entries
        .iter()
        .filter(|entry| entry.kind == MemoryCacheKind::SnapshotMemory)
        .count();
    let bytes = if report.dry_run {
        // Incomplete measurements stay unknown rather than silently contributing zero bytes.
        selected_entries
            .iter()
            .try_fold(0u64, |sum, entry| sum.checked_add(entry.logical_bytes?))
    } else {
        Some(report.logical_bytes_removed)
    };
    let in_use = report
        .entries
        .iter()
        .filter(|entry| entry.state == MemoryCacheState::InUse)
        .count();
    let pending = report
        .entries
        .iter()
        .filter(|entry| entry.state == MemoryCacheState::PendingHandoff)
        .count();
    let young = report
        .entries
        .iter()
        .filter(|entry| entry.state == MemoryCacheState::TooYoung)
        .count();
    let other = report
        .entries
        .iter()
        .filter(|entry| {
            matches!(
                entry.state,
                MemoryCacheState::MissingHandoffLock | MemoryCacheState::Changed
            )
        })
        .count();
    let bytes_label = if report.dry_run {
        "Logical size"
    } else {
        "Logical bytes removed"
    };
    let mut output = format!(
        "  Branch memory:          {branches} files\n  Snapshot memory:        {snapshots} files\n  {label:<22}  {}\n  Skipped:                {in_use} in use, {pending} pending handoff, {young} too young, {other} unverified\n",
        size_cell(bytes),
        label = format!("{bytes_label}:")
    );
    if report.dry_run {
        output.push_str("\nNo files removed.\n");
    }
    output
}

fn has_errors(report: &MemoryCacheReport) -> bool {
    report
        .entries
        .iter()
        .any(|entry| entry.state == MemoryCacheState::Error || entry.error.is_some())
}

fn eligible_count(report: &MemoryCacheReport) -> usize {
    report
        .entries
        .iter()
        .filter(|entry| entry.state == MemoryCacheState::Reclaimable)
        .count()
}

fn require_interactive_or_yes(args: &PruneArgs, interactive: bool) -> anyhow::Result<()> {
    if !args.dry_run && !args.yes && !interactive {
        anyhow::bail!("non-interactive terminal; use --yes to prune the runtime memory cache");
    }
    Ok(())
}

fn count_cell(value: Option<u64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "-".into())
}

fn size_cell(value: Option<u64>) -> String {
    value.map(format_bytes).unwrap_or_else(|| "-".into())
}

fn bool_cell(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "Yes",
        Some(false) => "No",
        None => "-",
    }
}

fn parse_age(value: &str) -> Result<Duration, String> {
    let (number, multiplier) = match value.as_bytes().last() {
        Some(b's') => (&value[..value.len() - 1], 1u64),
        Some(b'm') => (&value[..value.len() - 1], 60),
        Some(b'h') => (&value[..value.len() - 1], 60 * 60),
        Some(b'd') => (&value[..value.len() - 1], 24 * 60 * 60),
        _ => return Err("duration must be an integer followed by s, m, h, or d (e.g. 30m)".into()),
    };
    if number.is_empty() || !number.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("duration must be a non-negative integer followed by s, m, h, or d".into());
    }
    number
        .parse::<u64>()
        .ok()
        .and_then(|number| number.checked_mul(multiplier))
        .map(Duration::from_secs)
        .ok_or_else(|| "duration is too large".into())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use clap::Parser;
    use microsandbox::storage::{MemoryCacheEntry, StorageItemUsage};

    use super::*;

    #[derive(Parser)]
    struct PruneParser {
        #[command(flatten)]
        args: PruneArgs,
    }

    #[test]
    fn age_parser_checks_units_syntax_and_overflow() {
        for (input, seconds) in [("0s", 0), ("30m", 1800), ("2h", 7200), ("7d", 604800)] {
            assert_eq!(parse_age(input).unwrap(), Duration::from_secs(seconds));
        }
        for input in [
            "",
            "1",
            "s",
            "-1s",
            "+1s",
            "1.5h",
            "2H",
            " 2h",
            "18446744073709551615d",
        ] {
            assert!(parse_age(input).is_err(), "{input}");
        }
    }

    #[test]
    fn quiet_never_bypasses_confirmation_and_conflicts_with_json() {
        let args = PruneParser::try_parse_from(["prune", "-q"]).unwrap().args;
        assert!(require_interactive_or_yes(&args, false).is_err());
        assert!(PruneParser::try_parse_from(["prune", "-q", "--format", "json"]).is_err());
        for flags in [["prune", "--yes"], ["prune", "--dry-run"]] {
            let args = PruneParser::try_parse_from(flags).unwrap().args;
            assert!(require_interactive_or_yes(&args, false).is_ok());
        }
    }

    #[test]
    fn usage_always_lists_six_categories_and_preserves_unknowns() {
        let mut usage = StorageUsage::default();
        usage.branch_memory = StorageCategoryUsage {
            count: Some(0),
            in_use: Some(0),
            logical_bytes: Some(0),
            reclaimable_logical_bytes: Some(0),
            ..Default::default()
        };
        let output = render_usage(&usage, false);
        let plain = console::strip_ansi_codes(&output);
        for (name, _) in categories(&usage) {
            assert!(plain.lines().any(|line| line.starts_with(name)), "{name}");
        }
        let row = plain
            .lines()
            .find(|line| line.starts_with("branch memory"))
            .unwrap();
        assert!(row.ends_with("0 B"));
        let row = plain
            .lines()
            .find(|line| line.starts_with("images"))
            .unwrap();
        assert_eq!(
            row.split_whitespace().collect::<Vec<_>>(),
            ["images", "-", "-", "-", "-"]
        );
        assert!(plain.contains("Physical space freed may differ"));
    }

    #[test]
    fn verbose_usage_includes_paths_and_retention_reasons() {
        let mut usage = StorageUsage::default();
        usage.branch_memory.count = Some(1);
        usage.branch_memory.items.push(StorageItemUsage {
            name: "branch-one".into(),
            path: "/cache/memory/branches/branch-one.ram".into(),
            in_use: Some(true),
            reclaimable: Some(false),
            reasons: vec!["retained source baseline".into()],
            ..Default::default()
        });
        let output = render_usage(&usage, true);
        assert!(output.contains("branch-one.ram"));
        assert!(output.contains("retained source baseline"));
        assert!(output.contains("In use:        Yes"));
    }

    #[test]
    fn preview_reports_logical_size_without_claiming_removal() {
        let report = MemoryCacheReport {
            dry_run: true,
            entries: vec![MemoryCacheEntry {
                path: "/cache/memory/branches/branch-one.ram".into(),
                kind: MemoryCacheKind::BranchMemory,
                logical_bytes: Some(2 * 1024 * 1024),
                allocated_bytes: Some(4096),
                state: MemoryCacheState::Reclaimable,
                error: None,
            }],
            ..Default::default()
        };
        let text = render_prune_summary(&report);
        assert!(text.contains("2.0 MiB"));
        assert!(text.contains("No files removed."));
        assert!(!text.contains("Logical bytes removed"));
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["files_removed"], 0);
        assert_eq!(json["logical_bytes_removed"], 0);
        assert!(json["physical_bytes_reclaimed"].is_null());
    }
}
