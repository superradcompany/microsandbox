//! `msb self` subcommands for managing the msb installation itself.

use std::cmp::Ordering;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::future::Future;
use std::io::{IsTerminal, Write};
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::process::Command;
#[cfg(windows)]
use std::process::Stdio;
use std::time::Duration;

use clap::{Args, Subcommand};
use console::{Key, Term, style};
use microsandbox_migration::schema_metadata;
use microsandbox_migration::{Migrator, MigratorTrait};
use sea_orm::{ConnectionTrait, DatabaseBackend, DatabaseConnection, DbErr, Statement};
use serde::Deserialize;
use tokio::process::Command as TokioCommand;
#[cfg(windows)]
use windows_sys::Win32::Foundation::HANDLE;
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{LOCKFILE_EXCLUSIVE_LOCK, LockFileEx, UnlockFileEx};
#[cfg(windows)]
use windows_sys::Win32::System::IO::OVERLAPPED;

use super::install::is_generated_alias;
use crate::ui;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

const MIN_DOWNGRADE_VERSION: Version = Version {
    major: 0,
    minor: 6,
    patch: 0,
};

#[cfg(unix)]
const MARKER_START: &str = "# >>> microsandbox >>>";

#[cfg(unix)]
const MARKER_END: &str = "# <<< microsandbox <<<";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Update or uninstall msb.
#[derive(Debug, Args)]
pub struct SelfArgs {
    /// Subcommand to run.
    #[command(subcommand)]
    pub command: SelfCommand,
}

/// `msb self` subcommands.
#[derive(Debug, Subcommand)]
pub enum SelfCommand {
    /// Check local runtime and host virtualization prerequisites.
    #[command(visible_alias = "check")]
    Doctor(DoctorArgs),

    /// Update msb and libkrunfw to the latest release.
    #[command(visible_alias = "upgrade")]
    Update(SelfUpdateArgs),

    /// Downgrade msb and local state to an older supported release.
    Downgrade(SelfDowngradeArgs),

    /// Remove msb, libkrunfw, and command links.
    Uninstall(SelfUninstallArgs),
}

/// Arguments for `msb self update`.
#[derive(Debug, Args)]
pub struct SelfUpdateArgs {
    /// Re-download even if already on the latest version.
    #[arg(short, long)]
    pub force: bool,
}

/// Arguments for `msb self downgrade`.
#[derive(Debug, Args)]
pub struct SelfDowngradeArgs {
    /// Target release version.
    pub version: String,

    /// Skip destructive-step confirmations.
    #[arg(short, long)]
    pub yes: bool,

    /// Re-download and reinstall the target release.
    #[arg(short, long)]
    pub force: bool,

    /// Keep the image cache even when rollback metadata marks it affected.
    #[arg(long)]
    pub keep_cache: bool,

    /// Skip the database backup before rolling back local state.
    #[arg(long)]
    pub no_backup: bool,
}

/// Arguments for the hidden downgrade compatibility metadata command.
#[derive(Debug, Args)]
pub struct SchemaBaselineArgs {
    /// Print downgrade compatibility metadata as JSON.
    #[arg(long)]
    pub json: bool,
}

/// Arguments for the deferred Windows self-downgrade binary swap helper.
#[cfg(windows)]
#[derive(Debug, Args)]
pub struct WindowsSelfDowngradeSwapArgs {
    /// PID of the msb process that scheduled the swap.
    #[arg(long)]
    pub parent_pid: i32,

    /// Microsandbox base directory to mutate.
    #[arg(long)]
    pub base_dir: PathBuf,

    /// Temporary directory containing the staged target release.
    #[arg(long)]
    pub staged_dir: PathBuf,

    /// Target release version.
    #[arg(long)]
    pub target_version: String,

    /// Install-exclusive lease holder PID to clear after the swap.
    #[arg(long)]
    pub lease_holder_pid: Option<i32>,

    /// Install-exclusive lease expiry timestamp to clear after the swap.
    #[arg(long)]
    pub lease_expires_at: Option<String>,

    /// Log file for deferred swap diagnostics.
    #[arg(long)]
    pub log_path: PathBuf,
}

/// Arguments for `msb doctor` and `msb self doctor`.
#[derive(Debug, Args, Clone, Copy)]
pub struct DoctorArgs {
    /// Attempt supported host virtualization setup fixes.
    #[arg(long)]
    pub fix: bool,

    /// Apply fixes without prompting for confirmation.
    #[arg(long, short = 'y')]
    pub yes: bool,
}

/// Arguments for `msb self uninstall`.
#[derive(Debug, Args)]
pub struct SelfUninstallArgs {
    /// Skip confirmation prompt and remove everything.
    #[arg(long, short)]
    pub yes: bool,
}

/// A category of data that can be removed during uninstall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UninstallCategory {
    All,
    Sandboxes,
    Volumes,
    Cache,
    Installs,
    Database,
    Logs,
    Secrets,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Version {
    major: u64,
    minor: u64,
    patch: u64,
}

#[derive(Debug, Deserialize)]
struct SchemaBaseline {
    #[serde(alias = "schema_version")]
    schema_baseline_version: u32,
    #[allow(dead_code)]
    downgrade_floor: String,
    migrations: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
struct RollbackPlan<'a> {
    rollback: &'a [schema_metadata::MigrationMetadata],
    affects_cache: bool,
    affects_user_data: bool,
}

struct MigrationLock {
    file: File,
}

#[derive(Debug)]
enum DowngradeRunOutcome {
    #[cfg(not(windows))]
    Complete,
    #[cfg(windows)]
    WindowsSwapScheduled,
}

struct DowngradeRunContext<'a> {
    db: &'a microsandbox_db::connection::DbWriteConnection,
    base_dir: &'a Path,
    db_path: &'a Path,
    backup_path: Option<&'a Path>,
    target_version: Version,
    target_baseline: &'a SchemaBaseline,
    planned_applied_migrations: &'a [String],
    rollback_plan: &'a RollbackPlan<'static>,
    install_lease: Option<&'a mut microsandbox_runtime::maintenance::InstallExclusiveLease>,
    args: &'a SelfDowngradeArgs,
}

impl UninstallCategory {
    const ITEMS: &[Self] = &[
        Self::All,
        Self::Sandboxes,
        Self::Volumes,
        Self::Cache,
        Self::Installs,
        Self::Database,
        Self::Logs,
        Self::Secrets,
    ];

    fn label(&self) -> &'static str {
        match self {
            Self::All => "All — remove everything and command links",
            Self::Sandboxes => "Sandboxes — sandbox state and rootfs",
            Self::Volumes => "Volumes — named volumes",
            Self::Cache => "Cache — OCI image layers",
            Self::Installs => "Installs — installed command aliases",
            Self::Database => "Database — metadata store",
            Self::Logs => "Logs — log files",
            Self::Secrets => "Secrets — secrets, TLS certs, and SSH keys",
        }
    }

    fn short_name(&self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Sandboxes => "sandboxes",
            Self::Volumes => "volumes",
            Self::Cache => "cache",
            Self::Installs => "installs",
            Self::Database => "database",
            Self::Logs => "logs",
            Self::Secrets => "secrets",
        }
    }
}

impl Version {
    fn parse(input: &str) -> anyhow::Result<Self> {
        let clean = input.trim().strip_prefix('v').unwrap_or(input.trim());
        let mut parts = clean.split('.');
        let Some(major) = parts.next() else {
            anyhow::bail!("invalid version {input:?}");
        };
        let Some(minor) = parts.next() else {
            anyhow::bail!("invalid version {input:?}; expected MAJOR.MINOR.PATCH");
        };
        let Some(patch) = parts.next() else {
            anyhow::bail!("invalid version {input:?}; expected MAJOR.MINOR.PATCH");
        };
        if parts.next().is_some() {
            anyhow::bail!("invalid version {input:?}; expected MAJOR.MINOR.PATCH");
        }

        Ok(Self {
            major: major.parse()?,
            minor: minor.parse()?,
            patch: patch.parse()?,
        })
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.major, self.minor, self.patch).cmp(&(other.major, other.minor, other.patch))
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl RollbackPlan<'_> {
    fn steps(&self) -> usize {
        self.rollback.len()
    }

    fn has_destructive_steps(&self, keep_cache: bool) -> bool {
        self.steps() > 0 || (self.affects_cache && !keep_cache) || self.affects_user_data
    }
}

impl DowngradeRunOutcome {
    #[cfg(not(windows))]
    fn clear_lease_in_parent(&self) -> bool {
        let _ = self;
        true
    }

    #[cfg(windows)]
    fn clear_lease_in_parent(&self) -> bool {
        let _ = self;
        false
    }
}

impl MigrationLock {
    fn acquire(path: PathBuf) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;

        lock_migration_file(&file, &path)?;

        Ok(Self { file })
    }
}

impl Drop for MigrationLock {
    fn drop(&mut self) {
        let _ = unlock_migration_file(&self.file);
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Run a `msb self` subcommand.
pub async fn run(args: SelfArgs) -> anyhow::Result<()> {
    match args.command {
        SelfCommand::Doctor(args) => run_doctor(args),
        SelfCommand::Update(args) => run_update(args).await,
        SelfCommand::Downgrade(args) => run_downgrade(args).await,
        SelfCommand::Uninstall(args) => run_uninstall(args).await,
    }
}

/// Print this binary's downgrade compatibility metadata.
pub fn run_schema_baseline(args: SchemaBaselineArgs) -> anyhow::Result<()> {
    if !args.json {
        anyhow::bail!("__schema-baseline requires --json");
    }

    let baseline = serde_json::json!({
        "schema_baseline_version": schema_metadata::SCHEMA_BASELINE_FORMAT_VERSION,
        "msb_version": CURRENT_VERSION,
        "downgrade_floor": schema_metadata::DOWNGRADE_FLOOR,
        "migrations": schema_metadata::migration_ids().collect::<Vec<_>>(),
    });
    println!("{}", serde_json::to_string_pretty(&baseline)?);
    Ok(())
}

/// Check local runtime files and host virtualization prerequisites.
///
/// Renders each check in the spinner-completion style shared with `msb start`
/// and `msb pull` (`✓ <label> <detail>`), followed by a styled error block per
/// problem. With `--fix`, applies the safe auto-runnable remediation for each
/// problem (after a `[y/N]` prompt) and re-checks. Exits non-zero when the host
/// still cannot run local sandboxes.
pub fn run_doctor(args: DoctorArgs) -> anyhow::Result<()> {
    let diagnosis = diagnose_host();
    render_diagnosis(&diagnosis);

    if diagnosis.is_healthy() {
        done("Host setup is ready.");
        return Ok(());
    }

    let mut applied_any = false;
    let mut offered_any_fix = false;
    let mut relogin_pending = false;
    for problem in &diagnosis.problems {
        render_problem(problem, !args.fix);

        if args.fix
            && let Some(fix) = &problem.fix
        {
            offered_any_fix = true;
            if apply_fix(fix, args.yes)? {
                applied_any = true;
                relogin_pending |= fix.requires_relogin;
            }
        }
    }

    // Windows applies its fix through an elevated, UAC-gated PowerShell flow
    // rather than a `sudo` command, so it's handled out of band.
    #[cfg(windows)]
    if args.fix && has_windows_hypervisor_problem(&diagnosis) {
        offered_any_fix = true;
        if apply_windows_fix(args.yes)? {
            applied_any = true;
        }
    }

    if applied_any {
        let recheck = diagnose_host();
        render_diagnosis(&recheck);

        if recheck.is_healthy() {
            done("Host setup is ready.");
            return Ok(());
        }

        for problem in &recheck.problems {
            render_problem(problem, false);
        }
        if relogin_pending {
            ui::warn_with_lines(
                "some fixes apply fully only after you log out and back in",
                &[ui::ErrorLine::Hint(
                    "start a new shell (or re-login) to pick up group changes",
                )],
            );
        }
    } else if args.fix && offered_any_fix {
        ui::warn("no fixes were applied.");
    } else if args.fix {
        ui::warn("no automatic fixes are available for the problems above.");
    }

    std::process::exit(1);
}

/// Run the diagnosis behind a `Checking host` spinner.
///
/// The individual checks are near-instant, so they render as already-resolved
/// completion lines; this single spinner covers the whole pass (and is visible
/// on slower hosts, e.g. the Windows hypervisor probe).
fn diagnose_host() -> microsandbox::setup::Diagnosis {
    let spinner = ui::Spinner::start("Checking", "host");
    let diagnosis = microsandbox::setup::diagnose();
    spinner.finish_clear();
    diagnosis
}

/// Render the checks as a flat log: all `info <label>: <value>` facts first,
/// then the `✓`/`✗ <label> <detail>` rows — matching the CLI's convention of
/// leading with `info` metadata before the result rows.
fn render_diagnosis(diagnosis: &microsandbox::setup::Diagnosis) {
    use microsandbox::setup::CheckState;

    let checks: Vec<&microsandbox::setup::Check> =
        diagnosis.sections.iter().flat_map(|s| &s.checks).collect();
    let (mut facts, rows): (Vec<_>, Vec<_>) = checks
        .into_iter()
        .partition(|check| matches!(check.state, CheckState::Info));

    // Keep the pasteable support header stable while leaving any future facts
    // in model order after these two identity lines.
    facts.sort_by_key(|check| info_fact_rank(&check.label));

    for check in facts.into_iter().chain(rows) {
        render_check(check);
    }
}

fn info_fact_rank(label: &str) -> u8 {
    match label {
        "Platform" => 0,
        "Version" => 1,
        _ => 2,
    }
}

/// Render one check. Pass/fail use the `✓`/`✗ <label> <detail>` completion
/// format; informational facts render as an `info <label>: <value>` line.
fn render_check(check: &microsandbox::setup::Check) {
    use microsandbox::setup::CheckState;
    match check.state {
        CheckState::Pass => ui::success(&check.label, &check.value),
        CheckState::Fail => ui::failure(&check.label, &check.value),
        CheckState::Warn => {
            eprintln!(
                "   {} {:<12} {}",
                style("!").yellow(),
                check.label,
                check.value
            );
        }
        CheckState::Info => info(&format!("{}: {}", check.label, check.value)),
    }
}

/// Render a single problem as a styled `error:` block with `→` lines.
///
/// When the problem carries a [`Fix`](microsandbox::setup::Fix), its commands
/// are listed; `offer_fix_flag` adds a pointer to `msb doctor --fix` (shown
/// when we're not already in fix mode).
fn render_problem(problem: &microsandbox::setup::Problem, offer_fix_flag: bool) {
    let mut lines: Vec<String> = problem.hints.clone();

    if let Some(fix) = &problem.fix {
        lines.push(format!("fix: {}", fix.description));
        for command in &fix.commands {
            lines.push(format!("  {}", command.display()));
        }
        if offer_fix_flag {
            lines.push("apply automatically: msb doctor --fix".to_string());
        }
    }

    let error_lines: Vec<ui::ErrorLine<'_>> =
        lines.iter().map(|line| ui::ErrorLine::Hint(line)).collect();
    ui::error_with_lines(&problem.headline, &error_lines);
}

/// Apply a fix's commands after an optional confirmation prompt.
///
/// Returns whether the fix was attempted (i.e. the user agreed). Individual
/// command failures are reported but don't abort the remaining commands — the
/// re-check determines the real outcome.
fn apply_fix(fix: &microsandbox::setup::Fix, assume_yes: bool) -> anyhow::Result<bool> {
    if !assume_yes && !confirm(&format!("Apply fix — {}? [y/N] ", fix.description))? {
        info("Skipped.");
        return Ok(false);
    }

    // Pre-authenticate sudo up front so its password prompt doesn't collide
    // with the per-command spinner below. After this, the cached credential
    // lets the fix commands run without prompting.
    if fix.commands.iter().any(|command| command.program == "sudo") {
        let status = Command::new("sudo")
            .arg("-v")
            .status()
            .map_err(|e| anyhow::anyhow!("could not pre-authenticate sudo: {e}"))?;
        if !status.success() {
            anyhow::bail!("sudo authentication failed ({status}); no fix commands were run");
        }
    }

    for command in &fix.commands {
        let spinner = ui::Spinner::start("Applying", &command.display());
        match Command::new(&command.program).args(&command.args).status() {
            Ok(status) if status.success() => spinner.finish_success("Applied"),
            Ok(status) => {
                spinner.finish_fail("Failed");
                ui::warn(&format!("`{}` exited with {status}", command.display()));
            }
            Err(e) => {
                spinner.finish_fail("Failed");
                ui::warn(&format!("could not run `{}`: {e}", command.display()));
            }
        }
    }

    // The fix was attempted; the re-check determines the real outcome.
    Ok(true)
}

/// Prompt for a yes/no confirmation on stderr. Errors on a non-interactive
/// terminal so `--fix` never silently mutates the host without `--yes`.
fn confirm(prompt: &str) -> anyhow::Result<bool> {
    if !std::io::stdin().is_terminal() {
        anyhow::bail!("non-interactive terminal; pass --yes to apply fixes");
    }

    eprint!("{prompt}");
    std::io::stderr().flush().ok();

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    Ok(input.trim().eq_ignore_ascii_case("y"))
}

/// Whether this diagnosis includes the WHP host prerequisite problem.
#[cfg(windows)]
fn has_windows_hypervisor_problem(diagnosis: &microsandbox::setup::Diagnosis) -> bool {
    diagnosis
        .problems
        .iter()
        .any(|problem| problem.headline == "Windows Hypervisor Platform is not available")
}

/// Apply the elevated Windows Hypervisor Platform enable flow.
#[cfg(windows)]
fn apply_windows_fix(assume_yes: bool) -> anyhow::Result<bool> {
    if !assume_yes && !confirm("Apply fix — enable Windows Hypervisor Platform? [y/N] ")? {
        info("Skipped.");
        return Ok(false);
    }

    eprintln!();
    enable_windows_hypervisor_platform()?;
    Ok(true)
}

#[cfg(windows)]
fn enable_windows_hypervisor_platform() -> anyhow::Result<()> {
    let command = microsandbox::setup::ENABLE_HYPERVISOR_PLATFORM_COMMAND;
    let script = format!(
        "$p = Start-Process -FilePath powershell.exe -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-Command','{}') -Verb RunAs -Wait -PassThru; exit $p.ExitCode",
        command.replace('\'', "''")
    );

    info("Opening elevated PowerShell to enable Windows Hypervisor Platform.");
    let status = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &script,
        ])
        .status()?;

    if !status.success() {
        anyhow::bail!(
            "failed to enable Windows Hypervisor Platform (status: {status}); rerun without --fix for manual instructions"
        );
    }

    done("Windows Hypervisor Platform enable command completed.");
    Ok(())
}

/// Update msb and libkrunfw to the latest release.
pub async fn run_update(args: SelfUpdateArgs) -> anyhow::Result<()> {
    info(&format!("Current version: v{CURRENT_VERSION}"));

    let spinner = ui::Spinner::start("Checking", "latest release");
    let latest = fetch_latest_version().await?;
    spinner.finish_clear();

    info(&format!("Latest version: {latest}"));

    let latest_clean = latest.strip_prefix('v').unwrap_or(&latest);
    if !args.force && latest_clean == CURRENT_VERSION {
        done("Already up to date.");
        link_public_commands(&resolve_base_dir()?)?;
        return Ok(());
    }

    let base_dir = resolve_base_dir()?;
    let bin_dir = base_dir.join(microsandbox_utils::BIN_SUBDIR);
    let lib_dir = base_dir.join(microsandbox_utils::LIB_SUBDIR);

    let spinner = ui::Spinner::start("Updating", &format!("to {latest}"));
    let result = microsandbox::setup::Setup::builder()
        .base_dir(base_dir.clone())
        .version(latest_clean.to_string())
        .force(true)
        .build()
        .install()
        .await;

    match result {
        Ok(()) => {
            spinner.finish_clear();
            done(&format!("Updated msb in {}", bin_dir.display()));
            done(&format!("Updated libkrunfw in {}/", lib_dir.display()));
            link_public_commands(&base_dir)?;
        }
        Err(e) => {
            spinner.finish_clear();
            anyhow::bail!("update failed: {e}");
        }
    }

    Ok(())
}

/// Downgrade msb and local state to an older supported release.
pub async fn run_downgrade(args: SelfDowngradeArgs) -> anyhow::Result<()> {
    run_downgrade_local(args).await
}

async fn run_downgrade_local(args: SelfDowngradeArgs) -> anyhow::Result<()> {
    let current_version = Version::parse(CURRENT_VERSION)?;
    let target_version = Version::parse(&args.version)?;

    info(&format!("Current version: v{current_version}"));
    info(&format!("Target version: v{target_version}"));

    if target_version >= current_version {
        return refuse_static(
            &format!("v{target_version} is not older than the current version"),
            &["use `msb self update` to move to the latest release"],
        );
    }

    if target_version < MIN_DOWNGRADE_VERSION {
        return refuse_static(
            &format!("v{target_version} is below the supported downgrade floor"),
            &["minimum supported downgrade target: 0.6.0"],
        );
    }

    let spinner = ui::Spinner::start("Checking", &format!("release {target_version}"));
    let target_baseline = match async {
        fetch_release_tag(target_version).await?;
        load_target_schema_baseline(target_version).await
    }
    .await
    {
        Ok(baseline) => {
            spinner.finish_clear();
            baseline
        }
        Err(err) => {
            spinner.finish_clear();
            return Err(err);
        }
    };

    let base_dir = resolve_base_dir()?;
    let db_dir = base_dir.join(microsandbox_utils::DB_SUBDIR);
    let db_path = db_dir.join(microsandbox_utils::DB_FILENAME);
    let db = open_downgrade_db(&db_path).await?;
    let applied_migrations = applied_migrations(db.inner()).await?;
    let rollback_plan = build_rollback_plan(&target_baseline, &applied_migrations)?;
    refuse_irreversible_rollback(&rollback_plan)?;
    let user_data_warnings = if rollback_plan.affects_user_data {
        user_data_warnings(db.inner()).await?
    } else {
        Vec::new()
    };

    let backup_path = if rollback_plan.steps() > 0 && !args.no_backup {
        Some(next_backup_path(&db_dir, current_version, target_version)?)
    } else {
        None
    };

    if rollback_plan.has_destructive_steps(args.keep_cache) {
        warn_downgrade_plan(
            target_version,
            &rollback_plan,
            backup_path.as_deref(),
            &user_data_warnings,
            &args,
        );
        if !args.yes && !confirm_downgrade("Proceed?")? {
            info("Aborted.");
            return Ok(());
        }
    }

    let mut install_lease = if maintenance_lease_available(&applied_migrations) {
        Some(microsandbox_runtime::maintenance::acquire_install_exclusive_lease(&db).await?)
    } else {
        None
    };

    let result = run_downgrade_with_db(DowngradeRunContext {
        db: &db,
        base_dir: &base_dir,
        db_path: &db_path,
        backup_path: backup_path.as_deref(),
        target_version,
        target_baseline: &target_baseline,
        planned_applied_migrations: &applied_migrations,
        rollback_plan: &rollback_plan,
        install_lease: install_lease.as_mut(),
        args: &args,
    })
    .await;

    let clear_lease_in_parent = result
        .as_ref()
        .map(DowngradeRunOutcome::clear_lease_in_parent)
        .unwrap_or(true);
    if clear_lease_in_parent && let Some(lease) = install_lease.as_ref() {
        let clear_result =
            microsandbox_runtime::maintenance::clear_install_exclusive_lease(&db, lease).await;
        if let Err(err) = clear_result {
            ui::warn(&format!("failed to clear downgrade lease: {err}"));
        }
    }

    result.map(|_| ())
}

async fn run_downgrade_with_db(
    mut ctx: DowngradeRunContext<'_>,
) -> anyhow::Result<DowngradeRunOutcome> {
    let db_dir = ctx
        .db_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("database path has no parent: {}", ctx.db_path.display()))?;

    {
        let _migration_lock = acquire_migration_lock(db_dir)?;
        let fresh_applied = applied_migrations(ctx.db.inner()).await?;
        ensure_applied_unchanged(ctx.planned_applied_migrations, &fresh_applied)?;
        let fresh_plan = build_rollback_plan(ctx.target_baseline, &fresh_applied)?;
        refuse_irreversible_rollback(&fresh_plan)?;
        ensure_plan_unchanged(ctx.rollback_plan, &fresh_plan)?;
        renew_install_lease_if_present(ctx.db, &mut ctx.install_lease).await?;

        if !maintenance_lease_available(&fresh_applied) && fresh_plan.steps() > 0 {
            refuse_static(
                "downgrade needs the local-state lock table",
                &["run msb once with the current version, then retry"],
            )?;
            unreachable!("refuse_static always returns an error");
        }

        if fresh_plan.steps() > 0 || (cfg!(windows) && !fresh_applied.is_empty()) {
            refuse_if_active_sandboxes(ctx.db.inner()).await?;
        }

        if let Some(path) = ctx.backup_path {
            let spinner =
                ui::Spinner::start("Backing up", &relative_or_display(ctx.base_dir, path));
            match run_with_install_lease_renewal(ctx.db, &mut ctx.install_lease, async {
                vacuum_into(ctx.db.inner(), path).await
            })
            .await
            {
                Ok(()) => spinner.finish_success("Backed up"),
                Err(err) => {
                    spinner.finish_clear();
                    return Err(err);
                }
            }
            renew_install_lease_if_present(ctx.db, &mut ctx.install_lease).await?;
        }

        if fresh_plan.steps() > 0 {
            let spinner = ui::Spinner::start("Rolling back", "local database changes");
            match run_with_install_lease_renewal(ctx.db, &mut ctx.install_lease, async {
                rollback_schema(ctx.db.inner(), fresh_plan.steps()).await
            })
            .await
            {
                Ok(()) => spinner.finish_success("Rolled back"),
                Err(err) => {
                    spinner.finish_clear();
                    let _ = Migrator::up(ctx.db.inner(), None).await;
                    return Err(err);
                }
            }
            renew_install_lease_if_present(ctx.db, &mut ctx.install_lease).await?;
        }
    }

    if ctx.rollback_plan.affects_cache && !ctx.args.keep_cache {
        let spinner = ui::Spinner::start("Purging", "cache");
        let base_dir = ctx.base_dir.to_path_buf();
        match run_with_install_lease_renewal(ctx.db, &mut ctx.install_lease, async move {
            tokio::task::spawn_blocking(move || purge_cache(&base_dir)).await?
        })
        .await
        {
            Ok(()) => spinner.finish_success("Purged"),
            Err(err) => {
                spinner.finish_clear();
                return Err(err);
            }
        }
    }
    renew_install_lease_if_present(ctx.db, &mut ctx.install_lease).await?;

    install_target_release(&mut ctx).await
}

#[cfg(not(windows))]
async fn install_target_release(
    ctx: &mut DowngradeRunContext<'_>,
) -> anyhow::Result<DowngradeRunOutcome> {
    let spinner = ui::Spinner::start("Installing", &format!("msb v{}", ctx.target_version));
    let result = run_with_install_lease_renewal(ctx.db, &mut ctx.install_lease, async {
        microsandbox::setup::Setup::builder()
            .base_dir(ctx.base_dir.to_path_buf())
            .version(ctx.target_version.to_string())
            .allow_ci_local_bundle(false)
            .force(true)
            .build()
            .install()
            .await
            .map_err(anyhow::Error::from)
    })
    .await;
    match result {
        Ok(()) => spinner.finish_success("Installed"),
        Err(err) => {
            spinner.finish_clear();
            return Err(err);
        }
    }

    verify_installed_msb_version(ctx.base_dir, ctx.target_version).await?;
    link_public_commands(ctx.base_dir)?;
    done(&format!("Downgraded to v{}", ctx.target_version));
    Ok(DowngradeRunOutcome::Complete)
}

#[cfg(windows)]
async fn install_target_release(
    ctx: &mut DowngradeRunContext<'_>,
) -> anyhow::Result<DowngradeRunOutcome> {
    let staged_dir = stage_windows_target_release(ctx).await?;
    let log_path = schedule_windows_downgrade_swap(ctx, &staged_dir)?;

    ui::success(
        "Scheduled",
        &format!(
            "Windows swap after this msb process exits; log: {}",
            log_path.display()
        ),
    );
    done(&format!(
        "Downgrade to v{} will complete after exit",
        ctx.target_version
    ));

    Ok(DowngradeRunOutcome::WindowsSwapScheduled)
}

#[cfg(windows)]
async fn stage_windows_target_release(
    ctx: &mut DowngradeRunContext<'_>,
) -> anyhow::Result<PathBuf> {
    let temp = tempfile::Builder::new()
        .prefix("msb-downgrade-stage-")
        .tempdir()?;
    let staged_dir = temp.keep();

    let spinner = ui::Spinner::start("Staging", &format!("msb v{}", ctx.target_version));
    let install_dir = staged_dir.clone();
    let target_version = ctx.target_version;
    let target_version_string = target_version.to_string();
    let result = run_with_install_lease_renewal(ctx.db, &mut ctx.install_lease, async move {
        microsandbox::setup::Setup::builder()
            .base_dir(install_dir)
            .version(target_version_string)
            .allow_ci_local_bundle(false)
            .force(true)
            .build()
            .install()
            .await
            .map_err(anyhow::Error::from)
    })
    .await;
    match result {
        Ok(()) => spinner.finish_success("Staged"),
        Err(err) => {
            spinner.finish_clear();
            return Err(err);
        }
    }

    verify_installed_msb_version(&staged_dir, target_version).await?;
    Ok(staged_dir)
}

#[cfg(windows)]
fn schedule_windows_downgrade_swap(
    ctx: &DowngradeRunContext<'_>,
    staged_dir: &Path,
) -> anyhow::Result<PathBuf> {
    let helper_dir = tempfile::Builder::new()
        .prefix("msb-downgrade-helper-")
        .tempdir()?
        .keep();
    let helper_path = helper_dir.join(format!("msb-downgrade-helper-{}.exe", std::process::id()));
    fs::copy(std::env::current_exe()?, &helper_path)?;

    let log_dir = ctx.base_dir.join(microsandbox_utils::LOGS_SUBDIR);
    fs::create_dir_all(&log_dir)?;
    let log_path = log_dir.join(format!(
        "self-downgrade-{CURRENT_VERSION}-to-{}-{}.log",
        ctx.target_version,
        std::process::id()
    ));

    let mut command = Command::new(&helper_path);
    command
        .arg("__windows-self-downgrade-swap")
        .arg("--parent-pid")
        .arg(std::process::id().to_string())
        .arg("--base-dir")
        .arg(ctx.base_dir)
        .arg("--staged-dir")
        .arg(staged_dir)
        .arg("--target-version")
        .arg(ctx.target_version.to_string())
        .arg("--log-path")
        .arg(&log_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    if let Some(lease) = ctx.install_lease.as_ref() {
        let lease = **lease;
        command
            .arg("--lease-holder-pid")
            .arg(lease.holder_pid.to_string())
            .arg("--lease-expires-at")
            .arg(
                lease
                    .lease_expires_at
                    .and_utc()
                    .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
            );
    }

    command.spawn()?;
    Ok(log_path)
}

/// Complete a deferred Windows self-downgrade after the original msb exits.
#[cfg(windows)]
pub async fn run_windows_self_downgrade_swap(
    args: WindowsSelfDowngradeSwapArgs,
) -> anyhow::Result<()> {
    if let Some(parent) = args.log_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&args.log_path)?;

    writeln!(
        log,
        "starting deferred downgrade swap to v{}",
        args.target_version
    )?;
    let swap_result = perform_windows_downgrade_swap(&args, &mut log).await;
    if let Err(err) = &swap_result {
        let _ = writeln!(log, "swap failed: {err:#}");
    }

    if let Err(err) = clear_windows_downgrade_lease(&args, &mut log).await {
        let _ = writeln!(
            log,
            "warning: failed to clear install-exclusive lease: {err:#}"
        );
    }
    if let Err(err) = remove_windows_swap_staging(&args.staged_dir, &mut log) {
        let _ = writeln!(log, "warning: failed to remove staged release: {err:#}");
    }
    if let Err(err) = schedule_windows_helper_cleanup(&mut log) {
        let _ = writeln!(log, "warning: failed to schedule helper cleanup: {err:#}");
    }

    if swap_result.is_ok() {
        writeln!(log, "deferred downgrade swap completed")?;
    }

    swap_result
}

#[cfg(windows)]
async fn perform_windows_downgrade_swap(
    args: &WindowsSelfDowngradeSwapArgs,
    log: &mut File,
) -> anyhow::Result<()> {
    wait_for_parent_process_exit(args.parent_pid, log)?;

    let target_version = Version::parse(&args.target_version)?;
    let msb_name = microsandbox_utils::msb_binary_filename("windows");
    let libkrunfw_name = microsandbox_utils::libkrunfw_filename("windows");
    let staged_bin = args.staged_dir.join(microsandbox_utils::BIN_SUBDIR);
    let staged_lib = args.staged_dir.join(microsandbox_utils::LIB_SUBDIR);
    let target_bin = args.base_dir.join(microsandbox_utils::BIN_SUBDIR);
    let target_lib = args.base_dir.join(microsandbox_utils::LIB_SUBDIR);

    // Copy the executable before the DLL. If the swap fails halfway, a target
    // CLI with the newer current DLL is safer than a newer CLI against the
    // rolled-back database and an older DLL.
    copy_windows_swap_file_with_retries(
        &staged_bin.join(&msb_name),
        &target_bin.join(&msb_name),
        "msb.exe",
        log,
    )?;
    copy_windows_swap_file_with_retries(
        &staged_lib.join(&libkrunfw_name),
        &target_lib.join(&libkrunfw_name),
        "libkrunfw.dll",
        log,
    )?;

    verify_installed_msb_version(&args.base_dir, target_version).await?;
    Ok(())
}

#[cfg(windows)]
async fn clear_windows_downgrade_lease(
    args: &WindowsSelfDowngradeSwapArgs,
    log: &mut File,
) -> anyhow::Result<()> {
    let (Some(holder_pid), Some(expires_at)) =
        (args.lease_holder_pid, args.lease_expires_at.as_deref())
    else {
        writeln!(log, "no install-exclusive lease was passed to helper")?;
        return Ok(());
    };

    let lease_expires_at = chrono::DateTime::parse_from_rfc3339(expires_at)?.naive_utc();
    let lease = microsandbox_runtime::maintenance::InstallExclusiveLease {
        holder_pid,
        lease_expires_at,
    };
    let db_path = args
        .base_dir
        .join(microsandbox_utils::DB_SUBDIR)
        .join(microsandbox_utils::DB_FILENAME);
    let db = open_downgrade_db(&db_path).await?;
    microsandbox_runtime::maintenance::clear_install_exclusive_lease(&db, &lease).await?;

    writeln!(log, "cleared install-exclusive lease")?;
    Ok(())
}

#[cfg(windows)]
fn wait_for_parent_process_exit(parent_pid: i32, log: &mut File) -> anyhow::Result<()> {
    writeln!(log, "waiting for parent process {parent_pid} to exit")?;
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while microsandbox_utils::process::pid_is_alive(parent_pid)
        && std::time::Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(250));
    }
    Ok(())
}

#[cfg(windows)]
fn copy_windows_swap_file_with_retries(
    src: &Path,
    dest: &Path,
    label: &str,
    log: &mut File,
) -> anyhow::Result<()> {
    let Some(parent) = dest.parent() else {
        anyhow::bail!("target path has no parent: {}", dest.display());
    };
    fs::create_dir_all(parent)?;

    let mut last_err = None;
    for attempt in 1..=80 {
        match fs::copy(src, dest) {
            Ok(_) => {
                writeln!(log, "replaced {label} on attempt {attempt}")?;
                return Ok(());
            }
            Err(err) => {
                last_err = Some(err);
                std::thread::sleep(Duration::from_millis(250));
            }
        }
    }

    let err = last_err
        .map(|err| err.to_string())
        .unwrap_or_else(|| "unknown error".to_string());
    anyhow::bail!("failed to replace {label} after waiting for file locks: {err}");
}

#[cfg(windows)]
fn remove_windows_swap_staging(staged_dir: &Path, log: &mut File) -> anyhow::Result<()> {
    match fs::remove_dir_all(staged_dir) {
        Ok(()) => writeln!(log, "removed staged release {}", staged_dir.display())?,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }

    Ok(())
}

#[cfg(windows)]
fn schedule_windows_helper_cleanup(log: &mut File) -> anyhow::Result<()> {
    let helper_exe = std::env::current_exe()?;
    let Some(helper_dir) = helper_exe.parent() else {
        return Ok(());
    };

    let helper_dir_script = powershell_single_quote(&helper_dir.display().to_string());
    let parent_pid = std::process::id();
    let script = format!(
        r#"
$ErrorActionPreference = 'SilentlyContinue'
$helper = {helper_dir_script}
$parent = {parent_pid}
Wait-Process -Id $parent -Timeout 30
for ($i = 0; $i -lt 80; $i++) {{
    if (-not (Test-Path -LiteralPath $helper)) {{
        exit 0
    }}
    Remove-Item -LiteralPath $helper -Recurse -Force
    if (-not (Test-Path -LiteralPath $helper)) {{
        exit 0
    }}
    Start-Sleep -Milliseconds 250
}}
exit 1
"#
    );

    Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            &encode_powershell_command(&script),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    writeln!(
        log,
        "scheduled cleanup for helper directory {}",
        helper_dir.display()
    )?;
    Ok(())
}

async fn run_uninstall(args: SelfUninstallArgs) -> anyhow::Result<()> {
    let base_dir = resolve_base_dir()?;

    if !base_dir.exists() {
        info("Nothing to uninstall.");
        return Ok(());
    }

    // Non-interactive: remove everything.
    if args.yes {
        return uninstall_all(&base_dir);
    }

    let term = Term::stderr();
    if !term.is_term() {
        anyhow::bail!("non-interactive terminal; use --yes to remove everything");
    }

    ui::warn(&format!(
        "this will modify your {} installation",
        base_dir.display(),
    ));

    let labels: Vec<&str> = UninstallCategory::ITEMS.iter().map(|c| c.label()).collect();
    let selections = multi_select(&term, &labels)?;

    if selections.is_empty() {
        info("Nothing selected.");
        return Ok(());
    }

    let selected: Vec<UninstallCategory> = selections
        .iter()
        .map(|&i| UninstallCategory::ITEMS[i])
        .collect();

    let is_all = selected.contains(&UninstallCategory::All);

    // Confirmation.
    let prompt = if is_all {
        "Remove everything?".to_string()
    } else {
        let names: Vec<&str> = selected.iter().map(|c| c.short_name()).collect();
        format!("Remove {}?", names.join(", "))
    };
    eprint!("{prompt} [y/N] ");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    if !input.trim().eq_ignore_ascii_case("y") {
        info("Aborted.");
        return Ok(());
    }

    if is_all {
        uninstall_all(&base_dir)?;
    } else {
        for category in &selected {
            remove_category(&base_dir, *category)?;
        }
    }

    Ok(())
}

/// Remove everything: command links, legacy shell config, and entire base directory.
fn uninstall_all(base_dir: &Path) -> anyhow::Result<()> {
    remove_public_command_links(base_dir)?;
    clean_legacy_shell_config()?;

    #[cfg(windows)]
    {
        uninstall_all_windows(base_dir)
    }

    #[cfg(not(windows))]
    {
        fs::remove_dir_all(base_dir)?;
        ui::success("Removed", &base_dir.display().to_string());
        done("Uninstall complete.");
        Ok(())
    }
}

#[cfg(windows)]
fn uninstall_all_windows(base_dir: &Path) -> anyhow::Result<()> {
    let base_dir = fs::canonicalize(base_dir).unwrap_or_else(|_| base_dir.to_path_buf());
    let base_dir_script = powershell_single_quote(&base_dir.display().to_string());
    let parent_pid = std::process::id();

    let script = format!(
        r#"
$ErrorActionPreference = 'Stop'
$base = {base_dir_script}
$parent = {parent_pid}
try {{
    Wait-Process -Id $parent -Timeout 30 -ErrorAction SilentlyContinue
}} catch {{
    Start-Sleep -Milliseconds 500
}}
for ($i = 0; $i -lt 80; $i++) {{
    if (-not (Test-Path -LiteralPath $base)) {{
        exit 0
    }}
    try {{
        Remove-Item -LiteralPath $base -Recurse -Force -ErrorAction Stop
        exit 0
    }} catch {{
        Start-Sleep -Milliseconds 250
    }}
}}
exit 1
"#
    );

    // Windows keeps the running executable locked, so self-uninstall cannot remove the install
    // directory in-process. This helper waits for the CLI to exit, then removes the directory.
    Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            &encode_powershell_command(&script),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    ui::success("Scheduled removal", &base_dir.display().to_string());
    done("Uninstall will complete after this msb process exits.");
    Ok(())
}

#[cfg(windows)]
fn powershell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

#[cfg(windows)]
fn encode_powershell_command(script: &str) -> String {
    use base64::Engine as _;

    let mut bytes = Vec::with_capacity(script.len() * 2);
    for unit in script.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }

    base64::engine::general_purpose::STANDARD.encode(bytes)
}

//--------------------------------------------------------------------------------------------------
// Functions: Multi-Select
//--------------------------------------------------------------------------------------------------

/// SIGINT handler that restores cursor visibility before exiting.
extern "C" fn sigint_show_cursor(_: libc::c_int) {
    let _ = std::io::stderr().write_all(b"\x1b[?25h");
    unsafe { libc::_exit(130) };
}

/// RAII guard that installs a SIGINT handler to restore cursor visibility
/// and restores the previous handler on drop.
struct SigintGuard {
    prev: libc::sighandler_t,
}

impl SigintGuard {
    fn install() -> Self {
        let prev = unsafe {
            libc::signal(
                libc::SIGINT,
                sigint_show_cursor as *const () as libc::sighandler_t,
            )
        };
        Self { prev }
    }
}

impl Drop for SigintGuard {
    fn drop(&mut self) {
        unsafe {
            libc::signal(libc::SIGINT, self.prev);
        }
    }
}

/// Interactive multi-select prompt. Returns indices of selected items.
///
/// Index 0 is treated as an "All" toggle: selecting it checks every item,
/// deselecting it unchecks every item. When all individual items are checked,
/// "All" is auto-checked; unchecking any individual item unchecks "All".
fn multi_select(term: &Term, items: &[&str]) -> anyhow::Result<Vec<usize>> {
    let mut selected = vec![false; items.len()];
    let mut cursor = 0usize;

    let _sigint = SigintGuard::install();
    term.hide_cursor()?;
    let mut lines = render_select(term, items, &selected, cursor)?;

    loop {
        match term.read_key()? {
            Key::ArrowUp | Key::Char('k') => {
                cursor = cursor.saturating_sub(1);
            }
            Key::ArrowDown | Key::Char('j') => {
                cursor = (cursor + 1).min(items.len() - 1);
            }
            Key::Char(' ') => {
                toggle_select(&mut selected, cursor);
            }
            Key::Enter => break,
            Key::Escape => {
                selected.fill(false);
                break;
            }
            _ => continue,
        }

        term.clear_last_lines(lines)?;
        lines = render_select(term, items, &selected, cursor)?;
    }

    term.clear_last_lines(lines)?;
    term.show_cursor()?;

    Ok(selected
        .iter()
        .enumerate()
        .filter(|&(_, &s)| s)
        .map(|(i, _)| i)
        .collect())
}

/// Render the multi-select list. Returns the number of lines written.
fn render_select(
    term: &Term,
    items: &[&str],
    selected: &[bool],
    cursor: usize,
) -> anyhow::Result<usize> {
    let mut lines = 0;

    for (i, item) in items.iter().enumerate() {
        let pointer = if i == cursor { ">" } else { " " };
        let check = if selected[i] {
            format!("{}", style("[x]").green())
        } else {
            format!("{}", style("[ ]").dim())
        };
        let label = if i == cursor {
            style(*item).bold().to_string()
        } else {
            item.to_string()
        };
        term.write_line(&format!("  {pointer} {check} {label}"))?;
        lines += 1;
    }

    term.write_line(&format!(
        "  {}",
        style("↑↓ navigate · space select · enter confirm · esc cancel").dim(),
    ))?;
    lines += 1;

    Ok(lines)
}

/// Toggle selection at the given cursor position, with "All" (index 0) linkage.
fn toggle_select(selected: &mut [bool], cursor: usize) {
    selected[cursor] = !selected[cursor];

    if cursor == 0 {
        // "All" toggled — propagate to every individual item.
        let state = selected[0];
        for s in selected.iter_mut().skip(1) {
            *s = state;
        }
    } else if !selected[cursor] {
        // Unchecked an individual → uncheck "All".
        selected[0] = false;
    } else if selected[1..].iter().all(|&s| s) {
        // All individuals now checked → auto-check "All".
        selected[0] = true;
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

async fn load_target_schema_baseline(target: Version) -> anyhow::Result<SchemaBaseline> {
    let temp = tempfile::tempdir()?;
    microsandbox::setup::Setup::builder()
        .base_dir(temp.path().to_path_buf())
        .version(target.to_string())
        .skip_verify(true)
        .allow_ci_local_bundle(false)
        .force(true)
        .build()
        .install()
        .await?;

    let msb_name = microsandbox_utils::msb_binary_filename(std::env::consts::OS);
    let msb_path = temp
        .path()
        .join(microsandbox_utils::BIN_SUBDIR)
        .join(msb_name);

    let output = TokioCommand::new(&msb_path)
        .arg("__schema-baseline")
        .arg("--json")
        .output()
        .await;

    match output {
        Ok(output) if output.status.success() => {
            let baseline = serde_json::from_slice::<SchemaBaseline>(&output.stdout)?;
            validate_schema_baseline(&baseline)?;
            Ok(baseline)
        }
        Ok(_output) if target == MIN_DOWNGRADE_VERSION => Ok(floor_0_6_0_baseline()),
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!(
                "target v{target} cannot report downgrade compatibility metadata: {}",
                stderr.trim()
            );
        }
        Err(err) if target == MIN_DOWNGRADE_VERSION => {
            tracing::debug!(error = %err, "using built-in 0.6.0 downgrade metadata");
            Ok(floor_0_6_0_baseline())
        }
        Err(err) => Err(err.into()),
    }
}

fn floor_0_6_0_baseline() -> SchemaBaseline {
    SchemaBaseline {
        schema_baseline_version: schema_metadata::SCHEMA_BASELINE_FORMAT_VERSION,
        downgrade_floor: schema_metadata::DOWNGRADE_FLOOR.to_string(),
        migrations: schema_metadata::BASELINE_0_6_0_MIGRATIONS
            .iter()
            .map(|id| (*id).to_string())
            .collect(),
    }
}

async fn open_downgrade_db(
    db_path: &Path,
) -> anyhow::Result<microsandbox_db::connection::DbWriteConnection> {
    if let Some(parent) = db_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let config = microsandbox::config::load_persisted_config_or_default()?;
    let db = microsandbox_db::connection::DbWriteConnection::open(
        db_path,
        std::time::Duration::from_secs(config.database.connect_timeout_secs),
        std::time::Duration::from_secs(config.database.busy_timeout_secs),
    )
    .await?;
    Ok(db)
}

async fn applied_migrations(db: &DatabaseConnection) -> anyhow::Result<Vec<String>> {
    let rows = match db
        .query_all(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT version FROM seaql_migrations ORDER BY applied_at ASC, version ASC",
        ))
        .await
    {
        Ok(rows) => rows,
        Err(err) if is_missing_migrations_table(&err) => return Ok(Vec::new()),
        Err(err) => return Err(err.into()),
    };

    rows.iter()
        .map(|row| row.try_get_by_index::<String>(0).map_err(Into::into))
        .collect()
}

async fn user_data_warnings(db: &DatabaseConnection) -> anyhow::Result<Vec<String>> {
    let snapshot_count = optional_count(db, "SELECT COUNT(*) FROM snapshot_index").await?;
    let disk_volume_count = optional_count(
        db,
        "SELECT COUNT(*) FROM volume WHERE kind = 'disk' OR disk_format IS NOT NULL OR disk_fstype IS NOT NULL",
    )
    .await?;

    let mut lines = Vec::new();
    if snapshot_count > 0 {
        lines.push(format!(
            "snapshots left untouched: {snapshot_count} indexed snapshot(s) may require a newer msb"
        ));
    }
    if disk_volume_count > 0 {
        lines.push(format!(
            "disk volumes left untouched: {disk_volume_count} disk-backed named volume(s) may require a newer msb"
        ));
    }

    Ok(lines)
}

async fn optional_count(db: &DatabaseConnection, sql: &str) -> anyhow::Result<i64> {
    let row = match db
        .query_one(Statement::from_string(DatabaseBackend::Sqlite, sql))
        .await
    {
        Ok(row) => row,
        Err(err) if is_missing_table_or_column(&err) => return Ok(0),
        Err(err) => return Err(err.into()),
    };

    let Some(row) = row else {
        return Ok(0);
    };

    Ok(row.try_get_by_index::<i64>(0)?)
}

fn build_rollback_plan(
    baseline: &SchemaBaseline,
    applied: &[String],
) -> anyhow::Result<RollbackPlan<'static>> {
    validate_schema_baseline(baseline)?;

    let current = schema_metadata::MIGRATION_METADATA;

    if baseline.migrations.len() > current.len() {
        anyhow::bail!(
            "target release metadata lists {} database change(s), but this binary only knows {}",
            baseline.migrations.len(),
            current.len()
        );
    }

    for (index, migration) in baseline.migrations.iter().enumerate() {
        let Some(current_metadata) = current.get(index) else {
            anyhow::bail!("target release metadata is longer than this binary understands");
        };
        if current_metadata.id != migration {
            anyhow::bail!(
                "target release is not compatible with this downgrade path: expected database change {}, got {} at index {}",
                current_metadata.id,
                migration,
                index,
            );
        }
    }

    if applied.len() > current.len() {
        anyhow::bail!(
            "local database lists {} applied change(s), but this binary only knows {}",
            applied.len(),
            current.len()
        );
    }

    for (index, migration) in applied.iter().enumerate() {
        let Some(current_metadata) = current.get(index) else {
            anyhow::bail!("local database was updated by a newer msb");
        };
        if current_metadata.id != migration {
            anyhow::bail!(
                "local database was updated by a newer msb: expected database change {}, got {} at index {}",
                current_metadata.id,
                migration,
                index,
            );
        }
    }

    let rollback_start = baseline.migrations.len();
    let rollback_end = applied.len();
    let rollback = if rollback_end > rollback_start {
        &current[rollback_start..rollback_end]
    } else {
        &[]
    };
    let affects_cache = rollback.iter().any(|metadata| metadata.affects_cache);
    let affects_user_data = rollback.iter().any(|metadata| metadata.affects_user_data);

    Ok(RollbackPlan {
        rollback,
        affects_cache,
        affects_user_data,
    })
}

fn validate_schema_baseline(baseline: &SchemaBaseline) -> anyhow::Result<()> {
    if baseline.schema_baseline_version != schema_metadata::SCHEMA_BASELINE_FORMAT_VERSION {
        anyhow::bail!(
            "unsupported downgrade metadata format version {}; expected {}",
            baseline.schema_baseline_version,
            schema_metadata::SCHEMA_BASELINE_FORMAT_VERSION
        );
    }

    Ok(())
}

fn refuse_irreversible_rollback(plan: &RollbackPlan<'_>) -> anyhow::Result<()> {
    let irreversible: Vec<_> = plan
        .rollback
        .iter()
        .filter(|metadata| !metadata.reversible)
        .collect();
    if irreversible.is_empty() {
        return Ok(());
    }

    let lines = irreversible
        .iter()
        .map(|metadata| metadata.summary.to_string())
        .collect();
    refuse_owned(
        "downgrade would cross irreversible local-state changes",
        lines,
    )
}

fn ensure_plan_unchanged(
    expected: &RollbackPlan<'_>,
    actual: &RollbackPlan<'_>,
) -> anyhow::Result<()> {
    let expected_ids: Vec<_> = expected
        .rollback
        .iter()
        .map(|metadata| metadata.id)
        .collect();
    let actual_ids: Vec<_> = actual.rollback.iter().map(|metadata| metadata.id).collect();

    if expected_ids == actual_ids
        && expected.affects_cache == actual.affects_cache
        && expected.affects_user_data == actual.affects_user_data
    {
        return Ok(());
    }

    refuse_static(
        "local database changed while downgrade was waiting",
        &["retry the downgrade so msb can show the updated rollback plan"],
    )
}

fn ensure_applied_unchanged(expected: &[String], actual: &[String]) -> anyhow::Result<()> {
    if expected == actual {
        return Ok(());
    }

    refuse_static(
        "local database changed while downgrade was waiting",
        &["retry the downgrade so msb can show the updated rollback plan"],
    )
}

fn maintenance_lease_available(applied: &[String]) -> bool {
    applied
        .iter()
        .any(|migration| migration == schema_metadata::MAINTENANCE_LEASE_MIGRATION_ID)
}

fn warn_downgrade_plan(
    target: Version,
    plan: &RollbackPlan<'_>,
    backup_path: Option<&Path>,
    user_data_warnings: &[String],
    args: &SelfDowngradeArgs,
) {
    let mut lines: Vec<String> = plan
        .rollback
        .iter()
        .map(|metadata| metadata.summary.to_string())
        .collect();

    if plan.affects_cache && !args.keep_cache {
        lines.push("cache will be purged".to_string());
    }

    lines.extend(user_data_warnings.iter().cloned());

    if plan.steps() > 0 {
        match backup_path {
            Some(path) => lines.push(format!("backup: {}", path.display())),
            None if args.no_backup => lines.push("backup: disabled by --no-backup".to_string()),
            None => {}
        }
    }

    let refs: Vec<ui::ErrorLine<'_>> = lines.iter().map(|line| ui::ErrorLine::Hint(line)).collect();
    ui::warn_with_lines(
        &format!("Downgrade will roll back local database changes added after {target}"),
        &refs,
    );
}

async fn refuse_if_active_sandboxes(db: &DatabaseConnection) -> anyhow::Result<()> {
    let write = microsandbox_db::connection::DbWriteConnection::new(db.clone());
    let active =
        microsandbox_runtime::maintenance::active_sandboxes_for_schema_rollback(&write).await?;

    if active.is_empty() {
        return Ok(());
    }

    let mut lines: Vec<String> = active
        .iter()
        .map(|sandbox| match sandbox.pid {
            Some(pid) => format!("{} (pid {pid})", sandbox.name),
            None => sandbox.name.clone(),
        })
        .collect();
    lines.push("run: msb stop --all, then retry".to_string());

    refuse_owned(
        &format!(
            "this downgrade updates local state while {} sandbox{} active",
            active.len(),
            if active.len() == 1 { " is" } else { "es are" },
        ),
        lines,
    )
}

async fn vacuum_into(db: &DatabaseConnection, backup_path: &Path) -> anyhow::Result<()> {
    if let Some(parent) = backup_path.parent() {
        fs::create_dir_all(parent)?;
    }

    db.execute(Statement::from_sql_and_values(
        DatabaseBackend::Sqlite,
        "VACUUM INTO ?",
        [backup_path.display().to_string().into()],
    ))
    .await?;
    Ok(())
}

async fn rollback_schema(db: &DatabaseConnection, steps: usize) -> anyhow::Result<()> {
    db.execute_unprepared("BEGIN EXCLUSIVE").await?;
    let down_result = Migrator::down(db, Some(steps as u32)).await;

    match down_result {
        Ok(()) => {
            db.execute_unprepared("COMMIT").await?;
            Ok(())
        }
        Err(err) => {
            let _ = db.execute_unprepared("ROLLBACK").await;
            Err(err.into())
        }
    }
}

fn is_missing_migrations_table(err: &DbErr) -> bool {
    let message = err.to_string();
    message.contains("no such table") && message.contains("seaql_migrations")
}

fn is_missing_table_or_column(err: &DbErr) -> bool {
    let message = err.to_string();
    message.contains("no such table") || message.contains("no such column")
}

fn purge_cache(base_dir: &Path) -> anyhow::Result<()> {
    let path = base_dir.join(microsandbox_utils::CACHE_SUBDIR);
    match fs::remove_dir_all(&path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

async fn renew_install_lease_if_present(
    db: &microsandbox_db::connection::DbWriteConnection,
    install_lease: &mut Option<&mut microsandbox_runtime::maintenance::InstallExclusiveLease>,
) -> anyhow::Result<()> {
    if let Some(lease) = install_lease.as_deref_mut() {
        microsandbox_runtime::maintenance::renew_install_exclusive_lease(db, lease).await?;
    }

    Ok(())
}

async fn run_with_install_lease_renewal<F, T>(
    db: &microsandbox_db::connection::DbWriteConnection,
    install_lease: &mut Option<&mut microsandbox_runtime::maintenance::InstallExclusiveLease>,
    operation: F,
) -> anyhow::Result<T>
where
    F: Future<Output = anyhow::Result<T>>,
{
    let Some(lease) = install_lease.as_deref_mut() else {
        return operation.await;
    };

    let renew_every = Duration::from_secs(
        (microsandbox_runtime::maintenance::INSTALL_EXCLUSIVE_LEASE_SECS as u64 / 3).max(1),
    );
    let mut interval = tokio::time::interval(renew_every);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    tokio::pin!(operation);

    loop {
        tokio::select! {
            result = &mut operation => return result,
            _ = interval.tick() => {
                microsandbox_runtime::maintenance::renew_install_exclusive_lease(db, lease).await?;
            }
        }
    }
}

async fn verify_installed_msb_version(base_dir: &Path, target: Version) -> anyhow::Result<()> {
    let msb_name = microsandbox_utils::msb_binary_filename(std::env::consts::OS);
    let msb_path = base_dir.join(microsandbox_utils::BIN_SUBDIR).join(msb_name);
    let output = TokioCommand::new(&msb_path)
        .arg("--version")
        .output()
        .await?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "installed msb version check failed with status {}: {}",
            output.status,
            stderr.trim()
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let installed = stdout
        .trim()
        .strip_prefix("msb ")
        .ok_or_else(|| anyhow::anyhow!("unexpected msb --version output: {}", stdout.trim()))?;
    if installed != target.to_string() {
        anyhow::bail!("installed msb version is {installed}, expected {target}");
    }

    Ok(())
}

#[cfg(unix)]
fn lock_migration_file(file: &File, path: &Path) -> anyhow::Result<()> {
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    if rc != 0 {
        return Err(anyhow::anyhow!(
            "failed to lock migration file {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }

    Ok(())
}

#[cfg(windows)]
fn lock_migration_file(file: &File, path: &Path) -> anyhow::Result<()> {
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        LockFileEx(
            file.as_raw_handle() as HANDLE,
            LOCKFILE_EXCLUSIVE_LOCK,
            0,
            u32::MAX,
            u32::MAX,
            &mut overlapped,
        )
    };
    if rc == 0 {
        return Err(anyhow::anyhow!(
            "failed to lock migration file {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }

    Ok(())
}

#[cfg(unix)]
fn unlock_migration_file(file: &File) -> anyhow::Result<()> {
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    Ok(())
}

#[cfg(windows)]
fn unlock_migration_file(file: &File) -> anyhow::Result<()> {
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        UnlockFileEx(
            file.as_raw_handle() as HANDLE,
            0,
            u32::MAX,
            u32::MAX,
            &mut overlapped,
        )
    };
    if rc == 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    Ok(())
}

fn acquire_migration_lock(db_dir: &Path) -> anyhow::Result<MigrationLock> {
    MigrationLock::acquire(db_dir.join(format!(
        "{}.migration.lock",
        microsandbox_utils::DB_FILENAME
    )))
}

fn next_backup_path(
    db_dir: &Path,
    current_version: Version,
    target_version: Version,
) -> anyhow::Result<PathBuf> {
    let base_name = format!("msb.db.bak-{current_version}-to-{target_version}");
    let base_path = db_dir.join(&base_name);
    if !base_path.exists() {
        return Ok(base_path);
    }

    let timestamp = chrono::Utc::now().format("%Y%m%d%H%M%S");
    Ok(db_dir.join(format!("{base_name}-{timestamp}")))
}

fn confirm_downgrade(prompt: &str) -> anyhow::Result<bool> {
    let term = Term::stderr();
    if !term.is_term() || !std::io::stdin().is_terminal() {
        anyhow::bail!("non-interactive terminal; use --yes to downgrade");
    }

    eprint!("{prompt} [y/N] ");
    std::io::stderr().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    Ok(input.trim().eq_ignore_ascii_case("y"))
}

fn refuse_static(msg: &str, context: &[&str]) -> anyhow::Result<()> {
    ui::error_context(msg, context);
    Err(ui::AlreadyRenderedError.into())
}

fn refuse_owned(msg: &str, context: Vec<String>) -> anyhow::Result<()> {
    let refs: Vec<&str> = context.iter().map(String::as_str).collect();
    refuse_static(msg, &refs)
}

fn relative_or_display(base_dir: &Path, path: &Path) -> String {
    path.strip_prefix(base_dir)
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| path.display().to_string())
}

/// Fetch the latest release tag from GitHub.
async fn fetch_latest_version() -> anyhow::Result<String> {
    let url = format!(
        "https://api.github.com/repos/{}/{}/releases/latest",
        microsandbox_utils::GITHUB_ORG,
        microsandbox_utils::MICROSANDBOX_REPO,
    );

    let client = reqwest::Client::new();
    let resp: serde_json::Value = client
        .get(&url)
        .header("User-Agent", format!("msb/{CURRENT_VERSION}"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let tag = resp["tag_name"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("could not parse latest release tag"))?;

    Ok(tag.to_string())
}

/// Verify that a specific release tag exists on GitHub.
async fn fetch_release_tag(version: Version) -> anyhow::Result<String> {
    let url = format!(
        "https://api.github.com/repos/{}/{}/releases/tags/v{}",
        microsandbox_utils::GITHUB_ORG,
        microsandbox_utils::MICROSANDBOX_REPO,
        version,
    );

    let client = reqwest::Client::new();
    let response = client
        .get(&url)
        .header("User-Agent", format!("msb/{CURRENT_VERSION}"))
        .send()
        .await?;

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        anyhow::bail!("no published microsandbox release found for v{version}");
    }

    let resp: serde_json::Value = response.error_for_status()?.json().await?;
    let tag = resp["tag_name"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("could not parse release tag for v{version}"))?;

    Ok(tag.to_string())
}

fn resolve_base_dir() -> anyhow::Result<PathBuf> {
    Ok(microsandbox_utils::resolve_home())
}

#[cfg(unix)]
fn local_bin_dir() -> Option<PathBuf> {
    dirs::home_dir().map(|home| home.join(".local").join("bin"))
}

#[cfg(unix)]
fn public_command_links(base_dir: &Path) -> Option<Vec<(PathBuf, PathBuf)>> {
    let local_bin = local_bin_dir()?;
    let bin_dir = base_dir.join(microsandbox_utils::BIN_SUBDIR);

    Some(vec![
        (local_bin.join("msb"), bin_dir.join("msb")),
        (local_bin.join("microsandbox"), bin_dir.join("microsandbox")),
    ])
}

fn link_public_commands(base_dir: &Path) -> anyhow::Result<()> {
    #[cfg(not(unix))]
    {
        info(&format!(
            "Add {} to PATH to run msb from any terminal.",
            base_dir.join(microsandbox_utils::BIN_SUBDIR).display()
        ));
        Ok(())
    }

    #[cfg(unix)]
    {
        let Some(links) = public_command_links(base_dir) else {
            ui::warn("Skipped command links because no home directory was found");
            return Ok(());
        };

        if let Some(parent) = links.first().and_then(|(link, _)| link.parent()) {
            fs::create_dir_all(parent)?;
        }

        for (link, target) in links {
            if link.exists() && !link.is_symlink() {
                ui::warn(&format!(
                    "Skipped {} because it already exists",
                    link.display()
                ));
                continue;
            }

            if link.is_symlink() {
                fs::remove_file(&link)?;
            }

            #[cfg(unix)]
            std::os::unix::fs::symlink(&target, &link)?;

            ui::success(
                "Linked",
                &format!("{} -> {}", link.display(), target.display()),
            );
        }

        Ok(())
    }
}

fn remove_public_command_links(base_dir: &Path) -> anyhow::Result<()> {
    #[cfg(not(unix))]
    {
        let _ = base_dir;
        Ok(())
    }

    #[cfg(unix)]
    {
        let Some(links) = public_command_links(base_dir) else {
            return Ok(());
        };

        for (link, target) in links {
            if !link.is_symlink() {
                continue;
            }

            if fs::read_link(&link)? == target {
                fs::remove_file(&link)?;
                ui::success("Removed", &link.display().to_string());
            }
        }

        Ok(())
    }
}

fn info(msg: &str) {
    eprintln!("{} {msg}", style("info").cyan().bold());
}

fn done(msg: &str) {
    eprintln!("{} {msg}", style("done").green().bold());
}

/// Remove a single uninstall category from the base directory.
fn remove_category(base_dir: &Path, category: UninstallCategory) -> anyhow::Result<()> {
    match category {
        UninstallCategory::All => unreachable!("handled before calling remove_category"),
        UninstallCategory::Sandboxes => {
            remove_subdir(base_dir, microsandbox_utils::SANDBOXES_SUBDIR, "sandboxes")
        }
        UninstallCategory::Volumes => {
            remove_subdir(base_dir, microsandbox_utils::VOLUMES_SUBDIR, "volumes")
        }
        UninstallCategory::Cache => {
            remove_subdir(base_dir, microsandbox_utils::CACHE_SUBDIR, "cache")
        }
        UninstallCategory::Installs => remove_installed_aliases(base_dir),
        UninstallCategory::Database => {
            remove_subdir(base_dir, microsandbox_utils::DB_SUBDIR, "database")
        }
        UninstallCategory::Logs => remove_subdir(base_dir, microsandbox_utils::LOGS_SUBDIR, "logs"),
        UninstallCategory::Secrets => {
            remove_subdir(base_dir, microsandbox_utils::SECRETS_SUBDIR, "secrets")?;
            remove_subdir(base_dir, microsandbox_utils::TLS_SUBDIR, "tls")?;
            remove_subdir(base_dir, microsandbox_utils::SSH_SUBDIR, "ssh")
        }
    }
}

/// Remove a subdirectory within the base directory.
fn remove_subdir(base_dir: &Path, subdir: &str, label: &str) -> anyhow::Result<()> {
    let path = base_dir.join(subdir);
    if path.exists() {
        std::fs::remove_dir_all(&path)?;
        ui::success("Removed", label);
    }
    Ok(())
}

/// Remove only msb-install-generated alias scripts from the bin directory,
/// leaving core binaries (msb, agentd) intact.
fn remove_installed_aliases(base_dir: &Path) -> anyhow::Result<()> {
    let bin_dir = base_dir.join(microsandbox_utils::BIN_SUBDIR);
    if !bin_dir.is_dir() {
        return Ok(());
    }

    for entry in std::fs::read_dir(&bin_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if let Ok(content) = std::fs::read_to_string(&path)
            && is_generated_alias(&content)
        {
            fs::remove_file(&path)?;
            let name = entry.file_name().to_string_lossy().to_string();
            ui::success("Removed", &format!("alias {name}"));
        }
    }

    Ok(())
}

/// Remove microsandbox marker blocks from shell config files left by older installers.
#[cfg(unix)]
fn clean_legacy_shell_config() -> anyhow::Result<()> {
    let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("no home dir"))?;

    for rc in [".profile", ".bash_profile", ".bashrc", ".zshrc"] {
        let path = home.join(rc);
        if path.exists() && remove_marker_block(&path)? {
            ui::success("Cleaned legacy shell config", &format!("~/{rc}"));
        }
    }

    let fish_conf = home.join(".config/fish/conf.d/microsandbox.fish");
    if fish_conf.exists() {
        fs::remove_file(&fish_conf)?;
        ui::success(
            "Removed legacy shell config",
            "~/.config/fish/conf.d/microsandbox.fish",
        );
    }

    Ok(())
}

/// Windows installers do not write Unix shell marker blocks.
#[cfg(not(unix))]
fn clean_legacy_shell_config() -> anyhow::Result<()> {
    Ok(())
}

/// Remove the marker block from a shell config file. Returns true if modified.
#[cfg(unix)]
fn remove_marker_block(path: &Path) -> anyhow::Result<bool> {
    let content = std::fs::read_to_string(path)?;
    if !content.contains(MARKER_START) {
        return Ok(false);
    }

    let mut result = String::new();
    let mut skip = false;
    for line in content.lines() {
        if line.contains(MARKER_START) {
            skip = true;
            continue;
        }
        if line.contains(MARKER_END) {
            skip = false;
            continue;
        }
        if !skip {
            result.push_str(line);
            result.push('\n');
        }
    }

    std::fs::write(path, result)?;
    Ok(true)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn info_fact_rank_keeps_support_header_first() {
        assert_eq!(info_fact_rank("Platform"), 0);
        assert_eq!(info_fact_rank("Version"), 1);
        assert_eq!(info_fact_rank("MSB_HOME"), 2);
    }

    #[tokio::test]
    async fn vacuum_into_writes_backup_file() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("msb.db");
        let db = microsandbox_db::connection::DbWriteConnection::open(
            &db_path,
            std::time::Duration::from_secs(5),
            std::time::Duration::from_secs(5),
        )
        .await
        .unwrap();
        db.execute_unprepared("CREATE TABLE sample (id INTEGER PRIMARY KEY, value TEXT NOT NULL)")
            .await
            .unwrap();
        db.execute_unprepared("INSERT INTO sample (id, value) VALUES (1, 'wal-value')")
            .await
            .unwrap();

        let backup_path = dir.path().join("backup").join("msb.db.bak");
        vacuum_into(db.inner(), &backup_path).await.unwrap();

        assert!(backup_path.exists());

        let backup_db = microsandbox_db::connection::DbWriteConnection::open(
            &backup_path,
            std::time::Duration::from_secs(5),
            std::time::Duration::from_secs(5),
        )
        .await
        .unwrap();
        let row = backup_db
            .query_one(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT value FROM sample WHERE id = 1",
            ))
            .await
            .unwrap()
            .unwrap();

        assert_eq!(row.try_get_by_index::<String>(0).unwrap(), "wal-value");
    }

    #[tokio::test]
    async fn rollback_schema_rolls_back_latest_migration() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("msb.db");
        let db = microsandbox_db::connection::DbWriteConnection::open(
            &db_path,
            std::time::Duration::from_secs(5),
            std::time::Duration::from_secs(5),
        )
        .await
        .unwrap();
        Migrator::up(db.inner(), None).await.unwrap();

        // Three steps: the two latest migrations (root disk, bind rootfs shape)
        // have no-op downs; `sandbox.active_config` sits below them. Roll back
        // through all three so the observable schema change (the column) is undone.
        rollback_schema(db.inner(), 3).await.unwrap();

        // Rolling back through the active_config migration must drop the column
        // while leaving older tables intact.
        let rows = db
            .query_all(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT name FROM pragma_table_info('sandbox') WHERE name = 'active_config'",
            ))
            .await
            .unwrap();
        assert!(rows.is_empty());

        let rows = db
            .query_all(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'maintenance_lease'",
            ))
            .await
            .unwrap();
        assert!(!rows.is_empty());
    }

    #[tokio::test]
    async fn user_data_warnings_list_snapshots_and_disk_volumes() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("msb.db");
        let db = microsandbox_db::connection::DbWriteConnection::open(
            &db_path,
            std::time::Duration::from_secs(5),
            std::time::Duration::from_secs(5),
        )
        .await
        .unwrap();
        db.execute_unprepared("CREATE TABLE snapshot_index (digest TEXT PRIMARY KEY)")
            .await
            .unwrap();
        db.execute_unprepared(
            "CREATE TABLE volume (kind TEXT, disk_format TEXT, disk_fstype TEXT)",
        )
        .await
        .unwrap();
        db.execute_unprepared("INSERT INTO snapshot_index (digest) VALUES ('sha256:test')")
            .await
            .unwrap();
        db.execute_unprepared(
            "INSERT INTO volume (kind, disk_format, disk_fstype) VALUES ('disk', 'raw', 'ext4')",
        )
        .await
        .unwrap();

        let warnings = user_data_warnings(db.inner()).await.unwrap();

        assert_eq!(warnings.len(), 2);
        assert!(warnings[0].contains("snapshots left untouched"));
        assert!(warnings[1].contains("disk volumes left untouched"));
    }

    #[test]
    fn version_parse_orders_release_versions() {
        assert!(Version::parse("0.6.1").unwrap() > Version::parse("v0.6.0").unwrap());
        assert!(Version::parse("0.5.10").unwrap() < MIN_DOWNGRADE_VERSION);
        assert!(Version::parse("0.6").is_err());
    }

    #[test]
    fn rollback_plan_uses_target_prefix() {
        let baseline = SchemaBaseline {
            schema_baseline_version: schema_metadata::SCHEMA_BASELINE_FORMAT_VERSION,
            downgrade_floor: schema_metadata::DOWNGRADE_FLOOR.to_string(),
            migrations: schema_metadata::BASELINE_0_6_0_MIGRATIONS
                .iter()
                .map(|id| (*id).to_string())
                .collect(),
        };
        let applied: Vec<String> = schema_metadata::migration_ids()
            .map(str::to_string)
            .collect();

        let plan = build_rollback_plan(&baseline, &applied).unwrap();

        assert_eq!(
            plan.steps(),
            schema_metadata::MIGRATION_METADATA.len()
                - schema_metadata::BASELINE_0_6_0_MIGRATIONS.len()
        );
    }

    #[test]
    fn rollback_plan_uses_applied_migrations_not_current_binary_length() {
        let baseline = SchemaBaseline {
            schema_baseline_version: schema_metadata::SCHEMA_BASELINE_FORMAT_VERSION,
            downgrade_floor: schema_metadata::DOWNGRADE_FLOOR.to_string(),
            migrations: schema_metadata::BASELINE_0_6_0_MIGRATIONS
                .iter()
                .map(|id| (*id).to_string())
                .collect(),
        };
        let applied: Vec<String> = schema_metadata::BASELINE_0_6_0_MIGRATIONS
            .iter()
            .map(|id| (*id).to_string())
            .collect();

        let plan = build_rollback_plan(&baseline, &applied).unwrap();

        assert_eq!(plan.steps(), 0);
        assert!(!plan.affects_cache);
        assert!(!plan.affects_user_data);
    }

    #[test]
    fn rollback_plan_rejects_non_prefix_baseline() {
        let baseline = SchemaBaseline {
            schema_baseline_version: schema_metadata::SCHEMA_BASELINE_FORMAT_VERSION,
            downgrade_floor: schema_metadata::DOWNGRADE_FLOOR.to_string(),
            migrations: vec!["not_a_real_migration".to_string()],
        };
        let applied = Vec::new();

        let err = build_rollback_plan(&baseline, &applied).unwrap_err();
        assert!(err.to_string().contains("not compatible"));
    }
}
