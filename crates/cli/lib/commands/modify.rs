//! `msb modify` command — plan and apply sandbox configuration changes.

use std::time::Duration;

use clap::Args;
use console::style;
use microsandbox::MicrosandboxError;
use microsandbox::sandbox::{
    ChangeKind, ConfigPlannedChange, ModificationDisposition, ModificationWarning, PlannedChange,
    ResourceConvergenceState, ResourceKind, ResourceResizeStatus, Sandbox, SandboxHandle,
    SandboxModificationBuilder, SandboxModificationPlan, SecretChangeKind, SecretPlannedChange,
    SecretSource,
};
use microsandbox_protocol::control::DEFAULT_REQUEST_TIMEOUT;
use tokio::time::Instant;

use super::common;
use crate::ui;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const DEFAULT_RESIZE_WAIT_SECS: u64 = 60;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Modify a sandbox configuration.
#[derive(Debug, Args)]
pub struct ModifyArgs {
    /// Sandbox to modify.
    pub name: String,

    /// Compact sealed layers of the root and sandbox-owned data disks without changing snapshots.
    #[arg(long, conflicts_with_all = ["cpus", "max_cpus", "memory", "max_memory", "root_disk", "oci_upper_size", "env", "env_remove", "labels", "label_remove", "workdir", "secrets", "secret_remove", "next_start", "restart"])]
    pub compact: bool,

    /// Merge up to N oldest sealed physical layers per disk, including the base (minimum 2).
    #[arg(long, requires = "compact", value_name = "N")]
    pub layers: Option<usize>,

    /// Compact only this owned disk's guest mount path (`/` selects the root).
    #[arg(
        long,
        requires = "compact",
        conflicts_with = "root_disk_only",
        value_name = "GUEST"
    )]
    pub disk: Option<String>,

    /// Compact only the root disk.
    #[arg(long, requires = "compact", conflicts_with = "disk")]
    pub root_disk_only: bool,

    /// Desired effective vCPU count.
    #[arg(short = 'c', long)]
    pub cpus: Option<u8>,

    /// Desired boot-time maximum possible vCPU count.
    #[arg(long = "max-cpus")]
    pub max_cpus: Option<u8>,

    /// Desired effective guest memory size, such as `512M` or `4G`.
    #[arg(short, long)]
    pub memory: Option<String>,

    /// Desired boot-time maximum hotpluggable memory, such as `4G` or `16G`.
    #[arg(long = "max-memory")]
    pub max_memory: Option<String>,

    /// Desired root disk size, such as `8G` (managed: grow-only; tmpfs: any
    /// direction, next boot).
    #[arg(long = "root-disk", value_name = "SIZE")]
    pub root_disk: Option<String>,

    /// Deprecated alias for `--root-disk <SIZE>`.
    #[arg(
        long = "oci-upper-size",
        value_name = "SIZE",
        hide = true,
        conflicts_with = "root_disk"
    )]
    pub oci_upper_size: Option<String>,

    /// Set an environment variable for future execs (`KEY=VALUE`).
    #[arg(short, long = "env", value_name = "KEY=VALUE")]
    pub env: Vec<String>,

    /// Remove an environment variable by key.
    #[arg(long = "env-rm", value_name = "KEY")]
    pub env_remove: Vec<String>,

    /// Set a label (`KEY=VALUE`).
    #[arg(long = "label", value_name = "KEY=VALUE")]
    pub labels: Vec<String>,

    /// Remove a label by key.
    #[arg(long = "label-rm", value_name = "KEY")]
    pub label_remove: Vec<String>,

    /// Working directory for future execs.
    #[arg(short, long, value_name = "PATH")]
    pub workdir: Option<String>,

    /// Add or rotate a secret from a host environment variable
    /// (`NAME@HOST[,HOST...]`).
    #[arg(long = "secret", value_name = "NAME@HOST[,HOST...]")]
    pub secrets: Vec<String>,

    /// Remove a secret by name.
    #[arg(long = "secret-rm", value_name = "NAME")]
    pub secret_remove: Vec<String>,

    /// Show the plan without applying anything.
    #[arg(long)]
    pub dry_run: bool,

    /// Save changes for the next start without mutating a running VM.
    #[arg(long, conflicts_with = "restart")]
    pub next_start: bool,

    /// Restart if needed so restart-required changes become active now.
    #[arg(long)]
    pub restart: bool,

    /// Wait for any pending live CPU and memory resize to converge in the guest.
    #[arg(long, conflicts_with_all = ["dry_run", "next_start", "compact"])]
    pub wait: bool,

    /// Resize wait budget in seconds (default 60; 0 checks once).
    #[arg(long, requires = "wait", value_name = "SECS")]
    pub timeout: Option<u64>,

    /// Output format.
    #[arg(long, value_name = "FORMAT", value_parser = ["json"])]
    pub format: Option<String>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute the `msb modify` command.
pub async fn run(args: ModifyArgs) -> anyhow::Result<()> {
    let json = args.format.as_deref() == Some("json");
    let handle = Sandbox::get(&args.name).await?;
    if args.compact {
        let mut compact = handle.compact();
        if let Some(layers) = args.layers {
            compact = compact.layers(layers);
        }
        if let Some(disk) = args.disk {
            compact = compact.disk(disk);
        }
        if args.root_disk_only {
            compact = compact.root_disk_only();
        }
        let result = if args.dry_run {
            compact.dry_run().await?
        } else {
            compact.apply().await?
        };
        if json {
            println!("{}", serde_json::to_string_pretty(&result)?);
        } else {
            println!(
                "{}: {} → {} disk layers ({} selected, {} bytes materialized, {:.2} ms paused)",
                if args.dry_run { "Plan" } else { "Compacted" },
                result.input_layers,
                result.output_layers,
                result.selected_layers,
                result.materialized_bytes,
                result.pause_us as f64 / 1000.0
            );
            for disk in &result.disks {
                println!(
                    "  {}: {} → {} layers ({} selected, {} bytes materialized)",
                    disk.guest_path,
                    disk.input_layers,
                    disk.output_layers,
                    disk.selected_layers,
                    disk.materialized_bytes
                );
            }
        }
        return Ok(());
    }
    let mut builder = handle.modify();

    if args.next_start {
        builder = builder.next_start();
    } else if args.restart {
        builder = builder.restart();
    }

    builder = apply_resource_args(builder, &args)?;
    builder = apply_spec_args(builder, &args)?;
    builder = apply_secret_args(builder, &args)?;

    let plan = builder.clone().dry_run().await?;
    if args.dry_run {
        print_plan(&plan, json)?;
        return Ok(());
    }

    if let Some(blocked) = apply_blocker(&args, &plan) {
        if json {
            println!("{}", serde_json::to_string_pretty(&plan)?);
        } else {
            print_apply_blocker(&blocked);
        }
        return Err(ui::AlreadyRenderedError.into());
    }

    let mut applied = builder.apply().await?;
    let mut resized = false;
    if args.wait {
        let budget = resize_wait_budget(args.timeout);
        let (result, confirmed) =
            wait_for_resize(&handle, &args.name, &applied.resize_status, budget).await;
        resized = confirmed;
        match result {
            Ok(status) => {
                applied.resize_status = status;
            }
            Err(MicrosandboxError::ResizeTimeout {
                timeout, status, ..
            }) => {
                applied.resize_status = timeout_resize_status(applied.resize_status, status);
                if json {
                    println!("{}", serde_json::to_string_pretty(&applied)?);
                } else {
                    ui::success("Modified", &applied.sandbox);
                    print_resize_status(&applied.resize_status);
                    print_resize_timeout(&args.name, timeout);
                }
                return Err(ui::AlreadyRenderedError.into());
            }
            Err(error) => return Err(error.into()),
        }
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&applied)?);
    } else {
        print_apply_success(&applied, resized);
    }

    Ok(())
}

fn resize_wait_budget(timeout_secs: Option<u64>) -> Duration {
    Duration::from_secs(timeout_secs.unwrap_or(DEFAULT_RESIZE_WAIT_SECS))
}

/// Wait for live resize convergence within one budget, returning whether to confirm a resize.
///
/// When apply reported no resize, a first read decides the confirmation and counts against the
/// budget. A zero budget performs only that read.
async fn wait_for_resize(
    handle: &SandboxHandle,
    name: &str,
    applied: &[ResourceResizeStatus],
    budget: Duration,
) -> (Result<Vec<ResourceResizeStatus>, MicrosandboxError>, bool) {
    if !applied.is_empty() {
        let result = handle.wait_until_resized_with_timeout(budget).await;
        return (result, true);
    }

    let started = Instant::now();
    let first =
        match tokio::time::timeout(first_read_deadline(budget), handle.resize_status()).await {
            Ok(Ok(status)) => status,
            Ok(Err(error)) => return (Err(error), false),
            Err(_) => return (Err(resize_timeout(name, budget, Vec::new())), false),
        };
    let resized = confirm_resized(applied, &first);
    if resize_settled(&first) {
        return (Ok(first), resized);
    }
    let Some(remaining) = remaining_budget(budget, started.elapsed()) else {
        return (Err(resize_timeout(name, budget, first)), resized);
    };
    let result = match handle.wait_until_resized_with_timeout(remaining).await {
        Err(MicrosandboxError::ResizeTimeout { status, .. }) => Err(resize_timeout(
            name,
            budget,
            timeout_resize_status(first, status),
        )),
        result => result,
    };
    (result, resized)
}

/// Deadline for the first read; a zero budget still gets one control request.
fn first_read_deadline(budget: Duration) -> Duration {
    if budget.is_zero() {
        DEFAULT_REQUEST_TIMEOUT
    } else {
        budget
    }
}

/// Budget left for the wait, or `None` when it is spent.
fn remaining_budget(budget: Duration, elapsed: Duration) -> Option<Duration> {
    budget
        .checked_sub(elapsed)
        .filter(|remaining| !remaining.is_zero())
}

fn resize_settled(status: &[ResourceResizeStatus]) -> bool {
    status.iter().all(|entry| entry.state.is_terminal())
}

fn resize_timeout(
    name: &str,
    timeout: Duration,
    status: Vec<ResourceResizeStatus>,
) -> MicrosandboxError {
    MicrosandboxError::ResizeTimeout {
        name: name.to_string(),
        timeout,
        status,
    }
}

/// Confirm a resize when this call changed CPU or memory, or one was still settling.
fn confirm_resized(applied: &[ResourceResizeStatus], before_wait: &[ResourceResizeStatus]) -> bool {
    !applied.is_empty() || before_wait.iter().any(|status| !status.state.is_terminal())
}

/// Prefer the wait's last read, falling back to the apply status when no read completed.
fn timeout_resize_status(
    applied: Vec<ResourceResizeStatus>,
    observed: Vec<ResourceResizeStatus>,
) -> Vec<ResourceResizeStatus> {
    if observed.is_empty() {
        applied
    } else {
        observed
    }
}

fn print_resize_timeout(name: &str, timeout: Duration) {
    let title = format!(
        "resize did not converge within {}s",
        timeout.as_secs_f64().round() as u64
    );
    let retry = format!("run `msb modify {name} --wait --timeout 600` to keep waiting");
    ui::error_with_lines(
        &title,
        &[
            ui::ErrorLine::Cause("the host already enforces the new limit"),
            ui::ErrorLine::Hint("the guest may still converge"),
            ui::ErrorLine::Hint(&retry),
        ],
    );
}

fn apply_resource_args(
    mut builder: SandboxModificationBuilder,
    args: &ModifyArgs,
) -> anyhow::Result<SandboxModificationBuilder> {
    if let Some(cpus) = args.cpus {
        builder = builder.cpus(cpus);
    }
    if let Some(max_cpus) = args.max_cpus {
        builder = builder.max_cpus(max_cpus);
    }
    if let Some(memory) = &args.memory {
        builder = builder.memory(ui::parse_size_mib(memory).map_err(anyhow::Error::msg)?);
    }
    if let Some(max_memory) = &args.max_memory {
        builder = builder.max_memory(ui::parse_size_mib(max_memory).map_err(anyhow::Error::msg)?);
    }
    if let Some(size) = args.root_disk.as_ref().or(args.oci_upper_size.as_ref()) {
        builder = builder.root_disk_size(ui::parse_size_mib(size).map_err(anyhow::Error::msg)?);
    }
    Ok(builder)
}

fn apply_spec_args(
    mut builder: SandboxModificationBuilder,
    args: &ModifyArgs,
) -> anyhow::Result<SandboxModificationBuilder> {
    for entry in &args.env {
        let (key, value) = parse_key_value(entry, "--env")?;
        builder = builder.env(key, value);
    }
    for key in &args.env_remove {
        builder = builder.remove_env(key);
    }
    for entry in &args.labels {
        let (key, value) = parse_key_value(entry, "--label")?;
        builder = builder.label(key, value);
    }
    for key in &args.label_remove {
        builder = builder.remove_label(key);
    }
    if let Some(workdir) = &args.workdir {
        builder = builder.workdir(workdir);
    }
    Ok(builder)
}

fn apply_secret_args(
    mut builder: SandboxModificationBuilder,
    args: &ModifyArgs,
) -> anyhow::Result<SandboxModificationBuilder> {
    // Group hosts by secret name so repeated `--secret NAME@HOST[,HOST...]`
    // flags accumulate into one declarative spec per name.
    let mut specs: Vec<common::ParsedSecret> = Vec::new();
    for secret in &args.secrets {
        let parsed = common::parse_secret(secret, "modify")?;
        match specs
            .iter_mut()
            .find(|existing| existing.env_var == parsed.env_var)
        {
            Some(existing) => {
                for host in parsed.allowed_hosts {
                    if !existing.allowed_hosts.contains(&host) {
                        existing.allowed_hosts.push(host);
                    }
                }
                for host in parsed.passthrough_hosts {
                    if !existing.passthrough_hosts.contains(&host) {
                        existing.passthrough_hosts.push(host);
                    }
                }
                existing.substitute_headers &= parsed.substitute_headers;
                existing.substitute_query |= parsed.substitute_query;
                existing.substitute_body |= parsed.substitute_body;
            }
            None => specs.push(parsed),
        }
    }
    for spec in specs {
        let name = spec.env_var;
        builder = builder.secret(|mut s| {
            s = s
                .env(&name)
                .source(SecretSource::Env { var: name.clone() })
                .substitution(microsandbox_types::SecretSubstitution {
                    headers: spec.substitute_headers,
                    query: spec.substitute_query,
                    body: spec.substitute_body,
                });
            for host in spec.allowed_hosts {
                s = s.allow(host);
            }
            for host in spec.passthrough_hosts {
                s = s.allow_placeholder_for(host);
            }
            s
        });
    }

    for name in &args.secret_remove {
        builder = builder.remove_secret(name);
    }

    Ok(builder)
}

fn print_plan(plan: &SandboxModificationPlan, json: bool) -> anyhow::Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(plan)?);
    } else {
        print_human_plan(plan);
    }
    Ok(())
}

fn print_human_plan(plan: &SandboxModificationPlan) {
    let include_effect = plan_includes_effect(plan);
    let headers = if include_effect {
        vec!["FIELD", "CHANGE", "BEFORE", "AFTER", "EFFECT"]
    } else {
        vec!["FIELD", "CHANGE", "BEFORE", "AFTER"]
    };
    let mut table = ui::Table::new(&headers);

    for change in &plan.changes {
        match change {
            PlannedChange::Config(change) => {
                let mut row = config_row(change);
                if include_effect {
                    row.push(ui::format_disposition(disposition_label(
                        change.disposition,
                    )));
                }
                table.add_row(row);
            }
            PlannedChange::Secret(change) => {
                let mut row = secret_row(change);
                if include_effect {
                    row.push(ui::format_disposition(disposition_label(
                        change.disposition,
                    )));
                }
                table.add_row(row);
            }
        }
    }

    table.print();
    for warning in &plan.warnings {
        eprintln!("{}", style(warning_line(warning)).dim());
    }
    if include_effect {
        eprintln!("{}", style("   dry run · nothing applied").dim());
    } else {
        eprintln!(
            "{}",
            style("   dry run · applies on next start · nothing applied").dim()
        );
    }
}

fn warning_line(warning: &ModificationWarning) -> String {
    format!("   ! {}: {}", warning.field, warning.message)
}

fn apply_blocker(args: &ModifyArgs, plan: &SandboxModificationPlan) -> Option<ApplyBlocker> {
    if let Some(conflict) = plan.conflicts.first() {
        return Some(ApplyBlocker {
            title: format!("cannot modify \"{}\"", plan.sandbox),
            lines: vec![
                BlockerLine::cause(conflict.message.clone()),
                BlockerLine::hint("no changes were applied"),
            ],
        });
    }

    let unsupported = unsupported_apply_lines(plan);
    if !unsupported.is_empty() {
        let mut lines = unsupported
            .into_iter()
            .map(BlockerLine::cause)
            .collect::<Vec<_>>();
        lines.push(BlockerLine::hint("no changes were applied"));
        return Some(ApplyBlocker {
            title: format!("cannot apply this modification to \"{}\" yet", plan.sandbox),
            lines,
        });
    }

    let restart_lines = restart_required_lines(plan);
    if restart_lines.is_empty() {
        return None;
    }

    if args.restart {
        return None;
    }

    let mut lines = restart_lines
        .into_iter()
        .map(BlockerLine::cause)
        .collect::<Vec<_>>();
    let [restart, next_start] = restart_commands(args);
    lines.push(BlockerLine::hint("no changes were applied"));
    lines.push(BlockerLine::hint(format!("run `{restart}` to apply now")));
    lines.push(BlockerLine::hint(format!(
        "run `{next_start}` to save for the next start"
    )));

    Some(ApplyBlocker {
        title: format!("cannot modify \"{}\" without a restart", plan.sandbox),
        lines,
    })
}

fn unsupported_apply_lines(plan: &SandboxModificationPlan) -> Vec<String> {
    let mut lines = Vec::new();

    for change in &plan.changes {
        match change {
            PlannedChange::Config(change) => {
                if matches!(change.disposition, ModificationDisposition::Unsupported) {
                    lines.push(format!("{} is unsupported", change.field));
                }
            }
            PlannedChange::Secret(change) => {
                if matches!(change.disposition, ModificationDisposition::Unsupported) {
                    lines.push(match change.reason.as_deref() {
                        Some(reason) => format!("secret {}: {reason}", change.name),
                        None => format!("secret {} is unsupported", change.name),
                    });
                }
            }
        }
    }

    lines
}

fn restart_required_lines(plan: &SandboxModificationPlan) -> Vec<String> {
    plan.changes
        .iter()
        .filter_map(|change| match change {
            PlannedChange::Config(change)
                if matches!(change.disposition, ModificationDisposition::RequiresRestart) =>
            {
                Some(format!(
                    "{} requires restart: {} -> {}",
                    change.field,
                    visible_plain(change.before.as_deref()),
                    visible_plain(change.after.as_deref())
                ))
            }
            PlannedChange::Secret(change)
                if matches!(change.disposition, ModificationDisposition::RequiresRestart) =>
            {
                Some(format!("secret {} requires restart", change.name))
            }
            _ => None,
        })
        .collect()
}

fn print_apply_blocker(blocked: &ApplyBlocker) {
    let lines = blocked
        .lines
        .iter()
        .map(|line| match line.kind {
            BlockerLineKind::Cause => ui::ErrorLine::Cause(line.text.as_str()),
            BlockerLineKind::Hint => ui::ErrorLine::Hint(line.text.as_str()),
        })
        .collect::<Vec<_>>();

    ui::error_with_lines(&blocked.title, &lines);
}

fn print_apply_success(plan: &SandboxModificationPlan, resized: bool) {
    if plan.policy == microsandbox::sandbox::ModificationPolicy::Restart
        && plan_has_restart_required(plan)
    {
        ui::success("Modified", &plan.sandbox);
        ui::success("Restarted", &plan.sandbox);
    } else {
        let target = if plan.policy == microsandbox::sandbox::ModificationPolicy::NextStart
            && !matches!(plan.status.as_str(), "created" | "stopped" | "crashed")
        {
            format!("{} {}", plan.sandbox, style("(next start)").dim())
        } else {
            plan.sandbox.clone()
        };

        ui::success("Modified", &target);
    }

    if resized && !plan.resize_status.is_empty() {
        ui::success("Resized", &plan.sandbox);
    }

    if should_render_resize_status(&plan.resize_status) {
        print_resize_status(&plan.resize_status);
    }
}

/// Live resize is not necessarily instant: surface the convergence table only
/// when some accepted resize has not fully applied yet.
fn should_render_resize_status(resize_status: &[ResourceResizeStatus]) -> bool {
    resize_status
        .iter()
        .any(|status| status.state != ResourceConvergenceState::Applied)
}

fn print_resize_status(resize_status: &[ResourceResizeStatus]) {
    let mut table = ui::Table::new(&["FIELD", "REQUESTED", "ACTUAL", "ENFORCED", "STATE"]);
    for status in resize_status {
        table.add_row(vec![
            resource_label(status.resource).to_string(),
            status.requested.clone(),
            status.actual.clone(),
            status.enforced.clone(),
            convergence_cell(status.state),
        ]);
    }
    table.print();
}

fn resource_label(resource: ResourceKind) -> &'static str {
    match resource {
        ResourceKind::Cpus => "cpus",
        ResourceKind::Memory => "memory",
    }
}

fn convergence_label(state: ResourceConvergenceState) -> &'static str {
    match state {
        ResourceConvergenceState::Accepted => "accepted",
        ResourceConvergenceState::Converging => "converging",
        ResourceConvergenceState::Applied => "applied",
        ResourceConvergenceState::GuestRefused => "guest-refused",
        ResourceConvergenceState::Failed => "failed",
    }
}

fn convergence_cell(state: ResourceConvergenceState) -> String {
    let label = convergence_label(state);
    match state {
        ResourceConvergenceState::Converging => style(label).dim().to_string(),
        ResourceConvergenceState::GuestRefused | ResourceConvergenceState::Failed => {
            style(label).red().bold().to_string()
        }
        ResourceConvergenceState::Accepted | ResourceConvergenceState::Applied => label.to_string(),
    }
}

fn plan_has_restart_required(plan: &SandboxModificationPlan) -> bool {
    plan.changes.iter().any(|change| match change {
        PlannedChange::Config(change) => {
            matches!(change.disposition, ModificationDisposition::RequiresRestart)
        }
        PlannedChange::Secret(change) => {
            matches!(change.disposition, ModificationDisposition::RequiresRestart)
        }
    })
}

fn config_row(change: &ConfigPlannedChange) -> Vec<String> {
    vec![
        display_field(&change.field).to_string(),
        change_kind_label(change.change).to_string(),
        visible_cell(change.before.as_deref()),
        visible_cell(change.after.as_deref()),
    ]
}

fn secret_row(change: &SecretPlannedChange) -> Vec<String> {
    vec![
        display_field(&change.field).to_string(),
        secret_change_label(change.change).to_string(),
        visible_cell(change.before_ref.as_deref()),
        visible_cell(change.after_ref.as_deref()),
    ]
}

fn display_field(field: &str) -> &str {
    match field {
        "max_cpus" => "max CPUs",
        "max_memory" => "max memory",
        "root_disk_size" => "root disk size",
        field => field,
    }
}

fn visible_cell(value: Option<&str>) -> String {
    value
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .unwrap_or_else(|| style("-").dim().to_string())
}

fn visible_plain(value: Option<&str>) -> String {
    value
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .unwrap_or_else(|| "-".to_string())
}

fn plan_includes_effect(plan: &SandboxModificationPlan) -> bool {
    !matches!(plan.status.as_str(), "created" | "stopped" | "crashed")
}

fn change_kind_label(change: ChangeKind) -> &'static str {
    match change {
        ChangeKind::Added => "added",
        ChangeKind::Updated => "updated",
        ChangeKind::Removed => "removed",
    }
}

fn secret_change_label(change: SecretChangeKind) -> &'static str {
    match change {
        SecretChangeKind::Added => "added",
        SecretChangeKind::Rotated => "rotated",
        SecretChangeKind::Removed => "removed",
        SecretChangeKind::Renamed => "renamed",
        SecretChangeKind::HostsUpdated => "hosts updated",
        SecretChangeKind::PlaceholderUpdated => "placeholder updated",
    }
}

fn disposition_label(disposition: ModificationDisposition) -> &'static str {
    match disposition {
        ModificationDisposition::Live => "live",
        ModificationDisposition::NextStart => "next start",
        ModificationDisposition::RequiresRestart => "requires restart",
        ModificationDisposition::Unsupported => "unsupported",
    }
}

fn parse_key_value(entry: &str, flag: &str) -> anyhow::Result<(String, String)> {
    let Some((key, value)) = entry.split_once('=') else {
        anyhow::bail!("{flag} must be KEY=VALUE");
    };
    if key.is_empty() {
        anyhow::bail!("{flag} key must not be empty");
    }
    Ok((key.to_string(), value.to_string()))
}

fn restart_commands(args: &ModifyArgs) -> [String; 2] {
    let replayed = replayed_args(args);
    [
        format!("msb modify {} {replayed}--restart", args.name),
        format!("msb modify {} {replayed}--next-start", args.name),
    ]
}

fn replayed_args(args: &ModifyArgs) -> String {
    let mut rendered = Vec::new();

    if let Some(cpus) = args.cpus {
        rendered.push(format!("--cpus {cpus}"));
    }
    if let Some(max_cpus) = args.max_cpus {
        rendered.push(format!("--max-cpus {max_cpus}"));
    }
    if let Some(memory) = &args.memory {
        rendered.push(format!("--memory {memory}"));
    }
    if let Some(max_memory) = &args.max_memory {
        rendered.push(format!("--max-memory {max_memory}"));
    }
    if let Some(size) = &args.root_disk {
        rendered.push(format!("--root-disk {size}"));
    }
    if let Some(size) = &args.oci_upper_size {
        rendered.push(format!("--oci-upper-size {size}"));
    }
    for entry in &args.env {
        rendered.push(format!("--env {entry}"));
    }
    for key in &args.env_remove {
        rendered.push(format!("--env-rm {key}"));
    }
    for entry in &args.labels {
        rendered.push(format!("--label {entry}"));
    }
    for key in &args.label_remove {
        rendered.push(format!("--label-rm {key}"));
    }
    if let Some(workdir) = &args.workdir {
        rendered.push(format!("--workdir {workdir}"));
    }
    for secret in &args.secrets {
        let sanitized = common::parse_secret(secret, "modify")
            .map(|parsed| format!("{}@{}", parsed.env_var, parsed.allowed_hosts.join(",")))
            .unwrap_or_else(|_| "<secret>".to_string());
        rendered.push(format!("--secret {sanitized}"));
    }
    for secret in &args.secret_remove {
        rendered.push(format!("--secret-rm {secret}"));
    }

    if rendered.is_empty() {
        String::new()
    } else {
        format!("{} ", rendered.join(" "))
    }
}

struct ApplyBlocker {
    title: String,
    lines: Vec<BlockerLine>,
}

struct BlockerLine {
    kind: BlockerLineKind,
    text: String,
}

#[derive(Clone, Copy)]
enum BlockerLineKind {
    Cause,
    Hint,
}

impl BlockerLine {
    fn cause(text: impl Into<String>) -> Self {
        Self {
            kind: BlockerLineKind::Cause,
            text: text.into(),
        }
    }

    fn hint(text: impl Into<String>) -> Self {
        Self {
            kind: BlockerLineKind::Hint,
            text: text.into(),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        args: ModifyArgs,
    }

    fn parse_modify_args(args: &[&str]) -> ModifyArgs {
        TestCli::parse_from(std::iter::once("msb").chain(args.iter().copied())).args
    }

    #[test]
    fn parses_resource_dry_run() {
        let args = parse_modify_args(&[
            "api",
            "--cpus",
            "4",
            "--memory",
            "4G",
            "--max-cpus",
            "8",
            "--max-memory",
            "16G",
            "--dry-run",
        ]);

        assert_eq!(args.name, "api");
        assert_eq!(args.cpus, Some(4));
        assert_eq!(args.memory.as_deref(), Some("4G"));
        assert_eq!(args.max_cpus, Some(8));
        assert_eq!(args.max_memory.as_deref(), Some("16G"));
        assert!(args.dry_run);
    }

    #[test]
    fn compaction_is_explicit_and_cannot_mix_config_changes() {
        let args = parse_modify_args(&["api", "--compact", "--layers", "3", "--dry-run"]);
        assert!(args.compact && args.dry_run);
        assert_eq!(args.layers, Some(3));
        assert!(!args.root_disk_only && args.disk.is_none());
        assert_eq!(
            parse_modify_args(&["api", "--compact", "--disk", "/data"])
                .disk
                .as_deref(),
            Some("/data")
        );
        assert!(parse_modify_args(&["api", "--compact", "--root-disk-only"]).root_disk_only);
        for flags in [
            vec!["api", "--layers", "3"],
            vec!["api", "--disk", "/data"],
            vec!["api", "--root-disk-only"],
            vec!["api", "--compact", "--disk", "/", "--root-disk-only"],
            vec!["api", "--compact", "--cpus", "2"],
            vec!["api", "--compact", "--restart"],
        ] {
            assert!(TestCli::try_parse_from(std::iter::once("msb").chain(flags)).is_err());
        }
    }

    #[test]
    fn parses_wait_and_timeout() {
        let args = parse_modify_args(&["api", "--cpus", "4", "--wait", "--timeout", "30"]);
        assert!(args.wait);
        assert_eq!(args.timeout, Some(30));
        assert_eq!(resize_wait_budget(args.timeout), Duration::from_secs(30));
        assert_eq!(
            resize_wait_budget(None),
            Duration::from_secs(DEFAULT_RESIZE_WAIT_SECS)
        );
        assert_eq!(resize_wait_budget(Some(0)), Duration::ZERO);
    }

    #[test]
    fn restart_hints_parse() {
        let args = parse_modify_args(&[
            "api",
            "--cpus",
            "4",
            "--memory",
            "4G",
            "--label",
            "tier=web",
            "--secret",
            "API_KEY@api.example.com",
            "--wait",
            "--timeout",
            "30",
        ]);
        for command in restart_commands(&args) {
            assert!(!command.contains("--wait") && !command.contains("--timeout"));
            let parsed = TestCli::try_parse_from(command.split_whitespace().skip(1))
                .unwrap_or_else(|error| panic!("`{command}` does not parse: {error}"));
            assert_eq!(parsed.args.cpus, Some(4));
        }
    }

    #[test]
    fn timeout_requires_wait() {
        let flags = ["msb", "api", "--cpus", "4", "--timeout", "30"];
        assert!(TestCli::try_parse_from(flags).is_err());
    }

    #[test]
    fn wait_conflicts_with_dry_run() {
        for flags in [
            vec!["msb", "api", "--cpus", "4", "--wait", "--dry-run"],
            vec!["msb", "api", "--cpus", "4", "--wait", "--next-start"],
            vec!["msb", "api", "--compact", "--wait"],
        ] {
            assert!(TestCli::try_parse_from(flags).is_err());
        }
    }

    #[test]
    fn parses_root_disk_flag() {
        let args = parse_modify_args(&["api", "--root-disk", "16G", "--dry-run"]);

        assert_eq!(args.root_disk.as_deref(), Some("16G"));
        assert!(args.dry_run);
        assert_eq!(ui::parse_size_mib("16G").unwrap(), 16 * 1024);
    }

    #[test]
    fn parses_deprecated_oci_upper_size_alias() {
        let args = parse_modify_args(&["api", "--oci-upper-size", "16G", "--dry-run"]);

        assert_eq!(args.oci_upper_size.as_deref(), Some("16G"));
        assert!(args.root_disk.is_none());
    }

    #[test]
    fn parses_env_label_workdir_flags() {
        let args = parse_modify_args(&[
            "api",
            "--env",
            "MODE=prod",
            "--env",
            "NEW=1",
            "--env-rm",
            "EXTRA",
            "--label",
            "team=infra",
            "--label-rm",
            "old",
            "--workdir",
            "/srv",
        ]);

        assert_eq!(args.env, vec!["MODE=prod", "NEW=1"]);
        assert_eq!(args.env_remove, vec!["EXTRA"]);
        assert_eq!(args.labels, vec!["team=infra"]);
        assert_eq!(args.label_remove, vec!["old"]);
        assert_eq!(args.workdir.as_deref(), Some("/srv"));
    }

    #[test]
    fn parses_key_value_entries() {
        assert_eq!(
            parse_key_value("MODE=prod", "--env").unwrap(),
            ("MODE".to_string(), "prod".to_string())
        );
        assert_eq!(
            parse_key_value("URL=http://x?a=b", "--env").unwrap(),
            ("URL".to_string(), "http://x?a=b".to_string())
        );
        assert!(parse_key_value("MODE", "--env").is_err());
        assert!(parse_key_value("=value", "--label").is_err());
    }

    #[test]
    fn rejects_inline_secret_values_loudly() {
        // The old parser silently discarded the inline value; it must be a
        // loud error with the same wording as create's rejection.
        let err = common::parse_secret("API_KEY=secret-value@api.example.com", "modify")
            .unwrap_err()
            .to_string();

        assert!(
            err.contains("inline secret values"),
            "unexpected error: {err}"
        );
        assert!(err.contains("`modify`"), "unexpected error: {err}");
        assert!(err.contains("API_KEY@HOST"), "unexpected error: {err}");
        assert!(
            !err.contains("secret-value"),
            "error must not echo the value: {err}"
        );
    }

    fn resize_entry(
        resource: ResourceKind,
        state: ResourceConvergenceState,
    ) -> ResourceResizeStatus {
        ResourceResizeStatus {
            resource,
            requested: "4".to_string(),
            actual: "2".to_string(),
            enforced: "4".to_string(),
            state,
        }
    }

    #[test]
    fn resize_timeout_keeps_apply_status_without_a_read() {
        let applied = vec![resize_entry(
            ResourceKind::Cpus,
            ResourceConvergenceState::Accepted,
        )];
        let observed = vec![resize_entry(
            ResourceKind::Cpus,
            ResourceConvergenceState::Converging,
        )];
        assert_eq!(timeout_resize_status(applied.clone(), Vec::new()), applied);
        assert_eq!(timeout_resize_status(applied, observed.clone()), observed);
    }

    #[test]
    fn resize_wait_shares_one_budget() {
        let budget = Duration::from_secs(5);
        assert_eq!(
            remaining_budget(budget, Duration::from_secs(2)),
            Some(Duration::from_secs(3))
        );
        assert_eq!(remaining_budget(budget, budget), None);
        assert_eq!(remaining_budget(budget, Duration::from_secs(6)), None);
        assert_eq!(remaining_budget(Duration::ZERO, Duration::ZERO), None);
        assert_eq!(first_read_deadline(budget), budget);
        assert_eq!(first_read_deadline(Duration::ZERO), DEFAULT_REQUEST_TIMEOUT);
    }

    #[test]
    fn first_read_settles_only_when_every_resource_is_terminal() {
        let converging = resize_entry(ResourceKind::Cpus, ResourceConvergenceState::Converging);
        let applied = resize_entry(ResourceKind::Memory, ResourceConvergenceState::Applied);
        let refused = resize_entry(ResourceKind::Cpus, ResourceConvergenceState::GuestRefused);
        assert!(resize_settled(&[]));
        assert!(resize_settled(&[applied.clone(), refused]));
        assert!(!resize_settled(&[applied, converging]));
    }

    #[test]
    fn resize_timeout_reports_full_budget() {
        let status = vec![resize_entry(
            ResourceKind::Cpus,
            ResourceConvergenceState::Converging,
        )];
        let MicrosandboxError::ResizeTimeout {
            name,
            timeout,
            status: reported,
        } = resize_timeout("api", Duration::ZERO, status.clone())
        else {
            panic!("expected a resize timeout");
        };
        assert_eq!(name, "api");
        assert_eq!(timeout, Duration::ZERO);
        assert_eq!(reported, status);
    }

    #[test]
    fn resized_confirmation_tracks_changed_or_pending_resizes() {
        let converging = resize_entry(ResourceKind::Cpus, ResourceConvergenceState::Converging);
        let applied = resize_entry(ResourceKind::Memory, ResourceConvergenceState::Applied);
        assert!(confirm_resized(std::slice::from_ref(&applied), &[]));
        assert!(confirm_resized(&[], &[applied.clone(), converging]));
        assert!(!confirm_resized(&[], &[applied]));
        assert!(!confirm_resized(&[], &[]));
    }

    #[test]
    fn resize_table_renders_only_when_convergence_is_pending() {
        assert!(!should_render_resize_status(&[]));
        assert!(!should_render_resize_status(&[
            resize_entry(ResourceKind::Cpus, ResourceConvergenceState::Applied),
            resize_entry(ResourceKind::Memory, ResourceConvergenceState::Applied),
        ]));
        assert!(should_render_resize_status(&[
            resize_entry(ResourceKind::Cpus, ResourceConvergenceState::Applied),
            resize_entry(ResourceKind::Memory, ResourceConvergenceState::Converging),
        ]));
        assert!(should_render_resize_status(&[resize_entry(
            ResourceKind::Memory,
            ResourceConvergenceState::GuestRefused
        )]));
        assert!(should_render_resize_status(&[resize_entry(
            ResourceKind::Cpus,
            ResourceConvergenceState::Failed
        )]));
    }

    #[test]
    fn convergence_states_render_plainly() {
        assert_eq!(
            convergence_label(ResourceConvergenceState::Accepted),
            "accepted"
        );
        assert_eq!(
            convergence_label(ResourceConvergenceState::Converging),
            "converging"
        );
        assert_eq!(
            convergence_label(ResourceConvergenceState::Applied),
            "applied"
        );
        assert_eq!(
            convergence_label(ResourceConvergenceState::GuestRefused),
            "guest-refused"
        );
        assert_eq!(
            convergence_label(ResourceConvergenceState::Failed),
            "failed"
        );
    }

    #[test]
    fn warning_lines_use_field_message_shape() {
        let warning = ModificationWarning {
            field: "env".to_string(),
            message:
                "applies to future execs only; running processes keep their current environment"
                    .to_string(),
        };

        assert_eq!(
            warning_line(&warning),
            "   ! env: applies to future execs only; running processes keep their current environment"
        );
    }
}
