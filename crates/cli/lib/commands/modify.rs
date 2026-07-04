//! `msb modify` command — plan and apply sandbox configuration changes.

use clap::Args;
use console::style;
use microsandbox::sandbox::{
    ChangeKind, ConfigPlannedChange, ModificationDisposition, PlannedChange, Sandbox,
    SandboxModificationBuilder, SandboxModificationPlan, SecretChangeKind, SecretPlannedChange,
};

use crate::ui;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Modify a sandbox configuration.
#[derive(Debug, Args)]
pub struct ModifyArgs {
    /// Sandbox to modify.
    pub name: String,

    /// Desired effective vCPU count.
    #[arg(long)]
    pub cpus: Option<u8>,

    /// Desired boot-time maximum possible vCPU count.
    #[arg(long = "max-cpus")]
    pub max_cpus: Option<u8>,

    /// Desired effective guest memory size, such as `512M` or `4G`.
    #[arg(long)]
    pub memory: Option<String>,

    /// Desired boot-time maximum hotpluggable memory, such as `4G` or `16G`.
    #[arg(long = "max-memory")]
    pub max_memory: Option<String>,

    /// Set an environment variable for future execs (`KEY=VALUE`).
    #[arg(long = "env", value_name = "KEY=VALUE")]
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
    #[arg(long, value_name = "PATH")]
    pub workdir: Option<String>,

    /// Add or rotate a secret from a host environment variable (`NAME@HOST`).
    #[arg(long = "secret", value_name = "NAME@HOST")]
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

    /// Output format.
    #[arg(long, value_name = "FORMAT", value_parser = ["json"])]
    pub format: Option<String>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute the `msb modify` command.
pub async fn run(args: ModifyArgs) -> anyhow::Result<()> {
    super::common::require_experimental_modify("msb modify")?;
    let json = args.format.as_deref() == Some("json");
    let handle = Sandbox::get(&args.name).await?;
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

    let applied = builder.apply().await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&applied)?);
    } else {
        print_apply_success(&applied);
    }

    Ok(())
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
        builder = builder.memory_mib(ui::parse_size_mib(memory).map_err(anyhow::Error::msg)?);
    }
    if let Some(max_memory) = &args.max_memory {
        builder =
            builder.max_memory_mib(ui::parse_size_mib(max_memory).map_err(anyhow::Error::msg)?);
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
    for secret in &args.secrets {
        let parsed = parse_secret_spec(secret)?;
        builder = builder
            .secret_from_env(&parsed.name)
            .allow_secret_host(&parsed.name, parsed.host);
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
    if include_effect {
        eprintln!("{}", style("   dry run · nothing applied").dim());
    } else {
        eprintln!(
            "{}",
            style("   dry run · applies on next start · nothing applied").dim()
        );
    }
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
    lines.push(BlockerLine::hint("no changes were applied"));
    lines.push(BlockerLine::hint(format!(
        "run `msb modify {} {}--restart` to apply now",
        args.name,
        replayed_args(args)
    )));
    lines.push(BlockerLine::hint(format!(
        "run `msb modify {} {}--next-start` to save for the next start",
        args.name,
        replayed_args(args)
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
                lines.push(format!(
                    "secret {} waits on the secret store and runtime contract",
                    change.name
                ));
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

fn print_apply_success(plan: &SandboxModificationPlan) {
    if plan.policy == microsandbox::sandbox::ModificationPolicy::Restart
        && plan_has_restart_required(plan)
    {
        ui::success("Modified", &plan.sandbox);
        ui::success("Restarted", &plan.sandbox);
        return;
    }

    let target = if plan.policy == microsandbox::sandbox::ModificationPolicy::NextStart
        && !matches!(plan.status.as_str(), "created" | "stopped" | "crashed")
    {
        format!("{} {}", plan.sandbox, style("(next start)").dim())
    } else {
        plan.sandbox.clone()
    };

    ui::success("Modified", &target);
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

fn parse_secret_spec(spec: &str) -> anyhow::Result<ParsedSecretSpec> {
    let Some((left, host)) = spec.rsplit_once('@') else {
        anyhow::bail!("secret must be NAME@HOST");
    };
    let name = left.split_once('=').map(|(name, _)| name).unwrap_or(left);
    if name.is_empty() {
        anyhow::bail!("secret name must not be empty");
    }
    if host.is_empty() {
        anyhow::bail!("secret host must not be empty");
    }
    Ok(ParsedSecretSpec {
        name: name.to_string(),
        host: host.to_string(),
    })
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
        let sanitized = parse_secret_spec(secret)
            .map(|parsed| format!("{}@{}", parsed.name, parsed.host))
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

struct ParsedSecretSpec {
    name: String,
    host: String,
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
    fn parses_secret_without_exposing_inline_value() {
        let spec = parse_secret_spec("API_KEY=secret-value@api.example.com").unwrap();

        assert_eq!(spec.name, "API_KEY");
        assert_eq!(spec.host, "api.example.com");
    }
}
