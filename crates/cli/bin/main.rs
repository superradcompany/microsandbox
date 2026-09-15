//! Entry point for the `msb` CLI binary.

use std::io::{IsTerminal, Write};

use clap::{CommandFactory, Parser, Subcommand};
use console::style;
use microsandbox_cli::{
    commands::{
        completion, context, image, install, pull, registry, sandbox, self_cmd, snapshot,
        uninstall, volume,
    },
    log_args::{self, LogArgs},
    machine_cmd::{self, MachineArgs},
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const TOP_LEVEL_COMMAND_GROUPS: &[CommandGroup] = &[
    CommandGroup {
        heading: "Sandboxes",
        commands: &[
            "run", "create", "restore", "modify", "start", "stop", "pause", "resume", "branch",
            "restart", "ping", "touch", "list", "status", "metrics", "remove", "exec", "copy",
            "logs", "ssh", "inspect", "sandbox",
        ],
    },
    CommandGroup {
        heading: "Images",
        commands: &["image", "pull", "load", "save", "registry"],
    },
    CommandGroup {
        heading: "Storage",
        commands: &["volume", "snapshot"],
    },
    CommandGroup {
        heading: "Installation",
        commands: &[
            "install",
            "uninstall",
            "doctor",
            "update",
            "downgrade",
            "self",
            "completion",
        ],
    },
];

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Microsandbox CLI.
#[derive(Parser)]
#[command(
    name = "msb",
    version,
    about = format!("Microsandbox CLI v{}", env!("CARGO_PKG_VERSION")),
    styles = microsandbox_cli::styles::styles()
)]
struct Cli {
    /// Print the full command tree and exit.
    #[arg(long, global = true)]
    tree: bool,

    #[command(flatten)]
    logs: LogArgs,

    #[command(subcommand)]
    command: Commands,
}

/// Top-level commands.
#[derive(Subcommand)]
enum Commands {
    /// Run the VM process (internal).
    #[command(hide = true)]
    Machine(Box<MachineArgs>),

    /// Report launch wire capabilities without initializing a backend.
    #[command(name = "__launch-protocol", hide = true)]
    LaunchProtocol,

    /// Manage sandboxes (also available as top-level commands).
    #[command(visible_alias = "sbx")]
    Sandbox(sandbox::SandboxArgs),

    /// Convenient top-level forms of the sandbox commands.
    #[command(flatten)]
    SandboxShortcut(sandbox::SandboxCommands),

    /// Print the schema baseline owned by this binary (internal).
    #[command(name = "__schema-baseline", hide = true)]
    SchemaBaseline(self_cmd::SchemaBaselineArgs),

    /// Show the active backend and its selection source.
    #[command(visible_alias = "ctx")]
    Context(context::ContextArgs),

    /// Complete a deferred Windows self-update or self-downgrade swap (internal).
    #[cfg(windows)]
    #[command(name = "__windows-self-swap", hide = true)]
    WindowsSelfSwap(self_cmd::WindowsSelfSwapArgs),

    /// Manage OCI images.
    Image(image::ImageArgs),

    /// Download an image from a registry.
    Pull(pull::PullArgs),

    /// Load an image archive from tar.
    Load(image::ImageLoadArgs),

    /// Save one or more cached images to a tar archive.
    Save(image::ImageSaveArgs),

    /// Manage registry credentials.
    Registry(registry::RegistryArgs),

    /// Connect to a sandbox over SSH.
    #[cfg(feature = "ssh")]
    Ssh(microsandbox_cli::commands::ssh::SshArgs),

    /// List cached images (alias for `image ls`).
    #[command(hide = true)]
    Images(image::ImageListArgs),

    /// List named volumes (alias for `volume ls`).
    #[command(alias = "vols", hide = true)]
    Volumes(volume::VolumeListArgs),

    /// List disk snapshots (alias for `snapshot ls`).
    #[command(alias = "snaps", hide = true)]
    Snapshots(snapshot::SnapshotListArgs),

    /// List configured registries (alias for `registry ls`).
    #[command(alias = "regs", hide = true)]
    Registries(registry::RegistryListArgs),

    /// Remove a cached image (alias for `image rm`).
    #[command(hide = true)]
    Rmi(image::ImageRemoveArgs),

    /// Manage named volumes.
    #[command(visible_alias = "vol")]
    Volume(volume::VolumeArgs),

    /// Manage disk snapshots.
    #[command(visible_alias = "snap")]
    Snapshot(snapshot::SnapshotArgs),

    /// Install a sandbox as a system command.
    Install(install::InstallArgs),

    /// Remove an installed sandbox command.
    Uninstall(uninstall::UninstallArgs),

    /// Check local runtime and host virtualization prerequisites.
    Doctor(self_cmd::DoctorArgs),

    /// Update msb and libkrunfw to the latest release (alias for `self update`).
    #[command(visible_alias = "upgrade")]
    Update(self_cmd::SelfUpdateArgs),

    /// Downgrade msb and local state to an older supported release (alias for `self downgrade`).
    Downgrade(self_cmd::SelfDowngradeArgs),

    /// Manage the msb installation.
    #[command(name = "self")]
    Self_(self_cmd::SelfArgs),

    /// Generate a shell completion script.
    Completion(completion::CompletionArgs),
}

/// A visual group for top-level command help.
struct CommandGroup {
    heading: &'static str,
    commands: &'static [&'static str],
}

/// Rendered help text for one top-level command.
#[derive(Clone)]
struct CommandHelpLine {
    name: String,
    help: String,
}

/// ANSI styling state for custom top-level help.
struct HelpStyles {}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Commands {
    /// Normalize shortcuts before choosing the executor or resolving the backend.
    fn into_canonical(self) -> Self {
        match self {
            Self::SandboxShortcut(command) => Self::Sandbox(sandbox::SandboxArgs { command }),
            command => command,
        }
    }

    fn is_resident_control(&self) -> bool {
        matches!(self, Self::Sandbox(args) if args.command.is_resident_control())
    }
}

impl HelpStyles {
    /// Detect whether custom help should include ANSI styling.
    fn detect() -> Self {
        Self {}
    }

    /// Style a help heading like clap's configured header style.
    fn header(&self, value: &str) -> String {
        style(value).yellow().bold().to_string()
    }

    /// Style a command or flag literal like clap's configured literal style.
    fn literal(&self, value: &str) -> String {
        style(value).blue().bold().to_string()
    }

    /// Add light styling to the default clap help fragments we preserve.
    fn style_default_help_fragment(&self, value: &str) -> String {
        value.replacen("Usage:", &self.header("Usage:"), 1)
    }

    /// Style alias annotations in the same literal color as command names.
    fn style_aliases(&self, value: &str) -> String {
        let Some((help, aliases)) = value.split_once(" [aliases: ") else {
            return value.to_string();
        };
        let Some(aliases) = aliases.strip_suffix(']') else {
            return value.to_string();
        };

        format!("{help} [aliases: {}]", self.literal(aliases))
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn main() {
    // Ensure terminal echo is restored even if a panic aborts the process
    // (release profile sets `panic = "abort"`, so Drop impls don't run).
    microsandbox_cli::ui::install_panic_hook();

    // Auto-set MSB_PATH so the library can find the msb binary
    // when spawning sandbox processes.
    // Safety: called before any threads are spawned (single-threaded at this point).
    if std::env::var("MSB_PATH").is_err()
        && let Ok(exe) = std::env::current_exe()
    {
        unsafe { std::env::set_var("MSB_PATH", &exe) };
    }

    // Handle --tree before Cli::parse() so it works even when
    // required arguments (e.g. `msb run --tree`) are missing.
    if std::env::args_os().any(|arg| arg == "--tree")
        && let Some(tree) = microsandbox_cli::tree::try_show_tree(&Cli::command())
    {
        println!("{tree}");
        return;
    }
    if try_show_grouped_top_level_help() {
        return;
    }

    let mut argv: Vec<_> = std::env::args_os().collect();
    let legacy_launch = microsandbox_cli::launch_compat::route_legacy_launch(&mut argv);
    let cli = Cli::parse_from(argv);
    let log_level = cli.logs.selected_level();

    let exit_code = match cli.command.into_canonical() {
        Commands::LaunchProtocol => {
            println!(
                "{}",
                serde_json::to_string(&microsandbox_runtime::launch_protocol::LaunchCapabilities {
                    protocols: vec![2, 1]
                })
                .expect("serialize capabilities")
            );
            return;
        }
        // Sandbox process entry — never returns (VMM takes over).
        // Always install tracing for sandbox processes: default to info when
        // no explicit level is set so lifecycle events and VMM diagnostics
        // are captured in runtime.log for post-mortem debugging.
        Commands::Machine(args) => {
            let mut args = *args;
            args.legacy_launch = legacy_launch;
            let sandbox_level = args
                .log_level
                .or(log_level)
                .or(Some(microsandbox_runtime::logging::LogLevel::Info));
            args.log_level = sandbox_level;
            // The sandbox subprocess's stderr is redirected into
            // runtime.log via setup_log_capture(), so disable ANSI —
            // color escapes have nowhere useful to render.
            log_args::init_tracing(sandbox_level, false);
            if let Err(error) = microsandbox_filesystem::agentd::initialize_agentd_payload() {
                eprintln!("msb: failed to select agentd payload: {error}");
                std::process::exit(1);
            }
            machine_cmd::run(args); // returns `!`
        }
        command => {
            // CLI commands write tracing to the user's terminal.
            // Honor TTY detection + NO_COLOR; we set `ansi` explicitly
            // since with_ansi(true) overrides tracing-subscriber's
            // built-in detection.
            let ansi = std::io::stderr().is_terminal() && console::colors_enabled_stderr();
            log_args::init_tracing(log_level, ansi);
            match run_async_command_anyhow(command, log_level) {
                Ok(()) => 0,
                Err(e) => render_anyhow_error(&e),
            }
        }
    };

    if exit_code != 0 {
        std::process::exit(exit_code);
    }
}

/// Print grouped top-level help for `msb` and `msb --help`.
fn try_show_grouped_top_level_help() -> bool {
    if !is_top_level_help_request() {
        return false;
    }

    print!("{}", render_grouped_top_level_help());
    std::io::stdout()
        .flush()
        .expect("flushing grouped help should not fail");
    true
}

/// Return whether the current invocation is asking for only top-level help.
fn is_top_level_help_request() -> bool {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.is_empty() {
        return true;
    }

    let mut saw_help = false;
    for arg in args {
        let Some(arg) = arg.to_str() else {
            return false;
        };
        match arg {
            "-h" | "--help" => saw_help = true,
            "--error" | "--warn" | "--info" | "--debug" | "--trace" => {}
            _ => return false,
        }
    }

    saw_help
}

/// Render the top-level help with visually grouped commands.
fn render_grouped_top_level_help() -> String {
    let mut cmd = Cli::command();
    let styles = HelpStyles::detect();
    let mut help = Vec::new();
    cmd.write_help(&mut help)
        .expect("writing clap help into memory should not fail");

    let default_help = String::from_utf8(help).expect("clap help should be valid UTF-8");
    let Some((prefix, _)) = default_help.split_once("\nCommands:\n") else {
        return default_help;
    };
    let Some((_, suffix)) = default_help.split_once("\nOptions:\n") else {
        return default_help;
    };

    let mut output = String::new();
    output.push_str(&styles.style_default_help_fragment(prefix));
    output.push('\n');
    output.push_str(&render_grouped_commands(&cmd, &styles));
    output.push('\n');
    output.push_str(&styles.header("Options:"));
    output.push('\n');
    output.push_str(&styles.style_default_help_fragment(suffix));
    output
}

/// Render top-level commands under the configured visual groups.
fn render_grouped_commands(cmd: &clap::Command, styles: &HelpStyles) -> String {
    let lines = visible_command_help_lines(cmd, styles);
    let name_width = lines.iter().map(|line| line.name.len()).max().unwrap_or(0);
    let mut output = String::new();
    let mut rendered_commands = Vec::new();

    for (group_index, group) in TOP_LEVEL_COMMAND_GROUPS.iter().enumerate() {
        if group_index > 0 {
            output.push('\n');
        }

        output.push_str(&styles.header(&format!("{}:", group.heading)));
        output.push('\n');

        for command in group.commands {
            if let Some(line) = lines.iter().find(|line| line.name == *command) {
                output.push_str(&format_command_help_line(line, name_width, styles));
                rendered_commands.push(line.name.as_str());
            }
        }
    }

    let mut other_lines: Vec<_> = lines
        .iter()
        .filter(|line| !rendered_commands.contains(&line.name.as_str()))
        .cloned()
        .collect();
    if !other_lines.iter().any(|line| line.name == "help") {
        other_lines.push(CommandHelpLine {
            name: "help".to_string(),
            help: "Print this message or the help of the given subcommand(s)".to_string(),
        });
    }

    output.push('\n');
    output.push_str(&styles.header("Other:"));
    output.push('\n');
    for line in &other_lines {
        output.push_str(&format_command_help_line(line, name_width, styles));
    }

    output
}

/// Collect visible top-level commands from clap.
fn visible_command_help_lines(cmd: &clap::Command, styles: &HelpStyles) -> Vec<CommandHelpLine> {
    cmd.get_subcommands()
        .filter(|command| !command.is_hide_set())
        .map(|command| {
            let aliases: Vec<_> = command.get_visible_aliases().collect();
            let mut help = command
                .get_about()
                .map(ToString::to_string)
                .unwrap_or_default();

            if !aliases.is_empty() {
                help.push_str(&format!(" [aliases: {}]", aliases.join(", ")));
            }

            CommandHelpLine {
                name: command.get_name().to_string(),
                help: styles.style_aliases(&help),
            }
        })
        .collect()
}

/// Format one command help line with clap-like spacing.
fn format_command_help_line(
    line: &CommandHelpLine,
    name_width: usize,
    styles: &HelpStyles,
) -> String {
    let padded_name = format!("{:<width$}", line.name, width = name_width);
    format!(
        "  {name}  {help}\n",
        name = styles.literal(&padded_name),
        help = line.help
    )
}

/// Render an `anyhow::Error`, preferring the structured boot-error
/// block when the chain contains a `MicrosandboxError::BootStart`,
/// or the styled exec-failed block when the chain contains a
/// `MicrosandboxError::ExecFailed`. Returns the appropriate exit
/// code so callers don't conflate "rendered an error" with "1".
fn render_anyhow_error(err: &anyhow::Error) -> i32 {
    if err.chain().any(|cause| {
        cause
            .downcast_ref::<microsandbox_cli::ui::AlreadyRenderedError>()
            .is_some()
    }) {
        return 1;
    }
    if let Some((name, boot_err)) = find_boot_start_in_chain(err) {
        microsandbox_cli::boot_error_render::render(&name, &boot_err);
        return 1;
    }
    #[cfg(windows)]
    if let Some(setup_err) = find_windows_host_setup_in_chain(err) {
        let cause = setup_err.cause();
        let hints = setup_err.hints();
        let mut lines = Vec::with_capacity(hints.len() + 1);
        lines.push(microsandbox_cli::ui::ErrorLine::Cause(&cause));
        for hint in &hints {
            lines.push(microsandbox_cli::ui::ErrorLine::Hint(hint));
        }
        microsandbox_cli::ui::error_with_lines(setup_err.title(), &lines);
        return 1;
    }
    if find_unsupported_feature_in_chain(err) {
        microsandbox_cli::ui::error_with_lines(
            "this sandbox's runtime is too old for the requested feature",
            &[
                microsandbox_cli::ui::ErrorLine::Cause(
                    "the sandbox was started by an older microsandbox runtime",
                ),
                microsandbox_cli::ui::ErrorLine::Hint("exec and shell still work"),
                microsandbox_cli::ui::ErrorLine::Hint(
                    "restart the sandbox to update its runtime, then retry",
                ),
            ],
        );
        return 1;
    }
    if let Some(failed) = find_exec_failed_in_chain(err) {
        // Try the chain first (callers wrap with `failed to exec
        // "<cmd>"`); fall back to the cmd embedded in the ExecFailed
        // payload's message (agentd writes `spawn "<cmd>": ...`).
        let cmd = extract_quoted_token_str(&err.to_string())
            .or_else(|| extract_quoted_token_str(&failed.message))
            .unwrap_or_else(|| "<unknown>".into());
        microsandbox_cli::exec_error_render::render(&cmd, &failed);
        return microsandbox_cli::exec_error_render::exit_code_for(failed.kind);
    }
    microsandbox_cli::ui::error(&err.to_string());
    1
}

/// Walk the chain looking for a Windows host setup failure.
#[cfg(windows)]
fn find_windows_host_setup_in_chain(
    err: &anyhow::Error,
) -> Option<microsandbox::setup::WindowsHostSetupError> {
    for cause in err.chain() {
        if let Some(microsandbox::MicrosandboxError::WindowsHostSetup(setup_err)) =
            cause.downcast_ref::<microsandbox::MicrosandboxError>()
        {
            return Some(setup_err.clone());
        }
        if let Some(setup_err) = cause.downcast_ref::<microsandbox::setup::WindowsHostSetupError>()
        {
            return Some(setup_err.clone());
        }
    }
    None
}

/// Walk the anyhow chain looking for a `MicrosandboxError::BootStart`.
///
/// anyhow's `chain()` iterates every cause in the chain; downcasting
/// each lets us find the typed inner error regardless of how many
/// `.context(...)` layers wrap it.
fn find_boot_start_in_chain(
    err: &anyhow::Error,
) -> Option<(String, microsandbox_runtime::boot_error::BootError)> {
    for cause in err.chain() {
        if let Some(microsandbox::MicrosandboxError::BootStart { name, err: b }) =
            cause.downcast_ref::<microsandbox::MicrosandboxError>()
        {
            return Some((name.clone(), b.clone()));
        }
    }
    None
}

/// Walk the chain looking for `MicrosandboxError::ExecFailed`.
fn find_exec_failed_in_chain(
    err: &anyhow::Error,
) -> Option<microsandbox_protocol::exec::ExecFailed> {
    for cause in err.chain() {
        if let Some(microsandbox::MicrosandboxError::ExecFailed(payload)) =
            cause.downcast_ref::<microsandbox::MicrosandboxError>()
        {
            return Some(payload.clone());
        }
    }
    None
}

/// Walk the chain looking for a too-old-runtime feature rejection.
fn find_unsupported_feature_in_chain(err: &anyhow::Error) -> bool {
    for cause in err.chain() {
        if let Some(microsandbox::MicrosandboxError::AgentClient(
            microsandbox::AgentClientError::UnsupportedOperation { .. },
        )) = cause.downcast_ref::<microsandbox::MicrosandboxError>()
        {
            return true;
        }
    }
    false
}

/// Pull the first non-empty quoted token from a message. Used to
/// recover the command name for `ExecFailed` rendering — checked
/// against the top-level `anyhow::Error` display string and the
/// `ExecFailed.message` (agentd writes `spawn "<cmd>": ...`).
fn extract_quoted_token_str(s: &str) -> Option<String> {
    let start = s.find('"')? + 1;
    let rest = &s[start..];
    let end = rest.find('"')?;
    let name = &rest[..end];
    if name.is_empty() {
        return None;
    }
    Some(name.to_string())
}

fn run_async_command_anyhow(
    command: Commands,
    log_level: Option<microsandbox::LogLevel>,
) -> anyhow::Result<()> {
    // Internal maintenance commands do not execute sandbox operations and
    // must remain usable while diagnosing an invalid backend configuration.
    let command = match command {
        Commands::SchemaBaseline(args) => return self_cmd::run_schema_baseline(args),
        command => command,
    };

    // Pull and create can overlap network I/O, decompression, and progress UI.
    // Use a small-but-not-tiny worker pool so foreground UI tasks still get
    // scheduled while multiple layers are downloading and materializing.
    // Resident control performs one IPC exchange. It needs I/O and timers, not the image
    // pipeline's worker pool. Blocking filesystem/SQLite work keeps its normal executor.
    let mut builder = if command.is_resident_control() {
        tokio::runtime::Builder::new_current_thread()
    } else {
        let worker_threads = std::thread::available_parallelism()
            .map(|count| count.get().clamp(4, 8))
            .unwrap_or(4);
        let mut builder = tokio::runtime::Builder::new_multi_thread();
        builder.worker_threads(worker_threads);
        builder
    };
    let runtime = builder.enable_all().build()?;

    runtime.block_on(async move {
        // Stale-sandbox reaping and ephemeral cleanup are owned by host
        // runtime processes (`msb machine`) now, not the CLI; see
        // `microsandbox_runtime::maintenance`. The CLI no longer spawns a
        // reaper here.
        if !is_backend_independent_maintenance_command(&command) {
            // Resolve once, fallibly, before backend-dependent dispatch. Unlike
            // the SDK's ambient convenience fallback, the CLI must not run a
            // sandbox operation locally after an invalid explicit cloud selection.
            let backend = microsandbox::resolve_default_backend()?;
            microsandbox::set_default_backend(backend);
        }

        match command {
            Commands::Machine(_) | Commands::LaunchProtocol => {
                unreachable!("handled before Tokio starts")
            }
            Commands::SandboxShortcut(_) => unreachable!("normalized before dispatch"),
            Commands::SchemaBaseline(_) => unreachable!("handled before backend resolution"),
            Commands::Context(args) => context::run(args),
            #[cfg(windows)]
            Commands::WindowsSelfSwap(args) => self_cmd::run_windows_self_swap(args).await,

            Commands::Sandbox(args) => sandbox::run(args.command, log_level).await,
            Commands::Image(args) => image::run(args).await,
            Commands::Pull(args) => image::run_pull(args).await,
            Commands::Load(args) => image::run_load(args).await,
            Commands::Save(args) => image::run_save(args).await,
            Commands::Registry(args) => registry::run(args).await,
            #[cfg(feature = "ssh")]
            Commands::Ssh(args) => microsandbox_cli::commands::ssh::run(args).await,
            Commands::Images(args) => image::run_list(args).await,
            Commands::Volumes(args) => {
                volume::run(volume::VolumeArgs {
                    command: volume::VolumeCommands::List(args),
                })
                .await
            }
            Commands::Snapshots(args) => {
                snapshot::run(snapshot::SnapshotArgs {
                    command: snapshot::SnapshotCommands::List(args),
                })
                .await
            }
            Commands::Registries(args) => {
                registry::run(registry::RegistryArgs {
                    command: registry::RegistryCommands::List(args),
                })
                .await
            }
            Commands::Rmi(args) => image::run_remove(args).await,
            Commands::Volume(args) => volume::run(args).await,
            Commands::Snapshot(args) => snapshot::run(args).await,
            Commands::Install(args) => install::run(args).await,
            Commands::Uninstall(args) => uninstall::run(args).await,
            Commands::Doctor(args) => self_cmd::run_doctor(args),
            Commands::Update(args) => self_cmd::run_update(args).await,
            Commands::Downgrade(args) => self_cmd::run_downgrade(args).await,
            Commands::Self_(args) => self_cmd::run(args).await,
            Commands::Completion(args) => completion::run(args, Cli::command()),
        }
    })
}

/// Return whether a command manages the CLI installation rather than a backend.
///
/// These commands are deliberately available even when backend configuration is
/// invalid so users can diagnose, repair, downgrade, or uninstall that setup.
fn is_backend_independent_maintenance_command(command: &Commands) -> bool {
    match command {
        Commands::SchemaBaseline(_)
        | Commands::Doctor(_)
        | Commands::Update(_)
        | Commands::Downgrade(_)
        | Commands::Self_(_)
        | Commands::Completion(_) => true,
        #[cfg(windows)]
        Commands::WindowsSelfSwap(_) => true,
        _ => false,
    }
}

#[cfg(test)]
mod command_tests {
    use super::*;

    #[test]
    fn partial_capture_failure_keeps_artifact_locator_and_nonzero_exit() {
        let error: anyhow::Error = microsandbox::MicrosandboxError::SnapshotSourceRecovery(
            Box::new(microsandbox::SnapshotSourceRecoveryError {
                source_sandbox: "source".into(),
                checkpoint_id: "checkpoint_test".into(),
                checkpoint_root: "root".into(),
                checkpoint_path: "/runtime/checkpoint_test".into(),
                artifact: Some(microsandbox::PublishedSnapshotArtifact {
                    kind: microsandbox::SnapshotArtifactKind::Archive,
                    path: "/saved/snapshot.tar".into(),
                    snapshot_id: "snap_test".into(),
                    digest: "digest".into(),
                }),
                detail: "thaw acknowledgement timed out".into(),
                publication_error: None,
            }),
        )
        .into();
        // Quiet capture suppresses success output, never this top-level error renderer.
        assert_eq!(render_anyhow_error(&error), 1);
        let message = error.to_string();
        assert!(message.contains("/saved/snapshot.tar"));
        assert!(message.contains("requires recovery"));
        assert!(message.contains("thaw acknowledgement timed out"));
    }

    #[test]
    fn maintenance_commands_do_not_require_backend_resolution() {
        let maintenance_commands = [
            Cli::try_parse_from(["msb", "doctor"]).unwrap().command,
            Cli::try_parse_from(["msb", "update"]).unwrap().command,
            Cli::try_parse_from(["msb", "downgrade", "0.6.0"])
                .unwrap()
                .command,
            Cli::try_parse_from(["msb", "self", "doctor"])
                .unwrap()
                .command,
            Cli::try_parse_from(["msb", "completion", "bash"])
                .unwrap()
                .command,
        ];

        for command in &maintenance_commands {
            assert!(is_backend_independent_maintenance_command(command));
        }

        let context = Cli::try_parse_from(["msb", "context"]).unwrap();
        let create = Cli::try_parse_from(["msb", "create", "alpine:3.19"]).unwrap();
        assert!(!is_backend_independent_maintenance_command(
            &context.command
        ));
        assert!(!is_backend_independent_maintenance_command(&create.command));
    }

    #[test]
    fn command_aliases_route_to_their_canonical_commands() {
        let context = Cli::try_parse_from(["msb", "ctx"]).unwrap();
        let modify = Cli::try_parse_from(["msb", "mod", "demo", "--cpus", "2"]).unwrap();

        assert!(matches!(context.command, Commands::Context(_)));
        assert!(matches!(
            modify.command.into_canonical(),
            Commands::Sandbox(sandbox::SandboxArgs {
                command: sandbox::SandboxCommands::Modify(_)
            })
        ));
    }

    #[test]
    fn plural_resource_commands_route_to_list_actions() {
        let cli = Cli::try_parse_from(["msb", "images"]).unwrap();
        assert!(matches!(cli.command, Commands::Images(_)));

        for command in ["volumes", "vols"] {
            let cli = Cli::try_parse_from(["msb", command]).unwrap();
            assert!(matches!(cli.command, Commands::Volumes(_)));
        }

        for command in ["snapshots", "snaps"] {
            let cli = Cli::try_parse_from(["msb", command]).unwrap();
            assert!(matches!(cli.command, Commands::Snapshots(_)));
        }

        for command in ["registries", "regs"] {
            let cli = Cli::try_parse_from(["msb", command]).unwrap();
            assert!(matches!(cli.command, Commands::Registries(_)));
        }
    }
}

#[cfg(test)]
mod sandbox_command_tests {
    use super::*;

    fn parse_sandbox(prefix: &[&str], args: &[&str]) -> sandbox::SandboxCommands {
        let cli = Cli::try_parse_from(
            ["msb"]
                .into_iter()
                .chain(prefix.iter().copied())
                .chain(args.iter().copied()),
        )
        .unwrap();
        let Commands::Sandbox(args) = cli.command.into_canonical() else {
            panic!("expected a public sandbox command");
        };
        args.command
    }

    #[test]
    fn every_sandbox_operation_has_equivalent_public_spellings() {
        let cases: &[&[&str]] = &[
            &["run", "alpine", "--name", "demo", "--", "echo", "--help"],
            &["create", "alpine", "--name", "demo"],
            &["restore", "source:ready", "--name", "child"],
            &[
                "restore",
                "./saved.msb",
                "--name",
                "child",
                "--forked",
                "--snapshot-base",
                "source:base",
                "-v",
                "/data",
                "-u",
                "1000",
                "-q",
            ],
            &["restore", "source:ready", "--name", "child", "--disk-only"],
            #[cfg(feature = "net")]
            &[
                "restore",
                "source:ready",
                "--name",
                "child",
                "-v",
                "/srv/work:/workspace",
                "-p",
                "127.0.0.1:8081:80",
                "--external-mount-policy",
                "relaxed",
                "--dangerously-inherit-resources",
            ],
            &["modify", "demo", "--cpus", "2"],
            &["start", "demo"],
            &["stop", "demo", "--timeout", "3"],
            &["pause", "demo"],
            &["resume", "demo"],
            &["branch", "demo", "--name", "child"],
            #[cfg(feature = "net")]
            &[
                "branch", "demo", "--name", "child", "-v", "/data", "-p", "8081:80",
            ],
            &["restart", "demo"],
            &["ping", "demo"],
            &["touch", "demo"],
            &["list"],
            &["status"],
            &["metrics", "demo", "--format", "json"],
            &["remove", "demo"],
            &["exec", "demo", "--", "echo", "--help"],
            &["copy", "./source", "demo:/target"],
            &["logs", "demo"],
            &["inspect", "demo"],
        ];
        for args in cases {
            let short = format!("{:?}", parse_sandbox(&[], args));
            for prefix in [["sandbox"], ["sbx"]] {
                assert_eq!(
                    format!("{:?}", parse_sandbox(&prefix, args)),
                    short,
                    "{prefix:?} {args:?}"
                );
            }
        }
    }

    #[cfg(feature = "ssh")]
    #[test]
    fn ssh_remains_a_top_level_command_only() {
        // SSH owns connection, serving, and authorization workflows outside the sandbox group.
        for args in [
            &["ssh", "demo", "--", "uname", "-a"][..],
            &["ssh", "connect", "demo"][..],
            &["ssh", "serve", "demo", "--port", "2222"][..],
            &["ssh", "authorize", "--stdin"][..],
        ] {
            let cli = Cli::try_parse_from(["msb"].into_iter().chain(args.iter().copied())).unwrap();
            assert!(matches!(cli.command.into_canonical(), Commands::Ssh(_)));
            for group in ["sandbox", "sbx"] {
                assert!(
                    Cli::try_parse_from(["msb", group].into_iter().chain(args.iter().copied()))
                        .is_err()
                );
            }
        }
        let command = Cli::command();
        assert!(!command.find_subcommand("ssh").unwrap().is_hide_set());
        assert!(
            command
                .find_subcommand("sandbox")
                .unwrap()
                .find_subcommand("ssh")
                .is_none()
        );
    }

    #[test]
    fn existing_verb_aliases_work_inside_both_groups() {
        for (canonical, alias, arguments) in [
            ("list", "ls", &[][..]),
            ("status", "ps", &[][..]),
            ("remove", "rm", &["demo"][..]),
            ("modify", "mod", &["demo", "--cpus", "2"][..]),
            ("copy", "cp", &["./source", "demo:/target"][..]),
        ] {
            let original = [&[canonical][..], arguments].concat();
            let abbreviated = [&[alias][..], arguments].concat();
            for prefix in [&[][..], &["sandbox"][..], &["sbx"][..]] {
                assert_eq!(
                    format!("{:?}", parse_sandbox(prefix, &original)),
                    format!("{:?}", parse_sandbox(prefix, &abbreviated)),
                );
            }
        }
    }

    #[test]
    fn grouped_commands_preserve_global_flags_and_resident_executor() {
        for argv in [
            vec!["msb", "--debug", "sandbox", "pause", "demo"],
            vec!["msb", "sandbox", "--debug", "pause", "demo"],
            vec!["msb", "sbx", "pause", "demo", "--debug"],
        ] {
            let cli = Cli::try_parse_from(argv).unwrap();
            assert!(cli.logs.debug);
            let command = cli.command.into_canonical();
            assert!(command.is_resident_control());
            assert!(!is_backend_independent_maintenance_command(&command));
        }
        for prefix in [&[][..], &["sandbox"][..], &["sbx"][..]] {
            for verb in ["pause", "resume"] {
                assert!(parse_sandbox(prefix, &[verb, "demo"]).is_resident_control());
            }
            assert!(!parse_sandbox(prefix, &["start", "demo"]).is_resident_control());
        }
    }

    #[test]
    fn machine_launcher_is_separate_from_public_sandbox_commands() {
        let internal = [
            "--name",
            "demo",
            "--sandbox-id",
            "1",
            "--config-file",
            "launch.json",
        ];
        let cli = Cli::try_parse_from(["msb", "machine"].into_iter().chain(internal)).unwrap();
        assert!(matches!(cli.command, Commands::Machine(_)));
        let mut legacy: Vec<std::ffi::OsString> = ["msb", "sandbox"]
            .into_iter()
            .chain(internal)
            .map(Into::into)
            .collect();
        assert!(microsandbox_cli::launch_compat::route_legacy_launch(
            &mut legacy
        ));
        assert!(matches!(
            Cli::try_parse_from(legacy).unwrap().command,
            Commands::Machine(_)
        ));
        for group in ["sandbox", "sbx"] {
            assert!(Cli::try_parse_from(["msb", group].into_iter().chain(internal)).is_err());
        }
    }

    #[test]
    fn restore_rejects_boot_inputs_and_uses_the_creation_executor() {
        for prefix in [&[][..], &["sandbox"][..], &["sbx"][..]] {
            let restored = parse_sandbox(prefix, &["restore", "saved", "--name", "child"]);
            assert!(matches!(restored, sandbox::SandboxCommands::Restore(_)));
            assert!(!restored.is_resident_control());
            for extra in [
                &["--forked", "--disk-only"][..],
                &["--memory", "512M"][..],
                &["--cpus", "2"][..],
                &["--", "sh"][..],
                &["--replace"][..],
            ] {
                let argv = ["msb"]
                    .into_iter()
                    .chain(prefix.iter().copied())
                    .chain(["restore", "saved", "--name", "child"])
                    .chain(extra.iter().copied());
                assert!(
                    Cli::try_parse_from(argv).is_err(),
                    "accepted {prefix:?} restore {extra:?}"
                );
            }
            // The old create/run route must fail, not parse as an ordinary fresh boot.
            for verb in ["create", "run"] {
                let argv = ["msb"].into_iter().chain(prefix.iter().copied()).chain([
                    verb,
                    "--from-snapshot",
                    "saved",
                    "--name",
                    "child",
                ]);
                assert!(Cli::try_parse_from(argv).is_err());
            }
        }
    }

    #[test]
    fn restore_preserves_global_flags_through_all_public_forms() {
        for argv in [
            vec!["msb", "--debug", "restore", "saved", "--name", "child"],
            vec![
                "msb", "sandbox", "--debug", "restore", "saved", "--name", "child",
            ],
            vec![
                "msb", "sbx", "restore", "saved", "--name", "child", "--debug",
            ],
        ] {
            let cli = Cli::try_parse_from(argv).unwrap();
            assert!(cli.logs.debug);
            let command = cli.command.into_canonical();
            assert!(!command.is_resident_control());
            assert!(!is_backend_independent_maintenance_command(&command));
            assert!(matches!(
                command,
                Commands::Sandbox(sandbox::SandboxArgs {
                    command: sandbox::SandboxCommands::Restore(_)
                })
            ));
        }
    }

    #[test]
    fn help_exposes_the_group_and_shortcuts_but_hides_machine() {
        Cli::command().debug_assert();
        let command = Cli::command();
        let group = command.find_subcommand("sandbox").unwrap();
        assert!(!group.is_hide_set());
        assert!(group.get_visible_aliases().any(|alias| alias == "sbx"));
        assert!(command.find_subcommand("machine").unwrap().is_hide_set());
        for nested in group.get_subcommands() {
            let top_level = command.find_subcommand(nested.get_name()).unwrap();
            assert!(!top_level.is_hide_set());
        }
        let help = render_grouped_commands(&command, &HelpStyles::detect());
        assert!(help.contains("sandbox"));
        assert!(help.contains("sbx"));
        assert!(help.contains("branch"));
        assert!(help.contains("restore"));
        assert!(group.find_subcommand("restore").is_some());
        assert!(!help.contains("machine"));
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn finds_windows_host_setup_error_in_anyhow_chain() {
        let source = microsandbox::setup::WindowsHostSetupError::HypervisorNotPresent;
        let err = anyhow::Error::new(microsandbox::MicrosandboxError::WindowsHostSetup(
            source.clone(),
        ))
        .context("starting sandbox");

        let found =
            find_windows_host_setup_in_chain(&err).expect("setup error should be in the chain");

        assert_eq!(found, source);
    }
}
