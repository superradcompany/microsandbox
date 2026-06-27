//! Entry point for the `msb` CLI binary.

use std::io::{IsTerminal, Write};

use clap::{CommandFactory, Parser, Subcommand};
use microsandbox_cli::{
    commands::{
        copy, create, exec, image, inspect, install, list, logs, metrics, ps, pull, registry,
        remove, run, self_cmd, snapshot, start, stop, uninstall, volume,
    },
    log_args::{self, LogArgs},
    sandbox_cmd::{self, SandboxArgs},
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const TOP_LEVEL_COMMAND_GROUPS: &[CommandGroup] = &[
    CommandGroup {
        heading: "Sandboxes",
        commands: &[
            "run", "create", "start", "stop", "list", "status", "metrics", "remove", "exec",
            "copy", "logs", "ssh", "inspect",
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
        commands: &["install", "uninstall", "doctor", "self"],
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
    /// Run the sandbox process (internal).
    #[command(hide = true)]
    Sandbox(Box<SandboxArgs>),

    /// Create a sandbox from an image and run a command in it.
    Run(run::RunArgs),

    /// Create a sandbox and boot it in the background.
    Create(create::CreateArgs),

    /// Start a stopped sandbox.
    Start(start::StartArgs),

    /// Stop one or more running sandboxes.
    Stop(stop::StopArgs),

    /// List all sandboxes.
    #[command(visible_alias = "ls")]
    List(list::ListArgs),

    /// Show sandbox status.
    #[command(name = "status", visible_alias = "ps")]
    Status(ps::PsArgs),

    /// Show live metrics for a running sandbox.
    Metrics(metrics::MetricsArgs),

    /// Remove one or more sandboxes.
    #[command(visible_alias = "rm")]
    Remove(remove::RemoveArgs),

    /// Run a command in a running sandbox.
    Exec(exec::ExecArgs),

    /// Copy files between the host and a sandbox.
    #[command(visible_alias = "cp")]
    Copy(copy::CopyArgs),

    /// Show captured output from a sandbox.
    Logs(logs::LogsArgs),

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

    /// Remove a cached image (alias for `image rm`).
    #[command(hide = true)]
    Rmi(image::ImageRemoveArgs),

    /// Show detailed sandbox configuration and status.
    Inspect(inspect::InspectArgs),

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

    /// Manage the msb installation.
    #[command(name = "self")]
    Self_(self_cmd::SelfArgs),
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
struct HelpStyles {
    enabled: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl HelpStyles {
    /// Detect whether custom help should include ANSI styling.
    fn detect() -> Self {
        Self {
            enabled: std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none(),
        }
    }

    /// Style a help heading like clap's configured header style.
    fn header(&self, value: &str) -> String {
        if !self.enabled {
            return value.to_string();
        }

        format!("\x1b[1;33m{value}\x1b[0m")
    }

    /// Style a command or flag literal like clap's configured literal style.
    fn literal(&self, value: &str) -> String {
        if !self.enabled {
            return value.to_string();
        }

        format!("\x1b[1;34m{value}\x1b[0m")
    }

    /// Add light styling to the default clap help fragments we preserve.
    fn style_default_help_fragment(&self, value: &str) -> String {
        if !self.enabled {
            return value.to_string();
        }

        value.replacen("Usage:", &self.header("Usage:"), 1)
    }

    /// Style alias annotations in the same literal color as command names.
    fn style_aliases(&self, value: &str) -> String {
        if !self.enabled {
            return value.to_string();
        }

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
    if let Some(tree) = microsandbox_cli::tree::try_show_tree(&Cli::command()) {
        println!("{tree}");
        return;
    }
    if try_show_grouped_top_level_help() {
        return;
    }

    let cli = Cli::parse();
    let log_level = cli.logs.selected_level();

    let exit_code = match cli.command {
        // Sandbox process entry — never returns (VMM takes over).
        // Always install tracing for sandbox processes: default to info when
        // no explicit level is set so lifecycle events and VMM diagnostics
        // are captured in runtime.log for post-mortem debugging.
        Commands::Sandbox(args) => {
            let mut args = *args;
            let sandbox_level = args
                .log_level
                .or(log_level)
                .or(Some(microsandbox_runtime::logging::LogLevel::Info));
            args.log_level = sandbox_level;
            // The sandbox subprocess's stderr is redirected into
            // runtime.log via setup_log_capture(), so disable ANSI —
            // color escapes have nowhere useful to render.
            log_args::init_tracing(sandbox_level, false);
            sandbox_cmd::run(args); // returns `!`
        }
        command => {
            // CLI commands write tracing to the user's terminal.
            // Honor TTY detection + NO_COLOR; we set `ansi` explicitly
            // since with_ansi(true) overrides tracing-subscriber's
            // built-in detection.
            let ansi = std::io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none();
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
    // Pull and create can overlap network I/O, decompression, and progress UI.
    // Use a small-but-not-tiny worker pool so foreground UI tasks still get
    // scheduled while multiple layers are downloading and materializing.
    let worker_threads = std::thread::available_parallelism()
        .map(|count| count.get().clamp(4, 8))
        .unwrap_or(4);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_all()
        .build()?;

    runtime.block_on(async move {
        // Stale-sandbox reaping and ephemeral cleanup are owned by host
        // runtime processes (`msb sandbox`) now, not the CLI; see
        // `microsandbox_runtime::maintenance`. The CLI no longer spawns a
        // reaper here.
        match command {
            Commands::Sandbox(_) => unreachable!("handled before Tokio starts"),

            Commands::Run(args) => run::run(args, log_level).await,
            Commands::Create(args) => create::run(args, log_level).await,
            Commands::Start(args) => start::run(args).await,
            Commands::Stop(args) => stop::run(args).await,
            Commands::List(args) => list::run(args).await,
            Commands::Status(args) => ps::run(args).await,
            Commands::Metrics(args) => metrics::run(args).await,
            Commands::Remove(args) => remove::run(args).await,
            Commands::Exec(args) => exec::run(args).await,
            Commands::Copy(args) => copy::run(args).await,
            Commands::Logs(args) => logs::run(args).await,
            Commands::Image(args) => image::run(args).await,
            Commands::Pull(args) => image::run_pull(args).await,
            Commands::Load(args) => image::run_load(args).await,
            Commands::Save(args) => image::run_save(args).await,
            Commands::Registry(args) => registry::run(args).await,
            #[cfg(feature = "ssh")]
            Commands::Ssh(args) => microsandbox_cli::commands::ssh::run(args).await,
            Commands::Images(args) => image::run_list(args).await,
            Commands::Rmi(args) => image::run_remove(args).await,
            Commands::Inspect(args) => inspect::run(args).await,
            Commands::Volume(args) => volume::run(args).await,
            Commands::Snapshot(args) => snapshot::run(args).await,
            Commands::Install(args) => install::run(args).await,
            Commands::Uninstall(args) => uninstall::run(args).await,
            Commands::Doctor(args) => self_cmd::run_doctor(args),
            Commands::Self_(args) => self_cmd::run(args).await,
        }
    })
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
