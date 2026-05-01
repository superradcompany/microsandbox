//! Entry point for the `msb` CLI binary.

use std::io::IsTerminal;

use clap::{CommandFactory, Parser, Subcommand};
use microsandbox_cli::{
    commands::{
        create, exec, image, inspect, install, list, logs, metrics, ps, pull, registry, remove,
        run, self_cmd, snapshot, start, stop, uninstall, volume,
    },
    log_args::{self, LogArgs},
    sandbox_cmd::{self, SandboxArgs},
};

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

    /// Stop a running sandbox.
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

    /// Show captured output from a sandbox.
    Logs(logs::LogsArgs),

    /// Manage OCI images.
    Image(image::ImageArgs),

    /// Download an image from a registry.
    Pull(pull::PullArgs),

    /// Manage registry credentials.
    Registry(registry::RegistryArgs),

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

    /// Manage the msb installation.
    #[command(name = "self")]
    Self_(self_cmd::SelfArgs),
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

    let cli = Cli::parse();
    let log_level = cli.logs.selected_level();

    let exit_code = match cli.command {
        // Sandbox process entry — never returns (VMM takes over).
        // Always install tracing for sandbox processes: default to info when
        // no explicit level is set so lifecycle events and VMM diagnostics
        // are captured in runtime.log for post-mortem debugging.
        Commands::Sandbox(args) => {
            let sandbox_level = log_level.or(Some(microsandbox_runtime::logging::LogLevel::Info));
            // The sandbox subprocess's stderr is redirected into
            // runtime.log via setup_log_capture(), so disable ANSI —
            // color escapes have nowhere useful to render.
            log_args::init_tracing(sandbox_level, false);
            sandbox_cmd::run(*args, log_level); // returns `!`
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
    _log_level: Option<microsandbox::LogLevel>,
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
        // Fire-and-forget: reap sandboxes whose process crashed (SIGSEGV,
        // SIGKILL, etc.) without updating the database. Runs in the
        // background so it never delays the requested command.
        microsandbox::sandbox::spawn_reaper();

        match command {
            Commands::Sandbox(_) => unreachable!("handled before Tokio starts"),

            Commands::Run(args) => run::run(args).await,
            Commands::Create(args) => create::run(args).await,
            Commands::Start(args) => start::run(args).await,
            Commands::Stop(args) => stop::run(args).await,
            Commands::List(args) => list::run(args).await,
            Commands::Status(args) => ps::run(args).await,
            Commands::Metrics(args) => metrics::run(args).await,
            Commands::Remove(args) => remove::run(args).await,
            Commands::Exec(args) => exec::run(args).await,
            Commands::Logs(args) => logs::run(args).await,
            Commands::Image(args) => image::run(args).await,
            Commands::Pull(args) => image::run_pull(args).await,
            Commands::Registry(args) => registry::run(args).await,
            Commands::Images(args) => image::run_list(args).await,
            Commands::Rmi(args) => image::run_remove(args).await,
            Commands::Inspect(args) => inspect::run(args).await,
            Commands::Volume(args) => volume::run(args).await,
            Commands::Snapshot(args) => snapshot::run(args).await,
            Commands::Install(args) => install::run(args).await,
            Commands::Uninstall(args) => uninstall::run(args).await,
            Commands::Self_(args) => self_cmd::run(args).await,
        }
    })
}
