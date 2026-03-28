//! Entry point for the `msb` CLI binary.

use clap::{CommandFactory, Parser, Subcommand};
use microsandbox_cli::{
    commands::{
        create, exec, image, inspect, install, list, metrics, ps, pull, registry, remove, run,
        self_cmd, shell, start, stop, uninstall, volume,
    },
    log_args::{self, LogArgs},
    sandbox_cmd::{self, SandboxArgs},
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Microsandbox CLI.
#[derive(Parser)]
#[command(name = "msb", version, about = "Microsandbox CLI", styles = microsandbox_cli::styles::styles())]
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

    /// Open a shell in a running sandbox.
    Shell(shell::ShellArgs),

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
    log_args::init_tracing(log_level);

    let result: Result<(), Box<dyn std::error::Error>> = match cli.command {
        // Sandbox process entry — never returns (VMM takes over).
        Commands::Sandbox(args) => sandbox_cmd::run(*args, log_level),
        command => run_async_command(command, log_level),
    };

    if let Err(e) = result {
        microsandbox_cli::ui::error(&e.to_string());
        std::process::exit(1);
    }
}

fn run_async_command(
    command: Commands,
    _log_level: Option<microsandbox::LogLevel>,
) -> Result<(), Box<dyn std::error::Error>> {
    // CLI commands are foreground and short-lived, so a current-thread
    // runtime avoids worker startup overhead on each invocation.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    runtime.block_on(async move {
        // Fire-and-forget: reap sandboxes whose process crashed (SIGSEGV,
        // SIGKILL, etc.) without updating the database. Runs in the
        // background so it never delays the requested command.
        microsandbox::sandbox::spawn_reaper();

        match command {
            Commands::Sandbox(_) => unreachable!("handled before Tokio starts"),

            Commands::Run(args) => run::run(args).await.map_err(Into::into),
            Commands::Create(args) => create::run(args).await.map_err(Into::into),
            Commands::Start(args) => start::run(args).await.map_err(Into::into),
            Commands::Stop(args) => stop::run(args).await.map_err(Into::into),
            Commands::List(args) => list::run(args).await.map_err(Into::into),
            Commands::Status(args) => ps::run(args).await.map_err(Into::into),
            Commands::Metrics(args) => metrics::run(args).await.map_err(Into::into),
            Commands::Remove(args) => remove::run(args).await.map_err(Into::into),
            Commands::Exec(args) => exec::run(args).await.map_err(Into::into),
            Commands::Shell(args) => shell::run(args).await.map_err(Into::into),
            Commands::Image(args) => image::run(args).await.map_err(Into::into),
            Commands::Pull(args) => image::run_pull(args).await.map_err(Into::into),
            Commands::Registry(args) => registry::run(args).await.map_err(Into::into),
            Commands::Images(args) => image::run_list(args).await.map_err(Into::into),
            Commands::Rmi(args) => image::run_remove(args).await.map_err(Into::into),
            Commands::Inspect(args) => inspect::run(args).await.map_err(Into::into),
            Commands::Volume(args) => volume::run(args).await.map_err(Into::into),
            Commands::Install(args) => install::run(args).await.map_err(Into::into),
            Commands::Uninstall(args) => uninstall::run(args).await.map_err(Into::into),
            Commands::Self_(args) => self_cmd::run(args).await.map_err(Into::into),
        }
    })
}
