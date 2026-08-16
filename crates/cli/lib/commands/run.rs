//! `msb run` command — create and start a new sandbox.

use std::io::{IsTerminal, Write};
use std::time::Duration;

use clap::Args;
use futures::{FutureExt, StreamExt};
use microsandbox::logs::{LogSource, LogStreamOptions, LogStreamStart};
use microsandbox::sandbox::{ExecOutput, RlimitResource, Sandbox};

use super::common::{SandboxOpts, apply_sandbox_opts, apply_sandbox_opts_after_config};
use crate::{sandbox_config, ui};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Create a sandbox from an image and run a command in it.
#[derive(Debug, Args)]
pub struct RunArgs {
    /// Image to use (e.g. alpine, python, ./rootfs, ./disk.qcow2).
    ///
    /// Mutually exclusive with `--from-snapshot`. May be omitted when a config file supplies
    /// `image`.
    #[arg(conflicts_with = "from_snapshot")]
    pub image: Option<String>,

    /// Boot a fresh sandbox from a snapshot artifact (path or name).
    ///
    /// The snapshot pins the image; passing `--from-snapshot` is equivalent
    /// to specifying the snapshot's image plus pre-populating the
    /// upper layer from the artifact.
    #[arg(
        long = "from-snapshot",
        alias = "from-snap",
        value_name = "PATH_OR_NAME"
    )]
    pub from_snapshot: Option<String>,

    /// Run the resolved image command in the background and print the sandbox name.
    ///
    /// Use `msb create` to boot an idle sandbox without starting the image command.
    #[arg(short, long)]
    pub detach: bool,

    /// Allocate a pseudo-terminal (enables colors, line editing).
    #[arg(short = 't', long, conflicts_with = "no_tty")]
    pub tty: bool,

    /// Disable pseudo-terminal allocation and run non-interactively.
    #[arg(long = "no-tty", conflicts_with = "tty")]
    pub no_tty: bool,

    /// Kill the command after this duration (e.g. 30s, 5m, 1h).
    #[arg(long)]
    pub timeout: Option<String>,

    /// Set a POSIX resource limit (e.g. nofile=1024, nproc=64, as=1073741824).
    #[arg(long)]
    pub rlimit: Vec<String>,

    /// Key sequence to detach from interactive session (default: ctrl-]).
    #[arg(long)]
    pub detach_keys: Option<String>,

    /// Command to run inside the sandbox (after --).
    ///
    /// Replaces the image CMD while preserving its effective entrypoint.
    #[arg(last = true)]
    pub command: Vec<String>,

    /// Sandbox configuration options.
    #[command(flatten)]
    pub sandbox: SandboxOpts,
}

/// Parsed per-command execution options for `msb run`.
struct ExecOpts {
    tty: bool,
    timeout: Option<Duration>,
    rlimits: Vec<(RlimitResource, u64, u64)>,
    detach_keys: Option<String>,
}

impl ExecOpts {
    fn parse(args: &RunArgs) -> anyhow::Result<Self> {
        let rlimits: Vec<_> = args
            .rlimit
            .iter()
            .map(|s| super::common::parse_rlimit(s))
            .collect::<anyhow::Result<Vec<_>>>()?;

        let timeout = match &args.timeout {
            Some(t) => Some(Duration::from_secs(super::common::parse_duration_secs(t)?)),
            None => None,
        };

        Ok(Self {
            tty: args.tty,
            timeout,
            rlimits,
            detach_keys: args.detach_keys.clone(),
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute the `msb run` command.
pub async fn run(args: RunArgs, log_level: Option<microsandbox::LogLevel>) -> anyhow::Result<()> {
    let is_named = args.sandbox.name.is_some();
    let name = args.sandbox.name.clone().unwrap_or_else(ui::generate_name);

    // Named sandboxes are reused if they already exist (unless --replace
    // or --replace-with-timeout). --replace-with-timeout implies --replace,
    // so either flag opts out of the reuse path.
    let replace_requested = args.sandbox.replace || args.sandbox.replace_with_timeout.is_some();
    if is_named && !replace_requested && Sandbox::get(&name).await.is_ok() {
        return run_existing(name, args).await;
    }

    run_new(name, is_named, args, log_level).await
}

/// Run in an existing named sandbox — start if stopped, connect if running.
async fn run_existing(name: String, args: RunArgs) -> anyhow::Result<()> {
    if let Some(ignored) = ignored_existing_inputs(&args) {
        ui::warn(&format!(
            "sandbox '{name}' already exists; {ignored} ignored (use --replace to recreate)"
        ));
    }

    let sandbox = super::resolve_and_start(&name, args.sandbox.quiet).await?;

    // Detach mode: ensure running and exit.
    if args.detach {
        warn_detached_command_ignored(&name, &args);
        sandbox.detach().await;
        println!("{name}");
        return Ok(());
    }

    let exec_opts = ExecOpts::parse(&args)?;
    let interactive =
        super::common::use_interactive_tty(std::io::stdin().is_terminal(), args.no_tty);

    let result: anyhow::Result<i32> = async {
        let (cmd, cmd_args) =
            super::common::resolve_command(sandbox.config(), args.command, interactive)?;
        match cmd {
            Some(cmd) => exec_in_sandbox(&sandbox, &cmd, cmd_args, interactive, &exec_opts).await,
            None => Ok(0),
        }
    }
    .await;

    // Stop only if we own the lifecycle (i.e., we started it from stopped).
    // Always runs, even if resolve_command or exec failed.
    super::maybe_stop(&sandbox).await;

    handle_exit(result?)
}

/// Create a new sandbox and run in it.
async fn run_new(
    name: String,
    is_named: bool,
    mut args: RunArgs,
    log_level: Option<microsandbox::LogLevel>,
) -> anyhow::Result<()> {
    let launch_started_at = chrono::Utc::now();
    let resolved = sandbox_config::resolve(&args.sandbox.config)?;
    let image = resolved.image(args.image.as_deref(), args.from_snapshot.as_deref())?;
    let builder = resolved.apply(Sandbox::builder(&name))?;
    let builder = image.apply(builder)?;
    if args.sandbox.log_level.is_none()
        && let Some(log_level) = log_level
    {
        args.sandbox.log_level = Some(log_level.to_string());
    }
    let mut builder = if resolved.loaded() {
        apply_sandbox_opts_after_config(builder, &args.sandbox)?
    } else {
        apply_sandbox_opts(builder, &args.sandbox)?
    };
    if !is_named {
        // Unnamed `msb run` (including `--detach`) is a one-off: mark it
        // ephemeral so the host runtime removes its persisted state on exit.
        // Named runs stay persistent and inspectable. This sets policy intent
        // only; cleanup is owned by the runtime, not this CLI.
        builder = builder.ephemeral(true);
    }
    if args.detach {
        builder = builder.background_command(args.command.clone());
    } else {
        builder = builder.foreground_command(args.command.clone());
    }

    // Create sandbox with pull progress — select attached vs detached mode.
    let builder = builder.detached(args.detach);
    let (mut progress, task) = if args.detach {
        builder.create_detached_with_pull_progress()?
    } else {
        builder.create_with_pull_progress()?
    };

    let display_label = image.display();
    let mut display = if args.sandbox.quiet {
        ui::PullProgressDisplay::quiet(&display_label)
    } else {
        ui::PullProgressDisplay::new(&display_label)
    };

    while let Some(event) = progress.recv().await {
        display.handle_event(event);
    }

    display.finish();
    let sandbox = task
        .await
        .map_err(|e| anyhow::anyhow!("create task panicked: {e}"))??;

    // Detach mode: just print the name and exit.
    if args.detach {
        sandbox.detach().await;
        println!("{name}");
        return Ok(());
    }

    let exec_opts = ExecOpts::parse(&args)?;
    let interactive =
        super::common::use_interactive_tty(std::io::stdin().is_terminal(), args.no_tty);

    if sandbox.config().init_owns_boot_workload() {
        let observe = observe_init_owned_workload(&sandbox, launch_started_at);
        let result = match exec_opts.timeout {
            Some(duration) => match tokio::time::timeout(duration, observe).await {
                Ok(result) => result,
                Err(_) => Err(anyhow::anyhow!("command timed out after {duration:?}")),
            },
            None => observe.await,
        };

        if result.is_err()
            && let Err(error) = sandbox.stop().await
        {
            ui::warn(&format!("failed to stop sandbox: {error}"));
        }
        return handle_exit(result?);
    }

    let (cmd, cmd_args) =
        super::common::resolve_command(sandbox.config(), args.command, interactive)?;
    let (cmd, cmd_args) = match (cmd, cmd_args) {
        (Some(cmd), args) => (cmd, args),
        (None, _) => {
            if let Err(e) = sandbox.stop().await {
                ui::warn(&format!("failed to stop sandbox: {e}"));
            }
            return Ok(());
        }
    };

    let result = exec_in_sandbox(&sandbox, &cmd, cmd_args, interactive, &exec_opts).await;

    // Stop always runs, even on exec/attach/IO errors. Unnamed (ephemeral)
    // sandboxes are removed by the host runtime on exit, not here.
    if let Err(e) = sandbox.stop().await {
        ui::warn(&format!("failed to stop sandbox: {e}"));
    }

    handle_exit(result?)
}

/// Stream the VM console while an inherited image init owns the foreground workload.
///
/// Init-owned workloads are part of PID 1's argv, so issuing an agent exec would run them twice.
/// Their stdio is captured in the system console log and their exit is the VM process exit.
async fn observe_init_owned_workload(
    sandbox: &Sandbox,
    started_at: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<i32> {
    let options = LogStreamOptions {
        sources: vec![LogSource::System],
        start: LogStreamStart::Since(started_at),
        until: None,
        follow: true,
    };
    let mut logs = sandbox.log_stream(&options).await?;
    let wait = sandbox.wait();
    tokio::pin!(wait);

    loop {
        tokio::select! {
            status = &mut wait => {
                let status = status?;
                // The runtime can exit while its final console entries are already readable but
                // still queued behind the wait branch. Poll the stream to current EOF so attached
                // runs do not lose their last output chunk.
                loop {
                    match logs.next().now_or_never() {
                        Some(Some(Ok(entry))) => {
                            std::io::stdout().write_all(&entry.data)?;
                            std::io::stdout().flush()?;
                        }
                        Some(Some(Err(error))) => return Err(error.into()),
                        Some(None) | None => break,
                    }
                }
                return Ok(status.code().unwrap_or(1));
            }
            entry = logs.next() => {
                match entry {
                    Some(Ok(entry)) => {
                        std::io::stdout().write_all(&entry.data)?;
                        std::io::stdout().flush()?;
                    }
                    Some(Err(error)) => return Err(error.into()),
                    None => return Ok(wait.await?.code().unwrap_or(1)),
                }
            }
        }
    }
}

/// Execute or attach to a command in a sandbox.
async fn exec_in_sandbox(
    sandbox: &Sandbox,
    cmd: &str,
    cmd_args: Vec<String>,
    interactive: bool,
    opts: &ExecOpts,
) -> anyhow::Result<i32> {
    if interactive {
        let rlimits = opts.rlimits.clone();
        let detach_keys = opts.detach_keys.clone();
        let timeout = opts.timeout;
        let has_opts = !rlimits.is_empty() || detach_keys.is_some();

        let attach_fut = async {
            if has_opts {
                Ok(sandbox
                    .attach_with(cmd, |a| {
                        let mut a = a.args(cmd_args);
                        for (resource, soft, hard) in rlimits {
                            a = a.rlimit_range(resource, soft, hard);
                        }
                        if let Some(keys) = detach_keys {
                            a = a.detach_keys(keys);
                        }
                        a
                    })
                    .await?)
            } else {
                Ok(sandbox.attach(cmd, cmd_args).await?)
            }
        };

        match timeout {
            Some(duration) => match tokio::time::timeout(duration, attach_fut).await {
                Ok(result) => result,
                Err(_) => anyhow::bail!("command timed out after {duration:?}"),
            },
            None => attach_fut.await,
        }
    } else {
        let rlimits = opts.rlimits.clone();
        let timeout = opts.timeout;
        let tty = opts.tty;
        let has_opts = tty || timeout.is_some() || !rlimits.is_empty();
        let output: ExecOutput = if has_opts {
            sandbox
                .exec_with(cmd, |e| {
                    let mut e = e.args(cmd_args);
                    if tty {
                        e = e.tty(true);
                    }
                    if let Some(t) = timeout {
                        e = e.timeout(t);
                    }
                    for (resource, soft, hard) in rlimits {
                        e = e.rlimit_range(resource, soft, hard);
                    }
                    e
                })
                .await?
        } else {
            sandbox.exec(cmd, cmd_args).await?
        };

        std::io::stdout().write_all(output.stdout_bytes())?;
        std::io::stderr().write_all(output.stderr_bytes())?;

        Ok(if output.status().success {
            0
        } else {
            output.status().code
        })
    }
}

/// Exit the process with a non-zero code if needed.
fn handle_exit(exit_code: i32) -> anyhow::Result<()> {
    if exit_code != 0 {
        std::process::exit(exit_code);
    }
    Ok(())
}

/// Describe creation-only inputs that are ignored when reusing an
/// existing named sandbox.
fn ignored_existing_inputs(args: &RunArgs) -> Option<&'static str> {
    match (
        args.from_snapshot.is_some(),
        args.sandbox.has_creation_flags(),
    ) {
        (true, true) => Some("--from-snapshot and creation flags"),
        (true, false) => Some("--from-snapshot"),
        (false, true) => Some("creation flags"),
        (false, false) => None,
    }
}

/// Warn when a detached run reuses an existing sandbox and includes a command.
fn warn_detached_command_ignored(name: &str, args: &RunArgs) {
    if args.command.is_empty() {
        return;
    }

    ui::warn(&format!(
        "command after -- is not applied when reusing existing sandbox '{name}' in --detach mode (use `msb exec {name} -- ...`)"
    ));
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use clap::Parser;
    use clap::error::ErrorKind;

    use super::*;
    use crate::commands::common::SandboxConfigKind;

    #[derive(Debug, Parser)]
    struct TestCli {
        #[command(flatten)]
        args: RunArgs,
    }

    fn parse_run_args(args: &[&str]) -> RunArgs {
        TestCli::parse_from(std::iter::once("msb").chain(args.iter().copied())).args
    }

    #[test]
    fn no_tty_parses_after_image_before_command_delimiter() {
        let args = parse_run_args(&[
            "-q",
            "python:3-alpine",
            "--no-tty",
            "--",
            "python3",
            "-c",
            "print('ok')",
        ]);

        assert!(args.no_tty);
        assert_eq!(args.image.as_deref(), Some("python:3-alpine"));
        assert_eq!(
            args.command,
            vec![
                "python3".to_string(),
                "-c".to_string(),
                "print('ok')".to_string()
            ]
        );
    }

    #[test]
    fn no_tty_conflicts_with_tty() {
        let err =
            TestCli::try_parse_from(["msb", "--tty", "--no-tty", "python:3-alpine"]).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn detached_entrypoint_can_use_image_cmd() {
        let args = parse_run_args(&[
            "--detach",
            "--entrypoint",
            "start-desktop",
            "debian:bookworm-slim",
        ]);

        assert!(args.detach);
        assert_eq!(args.sandbox.entrypoint.as_deref(), Some("start-desktop"));
        assert!(args.command.is_empty());
    }

    #[test]
    fn detach_help_points_idle_workloads_to_create() {
        let mut help = Vec::new();
        <TestCli as clap::CommandFactory>::command()
            .write_long_help(&mut help)
            .unwrap();
        let help = String::from_utf8(help).unwrap();

        assert!(help.contains("Use `msb create` to boot an idle sandbox"));
    }

    #[cfg(feature = "net")]
    #[test]
    fn net_profiles_are_repeatable_and_preserve_comma_groups() {
        let args = parse_run_args(&["--net", "public,private", "--net", "host", "alpine"]);
        assert_eq!(args.sandbox.net, ["public,private", "host"]);
    }

    #[cfg(feature = "net")]
    #[test]
    fn net_profile_conflicts_with_low_level_default_baselines() {
        for conflicting in ["--no-net", "--net-default"] {
            let mut argv = vec!["msb", "--net", "public", conflicting];
            if conflicting == "--net-default" {
                argv.push("deny");
            }
            argv.push("alpine");
            let err = TestCli::try_parse_from(argv).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
        }
    }

    #[test]
    fn config_can_supply_the_image_before_a_trailing_command() {
        let args = parse_run_args(&[
            "--conf",
            "sandbox.yaml",
            "--net-conf",
            "network.yaml",
            "--",
            "python",
            "app.py",
        ]);

        assert!(args.image.is_none());
        assert_eq!(
            args.sandbox
                .config
                .iter()
                .map(|source| (source.kind, source.path.clone()))
                .collect::<Vec<_>>(),
            [
                (SandboxConfigKind::Root, PathBuf::from("sandbox.yaml")),
                (SandboxConfigKind::Network, PathBuf::from("network.yaml")),
            ]
        );
        assert_eq!(args.command, ["python", "app.py"]);
    }

    #[test]
    fn repeated_config_flags_preserve_cross_flag_command_line_order() {
        let args = parse_run_args(&[
            "python",
            "--resource-conf",
            "first.yaml",
            "--conf",
            "base.yaml",
            "--resource-conf",
            "second.yaml",
            "--net-conf",
            "network.yaml",
        ]);

        assert_eq!(
            args.sandbox
                .config
                .iter()
                .map(|source| (source.kind, source.path.clone()))
                .collect::<Vec<_>>(),
            [
                (SandboxConfigKind::Resources, PathBuf::from("first.yaml")),
                (SandboxConfigKind::Root, PathBuf::from("base.yaml")),
                (SandboxConfigKind::Resources, PathBuf::from("second.yaml")),
                (SandboxConfigKind::Network, PathBuf::from("network.yaml")),
            ]
        );
    }

    #[test]
    fn existing_reuse_does_not_warn_for_required_image() {
        let args = parse_run_args(&["--name", "box", "alpine", "--", "echo", "hello"]);

        assert_eq!(ignored_existing_inputs(&args), None);
    }

    #[test]
    fn existing_reuse_warns_for_snapshot() {
        let args = parse_run_args(&["--name", "box", "--detach", "--from-snapshot", "clean"]);

        assert_eq!(ignored_existing_inputs(&args), Some("--from-snapshot"));
    }

    #[test]
    fn from_snap_is_an_alias_for_from_snapshot() {
        let args = parse_run_args(&["--name", "box", "--from-snap", "clean"]);

        assert_eq!(args.from_snapshot.as_deref(), Some("clean"));
    }

    #[test]
    fn from_snap_alias_is_hidden_from_help() {
        let mut help = Vec::new();
        <TestCli as clap::CommandFactory>::command()
            .write_long_help(&mut help)
            .unwrap();
        let help = String::from_utf8(help).unwrap();

        assert!(help.contains("--from-snapshot"));
        assert!(!help.contains("--from-snap "));
    }

    #[test]
    fn existing_reuse_warns_for_snapshot_and_creation_flags() {
        let args = parse_run_args(&[
            "--name",
            "box",
            "--memory",
            "1G",
            "--from-snapshot",
            "clean",
        ]);

        assert_eq!(
            ignored_existing_inputs(&args),
            Some("--from-snapshot and creation flags")
        );
    }
}
