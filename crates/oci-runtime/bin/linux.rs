//! Linux entry point implementation for the `runmsb` OCI runtime binary.

#[path = "cli.rs"]
mod cli;
#[path = "commands.rs"]
mod commands;
#[path = "console.rs"]
mod console;
#[path = "features.rs"]
mod features;
#[path = "logging.rs"]
mod logging;

use std::fs;
use std::path::Path;
use std::process::{Command as ProcessCommand, Stdio};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use runmsb::{CreateOptions, DeleteOptions, ExecOptions, KillOptions, MicrosandboxOciRuntime};

use self::cli::Cli;
use self::commands::{
    Command, ContainerIdCommand, CreateCommand, CreateRunOptions, DeleteCommand, ExecCommand,
    ExecSupervisorCommand, KillCommand, RunCommand,
};
use self::console::setup_oci_console;
use self::features::oci_features_json;
use self::logging::{init_tracing, write_runtime_error_log};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

#[tokio::main]
pub(crate) async fn main() {
    let cli = Cli::parse();
    init_tracing(cli.debug, cli.log_level);
    let log = cli.log.clone();
    let log_format = cli.log_format;

    let code = match run(cli).await {
        Ok(code) => code,
        Err(error) => {
            eprintln!("runmsb: {error:#}");
            write_runtime_error_log(log.as_ref(), log_format, &format!("{error:#}"));
            1
        }
    };

    std::process::exit(code);
}

async fn run(cli: Cli) -> Result<i32> {
    let root = cli.root.clone();
    let runtime = MicrosandboxOciRuntime::new(root.clone());
    match cli.command {
        Command::Create(CreateCommand {
            options:
                CreateRunOptions {
                    bundle,
                    pid_file,
                    console_socket,
                    ..
                },
            id,
        }) => {
            let console = setup_oci_console(console_socket.as_ref())?;
            runtime
                .create(CreateOptions {
                    id: id.clone(),
                    bundle,
                    console: console.map(|console| console.into_slave()),
                })
                .await?;
            let state = runtime.state(&id).await?;
            let pid = state
                .pid
                .ok_or_else(|| anyhow::anyhow!("container `{id}` has no VMM host PID"))?;
            write_pid_file(pid_file.as_deref(), pid)?;
            Ok(0)
        }
        Command::Start(ContainerIdCommand { id }) => {
            runtime.start(&id).await?;
            Ok(0)
        }
        Command::Run(RunCommand {
            options:
                CreateRunOptions {
                    bundle,
                    pid_file,
                    console_socket,
                    ..
                },
            id,
        }) => {
            let console = setup_oci_console(console_socket.as_ref())?;
            runtime
                .create(CreateOptions {
                    id: id.clone(),
                    bundle,
                    console: console.map(|console| console.into_slave()),
                })
                .await?;
            let state = runtime.state(&id).await?;
            let pid = state
                .pid
                .ok_or_else(|| anyhow::anyhow!("container `{id}` has no VMM host PID"))?;
            write_pid_file(pid_file.as_deref(), pid)?;
            runtime.start(&id).await?;
            runtime.wait(&id).await
        }
        Command::Exec(command) => {
            let ExecCommand {
                process,
                console_socket,
                detach,
                pid_file,
                id,
                ..
            } = *command;
            let process = process.ok_or_else(|| {
                anyhow::anyhow!(
                    "command-style exec is not implemented; pass --process process.json"
                )
            })?;
            let console = setup_oci_console(console_socket.as_ref())?;
            let console_slave = console
                .as_ref()
                .map(|console| console.slave_path().to_path_buf());
            if detach {
                let pid_file =
                    pid_file.ok_or_else(|| anyhow::anyhow!("exec --detach requires --pid-file"))?;
                spawn_exec_supervisor(&root, &id, &process, console_slave.as_deref(), &pid_file)
                    .await?;
                return Ok(0);
            }
            write_pid_file(pid_file.as_deref(), std::process::id() as i32)?;
            let options = ExecOptions {
                id,
                process,
                pid_file: None,
            };
            let code = if let Some(console_slave) = console_slave {
                runtime.exec_console(options, console_slave).await?
            } else {
                runtime.exec(options).await?
            };
            Ok(code)
        }
        Command::ExecSupervisor(ExecSupervisorCommand {
            process,
            console,
            pid_file,
            id,
        }) => {
            let options = ExecOptions {
                id,
                process,
                pid_file: Some(pid_file),
            };
            let code = if let Some(console) = console {
                runtime.exec_console(options, console).await?
            } else {
                runtime.exec(options).await?
            };
            Ok(code)
        }
        Command::Kill(KillCommand { all, id, signal }) => {
            runtime.kill(KillOptions { id, signal, all }).await?;
            Ok(0)
        }
        Command::Delete(DeleteCommand { force, id }) => {
            runtime.delete(DeleteOptions { id, force }).await?;
            Ok(0)
        }
        Command::State(ContainerIdCommand { id }) => {
            let state = runtime.state(&id).await?;
            println!("{}", serde_json::to_string_pretty(&state)?);
            Ok(0)
        }
        Command::Pause(ContainerIdCommand { id }) => {
            runtime.pause(&id).await?;
            Ok(0)
        }
        Command::Resume(ContainerIdCommand { id }) => {
            runtime.resume(&id).await?;
            Ok(0)
        }
        Command::Features => {
            println!("{}", serde_json::to_string_pretty(&oci_features_json())?);
            Ok(0)
        }
    }
}

fn write_pid_file(path: Option<&Path>, pid: i32) -> Result<()> {
    let Some(path) = path else {
        return Ok(());
    };

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create pid-file directory `{}`", parent.display()))?;
    }

    fs::write(path, pid.to_string()).with_context(|| format!("write pid-file `{}`", path.display()))
}

async fn spawn_exec_supervisor(
    root: &Path,
    id: &str,
    process: &Path,
    console: Option<&Path>,
    pid_file: &Path,
) -> Result<()> {
    if let Some(parent) = pid_file.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create exec pid-file directory `{}`", parent.display()))?;
    }
    match fs::remove_file(pid_file) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("remove stale exec pid file `{}`", pid_file.display()));
        }
    }

    let executable = std::env::current_exe().context("resolve runmsb executable")?;
    let mut command = ProcessCommand::new(executable);
    command
        .arg("--root")
        .arg(root)
        .arg("__exec-supervisor")
        .arg("--process")
        .arg(process)
        .arg("--pid-file")
        .arg(pid_file);
    if let Some(console) = console {
        command.arg("--console").arg(console);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
    }
    command.arg(id);

    let mut child = command.spawn().context("spawn OCI exec supervisor")?;
    let expected_pid = child.id() as i32;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(contents) = fs::read_to_string(pid_file)
            && contents.trim().parse::<i32>().ok() == Some(expected_pid)
        {
            return Ok(());
        }
        if let Some(status) = child
            .try_wait()
            .context("poll OCI exec supervisor startup")?
        {
            anyhow::bail!("OCI exec supervisor exited before guest startup: {status}");
        }
        if tokio::time::Instant::now() >= deadline {
            let _ = child.kill();
            anyhow::bail!("timed out waiting for OCI exec supervisor to start guest process");
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
