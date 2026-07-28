//! Entry point for the `microsandbox-runtime` OCI runtime binary.

#[cfg(target_os = "linux")]
mod cli;
#[cfg(target_os = "linux")]
mod commands;
#[cfg(target_os = "linux")]
mod console;
#[cfg(target_os = "linux")]
mod features;
#[cfg(target_os = "linux")]
mod logging;
#[cfg(target_os = "linux")]
mod monitor;

#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::path::Path;

#[cfg(target_os = "linux")]
use anyhow::{Context, Result};
#[cfg(target_os = "linux")]
use clap::Parser;
#[cfg(target_os = "linux")]
use microsandbox_oci_runtime::{
    CreateOptions, DeleteOptions, ExecOptions, KillOptions, MicrosandboxOciRuntime,
};

#[cfg(target_os = "linux")]
use crate::cli::Cli;
#[cfg(target_os = "linux")]
use crate::commands::{
    Command, ContainerIdCommand, CreateCommand, CreateRunOptions, DeleteCommand, ExecCommand,
    KillCommand, MonitorCommand, RunCommand,
};
#[cfg(target_os = "linux")]
use crate::console::setup_oci_console;
#[cfg(target_os = "linux")]
use crate::features::oci_features_json;
#[cfg(target_os = "linux")]
use crate::logging::{init_tracing, write_runtime_error_log};
#[cfg(target_os = "linux")]
use crate::monitor::{request_monitor_start, spawn_create_monitor, wait_for_start_request};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    init_tracing(cli.debug, cli.log_level);
    let log = cli.log.clone();
    let log_format = cli.log_format;

    let code = match run(cli).await {
        Ok(code) => code,
        Err(error) => {
            eprintln!("microsandbox-runtime: {error:#}");
            write_runtime_error_log(log.as_ref(), log_format, &format!("{error:#}"));
            1
        }
    };

    std::process::exit(code);
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("microsandbox-runtime is only supported on Linux hosts");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
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
            runtime
                .create(CreateOptions {
                    id: id.clone(),
                    bundle,
                })
                .await?;
            let console_slave = setup_oci_console(console_socket.as_ref())?;
            let isolate_network_namespace = runtime.requires_fresh_network_namespace(&id)?;
            let monitor_pid = spawn_create_monitor(
                &root,
                &id,
                console_slave.as_ref(),
                isolate_network_namespace,
            )
            .await?;
            runtime.record_host_pid(&id, monitor_pid)?;
            write_pid_file(pid_file.as_deref(), monitor_pid)?;
            Ok(0)
        }
        Command::Start(ContainerIdCommand { id }) => {
            request_monitor_start(&runtime, &root, &id).await?;
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
            runtime
                .create(CreateOptions {
                    id: id.clone(),
                    bundle,
                })
                .await?;
            let console_slave = setup_oci_console(console_socket.as_ref())?;
            let isolate_network_namespace = runtime.requires_fresh_network_namespace(&id)?;
            let monitor_pid = spawn_create_monitor(
                &root,
                &id,
                console_slave.as_ref(),
                isolate_network_namespace,
            )
            .await?;
            runtime.record_host_pid(&id, monitor_pid)?;
            write_pid_file(pid_file.as_deref(), monitor_pid)?;
            request_monitor_start(&runtime, &root, &id).await?;
            Ok(0)
        }
        Command::Exec(command) => {
            let ExecCommand {
                process,
                console_socket,
                pid_file,
                id,
                ..
            } = *command;
            let process = process.ok_or_else(|| {
                anyhow::anyhow!(
                    "command-style exec is not implemented; pass --process process.json"
                )
            })?;
            write_pid_file(pid_file.as_deref(), std::process::id() as i32)?;
            let console_slave = setup_oci_console(console_socket.as_ref())?;
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
        Command::Monitor(MonitorCommand {
            wait_start,
            console_slave,
            id,
        }) => {
            if wait_start && !wait_for_start_request(&runtime, &root, &id).await? {
                eprintln!("OCI init monitor exiting before start request for `{id}`");
                return Ok(0);
            }
            runtime.monitor_init(&id, console_slave).await
        }
    }
}

#[cfg(target_os = "linux")]
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
