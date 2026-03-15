//! Supervisor process: spawns and monitors child processes (VM, msbnet).
//!
//! The supervisor is a separate process spawned by the `microsandbox` library.
//! It spawns the VM (and msbnet) as children, monitors them via waitpid,
//! captures console logs, updates the database, and manages the sandbox
//! lifecycle (idle detection, max duration, drain, graceful shutdown).
//!
//! The supervisor does NOT handle agent protocol communication — that stays
//! in the user application process via AgentBridge.

use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use microsandbox_db::entity::{
    microvm as microvm_entity, sandbox as sandbox_entity, supervisor as supervisor_entity,
};
use nix::sys::signal::Signal;
use sea_orm::{
    ColumnTrait, ConnectOptions, Database, DatabaseConnection, EntityTrait, QueryFilter, Set,
    sea_query::Expr,
};
use serde::Serialize;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    signal::unix::SignalKind,
};

use crate::{
    RuntimeResult,
    drain::{DrainPhase, DrainState},
    heartbeat::HeartbeatReader,
    logging::LogLevel,
    monitor::ChildProcess,
    policy::{ChildPolicies, ExitAction, SupervisorPolicy},
    termination::TerminationReason,
    vm::VmConfig,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Configuration for the supervisor process.
#[derive(Debug)]
pub struct SupervisorConfig {
    /// Name of the sandbox.
    pub sandbox_name: String,

    /// Database ID of the sandbox row.
    pub sandbox_id: i32,

    /// Selected tracing verbosity to apply to the supervisor and its children.
    pub log_level: Option<LogLevel>,

    /// Path to the sandbox database file.
    pub sandbox_db_path: PathBuf,

    /// Directory for log files.
    pub log_dir: PathBuf,

    /// Runtime directory (scripts, heartbeat).
    pub runtime_dir: PathBuf,

    /// Agent FD (inherited from parent, passed to VM for virtio-console).
    pub agent_fd: i32,

    /// Whether to forward VM console output to supervisor stdout.
    pub forward_output: bool,

    /// Policies for child processes.
    pub child_policies: ChildPolicies,

    /// Supervisor lifecycle policy.
    pub supervisor_policy: SupervisorPolicy,

    /// VM configuration (passed through to msb microvm).
    pub vm_config: VmConfig,
}

/// JSON structure written to stdout on supervisor startup.
#[derive(Debug, Serialize)]
struct StartupInfo {
    vm_pid: u32,
    msbnet_pid: Option<u32>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Run the supervisor event loop.
///
/// This is the main entry point for the `msb supervisor` hidden subcommand.
/// It spawns child processes, monitors them, handles signals, and manages
/// the sandbox lifecycle.
pub async fn run(config: SupervisorConfig) -> RuntimeResult<()> {
    tracing::info!(sandbox = %config.sandbox_name, "supervisor starting");

    // Validate agent FD.
    if config.agent_fd < 0 {
        return Err(crate::RuntimeError::Custom(format!(
            "invalid agent_fd: {}",
            config.agent_fd
        )));
    }

    // Connect to the database.
    let db = connect_db(&config.sandbox_db_path).await?;

    // Create supervisor record.
    let supervisor_db_id = insert_supervisor_record(&db, config.sandbox_id).await?;

    // Set up runtime directory.
    std::fs::create_dir_all(&config.runtime_dir)?;
    std::fs::create_dir_all(config.runtime_dir.join("scripts"))?;

    // Resolve the msb binary path (self) for spawning children.
    let msb_path = std::env::current_exe()?;

    // Spawn VM process.
    let mut vm_child = spawn_vm_process(&msb_path, &config)?;
    let vm_pid = vm_child.id().ok_or_else(|| {
        crate::RuntimeError::Custom("VM child exited before PID could be read".to_string())
    })?;

    // Create microvm record.
    let microvm_db_id =
        insert_microvm_record(&db, config.sandbox_id, supervisor_db_id, vm_pid).await?;

    // Write startup info to stdout (the parent reads this).
    let startup = StartupInfo {
        vm_pid,
        msbnet_pid: None,
    };
    println!("{}", serde_json::to_string(&startup)?);

    // Set up console output capture.
    spawn_log_tasks(
        vm_child.stdout.take(),
        vm_child.stderr.take(),
        config.log_dir.clone(),
        config.forward_output,
    );

    // Initialize child process monitor.
    let vm_policy = config.child_policies.vm.clone();
    let mut vm_monitor = ChildProcess::new(vm_pid, "vm".to_string(), vm_policy);

    // Heartbeat reader.
    let heartbeat_reader = HeartbeatReader::new(&config.runtime_dir);

    // Set up signal handlers.
    let mut sigterm = tokio::signal::unix::signal(SignalKind::terminate())?;
    let mut sigint = tokio::signal::unix::signal(SignalKind::interrupt())?;
    let mut sigusr1 = tokio::signal::unix::signal(SignalKind::user_defined1())?;

    // Periodic timers.
    let mut idle_interval = tokio::time::interval(Duration::from_secs(5));

    // Drain state.
    let mut drain: Option<DrainState> = None;

    // Grace timer (initially inactive — set to far future).
    let grace_timer = tokio::time::sleep(Duration::from_secs(86400 * 365));
    tokio::pin!(grace_timer);
    let mut grace_timer_active = false;

    // Kill timer (initially inactive).
    let kill_timer = tokio::time::sleep(Duration::from_secs(86400 * 365));
    tokio::pin!(kill_timer);
    let mut kill_timer_active = false;

    // Max duration timer.
    let has_max_duration = config.supervisor_policy.max_duration_secs.is_some();
    let max_dur_secs = config
        .supervisor_policy
        .max_duration_secs
        .unwrap_or(86400 * 365);
    let max_duration_timer = tokio::time::sleep(Duration::from_secs(max_dur_secs));
    tokio::pin!(max_duration_timer);

    let vm_exit_status;

    loop {
        tokio::select! {
            // ── VM process exit ──────────────────────────────────────────
            //
            // Child::wait() is cancel-safe — safe to call across select
            // iterations without pinning.
            status = vm_child.wait(), if !vm_monitor.has_exited() => {
                let status = status?;
                tracing::info!(pid = vm_pid, ?status, "VM process exited");
                vm_monitor.mark_exited();
                vm_exit_status = Some(status);

                // For Phase 3 (VM only), Restart falls through to
                // ShutdownAll since the VM is the sole child process.
                match vm_monitor.policy().on_exit {
                    ExitAction::ShutdownAll | ExitAction::Restart => {
                        let reason = if status.success() {
                            TerminationReason::VmCompleted
                        } else {
                            TerminationReason::VmFailed
                        };
                        if drain.is_none() {
                            drain = Some(DrainState::new(reason));
                        }
                        break;
                    }
                    ExitAction::Ignore => {
                        tracing::info!("VM exited, policy is Ignore — no children remain, exiting");
                        if drain.is_none() {
                            drain = Some(DrainState::new(TerminationReason::VmCompleted));
                        }
                        break;
                    }
                }
            }

            // ── Idle check ───────────────────────────────────────────────
            _ = idle_interval.tick(), if drain.is_none()
                && config.supervisor_policy.idle_timeout_secs.is_some()
                && !vm_monitor.has_exited() =>
            {
                let timeout = config.supervisor_policy.idle_timeout_secs.unwrap();
                if heartbeat_reader.is_idle(timeout) {
                    tracing::info!(timeout_secs = timeout, "idle timeout reached, triggering drain");
                    let mut d = DrainState::new(TerminationReason::IdleTimeout);
                    begin_drain(
                        &mut d,
                        &config.supervisor_policy,
                        &mut vm_monitor,
                        &mut grace_timer,
                        &mut grace_timer_active,
                        &mut kill_timer,
                        &mut kill_timer_active,
                    );
                    drain = Some(d);
                }
            }

            // ── Max duration timer ───────────────────────────────────────
            _ = &mut max_duration_timer, if has_max_duration && drain.is_none() => {
                tracing::info!("max duration exceeded, triggering drain");
                let mut d = DrainState::new(TerminationReason::MaxDurationExceeded);
                begin_drain(
                    &mut d,
                    &config.supervisor_policy,
                    &mut vm_monitor,
                    &mut grace_timer,
                    &mut grace_timer_active,
                    &mut kill_timer,
                    &mut kill_timer_active,
                );
                drain = Some(d);
            }

            // ── SIGUSR1 — graceful drain request ─────────────────────────
            _ = sigusr1.recv() => {
                try_start_drain(
                    TerminationReason::DrainRequested,
                    "received SIGUSR1, triggering drain",
                    &mut drain,
                    &config.supervisor_policy,
                    &mut vm_monitor,
                    &mut grace_timer,
                    &mut grace_timer_active,
                    &mut kill_timer,
                    &mut kill_timer_active,
                );
            }

            // ── SIGTERM — external shutdown ───────────────────────────────
            _ = sigterm.recv() => {
                try_start_drain(
                    TerminationReason::SupervisorSignal,
                    "received SIGTERM, triggering drain",
                    &mut drain,
                    &config.supervisor_policy,
                    &mut vm_monitor,
                    &mut grace_timer,
                    &mut grace_timer_active,
                    &mut kill_timer,
                    &mut kill_timer_active,
                );
            }

            // ── SIGINT — external shutdown ────────────────────────────────
            _ = sigint.recv() => {
                try_start_drain(
                    TerminationReason::SupervisorSignal,
                    "received SIGINT, triggering drain",
                    &mut drain,
                    &config.supervisor_policy,
                    &mut vm_monitor,
                    &mut grace_timer,
                    &mut grace_timer_active,
                    &mut kill_timer,
                    &mut kill_timer_active,
                );
            }

            // ── Grace timer — escalate to SIGTERM ─────────────────────────
            _ = &mut grace_timer, if grace_timer_active => {
                grace_timer_active = false;
                if let Some(ref mut d) = drain {
                    tracing::info!("grace period expired, sending SIGTERM");
                    d.advance(DrainPhase::SentSigterm);
                    d.record_signal("SIGTERM");
                    let _ = vm_monitor.signal_group(Signal::SIGTERM);
                    kill_timer
                        .as_mut()
                        .reset(tokio::time::Instant::now() + Duration::from_secs(config.supervisor_policy.grace_secs));
                    kill_timer_active = true;
                }
            }

            // ── Kill timer — escalate to SIGKILL ──────────────────────────
            _ = &mut kill_timer, if kill_timer_active => {
                kill_timer_active = false;
                if let Some(ref mut d) = drain {
                    tracing::info!("kill timer expired, sending SIGKILL");
                    d.advance(DrainPhase::SentSigkill);
                    d.record_signal("SIGKILL");
                    let _ = vm_monitor.signal_group(Signal::SIGKILL);
                }
            }
        }
    }

    // ── Shutdown: record results ─────────────────────────────────────────────

    let reason = drain
        .as_ref()
        .map(|d| *d.reason())
        .unwrap_or(TerminationReason::VmCompleted);

    let signals = drain
        .as_ref()
        .map(|d| d.signals_sent().join(","))
        .filter(|s| !s.is_empty());

    let exit_code = vm_exit_status.and_then(|s| s.code());

    update_microvm_record(&db, microvm_db_id, exit_code, reason, signals).await?;
    update_supervisor_record(&db, supervisor_db_id).await?;

    let final_status = match reason {
        TerminationReason::VmCompleted
        | TerminationReason::DrainRequested
        | TerminationReason::SupervisorSignal
        | TerminationReason::IdleTimeout
        | TerminationReason::MaxDurationExceeded => sandbox_entity::SandboxStatus::Stopped,
        _ => sandbox_entity::SandboxStatus::Crashed,
    };
    update_sandbox_status(&db, config.sandbox_id, final_status).await?;

    tracing::info!(
        sandbox = %config.sandbox_name,
        reason = %reason,
        status = ?final_status,
        "supervisor exiting",
    );

    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Functions: Child Process Spawning
//--------------------------------------------------------------------------------------------------

fn spawn_vm_process(
    msb_path: &Path,
    config: &SupervisorConfig,
) -> RuntimeResult<tokio::process::Child> {
    let mut cmd = tokio::process::Command::new(msb_path);
    cmd.args(microvm_cli_args(config));

    // Spawn in its own process group for clean signal delivery.
    cmd.process_group(0);

    // Redirect stdin to /dev/null so the VM child never reads from the caller's
    // terminal. Without this, libkrun's implicit console reads STDIN_FILENO,
    // and the background process group gets SIGTTIN (stopped).
    cmd.stdin(Stdio::null());

    // Pipe stdout/stderr for log capture.
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    // Clear CLOEXEC on the agent FD so it survives exec.
    let agent_fd = config.agent_fd;
    unsafe {
        cmd.pre_exec(move || {
            let flags = libc::fcntl(agent_fd, libc::F_GETFD);
            if flags == -1 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::fcntl(agent_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let child = cmd.spawn()?;
    tracing::info!(pid = child.id(), "spawned VM process");

    Ok(child)
}

fn microvm_cli_args(config: &SupervisorConfig) -> Vec<OsString> {
    let mut args = Vec::new();
    args.push(OsString::from("microvm"));

    if let Some(log_level) = config.log_level {
        args.push(OsString::from(log_level.as_cli_flag()));
    }

    args.push(OsString::from("--libkrunfw-path"));
    args.push(config.vm_config.libkrunfw_path.clone().into_os_string());
    args.push(OsString::from("--vcpus"));
    args.push(OsString::from(config.vm_config.vcpus.to_string()));
    args.push(OsString::from("--memory-mib"));
    args.push(OsString::from(config.vm_config.memory_mib.to_string()));

    if let Some(ref rootfs_path) = config.vm_config.rootfs_path {
        args.push(OsString::from("--rootfs-path"));
        args.push(rootfs_path.clone().into_os_string());
    }

    for lower in &config.vm_config.rootfs_lowers {
        args.push(OsString::from("--rootfs-lower"));
        args.push(lower.clone().into_os_string());
    }
    if let Some(ref upper_dir) = config.vm_config.rootfs_upper {
        args.push(OsString::from("--rootfs-upper"));
        args.push(upper_dir.clone().into_os_string());
    }
    if let Some(ref staging_dir) = config.vm_config.rootfs_staging {
        args.push(OsString::from("--rootfs-staging"));
        args.push(staging_dir.clone().into_os_string());
    }

    if let Some(ref disk_path) = config.vm_config.rootfs_disk {
        args.push(OsString::from("--rootfs-disk"));
        args.push(disk_path.clone().into_os_string());
    }
    if let Some(ref disk_format) = config.vm_config.rootfs_disk_format {
        args.push(OsString::from("--rootfs-disk-format"));
        args.push(OsString::from(disk_format));
    }
    if config.vm_config.rootfs_disk_readonly {
        args.push(OsString::from("--rootfs-disk-readonly"));
    }

    for mount in &config.vm_config.mounts {
        args.push(OsString::from("--mount"));
        args.push(OsString::from(mount));
    }

    // Inject the runtime directory as a virtiofs mount so the guest can access
    // scripts and write heartbeat at the canonical mount point (/.msb).
    args.push(OsString::from("--mount"));
    args.push(OsString::from(format!(
        "{}:{}",
        microsandbox_protocol::RUNTIME_FS_TAG,
        config.runtime_dir.display()
    )));

    if let Some(ref init_path) = config.vm_config.init_path {
        args.push(OsString::from("--init-path"));
        args.push(init_path.clone().into_os_string());
    }

    for env_var in &config.vm_config.env {
        args.push(OsString::from("--env"));
        args.push(OsString::from(env_var));
    }

    if let Some(ref workdir) = config.vm_config.workdir {
        args.push(OsString::from("--workdir"));
        args.push(workdir.clone().into_os_string());
    }

    if let Some(ref exec_path) = config.vm_config.exec_path {
        args.push(OsString::from("--exec-path"));
        args.push(exec_path.clone().into_os_string());
    }

    args.push(OsString::from("--agent-fd"));
    args.push(OsString::from(config.agent_fd.to_string()));

    if !config.vm_config.exec_args.is_empty() {
        args.push(OsString::from("--"));
        args.extend(config.vm_config.exec_args.iter().map(OsString::from));
    }

    args
}

//--------------------------------------------------------------------------------------------------
// Functions: Drain Management
//--------------------------------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn try_start_drain(
    reason: TerminationReason,
    msg: &str,
    drain: &mut Option<DrainState>,
    policy: &SupervisorPolicy,
    vm_monitor: &mut ChildProcess,
    grace_timer: &mut std::pin::Pin<&mut tokio::time::Sleep>,
    grace_timer_active: &mut bool,
    kill_timer: &mut std::pin::Pin<&mut tokio::time::Sleep>,
    kill_timer_active: &mut bool,
) {
    if drain.is_none() {
        tracing::info!("{msg}");
        let mut d = DrainState::new(reason);
        begin_drain(
            &mut d,
            policy,
            vm_monitor,
            grace_timer,
            grace_timer_active,
            kill_timer,
            kill_timer_active,
        );
        *drain = Some(d);
    }
}

fn begin_drain(
    drain: &mut DrainState,
    policy: &SupervisorPolicy,
    vm_monitor: &mut ChildProcess,
    grace_timer: &mut std::pin::Pin<&mut tokio::time::Sleep>,
    grace_timer_active: &mut bool,
    kill_timer: &mut std::pin::Pin<&mut tokio::time::Sleep>,
    kill_timer_active: &mut bool,
) {
    let initial = DrainState::initial_phase(&policy.shutdown_mode);
    drain.advance(initial.clone());

    match initial {
        DrainPhase::WaitingVoluntary => {
            // Start grace timer — if nothing exits voluntarily, escalate to SIGTERM.
            grace_timer
                .as_mut()
                .reset(tokio::time::Instant::now() + Duration::from_secs(policy.grace_secs));
            *grace_timer_active = true;
        }
        DrainPhase::SentSigterm => {
            // Send SIGTERM immediately.
            drain.record_signal("SIGTERM");
            let _ = vm_monitor.signal_group(Signal::SIGTERM);
            // Start kill timer.
            kill_timer
                .as_mut()
                .reset(tokio::time::Instant::now() + Duration::from_secs(policy.grace_secs));
            *kill_timer_active = true;
        }
        DrainPhase::SentSigkill => {
            // Send SIGKILL immediately.
            drain.record_signal("SIGKILL");
            let _ = vm_monitor.signal_group(Signal::SIGKILL);
        }
        DrainPhase::Complete => {}
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Log Capture
//--------------------------------------------------------------------------------------------------

fn spawn_log_tasks(
    stdout: Option<tokio::process::ChildStdout>,
    stderr: Option<tokio::process::ChildStderr>,
    log_dir: PathBuf,
    forward: bool,
) {
    if let Some(stdout) = stdout {
        let path = log_dir.join("vm.stdout.log");
        tokio::spawn(pipe_to_log(stdout, path, forward.then(tokio::io::stdout)));
    }

    if let Some(stderr) = stderr {
        let path = log_dir.join("vm.stderr.log");
        tokio::spawn(pipe_to_log(stderr, path, forward.then(tokio::io::stderr)));
    }
}

async fn pipe_to_log<R, W>(mut reader: R, file_path: PathBuf, mut forward_to: Option<W>)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let Ok(mut file) = tokio::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&file_path)
        .await
    else {
        tracing::warn!(path = %file_path.display(), "failed to open log file");
        return;
    };

    let mut buf = vec![0u8; 4096];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                if let Err(e) = file.write_all(&buf[..n]).await {
                    tracing::warn!(path = %file_path.display(), error = %e, "log file write failed");
                }
                if let Some(ref mut w) = forward_to {
                    let _ = w.write_all(&buf[..n]).await;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                tracing::warn!(path = %file_path.display(), error = %e, "log capture read error");
                break;
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Database Operations
//--------------------------------------------------------------------------------------------------

async fn connect_db(db_path: &Path) -> RuntimeResult<DatabaseConnection> {
    let db_path_str = db_path.to_str().ok_or_else(|| {
        crate::RuntimeError::Custom(format!(
            "database path is not valid UTF-8: {}",
            db_path.display()
        ))
    })?;

    let db_url = format!("sqlite://{db_path_str}?mode=rwc");
    let mut opts = ConnectOptions::new(&db_url);
    opts.max_connections(1);

    let conn = Database::connect(opts).await?;
    Ok(conn)
}

async fn insert_supervisor_record(db: &DatabaseConnection, sandbox_id: i32) -> RuntimeResult<i32> {
    let pid = i32::try_from(std::process::id()).map_err(|e| {
        crate::RuntimeError::Custom(format!("supervisor PID does not fit in i32: {e}"))
    })?;
    let now = chrono::Utc::now().naive_utc();

    let model = supervisor_entity::ActiveModel {
        sandbox_id: Set(sandbox_id),
        pid: Set(Some(pid)),
        status: Set(supervisor_entity::SupervisorStatus::Running),
        started_at: Set(Some(now)),
        ..Default::default()
    };

    let result = supervisor_entity::Entity::insert(model).exec(db).await?;
    Ok(result.last_insert_id)
}

async fn insert_microvm_record(
    db: &DatabaseConnection,
    sandbox_id: i32,
    supervisor_id: i32,
    vm_pid: u32,
) -> RuntimeResult<i32> {
    let vm_pid = i32::try_from(vm_pid)
        .map_err(|e| crate::RuntimeError::Custom(format!("VM PID does not fit in i32: {e}")))?;
    let now = chrono::Utc::now().naive_utc();

    let model = microvm_entity::ActiveModel {
        sandbox_id: Set(sandbox_id),
        supervisor_id: Set(supervisor_id),
        pid: Set(Some(vm_pid)),
        status: Set(microvm_entity::MicrovmStatus::Running),
        started_at: Set(Some(now)),
        ..Default::default()
    };

    let result = microvm_entity::Entity::insert(model).exec(db).await?;
    Ok(result.last_insert_id)
}

async fn update_sandbox_status(
    db: &DatabaseConnection,
    sandbox_id: i32,
    status: sandbox_entity::SandboxStatus,
) -> RuntimeResult<()> {
    let result = sandbox_entity::Entity::update_many()
        .col_expr(sandbox_entity::Column::Status, Expr::value(status))
        .col_expr(
            sandbox_entity::Column::UpdatedAt,
            Expr::value(chrono::Utc::now().naive_utc()),
        )
        .filter(sandbox_entity::Column::Id.eq(sandbox_id))
        .exec(db)
        .await?;

    if result.rows_affected == 0 {
        tracing::warn!(sandbox_id, "update_sandbox_status matched zero rows");
    }

    Ok(())
}

async fn update_microvm_record(
    db: &DatabaseConnection,
    microvm_id: i32,
    exit_code: Option<i32>,
    reason: TerminationReason,
    signals: Option<String>,
) -> RuntimeResult<()> {
    let now = chrono::Utc::now().naive_utc();

    microvm_entity::Entity::update_many()
        .col_expr(
            microvm_entity::Column::Status,
            Expr::value(microvm_entity::MicrovmStatus::Terminated),
        )
        .col_expr(microvm_entity::Column::ExitCode, Expr::value(exit_code))
        .col_expr(
            microvm_entity::Column::TerminationReason,
            Expr::value(reason),
        )
        .col_expr(microvm_entity::Column::SignalsSent, Expr::value(signals))
        .col_expr(microvm_entity::Column::TerminatedAt, Expr::value(now))
        .filter(microvm_entity::Column::Id.eq(microvm_id))
        .exec(db)
        .await?;

    Ok(())
}

async fn update_supervisor_record(
    db: &DatabaseConnection,
    supervisor_id: i32,
) -> RuntimeResult<()> {
    let now = chrono::Utc::now().naive_utc();

    supervisor_entity::Entity::update_many()
        .col_expr(
            supervisor_entity::Column::Status,
            Expr::value(supervisor_entity::SupervisorStatus::Stopped),
        )
        .col_expr(supervisor_entity::Column::StoppedAt, Expr::value(now))
        .filter(supervisor_entity::Column::Id.eq(supervisor_id))
        .exec(db)
        .await?;

    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{ChildPolicies, SupervisorPolicy};

    fn test_supervisor_config(log_level: Option<LogLevel>) -> SupervisorConfig {
        SupervisorConfig {
            sandbox_name: "test".into(),
            sandbox_id: 1,
            log_level,
            sandbox_db_path: PathBuf::from("/tmp/test.db"),
            log_dir: PathBuf::from("/tmp/logs"),
            runtime_dir: PathBuf::from("/tmp/runtime"),
            agent_fd: 7,
            forward_output: false,
            child_policies: ChildPolicies::default(),
            supervisor_policy: SupervisorPolicy::default(),
            vm_config: VmConfig {
                libkrunfw_path: PathBuf::from("/tmp/libkrunfw.dylib"),
                vcpus: 1,
                memory_mib: 512,
                rootfs_path: Some(PathBuf::from("/tmp/rootfs")),
                rootfs_lowers: Vec::new(),
                rootfs_upper: None,
                rootfs_staging: None,
                rootfs_disk: None,
                rootfs_disk_format: None,
                rootfs_disk_readonly: false,
                mounts: vec!["data:/tmp/data".into()],
                backends: Vec::new(),
                init_path: None,
                env: vec!["FOO=bar".into()],
                workdir: Some(PathBuf::from("/work")),
                exec_path: Some(PathBuf::from("/bin/sh")),
                exec_args: vec!["-lc".into(), "echo hi".into()],
                net_fd: None,
                agent_fd: None,
            },
        }
    }

    #[test]
    fn test_microvm_cli_args_include_selected_log_level() {
        let args = microvm_cli_args(&test_supervisor_config(Some(LogLevel::Debug)));
        let rendered = args
            .into_iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        assert_eq!(rendered[0], "microvm");
        assert!(rendered.contains(&"--debug".to_string()));
        assert!(rendered.contains(&"--agent-fd".to_string()));
    }

    #[test]
    fn test_microvm_cli_args_are_silent_by_default() {
        let args = microvm_cli_args(&test_supervisor_config(None));
        let rendered = args
            .into_iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        assert_eq!(rendered[0], "microvm");
        assert!(!rendered.iter().any(|arg| arg == "--error"));
        assert!(!rendered.iter().any(|arg| arg == "--warn"));
        assert!(!rendered.iter().any(|arg| arg == "--info"));
        assert!(!rendered.iter().any(|arg| arg == "--debug"));
        assert!(!rendered.iter().any(|arg| arg == "--trace"));
    }

    #[test]
    fn test_microvm_cli_args_include_overlay_rootfs_paths() {
        let mut config = test_supervisor_config(None);
        config.vm_config.rootfs_path = None;
        config.vm_config.rootfs_lowers = vec![PathBuf::from("/tmp/layer0")];
        config.vm_config.rootfs_upper = Some(PathBuf::from("/tmp/rw"));
        config.vm_config.rootfs_staging = Some(PathBuf::from("/tmp/staging"));

        let args = microvm_cli_args(&config);
        let rendered = args
            .into_iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        assert!(rendered.contains(&"--rootfs-lower".to_string()));
        assert!(rendered.contains(&"/tmp/layer0".to_string()));
        assert!(rendered.contains(&"--rootfs-upper".to_string()));
        assert!(rendered.contains(&"/tmp/rw".to_string()));
        assert!(rendered.contains(&"--rootfs-staging".to_string()));
        assert!(rendered.contains(&"/tmp/staging".to_string()));
    }
}
