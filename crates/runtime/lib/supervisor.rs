//! Supervisor process: spawns and monitors child processes (VM, msbnet).
//!
//! The supervisor is a separate process spawned by the `microsandbox` library.
//! It spawns the VM (and msbnet) as children, monitors them via waitpid,
//! captures console logs, updates the database, and manages the sandbox
//! lifecycle (idle detection, max duration, drain, graceful shutdown).
//!
//! The supervisor does NOT handle agent protocol communication — that stays
//! in the user application process via AgentBridge.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use microsandbox_db::entity::{
    microvm as microvm_entity, sandbox as sandbox_entity, supervisor as supervisor_entity,
};
use nix::sys::signal::Signal;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectOptions, Database, DatabaseConnection, EntityTrait,
    QueryFilter, Set,
};
use sea_orm::sea_query::Expr;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::signal::unix::SignalKind;

use crate::drain::{DrainPhase, DrainState};
use crate::heartbeat::HeartbeatReader;
use crate::monitor::ChildProcess;
use crate::policy::{ChildPolicies, ExitAction, SupervisorPolicy};
use crate::termination::TerminationReason;
use crate::vm::VmConfig;
use crate::RuntimeResult;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Configuration for the supervisor process.
#[derive(Debug)]
pub struct SupervisorConfig {
    /// Name of the sandbox.
    pub sandbox_name: String,

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

    // Resolve sandbox ID once (used by both insert functions).
    let sandbox_id = get_sandbox_id(&db, &config.sandbox_name).await?;

    // Create supervisor record.
    let supervisor_db_id = insert_supervisor_record(&db, sandbox_id).await?;

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
        insert_microvm_record(&db, sandbox_id, supervisor_db_id, vm_pid).await?;

    // Update sandbox status to Running.
    update_sandbox_status(&db, &config.sandbox_name, sandbox_entity::SandboxStatus::Running).await?;

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
    update_sandbox_status(&db, &config.sandbox_name, final_status).await?;

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
    cmd.arg("microvm");

    cmd.arg("--libkrunfw-path")
        .arg(&config.vm_config.libkrunfw_path);
    cmd.arg("--vcpus").arg(config.vm_config.vcpus.to_string());
    cmd.arg("--memory-mib")
        .arg(config.vm_config.memory_mib.to_string());

    for layer in &config.vm_config.rootfs_layers {
        cmd.arg("--rootfs-layer").arg(layer);
    }

    for mount in &config.vm_config.mounts {
        cmd.arg("--mount").arg(mount);
    }

    if let Some(ref init_path) = config.vm_config.init_path {
        cmd.arg("--init-path").arg(init_path);
    }

    for env_var in &config.vm_config.env {
        cmd.arg("--env").arg(env_var);
    }

    if let Some(ref workdir) = config.vm_config.workdir {
        cmd.arg("--workdir").arg(workdir);
    }

    if let Some(ref exec_path) = config.vm_config.exec_path {
        cmd.arg("--exec-path").arg(exec_path);
    }

    cmd.arg("--agent-fd").arg(config.agent_fd.to_string());

    if !config.vm_config.exec_args.is_empty() {
        cmd.arg("--");
        cmd.args(&config.vm_config.exec_args);
    }

    // Spawn in its own process group for clean signal delivery.
    cmd.process_group(0);

    // Pipe stdout/stderr for log capture.
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    // Clear CLOEXEC on the agent FD so it survives exec.
    let agent_fd = config.agent_fd;
    unsafe {
        cmd.pre_exec(move || {
            if libc::fcntl(agent_fd, libc::F_SETFD, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let child = cmd.spawn()?;
    tracing::info!(pid = child.id(), "spawned VM process");

    Ok(child)
}

//--------------------------------------------------------------------------------------------------
// Functions: Drain Management
//--------------------------------------------------------------------------------------------------

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
        tokio::spawn(pipe_to_log(
            stdout,
            path,
            forward.then(|| tokio::io::stdout()),
        ));
    }

    if let Some(stderr) = stderr {
        let path = log_dir.join("vm.stderr.log");
        tokio::spawn(pipe_to_log(
            stderr,
            path,
            forward.then(|| tokio::io::stderr()),
        ));
    }
}

async fn pipe_to_log<R, W>(mut reader: R, file_path: PathBuf, mut forward_to: Option<W>)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let Ok(mut file) = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
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

async fn insert_supervisor_record(
    db: &DatabaseConnection,
    sandbox_id: i32,
) -> RuntimeResult<i32> {
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

    let result = model.insert(db).await?;
    Ok(result.id)
}

async fn insert_microvm_record(
    db: &DatabaseConnection,
    sandbox_id: i32,
    supervisor_id: i32,
    vm_pid: u32,
) -> RuntimeResult<i32> {
    let vm_pid = i32::try_from(vm_pid).map_err(|e| {
        crate::RuntimeError::Custom(format!("VM PID does not fit in i32: {e}"))
    })?;
    let now = chrono::Utc::now().naive_utc();

    let model = microvm_entity::ActiveModel {
        sandbox_id: Set(sandbox_id),
        supervisor_id: Set(supervisor_id),
        pid: Set(Some(vm_pid)),
        status: Set(microvm_entity::MicrovmStatus::Running),
        started_at: Set(Some(now)),
        ..Default::default()
    };

    let result = model.insert(db).await?;
    Ok(result.id)
}

async fn update_sandbox_status(
    db: &DatabaseConnection,
    sandbox_name: &str,
    status: sandbox_entity::SandboxStatus,
) -> RuntimeResult<()> {
    let result = sandbox_entity::Entity::update_many()
        .col_expr(sandbox_entity::Column::Status, Expr::value(status))
        .col_expr(
            sandbox_entity::Column::UpdatedAt,
            Expr::value(chrono::Utc::now().naive_utc()),
        )
        .filter(sandbox_entity::Column::Name.eq(sandbox_name))
        .exec(db)
        .await?;

    if result.rows_affected == 0 {
        tracing::warn!(sandbox = sandbox_name, "update_sandbox_status matched zero rows");
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
        .col_expr(
            microvm_entity::Column::SignalsSent,
            Expr::value(signals),
        )
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

async fn get_sandbox_id(db: &DatabaseConnection, sandbox_name: &str) -> RuntimeResult<i32> {
    let model = sandbox_entity::Entity::find()
        .filter(sandbox_entity::Column::Name.eq(sandbox_name))
        .one(db)
        .await?
        .ok_or_else(|| {
            crate::RuntimeError::Custom(format!(
                "sandbox '{}' not found in database",
                sandbox_name,
            ))
        })?;

    Ok(model.id)
}
