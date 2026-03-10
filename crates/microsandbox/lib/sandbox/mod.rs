//! Sandbox lifecycle management.
//!
//! The [`Sandbox`] struct represents a running sandbox. It is created via
//! [`Sandbox::builder`] or [`Sandbox::create`], and provides lifecycle
//! methods (stop, kill, drain, wait) and access to the [`AgentBridge`]
//! for guest communication.

mod attach;
mod builder;
mod config;
pub mod exec;
pub mod fs;
mod types;

use std::process::ExitStatus;
use std::sync::Arc;

use bytes::Bytes;
use microsandbox_protocol::exec::{
    ExecExited, ExecRequest, ExecRlimit, ExecStarted, ExecStderr, ExecStdin, ExecStdout,
};
use microsandbox_protocol::message::{Message, MessageType};
use sea_orm::sea_query::{Expr, OnConflict};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, QueryFilter, QueryOrder, Set,
};
use tokio::sync::{Mutex, mpsc};

use crate::MicrosandboxResult;
use crate::agent::AgentBridge;
use crate::db::entity::sandbox as sandbox_entity;
use crate::db::entity::sandbox::SandboxStatus;
use crate::runtime::{SupervisorHandle, spawn_supervisor};

use self::exec::{ExecEvent, ExecHandle, ExecOutput, ExecSink, IntoExecOptions, StdinMode};

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use attach::{AttachBuilder, AttachConfig, IntoAttachConfig, SessionInfo};
pub use builder::SandboxBuilder;
pub use config::SandboxConfig;
pub use exec::{ExecOptionsBuilder, ExitStatus as ExecExitStatus, Rlimit, RlimitResource, SizeExt};
pub use fs::{FsEntry, FsEntryKind, FsMetadata, FsReadStream, FsWriteSink, SandboxFs};
pub use types::{
    MountBuilder, NetworkConfig, Patch, RootfsSource, SecretsConfig, SshConfig, VolumeMount,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A running sandbox.
///
/// Created via [`Sandbox::builder`] or [`Sandbox::create`]. Provides
/// lifecycle management and access to the agent bridge for guest communication.
pub struct Sandbox {
    config: SandboxConfig,
    handle: Arc<Mutex<SupervisorHandle>>,
    bridge: Arc<AgentBridge>,
}

/// Summary information about a sandbox (re-exported from entity model).
pub type SandboxInfo = sandbox_entity::Model;

//--------------------------------------------------------------------------------------------------
// Methods: Static
//--------------------------------------------------------------------------------------------------

impl Sandbox {
    /// Create a builder for a new sandbox.
    pub fn builder(name: impl Into<String>) -> SandboxBuilder {
        SandboxBuilder::new(name)
    }

    /// Create a sandbox from a config.
    ///
    /// Boots the VM with agentd ready to accept commands. Does not run
    /// any user workload — use `exec()`, `shell()`, etc. afterward.
    pub async fn create(config: SandboxConfig) -> MicrosandboxResult<Self> {
        // Initialize the database.
        let db =
            crate::db::init_global(Some(crate::config::config().database.max_connections)).await?;

        // Upsert sandbox record.
        upsert_sandbox_record(db, &config).await?;

        // Spawn supervisor + create bridge. On failure, mark the sandbox
        // as stopped so it doesn't appear as a phantom "Running" entry.
        match Self::create_inner(&config).await {
            Ok(sandbox) => Ok(sandbox),
            Err(e) => {
                let _ = update_sandbox_status(db, &config.name, SandboxStatus::Stopped).await;
                Err(e)
            }
        }
    }

    /// Inner create logic separated for error-cleanup wrapper.
    async fn create_inner(config: &SandboxConfig) -> MicrosandboxResult<Self> {
        let (handle, agent_host_fd) = spawn_supervisor(config).await?;
        let bridge = AgentBridge::new(agent_host_fd)?;
        let ready = bridge.wait_ready().await?;

        tracing::info!(
            boot_time_ms = ready.boot_time_ns / 1_000_000,
            init_time_ms = ready.init_time_ns / 1_000_000,
            ready_time_ms = ready.ready_time_ns / 1_000_000,
            "sandbox ready",
        );

        Ok(Self {
            config: config.clone(),
            handle: Arc::new(Mutex::new(handle)),
            bridge: Arc::new(bridge),
        })
    }

    /// Get sandbox info by name from the database.
    pub async fn get(name: &str) -> MicrosandboxResult<SandboxInfo> {
        let db =
            crate::db::init_global(Some(crate::config::config().database.max_connections)).await?;

        sandbox_entity::Entity::find()
            .filter(sandbox_entity::Column::Name.eq(name))
            .one(db)
            .await?
            .ok_or_else(|| crate::MicrosandboxError::SandboxNotFound(name.into()))
    }

    /// List all sandboxes from the database.
    pub async fn list() -> MicrosandboxResult<Vec<SandboxInfo>> {
        let db =
            crate::db::init_global(Some(crate::config::config().database.max_connections)).await?;

        sandbox_entity::Entity::find()
            .order_by_desc(sandbox_entity::Column::CreatedAt)
            .all(db)
            .await
            .map_err(Into::into)
    }

    /// Remove a stopped sandbox from the database.
    pub async fn remove(name: &str) -> MicrosandboxResult<()> {
        // Check if the sandbox exists and its status.
        let model = Self::get(name).await?;
        if model.status == SandboxStatus::Running || model.status == SandboxStatus::Draining {
            return Err(crate::MicrosandboxError::SandboxStillRunning(format!(
                "cannot remove sandbox '{name}': still running"
            )));
        }

        let db =
            crate::db::init_global(Some(crate::config::config().database.max_connections)).await?;

        model.into_active_model().delete(db).await?;

        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: Instance
//--------------------------------------------------------------------------------------------------

impl Sandbox {
    /// Get the sandbox name.
    pub fn name(&self) -> &str {
        &self.config.name
    }

    /// Get the sandbox configuration.
    pub fn config(&self) -> &SandboxConfig {
        &self.config
    }

    /// Get the agent bridge for low-level communication with agentd.
    pub fn bridge(&self) -> &AgentBridge {
        &self.bridge
    }

    /// Access the filesystem API for this sandbox.
    pub fn fs(&self) -> fs::SandboxFs<'_> {
        fs::SandboxFs::new(&self.bridge)
    }

    /// Stop the sandbox gracefully by sending `core.shutdown` to agentd.
    pub async fn stop(&self) -> MicrosandboxResult<()> {
        let msg = Message::new(MessageType::Shutdown, 0, Vec::new());
        self.bridge.send(&msg).await
    }

    /// Kill the sandbox immediately (SIGKILL to VM process).
    pub async fn kill(&self) -> MicrosandboxResult<()> {
        self.handle.lock().await.kill_vm()
    }

    /// Trigger a graceful drain (SIGUSR1 to supervisor).
    pub async fn drain(&self) -> MicrosandboxResult<()> {
        self.handle.lock().await.drain_supervisor()
    }

    /// Wait for the supervisor process to exit.
    ///
    /// Updates the sandbox status in the database to `Stopped` after exit.
    pub async fn wait(&self) -> MicrosandboxResult<ExitStatus> {
        let status = self.handle.lock().await.wait().await?;

        // Update the DB status now that the supervisor has exited.
        if let Ok(db) =
            crate::db::init_global(Some(crate::config::config().database.max_connections)).await
        {
            let _ = update_sandbox_status(db, &self.config.name, SandboxStatus::Stopped).await;
        }

        Ok(status)
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: Execution
//--------------------------------------------------------------------------------------------------

impl Sandbox {
    /// Execute a command and return a streaming handle.
    ///
    /// This is the foundational exec method. All other exec methods delegate to it.
    pub async fn exec_stream(
        &self,
        cmd: impl Into<String>,
        opts: impl IntoExecOptions,
    ) -> MicrosandboxResult<ExecHandle> {
        let cmd = cmd.into();
        let opts = opts.into_exec_options();

        // Allocate correlation ID and subscribe BEFORE sending.
        let id = self.bridge.next_id();
        let rx = self.bridge.subscribe(id).await;

        let req = build_exec_request(
            &self.config,
            cmd,
            opts.args.clone(),
            opts.cwd.clone(),
            &opts.env,
            &opts.rlimits,
            opts.tty,
            24,
            80,
        );
        let msg = Message::with_payload(MessageType::ExecRequest, id, &req)?;
        self.bridge.send(&msg).await?;

        // Build stdin sink (if Pipe mode).
        let stdin = match &opts.stdin {
            StdinMode::Pipe => Some(ExecSink::new(id, Arc::clone(&self.bridge))),
            _ => None,
        };

        // Handle StdinMode::Bytes — send bytes then close.
        if let StdinMode::Bytes(ref data) = opts.stdin {
            let data = data.clone();
            let bridge = Arc::clone(&self.bridge);
            tokio::spawn(async move {
                let payload = ExecStdin { data };
                if let Ok(msg) = Message::with_payload(MessageType::ExecStdin, id, &payload) {
                    let _ = bridge.send(&msg).await;
                }
                // Send empty to signal EOF.
                let close = ExecStdin { data: Vec::new() };
                if let Ok(msg) = Message::with_payload(MessageType::ExecStdin, id, &close) {
                    let _ = bridge.send(&msg).await;
                }
            });
        }

        // Transform raw protocol messages into ExecEvents.
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        tokio::spawn(event_mapper_task(rx, event_tx));

        Ok(ExecHandle::new(
            id,
            event_rx,
            stdin,
            Arc::clone(&self.bridge),
        ))
    }

    /// Execute a command and wait for completion.
    ///
    /// Returns captured stdout/stderr.
    ///
    /// - `sandbox.exec("ls", ["-la"])` — command + args
    /// - `sandbox.exec("python", |e| e.args(["-c", "print('hi')"]).env("HOME", "/root"))` — closure
    /// - `sandbox.exec("cat", ())` — no options
    pub async fn exec(
        &self,
        cmd: impl Into<String>,
        opts: impl IntoExecOptions,
    ) -> MicrosandboxResult<ExecOutput> {
        let opts = opts.into_exec_options();
        let timeout_duration = opts.timeout;
        let mut handle = self.exec_stream(cmd, opts).await?;

        match timeout_duration {
            Some(duration) => {
                match tokio::time::timeout(duration, handle.collect()).await {
                    Ok(result) => result,
                    Err(_) => {
                        // Timed out — kill the process and drain remaining events.
                        let _ = handle.kill().await;
                        match tokio::time::timeout(
                            std::time::Duration::from_secs(5),
                            handle.collect(),
                        )
                        .await
                        {
                            Ok(result) => result,
                            Err(_) => Err(crate::MicrosandboxError::ExecTimeout(duration)),
                        }
                    }
                }
            }
            None => handle.collect().await,
        }
    }

    /// Execute a shell command and wait for completion.
    ///
    /// Uses the sandbox's configured shell (default: `/bin/sh`).
    ///
    /// - `sandbox.shell("echo hello", ())` — no options
    /// - `sandbox.shell("make test", |e| e.env("CI", "true"))` — with env
    pub async fn shell(
        &self,
        script: impl Into<String>,
        opts: impl IntoExecOptions,
    ) -> MicrosandboxResult<ExecOutput> {
        let shell = self.config.shell.as_deref().unwrap_or("/bin/sh");
        let mut opts = opts.into_exec_options();
        opts.args = vec!["-c".to_string(), script.into()];
        self.exec(shell, opts).await
    }

    /// Execute a shell command with streaming I/O.
    pub async fn shell_stream(
        &self,
        script: impl Into<String>,
        opts: impl IntoExecOptions,
    ) -> MicrosandboxResult<ExecHandle> {
        let shell = self.config.shell.as_deref().unwrap_or("/bin/sh");
        let mut opts = opts.into_exec_options();
        opts.args = vec!["-c".to_string(), script.into()];
        self.exec_stream(shell, opts).await
    }

    /// Run a named script (defined via `.script()` in builder).
    ///
    /// Scripts are available at `/.msb/scripts/<name>` in the guest.
    pub async fn run(
        &self,
        name: &str,
        opts: impl IntoExecOptions,
    ) -> MicrosandboxResult<ExecOutput> {
        if !self.config.scripts.contains_key(name) {
            return Err(crate::MicrosandboxError::ScriptNotFound(name.to_string()));
        }
        let script_path = format!("/.msb/scripts/{name}");
        self.shell(&format!("sh {script_path}"), opts).await
    }

    /// Run a named script with streaming I/O.
    pub async fn run_stream(
        &self,
        name: &str,
        opts: impl IntoExecOptions,
    ) -> MicrosandboxResult<ExecHandle> {
        if !self.config.scripts.contains_key(name) {
            return Err(crate::MicrosandboxError::ScriptNotFound(name.to_string()));
        }
        let script_path = format!("/.msb/scripts/{name}");
        self.shell_stream(&format!("sh {script_path}"), opts).await
    }

    /// Start the sandbox by running the `"start"` script.
    ///
    /// Returns error if no `"start"` script is defined.
    pub async fn start(&self) -> MicrosandboxResult<ExecOutput> {
        self.run("start", ()).await
    }

    /// Start the sandbox with streaming I/O.
    pub async fn start_stream(&self) -> MicrosandboxResult<ExecHandle> {
        self.run_stream("start", ()).await
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: Attach
//--------------------------------------------------------------------------------------------------

impl Sandbox {
    /// Attach to the sandbox with an interactive terminal session.
    ///
    /// Bridges the host terminal to a guest process running in a PTY.
    /// Returns the exit code when the process exits or the user detaches.
    ///
    /// - `sandbox.attach(())` — default shell
    /// - `sandbox.attach("bash")` — specific command
    /// - `sandbox.attach(|a| a.cmd("zsh").env("TERM", "xterm"))` — closure
    pub async fn attach(&self, config: impl attach::IntoAttachConfig) -> MicrosandboxResult<i32> {
        use microsandbox_protocol::exec::ExecResize;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let config = config.into_attach_config();
        let detach_keys = match &config.detach_keys {
            Some(spec) => attach::DetachKeys::parse(spec)?,
            None => attach::DetachKeys::default_keys(),
        };

        // Resolve command (default to sandbox shell).
        let cmd = config.cmd.unwrap_or_else(|| {
            self.config
                .shell
                .clone()
                .unwrap_or_else(|| "/bin/sh".into())
        });

        // Get terminal size.
        let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));

        // Allocate ID and subscribe.
        let id = self.bridge.next_id();
        let mut rx = self.bridge.subscribe(id).await;

        // Build ExecRequest with tty=true.
        let req = build_exec_request(
            &self.config,
            cmd,
            config.args,
            config.cwd,
            &config.env,
            &config.rlimits,
            true,
            rows,
            cols,
        );
        let msg = Message::with_payload(MessageType::ExecRequest, id, &req)?;
        self.bridge.send(&msg).await?;

        // Enter raw mode.
        crossterm::terminal::enable_raw_mode()
            .map_err(|e| crate::MicrosandboxError::Terminal(e.to_string()))?;
        let _raw_guard = scopeguard::guard((), |_| {
            let _ = crossterm::terminal::disable_raw_mode();
        });

        // Set up async I/O.
        let mut stdin = tokio::io::stdin();
        let mut stdout = tokio::io::stdout();
        let mut sigwinch =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
                .map_err(|e| crate::MicrosandboxError::Runtime(format!("sigwinch: {e}")))?;

        let mut exit_code: i32 = -1;
        let detach_seq = detach_keys.sequence();
        let mut match_pos = 0usize;

        loop {
            let mut input_buf = [0u8; 1024];

            tokio::select! {
                // Read stdin from host terminal.
                result = stdin.read(&mut input_buf) => {
                    match result {
                        Ok(0) => break,
                        Ok(n) => {
                            let data = &input_buf[..n];

                            // Check for detach key sequence.
                            let mut detached = false;
                            for &b in data {
                                if b == detach_seq[match_pos] {
                                    match_pos += 1;
                                    if match_pos == detach_seq.len() {
                                        detached = true;
                                        break;
                                    }
                                } else {
                                    match_pos = 0;
                                    // Check if this byte starts a new match.
                                    if b == detach_seq[0] {
                                        match_pos = 1;
                                    }
                                }
                            }

                            if detached {
                                break;
                            }

                            // Forward to guest.
                            let payload = ExecStdin { data: data.to_vec() };
                            if let Ok(msg) = Message::with_payload(MessageType::ExecStdin, id, &payload) {
                                let _ = self.bridge.send(&msg).await;
                            }
                        }
                        Err(_) => break,
                    }
                }

                // Receive output from guest.
                Some(msg) = rx.recv() => {
                    match msg.t {
                        MessageType::ExecStdout => {
                            if let Ok(out) = msg.payload::<ExecStdout>() {
                                let _ = stdout.write_all(&out.data).await;
                                let _ = stdout.flush().await;
                            }
                        }
                        MessageType::ExecExited => {
                            if let Ok(exited) = msg.payload::<ExecExited>() {
                                exit_code = exited.code;
                            }
                            break;
                        }
                        _ => {}
                    }
                }

                // Terminal resize.
                _ = sigwinch.recv() => {
                    if let Ok((new_cols, new_rows)) = crossterm::terminal::size() {
                        let payload = ExecResize { rows: new_rows, cols: new_cols };
                        if let Ok(msg) = Message::with_payload(MessageType::ExecResize, id, &payload) {
                            let _ = self.bridge.send(&msg).await;
                        }
                    }
                }
            }
        }

        // Raw mode restored by scopeguard drop.
        Ok(exit_code)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Build an `ExecRequest` by merging sandbox config with caller-provided overrides.
fn build_exec_request(
    config: &SandboxConfig,
    cmd: String,
    args: Vec<String>,
    cwd: Option<String>,
    env: &[(String, String)],
    rlimits: &[Rlimit],
    tty: bool,
    rows: u16,
    cols: u16,
) -> ExecRequest {
    let env: Vec<String> = config
        .env
        .iter()
        .chain(env.iter())
        .map(|(k, v)| format!("{k}={v}"))
        .collect();

    let rlimits: Vec<ExecRlimit> = rlimits
        .iter()
        .map(|rl| ExecRlimit {
            resource: rl.resource.as_str().to_string(),
            soft: rl.soft,
            hard: rl.hard,
        })
        .collect();

    ExecRequest {
        cmd,
        args,
        env,
        cwd: cwd.or_else(|| config.workdir.clone()),
        tty,
        rows,
        cols,
        rlimits,
    }
}

/// Background task that converts raw protocol messages into [`ExecEvent`]s.
async fn event_mapper_task(
    mut rx: mpsc::UnboundedReceiver<Message>,
    tx: mpsc::UnboundedSender<ExecEvent>,
) {
    while let Some(msg) = rx.recv().await {
        let event = match msg.t {
            MessageType::ExecStarted => {
                if let Ok(started) = msg.payload::<ExecStarted>() {
                    ExecEvent::Started { pid: started.pid }
                } else {
                    continue;
                }
            }
            MessageType::ExecStdout => {
                if let Ok(out) = msg.payload::<ExecStdout>() {
                    ExecEvent::Stdout(Bytes::from(out.data))
                } else {
                    continue;
                }
            }
            MessageType::ExecStderr => {
                if let Ok(err) = msg.payload::<ExecStderr>() {
                    ExecEvent::Stderr(Bytes::from(err.data))
                } else {
                    continue;
                }
            }
            MessageType::ExecExited => {
                if let Ok(exited) = msg.payload::<ExecExited>() {
                    let _ = tx.send(ExecEvent::Exited { code: exited.code });
                }
                break;
            }
            _ => continue,
        };
        if tx.send(event).is_err() {
            break;
        }
    }
}

/// Update the sandbox status in the database.
async fn update_sandbox_status(
    db: &sea_orm::DatabaseConnection,
    name: &str,
    status: SandboxStatus,
) -> MicrosandboxResult<()> {
    sandbox_entity::Entity::update_many()
        .col_expr(sandbox_entity::Column::Status, Expr::value(status))
        .col_expr(
            sandbox_entity::Column::UpdatedAt,
            Expr::value(chrono::Utc::now().naive_utc()),
        )
        .filter(sandbox_entity::Column::Name.eq(name))
        .exec(db)
        .await?;

    Ok(())
}

/// Insert or update the sandbox record in the database.
async fn upsert_sandbox_record(
    db: &sea_orm::DatabaseConnection,
    config: &SandboxConfig,
) -> MicrosandboxResult<()> {
    let now = chrono::Utc::now().naive_utc();
    let config_json = serde_json::to_string(config)?;

    let model = sandbox_entity::ActiveModel {
        name: Set(config.name.clone()),
        config: Set(config_json),
        status: Set(SandboxStatus::Running),
        created_at: Set(Some(now)),
        updated_at: Set(Some(now)),
        ..Default::default()
    };

    sandbox_entity::Entity::insert(model)
        .on_conflict(
            OnConflict::column(sandbox_entity::Column::Name)
                .update_columns([
                    sandbox_entity::Column::Status,
                    sandbox_entity::Column::Config,
                    sandbox_entity::Column::UpdatedAt,
                ])
                .to_owned(),
        )
        .exec(db)
        .await?;

    Ok(())
}
