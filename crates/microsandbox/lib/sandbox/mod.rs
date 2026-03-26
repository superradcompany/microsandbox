//! Sandbox lifecycle management.
//!
//! The [`Sandbox`] struct represents a running sandbox. It is created via
//! [`Sandbox::builder`] or [`Sandbox::create`], and provides lifecycle
//! methods (stop, kill, drain, wait) and access to the [`AgentClient`]
//! for guest communication.

mod attach;
mod builder;
mod config;
pub mod exec;
pub mod fs;
mod handle;
mod types;

use std::{path::Path, process::ExitStatus, sync::Arc};

use bytes::Bytes;
use microsandbox_protocol::{
    exec::{ExecExited, ExecRequest, ExecRlimit, ExecStarted, ExecStderr, ExecStdin, ExecStdout},
    message::{Message, MessageType},
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, IntoActiveModel, QueryFilter,
    QueryOrder, Set, TransactionTrait, sea_query::Expr,
};
use tokio::sync::{Mutex, mpsc};

use crate::{
    MicrosandboxResult,
    agent::AgentClient,
    db::entity::{
        run as run_entity, sandbox as sandbox_entity, sandbox_image as sandbox_image_entity,
    },
    runtime::{ProcessHandle, SpawnMode, spawn_sandbox},
};

use self::exec::{ExecEvent, ExecHandle, ExecOptions, ExecSink, StdinMode};

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use crate::db::entity::sandbox::SandboxStatus;
pub use attach::{AttachOptionsBuilder, IntoAttachOptions};
pub use builder::SandboxBuilder;
pub use config::SandboxConfig;
pub use exec::{ExecOptionsBuilder, ExecOutput, IntoExecOptions, Rlimit, RlimitResource};
pub use fs::{FsEntry, FsEntryKind, FsMetadata, FsReadStream, FsWriteSink, SandboxFs};
pub use handle::SandboxHandle;
pub use microsandbox_image::{PullPolicy, PullProgress, PullProgressHandle};
#[cfg(feature = "net")]
pub use microsandbox_network::builder::SecretBuilder;
#[cfg(feature = "net")]
pub use microsandbox_network::config::NetworkConfig;
#[cfg(feature = "net")]
pub use microsandbox_network::policy::NetworkPolicy;
pub use microsandbox_runtime::logging::LogLevel;
pub use types::{
    DiskImageFormat, ImageBuilder, ImageSource, IntoImage, MountBuilder, Patch, RootfsSource,
    SecretsConfig, SshConfig, VolumeMount,
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
    handle: Option<Arc<Mutex<ProcessHandle>>>,
    client: Arc<AgentClient>,
}

/// Wrapper for using a raw stdin fd with [`tokio::io::unix::AsyncFd`].
///
/// `AsyncFd` requires `AsRawFd`. This wraps the raw fd without taking
/// ownership — the fd is managed by the process's stdin and must not
/// be closed by this wrapper.
struct StdinRawFd(std::os::fd::RawFd);

impl std::os::fd::AsRawFd for StdinRawFd {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.0
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: Static
//--------------------------------------------------------------------------------------------------

impl Sandbox {
    /// Start building a new sandbox configuration.
    pub fn builder(name: impl Into<String>) -> SandboxBuilder {
        SandboxBuilder::new(name)
    }

    /// Create a sandbox from a config.
    ///
    /// Boots the VM with agentd ready to accept commands. Does not run
    /// any user workload — use `exec()`, `shell()`, etc. afterward.
    pub async fn create(config: SandboxConfig) -> MicrosandboxResult<Self> {
        Self::create_with_mode(config, SpawnMode::Attached, None).await
    }

    /// Create a sandbox that must survive after the creating process exits.
    ///
    /// This is intended for detached CLI workflows such as `msb create` and
    /// `msb run --detach`, where the sandbox should keep running in the
    /// background after the command returns.
    pub async fn create_detached(config: SandboxConfig) -> MicrosandboxResult<Self> {
        Self::create_with_mode(config, SpawnMode::Detached, None).await
    }

    /// Create a sandbox with pull progress reporting.
    ///
    /// Returns a progress handle for per-layer pull events and a task handle
    /// for the sandbox creation result. The caller should consume progress
    /// events until the channel closes, then await the task.
    pub fn create_with_pull_progress(
        config: SandboxConfig,
    ) -> (
        microsandbox_image::PullProgressHandle,
        tokio::task::JoinHandle<MicrosandboxResult<Self>>,
    ) {
        Self::create_with_pull_progress_and_mode(config, SpawnMode::Attached)
    }

    /// Create a detached sandbox with pull progress reporting.
    ///
    /// Like `create_with_pull_progress` but spawns the supervisor in detached
    /// mode so the sandbox survives after the creating process exits.
    pub fn create_detached_with_pull_progress(
        config: SandboxConfig,
    ) -> (
        microsandbox_image::PullProgressHandle,
        tokio::task::JoinHandle<MicrosandboxResult<Self>>,
    ) {
        Self::create_with_pull_progress_and_mode(config, SpawnMode::Detached)
    }

    fn create_with_pull_progress_and_mode(
        config: SandboxConfig,
        mode: SpawnMode,
    ) -> (
        microsandbox_image::PullProgressHandle,
        tokio::task::JoinHandle<MicrosandboxResult<Self>>,
    ) {
        let (handle, sender) = microsandbox_image::progress_channel();
        let task =
            tokio::spawn(async move { Self::create_with_mode(config, mode, Some(sender)).await });
        (handle, task)
    }

    /// Start an existing stopped sandbox from persisted state.
    ///
    /// Reuses the serialized sandbox config and pinned rootfs state without
    /// re-resolving the original OCI reference.
    pub async fn start(name: &str) -> MicrosandboxResult<Self> {
        Self::start_with_mode(name, SpawnMode::Attached).await
    }

    /// Start an existing sandbox in detached/background mode.
    pub async fn start_detached(name: &str) -> MicrosandboxResult<Self> {
        Self::start_with_mode(name, SpawnMode::Detached).await
    }

    async fn create_with_mode(
        mut config: SandboxConfig,
        mode: SpawnMode,
        progress: Option<microsandbox_image::PullProgressSender>,
    ) -> MicrosandboxResult<Self> {
        let mut pinned_manifest_digest: Option<String> = None;
        let mut pinned_reference: Option<String> = None;

        validate_rootfs_source(&config.image)?;

        // Initialize the database before any expensive image pull so we can
        // fail fast on conflicting persisted sandbox state.
        let db =
            crate::db::init_global(Some(crate::config::config().database.max_connections)).await?;
        let sandbox_dir = crate::config::config().sandboxes_dir().join(&config.name);
        prepare_create_target(db, &config, &sandbox_dir).await?;

        // Resolve OCI images before spawning the supervisor.
        if let RootfsSource::Oci(reference) = config.image.clone() {
            let pull_result =
                pull_oci_image(&reference, config.registry_auth.take(), progress).await?;

            // Merge image config defaults under user-provided config.
            config.merge_image_defaults(&pull_result.config);

            // Store resolved layer paths for spawn_sandbox.
            config.resolved_rootfs_layers = pull_result.layers;
            pinned_manifest_digest = Some(pull_result.manifest_digest.to_string());
            pinned_reference = Some(reference.clone());

            // Persist full image metadata to database.
            let cache_dir = crate::config::config().cache_dir();
            if let Ok(cache) = microsandbox_image::GlobalCache::new(&cache_dir)
                && let Ok(image_ref) = reference.parse::<microsandbox_image::Reference>()
                && let Ok(Some(metadata)) = cache.read_image_metadata(&image_ref)
                && let Err(e) = crate::image::Image::persist(&reference, metadata).await
            {
                tracing::warn!(error = %e, "failed to persist image metadata to database");
            }
        }

        // Insert the sandbox record and keep its stable database ID.
        let sandbox_id = insert_sandbox_record(db, &config).await?;

        // Spawn supervisor + create bridge. On failure, mark the sandbox
        // as stopped so it doesn't appear as a phantom "Running" entry.
        let sandbox = match Self::create_inner(config, sandbox_id, mode).await {
            Ok(sandbox) => sandbox,
            Err(e) => {
                let _ = update_sandbox_status(db, sandbox_id, SandboxStatus::Stopped).await;
                return Err(e);
            }
        };

        if let (Some(reference), Some(manifest_digest)) = (
            pinned_reference.as_deref(),
            pinned_manifest_digest.as_deref(),
        ) && let Err(err) =
            persist_oci_manifest_pin(db, sandbox_id, reference, manifest_digest).await
        {
            let _ = sandbox.stop().await;
            let _ = update_sandbox_status(db, sandbox_id, SandboxStatus::Stopped).await;
            return Err(err);
        }

        Ok(sandbox)
    }

    pub(super) async fn start_with_mode(name: &str, mode: SpawnMode) -> MicrosandboxResult<Self> {
        let db =
            crate::db::init_global(Some(crate::config::config().database.max_connections)).await?;
        let model = load_sandbox_record_reconciled(db, name).await?;

        if model.status == SandboxStatus::Running || model.status == SandboxStatus::Draining {
            return Err(crate::MicrosandboxError::SandboxStillRunning(format!(
                "cannot start sandbox '{name}': already running"
            )));
        }

        if model.status != SandboxStatus::Stopped && model.status != SandboxStatus::Crashed {
            return Err(crate::MicrosandboxError::Custom(format!(
                "cannot start sandbox '{name}': status is {:?} (expected Stopped or Crashed)",
                model.status
            )));
        }

        let config: SandboxConfig = serde_json::from_str(&model.config)?;
        validate_rootfs_source(&config.image)?;
        validate_start_state(&config, &crate::config::config().sandboxes_dir().join(name))?;
        update_sandbox_status(db, model.id, SandboxStatus::Running).await?;

        match Self::create_inner(config, model.id, mode).await {
            Ok(sandbox) => Ok(sandbox),
            Err(err) => {
                let _ = update_sandbox_status(db, model.id, SandboxStatus::Stopped).await;
                Err(err)
            }
        }
    }

    /// Inner create logic separated for error-cleanup wrapper.
    async fn create_inner(
        config: SandboxConfig,
        sandbox_id: i32,
        mode: SpawnMode,
    ) -> MicrosandboxResult<Self> {
        #[cfg(feature = "prebuilt")]
        {
            static SETUP_DONE: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();
            SETUP_DONE.get_or_try_init(crate::setup::install).await?;
        }

        let (handle, agent_sock_path) = spawn_sandbox(&config, sandbox_id, mode).await?;

        // Wait for the relay socket to become available.
        let client = wait_for_relay(&agent_sock_path).await?;

        let ready = client.ready();
        tracing::info!(
            boot_time_ms = ready.boot_time_ns / 1_000_000,
            init_time_ms = ready.init_time_ns / 1_000_000,
            ready_time_ms = ready.ready_time_ns / 1_000_000,
            "sandbox ready",
        );

        Ok(Self {
            config,
            handle: Some(Arc::new(Mutex::new(handle))),
            client: Arc::new(client),
        })
    }

    /// Get a sandbox handle by name from the database.
    pub async fn get(name: &str) -> MicrosandboxResult<SandboxHandle> {
        let db =
            crate::db::init_global(Some(crate::config::config().database.max_connections)).await?;

        let model = sandbox_entity::Entity::find()
            .filter(sandbox_entity::Column::Name.eq(name))
            .one(db)
            .await?
            .ok_or_else(|| crate::MicrosandboxError::SandboxNotFound(name.into()))?;

        let model = reconcile_sandbox_runtime_state(db, model).await?;
        build_handle(db, model).await
    }

    /// List all sandboxes from the database.
    pub async fn list() -> MicrosandboxResult<Vec<SandboxHandle>> {
        let db =
            crate::db::init_global(Some(crate::config::config().database.max_connections)).await?;

        let sandboxes = sandbox_entity::Entity::find()
            .order_by_desc(sandbox_entity::Column::CreatedAt)
            .all(db)
            .await?;

        let mut handles = Vec::with_capacity(sandboxes.len());
        for sandbox in sandboxes {
            let model = reconcile_sandbox_runtime_state(db, sandbox).await?;
            handles.push(build_handle(db, model).await?);
        }

        Ok(handles)
    }

    /// Remove a stopped sandbox from the database.
    ///
    /// Convenience method equivalent to `Sandbox::get(name).await?.remove().await`.
    pub async fn remove(name: &str) -> MicrosandboxResult<()> {
        Self::get(name).await?.remove().await
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: Instance
//--------------------------------------------------------------------------------------------------

impl Sandbox {
    /// Unique name identifying this sandbox.
    pub fn name(&self) -> &str {
        &self.config.name
    }

    /// The full configuration this sandbox was created with (image, cpus,
    /// memory, env, mounts, etc.).
    pub fn config(&self) -> &SandboxConfig {
        &self.config
    }

    /// Low-level access to the guest agent client. Use this for custom
    /// extensions — prefer [`exec`](Self::exec), [`shell`](Self::shell),
    /// and [`fs`](Self::fs) for standard operations.
    pub fn client(&self) -> &AgentClient {
        &self.client
    }

    /// Returns `true` if this sandbox handle owns the process lifecycle.
    ///
    /// When `true`, dropping this handle or calling [`stop`](Self::stop)
    /// will terminate the sandbox. When `false`, the sandbox was created by
    /// another process and will continue running after disconnect.
    pub fn owns_lifecycle(&self) -> bool {
        self.handle.is_some()
    }

    /// Read, write, and manage files inside the running sandbox.
    /// Operations go through the guest agent (agentd).
    pub fn fs(&self) -> fs::SandboxFs<'_> {
        fs::SandboxFs::new(&self.client)
    }

    /// Stop the sandbox gracefully by sending `core.shutdown` to agentd.
    pub async fn stop(&self) -> MicrosandboxResult<()> {
        let msg = Message::new(MessageType::Shutdown, 0, Vec::new());
        self.client.send(&msg).await
    }

    /// Stop the sandbox gracefully and wait for the process to exit.
    ///
    /// If this handle does not own the lifecycle (connected to an existing
    /// sandbox), only the stop signal is sent — wait is skipped since we
    /// don't have a supervisor handle to wait on.
    pub async fn stop_and_wait(&self) -> MicrosandboxResult<ExitStatus> {
        let stop_result = self.stop().await;
        if self.handle.is_none() {
            stop_result?;
            // No handle to wait on — return a synthetic success status.
            return Ok(std::process::ExitStatus::default());
        }
        let wait_result = self.wait().await;
        stop_result?;
        wait_result
    }

    /// Kill the sandbox immediately (SIGKILL).
    pub async fn kill(&self) -> MicrosandboxResult<()> {
        match &self.handle {
            Some(h) => h.lock().await.kill(),
            None => Err(crate::MicrosandboxError::Runtime(
                "cannot kill: not the lifecycle owner".into(),
            )),
        }
    }

    /// Trigger a graceful drain (SIGUSR1).
    pub async fn drain(&self) -> MicrosandboxResult<()> {
        match &self.handle {
            Some(h) => h.lock().await.drain(),
            None => Err(crate::MicrosandboxError::Runtime(
                "cannot drain: not the lifecycle owner".into(),
            )),
        }
    }

    /// Wait for the sandbox process to exit.
    pub async fn wait(&self) -> MicrosandboxResult<ExitStatus> {
        match &self.handle {
            Some(h) => h.lock().await.wait().await,
            None => Err(crate::MicrosandboxError::Runtime(
                "cannot wait: not the lifecycle owner".into(),
            )),
        }
    }

    /// Detach this handle without stopping the sandbox.
    ///
    /// Disarms the SIGTERM safety net so the sandbox keeps running after
    /// this handle is dropped. Intended for CLI flows like `create`, `start`,
    /// and `run --detach`.
    pub async fn detach(self) {
        if let Some(h) = &self.handle {
            h.lock().await.disarm();
        }
        // Normal drop runs — client reader task is aborted and
        // ProcessHandle drops without sending SIGTERM.
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: Execution
//--------------------------------------------------------------------------------------------------

impl Sandbox {
    /// Execute a command and return a streaming handle.
    ///
    /// This is the foundational exec method. All other exec methods delegate to it.
    ///
    /// - `sandbox.exec_stream("tail", ["-f", "/var/log/app.log"])` — args array
    /// - `sandbox.exec_stream("python", |e| e.args(["-c", "x"]).env("K", "V"))` — closure
    pub async fn exec_stream(
        &self,
        cmd: impl Into<String>,
        opts: impl exec::IntoExecOptions,
    ) -> MicrosandboxResult<ExecHandle> {
        let opts = opts.into_exec_options();
        self.exec_stream_inner(cmd.into(), opts).await
    }

    async fn exec_stream_inner(
        &self,
        cmd: String,
        opts: ExecOptions,
    ) -> MicrosandboxResult<ExecHandle> {
        let ExecOptions {
            args,
            cwd,
            env,
            rlimits,
            tty,
            stdin: stdin_mode,
            timeout: _,
        } = opts;

        // Allocate correlation ID and subscribe BEFORE sending.
        let id = self.client.next_id();
        let rx = self.client.subscribe(id).await;

        let req = build_exec_request(&self.config, cmd, args, cwd, &env, &rlimits, tty, 24, 80);
        let msg = Message::with_payload(MessageType::ExecRequest, id, &req)?;
        self.client.send(&msg).await?;

        // Build stdin sink (if Pipe mode).
        let stdin = match &stdin_mode {
            StdinMode::Pipe => Some(ExecSink::new(id, Arc::clone(&self.client))),
            _ => None,
        };

        // Handle StdinMode::Bytes — send bytes then close.
        if let StdinMode::Bytes(ref data) = stdin_mode {
            let data = data.clone();
            let bridge = Arc::clone(&self.client);
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
            Arc::clone(&self.client),
        ))
    }

    /// Execute a command and wait for completion.
    ///
    /// Returns captured stdout/stderr.
    ///
    /// - `sandbox.exec("python", ["-c", "print('hi')"])` — args array
    /// - `sandbox.exec("python", |e| e.args(["compute.py"]).env("HOME", "/root"))` — closure
    pub async fn exec(
        &self,
        cmd: impl Into<String>,
        opts: impl exec::IntoExecOptions,
    ) -> MicrosandboxResult<ExecOutput> {
        let opts = opts.into_exec_options();
        let timeout_duration = opts.timeout;
        let mut handle = self.exec_stream_inner(cmd.into(), opts).await?;

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

    /// Run a shell command and wait for completion.
    ///
    /// Uses the sandbox's configured shell (default: `/bin/sh`) to interpret
    /// the script via `<shell> -c "<script>"`.
    ///
    /// - `sandbox.shell("echo hello")`
    /// - `sandbox.shell("ENV=val cmd | other_cmd")`
    pub async fn shell(&self, script: impl Into<String>) -> MicrosandboxResult<ExecOutput> {
        let mut handle = self.shell_stream(script).await?;
        handle.collect().await
    }

    /// Run a shell command with streaming I/O.
    ///
    /// Like [`shell`](Self::shell) but returns a streaming [`ExecHandle`]
    /// instead of waiting for completion.
    pub async fn shell_stream(&self, script: impl Into<String>) -> MicrosandboxResult<ExecHandle> {
        let shell = self.config.shell.as_deref().unwrap_or("/bin/sh");
        let opts = ExecOptions {
            args: vec!["-c".to_string(), script.into()],
            ..Default::default()
        };
        self.exec_stream_inner(shell.to_string(), opts).await
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
    /// - `sandbox.attach("bash", ["-l"])` — command with args
    /// - `sandbox.attach("/bin/sh", |a| a.detach_keys("ctrl-q"))` — with options
    /// - `sandbox.attach("zsh", |a| a.env("TERM", "xterm"))` — command with options
    pub async fn attach(
        &self,
        cmd: impl Into<String>,
        opts: impl attach::IntoAttachOptions,
    ) -> MicrosandboxResult<i32> {
        use std::os::fd::AsRawFd;

        use microsandbox_protocol::exec::ExecResize;
        use tokio::io::{AsyncWriteExt, unix::AsyncFd};

        let opts = opts.into_attach_options();
        let detach_keys = match &opts.detach_keys {
            Some(spec) => attach::DetachKeys::parse(spec)?,
            None => attach::DetachKeys::default_keys(),
        };

        let cmd = cmd.into();

        // Get terminal size.
        let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));

        // Allocate ID and subscribe.
        let id = self.client.next_id();
        let mut rx = self.client.subscribe(id).await;

        // Build ExecRequest with tty=true.
        let req = build_exec_request(
            &self.config,
            cmd,
            opts.args,
            opts.cwd,
            &opts.env,
            &opts.rlimits,
            true,
            rows,
            cols,
        );
        let msg = Message::with_payload(MessageType::ExecRequest, id, &req)?;
        self.client.send(&msg).await?;

        // Enter raw mode.
        crossterm::terminal::enable_raw_mode()
            .map_err(|e| crate::MicrosandboxError::Terminal(e.to_string()))?;
        let _raw_guard = scopeguard::guard((), |_| {
            let _ = crossterm::terminal::disable_raw_mode();
        });

        // Set stdin to non-blocking so the async read can be cleanly cancelled.
        // tokio::io::stdin() uses a blocking thread that can't be cancelled,
        // causing the first keystroke after exit to be swallowed.
        let stdin_fd = std::io::stdin().as_raw_fd();
        let old_stdin_flags = unsafe { libc::fcntl(stdin_fd, libc::F_GETFL) };
        if old_stdin_flags == -1 {
            return Err(crate::MicrosandboxError::Terminal(format!(
                "failed to get stdin flags: {}",
                std::io::Error::last_os_error()
            )));
        }
        if unsafe { libc::fcntl(stdin_fd, libc::F_SETFL, old_stdin_flags | libc::O_NONBLOCK) } == -1
        {
            return Err(crate::MicrosandboxError::Terminal(format!(
                "failed to set stdin non-blocking: {}",
                std::io::Error::last_os_error()
            )));
        }
        let _nonblock_guard = scopeguard::guard((), |_| {
            if unsafe { libc::fcntl(stdin_fd, libc::F_SETFL, old_stdin_flags) } == -1 {
                tracing::warn!(
                    error = %std::io::Error::last_os_error(),
                    "failed to restore stdin blocking mode"
                );
            }
        });

        let stdin_async = AsyncFd::new(StdinRawFd(stdin_fd))
            .map_err(|e| crate::MicrosandboxError::Terminal(format!("async stdin: {e}")))?;

        // Set up async I/O.
        let mut stdout = tokio::io::stdout();
        let mut sigwinch =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
                .map_err(|e| crate::MicrosandboxError::Runtime(format!("sigwinch: {e}")))?;

        let mut exit_code: i32 = -1;
        let detach_seq = detach_keys.sequence();
        let mut match_pos = 0usize;

        loop {
            tokio::select! {
                // Read stdin from host terminal (non-blocking fd).
                result = stdin_async.readable() => {
                    let mut guard = match result {
                        Ok(g) => g,
                        Err(_) => break,
                    };

                    let mut input_buf = [0u8; 1024];
                    let n = unsafe {
                        libc::read(
                            stdin_fd,
                            input_buf.as_mut_ptr() as *mut libc::c_void,
                            input_buf.len(),
                        )
                    };

                    if n > 0 {
                        let data = &input_buf[..n as usize];

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
                            let _ = self.client.send(&msg).await;
                        }
                    } else if n == 0 {
                        break; // EOF
                    } else {
                        let err = std::io::Error::last_os_error();
                        match err.kind() {
                            std::io::ErrorKind::WouldBlock => guard.clear_ready(),
                            std::io::ErrorKind::Interrupted => {} // EINTR — retry
                            _ => break,
                        }
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
                            let _ = self.client.send(&msg).await;
                        }
                    }
                }
            }
        }

        // Guards restore: non-blocking → blocking, raw mode → cooked.
        Ok(exit_code)
    }

    /// Attach to the sandbox's default shell.
    ///
    /// Uses the sandbox's configured shell (default: `/bin/sh`).
    /// Equivalent to `attach(shell, |a| a)` with the configured shell.
    pub async fn attach_shell(&self) -> MicrosandboxResult<i32> {
        let shell = self.config.shell.as_deref().unwrap_or("/bin/sh");
        self.attach(shell, |a| a).await
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Wait for the agent relay socket to become available and connect.
///
/// The supervisor creates the relay socket asynchronously during startup.
/// This function retries the connection with brief delays until it succeeds
/// or a timeout is reached.
async fn wait_for_relay(sock_path: &std::path::Path) -> MicrosandboxResult<AgentClient> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);

    loop {
        match AgentClient::connect(sock_path).await {
            Ok(client) => return Ok(client),
            Err(_) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Build a [`SandboxHandle`] by eagerly loading the microVM PID.
async fn build_handle(
    db: &sea_orm::DatabaseConnection,
    model: sandbox_entity::Model,
) -> MicrosandboxResult<SandboxHandle> {
    let run = load_active_run(db, model.id).await?;
    let pid = run.and_then(|m| m.pid).filter(|pid| pid_is_alive(*pid));

    Ok(SandboxHandle::new(model, pid))
}

/// Build an `ExecRequest` by merging sandbox config with caller-provided overrides.
#[allow(clippy::too_many_arguments)]
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
    let mut env: Vec<String> = config
        .env
        .iter()
        .chain(env.iter())
        .map(|(k, v)| format!("{k}={v}"))
        .collect();

    // Inject TERM for TTY sessions if not already set (mirrors Docker behavior).
    if tty && !env.iter().any(|e| e.starts_with("TERM=")) {
        env.push("TERM=xterm-256color".to_string());
    }

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
pub(super) async fn update_sandbox_status(
    db: &sea_orm::DatabaseConnection,
    sandbox_id: i32,
    status: SandboxStatus,
) -> MicrosandboxResult<()> {
    sandbox_entity::Entity::update_many()
        .col_expr(sandbox_entity::Column::Status, Expr::value(status))
        .col_expr(
            sandbox_entity::Column::UpdatedAt,
            Expr::value(chrono::Utc::now().naive_utc()),
        )
        .filter(sandbox_entity::Column::Id.eq(sandbox_id))
        .exec(db)
        .await?;

    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Functions: State Reconciliation
//--------------------------------------------------------------------------------------------------

pub(super) async fn load_sandbox_record_reconciled(
    db: &sea_orm::DatabaseConnection,
    name: &str,
) -> MicrosandboxResult<sandbox_entity::Model> {
    let sandbox = load_sandbox_record(db, name).await?;
    reconcile_sandbox_runtime_state(db, sandbox).await
}

pub(super) async fn reconcile_sandbox_runtime_state(
    db: &sea_orm::DatabaseConnection,
    sandbox: sandbox_entity::Model,
) -> MicrosandboxResult<sandbox_entity::Model> {
    if !matches!(
        sandbox.status,
        SandboxStatus::Running | SandboxStatus::Draining
    ) {
        return Ok(sandbox);
    }

    let run = load_active_run(db, sandbox.id).await?;

    let run_alive = run
        .as_ref()
        .and_then(|model| model.pid)
        .is_some_and(pid_is_alive);

    if run_alive {
        return Ok(sandbox);
    }

    mark_sandbox_runtime_stale(db, sandbox.id, run.as_ref().map(|model| model.id)).await?;

    sandbox_entity::Entity::find_by_id(sandbox.id)
        .one(db)
        .await?
        .ok_or_else(|| crate::MicrosandboxError::SandboxNotFound(sandbox.name))
}

pub(super) async fn load_active_run(
    db: &sea_orm::DatabaseConnection,
    sandbox_id: i32,
) -> MicrosandboxResult<Option<run_entity::Model>> {
    run_entity::Entity::find()
        .filter(run_entity::Column::SandboxId.eq(sandbox_id))
        .filter(run_entity::Column::Status.eq(run_entity::RunStatus::Running))
        .order_by_desc(run_entity::Column::StartedAt)
        .one(db)
        .await
        .map_err(Into::into)
}

async fn mark_sandbox_runtime_stale(
    db: &sea_orm::DatabaseConnection,
    sandbox_id: i32,
    run_id: Option<i32>,
) -> MicrosandboxResult<()> {
    let txn = db.begin().await?;
    let now = chrono::Utc::now().naive_utc();

    if let Some(run_id) = run_id {
        run_entity::Entity::update_many()
            .col_expr(
                run_entity::Column::Status,
                Expr::value(run_entity::RunStatus::Terminated),
            )
            .col_expr(
                run_entity::Column::TerminationReason,
                Expr::value(run_entity::TerminationReason::InternalError),
            )
            .col_expr(run_entity::Column::TerminatedAt, Expr::value(now))
            .filter(run_entity::Column::Id.eq(run_id))
            .exec(&txn)
            .await?;
    }

    // Only mark Crashed if the sandbox is still Running or Draining. This
    // prevents a concurrent start() from having its Running status overwritten.
    sandbox_entity::Entity::update_many()
        .col_expr(
            sandbox_entity::Column::Status,
            Expr::value(SandboxStatus::Crashed),
        )
        .col_expr(sandbox_entity::Column::UpdatedAt, Expr::value(now))
        .filter(sandbox_entity::Column::Id.eq(sandbox_id))
        .filter(
            sandbox_entity::Column::Status.is_in([SandboxStatus::Running, SandboxStatus::Draining]),
        )
        .exec(&txn)
        .await?;

    txn.commit().await?;
    Ok(())
}

pub(super) fn pid_is_alive(pid: i32) -> bool {
    let result = unsafe { libc::kill(pid, 0) };
    if result == 0 {
        return true;
    }

    matches!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(code) if code == libc::EPERM
    )
}

/// Pull an OCI image and return the pull result.
///
/// Auth resolution:
/// 1. Explicit `RegistryAuth` from `SandboxBuilder::registry_auth()` (if provided)
/// 2. Global config `registries.auth` matched by registry hostname
/// 3. Anonymous fallback
///
/// When `progress` is `Some`, uses `pull_with_sender()` to emit per-layer
/// progress events. The caller must consume the corresponding `PullProgressHandle`.
async fn pull_oci_image(
    reference: &str,
    explicit_auth: Option<microsandbox_image::RegistryAuth>,
    progress: Option<microsandbox_image::PullProgressSender>,
) -> MicrosandboxResult<microsandbox_image::PullResult> {
    let global = crate::config::config();
    let cache = microsandbox_image::GlobalCache::new(&global.cache_dir())?;
    let platform = microsandbox_image::Platform::host_linux();
    let image_ref: microsandbox_image::Reference = reference.parse().map_err(|e| {
        crate::MicrosandboxError::InvalidConfig(format!("invalid image reference: {e}"))
    })?;

    let auth = match explicit_auth {
        Some(auth) => auth,
        None => global.resolve_registry_auth(image_ref.registry())?,
    };

    let registry = microsandbox_image::Registry::with_auth(platform, cache, auth)?;
    let options = microsandbox_image::PullOptions::default();

    if let Some(sender) = progress {
        let task = registry.pull_with_sender(&image_ref, &options, sender);
        let result = task
            .await
            .map_err(|e| crate::MicrosandboxError::Custom(format!("pull task panicked: {e}")))??;
        Ok(result)
    } else {
        let result = registry.pull(&image_ref, &options).await?;
        Ok(result)
    }
}

/// Validate rootfs configuration that depends on host filesystem state.
fn validate_rootfs_source(rootfs: &RootfsSource) -> MicrosandboxResult<()> {
    match rootfs {
        RootfsSource::Bind(path) => {
            if !path.exists() {
                return Err(crate::MicrosandboxError::InvalidConfig(format!(
                    "rootfs bind path does not exist: {}",
                    path.display()
                )));
            }

            if !path.is_dir() {
                return Err(crate::MicrosandboxError::InvalidConfig(format!(
                    "rootfs bind path is not a directory: {}",
                    path.display()
                )));
            }
        }
        RootfsSource::Oci(_) => {}
        RootfsSource::DiskImage { path, .. } => {
            if !path.exists() {
                return Err(crate::MicrosandboxError::InvalidConfig(format!(
                    "disk image does not exist: {}",
                    path.display()
                )));
            }

            if !path.is_file() {
                return Err(crate::MicrosandboxError::InvalidConfig(format!(
                    "disk image is not a regular file: {}",
                    path.display()
                )));
            }
        }
    }

    Ok(())
}

pub(super) fn remove_dir_if_exists(path: &Path) -> MicrosandboxResult<()> {
    match std::fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

/// Load a sandbox row by name.
pub(super) async fn load_sandbox_record(
    db: &sea_orm::DatabaseConnection,
    name: &str,
) -> MicrosandboxResult<sandbox_entity::Model> {
    sandbox_entity::Entity::find()
        .filter(sandbox_entity::Column::Name.eq(name))
        .one(db)
        .await?
        .ok_or_else(|| crate::MicrosandboxError::SandboxNotFound(name.into()))
}

async fn prepare_create_target(
    db: &sea_orm::DatabaseConnection,
    config: &SandboxConfig,
    sandbox_dir: &Path,
) -> MicrosandboxResult<()> {
    let existing = sandbox_entity::Entity::find()
        .filter(sandbox_entity::Column::Name.eq(&config.name))
        .one(db)
        .await?;

    let dir_exists = sandbox_dir.exists();

    if !config.replace_existing {
        if existing.is_some() || dir_exists {
            return Err(crate::MicrosandboxError::Custom(format!(
                "sandbox '{}' already exists; remove it, start the stopped sandbox, or recreate with .overwrite()",
                config.name
            )));
        }

        return Ok(());
    }

    if let Some(model) = existing {
        let model = reconcile_sandbox_runtime_state(db, model).await?;
        if matches!(
            model.status,
            SandboxStatus::Running | SandboxStatus::Draining | SandboxStatus::Paused
        ) {
            return Err(crate::MicrosandboxError::SandboxStillRunning(format!(
                "cannot replace sandbox '{}': existing sandbox is still active",
                config.name
            )));
        }

        model.into_active_model().delete(db).await?;
    }

    remove_dir_if_exists(sandbox_dir)?;
    Ok(())
}

fn validate_start_state(config: &SandboxConfig, sandbox_dir: &Path) -> MicrosandboxResult<()> {
    if !sandbox_dir.exists() {
        return Err(crate::MicrosandboxError::Custom(format!(
            "sandbox state missing for '{}': {}",
            config.name,
            sandbox_dir.display()
        )));
    }

    if let RootfsSource::Oci(_) = &config.image {
        for lower in &config.resolved_rootfs_layers {
            if !lower.is_dir() {
                return Err(crate::MicrosandboxError::Custom(format!(
                    "sandbox '{}' cannot start: pinned OCI lower is missing: {}",
                    config.name,
                    lower.display()
                )));
            }
        }
    }

    Ok(())
}

/// Insert the sandbox record in the database and return its ID.
async fn insert_sandbox_record(
    db: &sea_orm::DatabaseConnection,
    config: &SandboxConfig,
) -> MicrosandboxResult<i32> {
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

    let result = sandbox_entity::Entity::insert(model).exec(db).await?;
    Ok(result.last_insert_id)
}

async fn persist_oci_manifest_pin(
    db: &sea_orm::DatabaseConnection,
    sandbox_id: i32,
    reference: &str,
    manifest_digest: &str,
) -> MicrosandboxResult<()> {
    let reference = reference.to_string();
    let manifest_digest = manifest_digest.to_string();

    db.transaction::<_, (), crate::MicrosandboxError>(|txn| {
        Box::pin(async move {
            replace_oci_manifest_pin(txn, sandbox_id, &reference, &manifest_digest).await
        })
    })
    .await
    .map_err(|err| match err {
        sea_orm::TransactionError::Connection(db_err) => db_err.into(),
        sea_orm::TransactionError::Transaction(err) => err,
    })
}

async fn replace_oci_manifest_pin<C: ConnectionTrait>(
    db: &C,
    sandbox_id: i32,
    reference: &str,
    manifest_digest: &str,
) -> MicrosandboxResult<()> {
    let image_id = crate::image::upsert_image_record(db, reference, None).await?;
    let now = chrono::Utc::now().naive_utc();

    sandbox_image_entity::Entity::delete_many()
        .filter(sandbox_image_entity::Column::SandboxId.eq(sandbox_id))
        .exec(db)
        .await?;

    sandbox_image_entity::Entity::insert(sandbox_image_entity::ActiveModel {
        sandbox_id: Set(sandbox_id),
        image_id: Set(image_id),
        manifest_digest: Set(manifest_digest.to_string()),
        created_at: Set(Some(now)),
        ..Default::default()
    })
    .exec(db)
    .await?;

    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use microsandbox_db::entity::{
        image as image_entity, run as run_entity, sandbox_image as sandbox_image_entity,
    };
    use microsandbox_migration::{Migrator, MigratorTrait};
    use sea_orm::{ConnectOptions, Database, EntityTrait, Set};
    use tempfile::tempdir;

    use super::{
        RootfsSource, SandboxConfig, SandboxStatus, insert_sandbox_record,
        persist_oci_manifest_pin, prepare_create_target, reconcile_sandbox_runtime_state,
        remove_dir_if_exists, validate_rootfs_source,
    };

    fn unique_temp_path(suffix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("microsandbox-rootfs-{suffix}-{nanos}"))
    }

    fn dead_pid() -> i32 {
        let mut pid = 900_000;
        while super::pid_is_alive(pid) {
            pid += 1;
        }
        pid
    }

    #[test]
    fn test_validate_rootfs_source_missing_bind_path() {
        let path = unique_temp_path("missing");
        let err = validate_rootfs_source(&RootfsSource::Bind(path.clone())).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "invalid config: rootfs bind path does not exist: {}",
                path.display()
            )
        );
    }

    #[test]
    fn test_validate_rootfs_source_bind_path_must_be_directory() {
        let path = unique_temp_path("file");
        fs::write(&path, b"not a directory").unwrap();

        let err = validate_rootfs_source(&RootfsSource::Bind(path.clone())).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "invalid config: rootfs bind path is not a directory: {}",
                path.display()
            )
        );

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_validate_rootfs_source_existing_bind_directory() {
        let path = unique_temp_path("dir");
        fs::create_dir(&path).unwrap();

        validate_rootfs_source(&RootfsSource::Bind(path.clone())).unwrap();

        fs::remove_dir(path).unwrap();
    }

    #[test]
    fn test_remove_dir_if_exists_removes_existing_sandbox_tree() {
        let temp = tempdir().unwrap();
        let sandbox_dir = temp.path().join("sandbox");
        fs::create_dir_all(sandbox_dir.join("runtime/scripts")).unwrap();
        fs::write(sandbox_dir.join("runtime/scripts/start.sh"), b"echo hi").unwrap();
        fs::create_dir_all(sandbox_dir.join("rw")).unwrap();

        remove_dir_if_exists(&sandbox_dir).unwrap();

        assert!(!sandbox_dir.exists());
    }

    #[test]
    fn test_remove_dir_if_exists_ignores_missing_directory() {
        let temp = tempdir().unwrap();
        let sandbox_dir = temp.path().join("missing");

        remove_dir_if_exists(&sandbox_dir).unwrap();

        assert!(!sandbox_dir.exists());
    }

    #[tokio::test]
    async fn test_persist_oci_manifest_pin_upserts_image_and_manifest_digest() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test.db");
        let db_url = format!("sqlite://{}?mode=rwc", db_path.display());
        let conn = Database::connect(ConnectOptions::new(&db_url))
            .await
            .unwrap();
        Migrator::up(&conn, None).await.unwrap();

        let mut config = SandboxConfig {
            name: "pinned".into(),
            image: RootfsSource::Oci("docker.io/library/alpine:latest".into()),
            ..Default::default()
        };
        config.resolved_rootfs_layers = vec!["/tmp/layer0".into()];
        let sandbox_id = insert_sandbox_record(&conn, &config).await.unwrap();

        persist_oci_manifest_pin(
            &conn,
            sandbox_id,
            "docker.io/library/alpine:latest",
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        )
        .await
        .unwrap();

        persist_oci_manifest_pin(
            &conn,
            sandbox_id,
            "docker.io/library/alpine:latest",
            "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        )
        .await
        .unwrap();

        let images = image_entity::Entity::find().all(&conn).await.unwrap();
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].reference, "docker.io/library/alpine:latest");

        let pins = sandbox_image_entity::Entity::find()
            .all(&conn)
            .await
            .unwrap();
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[0].sandbox_id, sandbox_id);
        assert_eq!(pins[0].image_id, images[0].id);
        assert_eq!(
            pins[0].manifest_digest,
            "sha256:2222222222222222222222222222222222222222222222222222222222222222"
        );
    }

    #[tokio::test]
    async fn test_persist_oci_manifest_pin_replaces_stale_pin_for_different_reference() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test.db");
        let db_url = format!("sqlite://{}?mode=rwc", db_path.display());
        let conn = Database::connect(ConnectOptions::new(&db_url))
            .await
            .unwrap();
        Migrator::up(&conn, None).await.unwrap();

        let mut config = SandboxConfig {
            name: "recreated".into(),
            image: RootfsSource::Oci("docker.io/library/alpine:latest".into()),
            ..Default::default()
        };
        config.resolved_rootfs_layers = vec!["/tmp/layer0".into()];
        let sandbox_id = insert_sandbox_record(&conn, &config).await.unwrap();

        persist_oci_manifest_pin(
            &conn,
            sandbox_id,
            "docker.io/library/alpine:latest",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .await
        .unwrap();

        persist_oci_manifest_pin(
            &conn,
            sandbox_id,
            "docker.io/library/busybox:latest",
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .await
        .unwrap();

        let images = image_entity::Entity::find().all(&conn).await.unwrap();
        assert_eq!(images.len(), 2);

        let pins = sandbox_image_entity::Entity::find()
            .all(&conn)
            .await
            .unwrap();
        assert_eq!(pins.len(), 1);

        let busybox_id = images
            .iter()
            .find(|image| image.reference == "docker.io/library/busybox:latest")
            .unwrap()
            .id;
        assert_eq!(pins[0].sandbox_id, sandbox_id);
        assert_eq!(pins[0].image_id, busybox_id);
        assert_eq!(
            pins[0].manifest_digest,
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
    }

    #[tokio::test]
    async fn test_insert_sandbox_record_persists_resolved_rootfs_layers_in_config_json() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test.db");
        let db_url = format!("sqlite://{}?mode=rwc", db_path.display());
        let conn = Database::connect(ConnectOptions::new(&db_url))
            .await
            .unwrap();
        Migrator::up(&conn, None).await.unwrap();

        let mut config = SandboxConfig {
            name: "persisted-lowers".into(),
            image: RootfsSource::Oci("docker.io/library/alpine:latest".into()),
            ..Default::default()
        };
        config.resolved_rootfs_layers = vec!["/tmp/layer0".into(), "/tmp/layer1".into()];

        let sandbox_id = insert_sandbox_record(&conn, &config).await.unwrap();
        let row = super::sandbox_entity::Entity::find_by_id(sandbox_id)
            .one(&conn)
            .await
            .unwrap()
            .unwrap();
        let decoded: SandboxConfig = serde_json::from_str(&row.config).unwrap();

        assert_eq!(
            decoded.resolved_rootfs_layers,
            config.resolved_rootfs_layers
        );
    }

    #[tokio::test]
    async fn test_prepare_create_target_rejects_existing_state_without_force() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test.db");
        let db_url = format!("sqlite://{}?mode=rwc", db_path.display());
        let conn = Database::connect(ConnectOptions::new(&db_url))
            .await
            .unwrap();
        Migrator::up(&conn, None).await.unwrap();

        let sandbox_dir = temp.path().join("sandboxes").join("existing");
        fs::create_dir_all(&sandbox_dir).unwrap();

        let config = SandboxConfig {
            name: "existing".into(),
            ..Default::default()
        };

        let err = prepare_create_target(&conn, &config, &sandbox_dir)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("already exists"));
    }

    #[tokio::test]
    async fn test_prepare_create_target_force_replaces_stopped_sandbox_state() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test.db");
        let db_url = format!("sqlite://{}?mode=rwc", db_path.display());
        let conn = Database::connect(ConnectOptions::new(&db_url))
            .await
            .unwrap();
        Migrator::up(&conn, None).await.unwrap();

        let sandbox_dir = temp.path().join("sandboxes").join("replaceable");
        fs::create_dir_all(sandbox_dir.join("rw")).unwrap();
        let config = SandboxConfig {
            name: "replaceable".into(),
            ..Default::default()
        };
        let sandbox_id = insert_sandbox_record(&conn, &config).await.unwrap();
        super::update_sandbox_status(&conn, sandbox_id, super::SandboxStatus::Stopped)
            .await
            .unwrap();

        let mut forced = SandboxConfig {
            name: "replaceable".into(),
            ..Default::default()
        };
        forced.replace_existing = true;

        prepare_create_target(&conn, &forced, &sandbox_dir)
            .await
            .unwrap();

        assert!(!sandbox_dir.exists());
        assert!(
            super::sandbox_entity::Entity::find_by_id(sandbox_id)
                .one(&conn)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_reconcile_sandbox_runtime_state_marks_dead_processes_crashed() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test.db");
        let db_url = format!("sqlite://{}?mode=rwc", db_path.display());
        let conn = Database::connect(ConnectOptions::new(&db_url))
            .await
            .unwrap();
        Migrator::up(&conn, None).await.unwrap();

        let config = SandboxConfig {
            name: "stale".into(),
            ..Default::default()
        };
        let sandbox_id = insert_sandbox_record(&conn, &config).await.unwrap();
        let dead_run_pid = dead_pid();

        let run = run_entity::ActiveModel {
            sandbox_id: Set(sandbox_id),
            pid: Set(Some(dead_run_pid)),
            status: Set(run_entity::RunStatus::Running),
            ..Default::default()
        };
        let run_id = run_entity::Entity::insert(run)
            .exec(&conn)
            .await
            .unwrap()
            .last_insert_id;

        let sandbox = super::sandbox_entity::Entity::find_by_id(sandbox_id)
            .one(&conn)
            .await
            .unwrap()
            .unwrap();
        let reconciled = reconcile_sandbox_runtime_state(&conn, sandbox)
            .await
            .unwrap();
        assert_eq!(reconciled.status, SandboxStatus::Crashed);

        let run = run_entity::Entity::find_by_id(run_id)
            .one(&conn)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(run.status, run_entity::RunStatus::Terminated);
        assert_eq!(
            run.termination_reason,
            Some(run_entity::TerminationReason::InternalError)
        );
        assert!(run.terminated_at.is_some());
    }

    #[tokio::test]
    async fn test_prepare_create_target_force_replaces_stale_running_sandbox_state() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test.db");
        let db_url = format!("sqlite://{}?mode=rwc", db_path.display());
        let conn = Database::connect(ConnectOptions::new(&db_url))
            .await
            .unwrap();
        Migrator::up(&conn, None).await.unwrap();

        let sandbox_dir = temp.path().join("sandboxes").join("stale-running");
        fs::create_dir_all(sandbox_dir.join("rw")).unwrap();
        let config = SandboxConfig {
            name: "stale-running".into(),
            ..Default::default()
        };
        let sandbox_id = insert_sandbox_record(&conn, &config).await.unwrap();

        let run = run_entity::ActiveModel {
            sandbox_id: Set(sandbox_id),
            pid: Set(Some(dead_pid())),
            status: Set(run_entity::RunStatus::Running),
            ..Default::default()
        };
        run_entity::Entity::insert(run).exec(&conn).await.unwrap();

        let mut forced = SandboxConfig {
            name: "stale-running".into(),
            ..Default::default()
        };
        forced.replace_existing = true;

        prepare_create_target(&conn, &forced, &sandbox_dir)
            .await
            .unwrap();

        assert!(!sandbox_dir.exists());
        assert!(
            super::sandbox_entity::Entity::find_by_id(sandbox_id)
                .one(&conn)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_prepare_create_target_force_rejects_running_sandbox() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test.db");
        let db_url = format!("sqlite://{}?mode=rwc", db_path.display());
        let conn = Database::connect(ConnectOptions::new(&db_url))
            .await
            .unwrap();
        Migrator::up(&conn, None).await.unwrap();

        let sandbox_dir = temp.path().join("sandboxes").join("running");
        fs::create_dir_all(&sandbox_dir).unwrap();
        let config = SandboxConfig {
            name: "running".into(),
            ..Default::default()
        };
        let sandbox_id = insert_sandbox_record(&conn, &config).await.unwrap();

        // Insert a run with the current process PID so reconciliation
        // considers the sandbox genuinely alive.
        let live_pid = std::process::id() as i32;
        let run = run_entity::ActiveModel {
            sandbox_id: Set(sandbox_id),
            pid: Set(Some(live_pid)),
            status: Set(run_entity::RunStatus::Running),
            ..Default::default()
        };
        run_entity::Entity::insert(run).exec(&conn).await.unwrap();

        let mut forced = SandboxConfig {
            name: "running".into(),
            ..Default::default()
        };
        forced.replace_existing = true;

        let err = prepare_create_target(&conn, &forced, &sandbox_dir)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            crate::MicrosandboxError::SandboxStillRunning(_)
        ));
        assert!(sandbox_dir.exists());
    }

    #[test]
    fn test_validate_start_state_requires_existing_sandbox_dir() {
        let temp = tempdir().unwrap();
        let sandbox_dir = temp.path().join("missing");
        let config = SandboxConfig {
            name: "missing".into(),
            ..Default::default()
        };

        let err = super::validate_start_state(&config, &sandbox_dir).unwrap_err();
        assert!(err.to_string().contains("sandbox state missing"));
    }

    #[test]
    fn test_validate_start_state_requires_persisted_oci_lowers() {
        let temp = tempdir().unwrap();
        let sandbox_dir = temp.path().join("persisted");
        fs::create_dir_all(&sandbox_dir).unwrap();

        let mut config = SandboxConfig {
            name: "persisted".into(),
            image: RootfsSource::Oci("docker.io/library/alpine:latest".into()),
            ..Default::default()
        };
        config.resolved_rootfs_layers = vec![temp.path().join("missing-lower")];

        let err = super::validate_start_state(&config, &sandbox_dir).unwrap_err();
        assert!(err.to_string().contains("pinned OCI lower is missing"));
    }
}
