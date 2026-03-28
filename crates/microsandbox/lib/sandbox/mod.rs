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
mod metrics;
mod patch;
mod types;

use std::{path::Path, process::ExitStatus, sync::Arc};

use bytes::Bytes;
use microsandbox_protocol::{
    exec::{ExecExited, ExecRequest, ExecRlimit, ExecStarted, ExecStderr, ExecStdin, ExecStdout},
    message::{Message, MessageType},
};
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QueryOrder, Set, TransactionTrait,
    sea_query::Expr,
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
pub use metrics::{SandboxMetrics, all_sandbox_metrics};
pub use microsandbox_image::{PullPolicy, PullProgress, PullProgressHandle};
#[cfg(feature = "net")]
pub use microsandbox_network::builder::SecretBuilder;
#[cfg(feature = "net")]
pub use microsandbox_network::config::NetworkConfig;
#[cfg(feature = "net")]
pub use microsandbox_network::policy::NetworkPolicy;
pub use microsandbox_runtime::logging::LogLevel;
pub use types::{
    DiskImageFormat, ImageBuilder, ImageSource, IntoImage, MountBuilder, Patch, PatchBuilder,
    RootfsSource, SecretsConfig, SshConfig, VolumeMount,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A running sandbox.
///
/// Created via [`Sandbox::builder`] or [`Sandbox::create`]. Provides
/// lifecycle management and access to the agent bridge for guest communication.
pub struct Sandbox {
    db_id: i32,
    config: SandboxConfig,
    handle: Option<Arc<Mutex<ProcessHandle>>>,
    client: Arc<AgentClient>,
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
    /// Like `create_with_pull_progress` but spawns the sandbox process in detached
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

        // Resolve OCI images before spawning the sandbox process.
        if let RootfsSource::Oci(reference) = config.image.clone() {
            let pull_result = pull_oci_image(
                &reference,
                config.pull_policy,
                config.registry_auth.take(),
                progress,
            )
            .await?;

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

        // Apply rootfs patches before VM start.
        if !config.patches.is_empty() {
            patch::apply_patches(
                &config.image,
                &config.patches,
                &sandbox_dir,
                &config.resolved_rootfs_layers,
            )
            .await?;
        }

        // Insert the sandbox record and keep its stable database ID.
        let sandbox_id = insert_sandbox_record(db, &config).await?;

        // Spawn the sandbox process and create the bridge. On failure, mark the sandbox
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
            db_id: sandbox_id,
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
    /// Remove this sandbox's persisted state after it has fully stopped.
    pub async fn remove_persisted(self) -> MicrosandboxResult<()> {
        let db =
            crate::db::init_global(Some(crate::config::config().database.max_connections)).await?;

        remove_dir_if_exists(
            &crate::config::config()
                .sandboxes_dir()
                .join(&self.config.name),
        )?;
        sandbox_entity::Entity::delete_by_id(self.db_id)
            .exec(db)
            .await?;

        Ok(())
    }

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
    /// don't have a process handle to wait on.
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
            user,
            env,
            rlimits,
            tty,
            stdin: stdin_mode,
            timeout: _,
        } = opts;

        // Allocate correlation ID and subscribe BEFORE sending.
        let id = self.client.next_id();
        let rx = self.client.subscribe(id).await;

        let req = build_exec_request(
            &self.config,
            cmd,
            args,
            cwd,
            user,
            &env,
            &rlimits,
            tty,
            24,
            80,
        );
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
            opts.user,
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

        // Re-open the controlling terminal for input and set only that fresh
        // fd non-blocking. Toggling O_NONBLOCK on fd 0 would also affect
        // stdout/stderr when all three stdio fds share the same TTY open file
        // description, which truncates large terminal writes.
        let tty_input_path = terminal_path_for_fd(std::io::stdin().as_raw_fd())
            .map_err(|e| crate::MicrosandboxError::Terminal(format!("resolve tty path: {e}")))?;
        let tty_input = open_nonblocking_terminal_input(&tty_input_path)
            .map_err(|e| crate::MicrosandboxError::Terminal(format!("open tty input: {e}")))?;
        let stdin_async = AsyncFd::new(tty_input)
            .map_err(|e| crate::MicrosandboxError::Terminal(format!("async tty input: {e}")))?;

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
                    match guard.try_io(|inner| {
                        read_from_fd(inner.get_ref().as_raw_fd(), &mut input_buf)
                    }) {
                        Ok(Ok(0)) => break, // EOF
                        Ok(Ok(n)) => {
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
                        }
                        Ok(Err(e)) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Ok(Err(_)) => break,
                        Err(_would_block) => continue,
                    }
                }

                // Receive output from guest.
                //
                // TUI apps (e.g. Ink-based CLIs) write a full re-render as one
                // write(), but the guest PTY reader chunks it into ~4 KB
                // ExecStdout messages. Writing each chunk to the host terminal
                // separately lets the terminal emulator render intermediate
                // states — partial cursor movements, partially overwritten
                // lines — producing visible afterimage artifacts.
                //
                // Fix: after receiving the first message, drain all immediately
                // available ExecStdout messages and batch their data into a
                // single write. This coalesces the output so the terminal
                // processes each re-render atomically.
                Some(msg) = rx.recv() => {
                    let mut should_break = false;

                    match msg.t {
                        MessageType::ExecStdout => {
                            if let Ok(out) = msg.payload::<ExecStdout>() {
                                let _ = stdout.write_all(&out.data).await;
                            }
                        }
                        MessageType::ExecExited => {
                            if let Ok(exited) = msg.payload::<ExecExited>() {
                                exit_code = exited.code;
                            }
                            should_break = true;
                        }
                        _ => {}
                    }

                    // Drain all buffered messages before flushing.
                    if !should_break {
                        while let Ok(next) = rx.try_recv() {
                            match next.t {
                                MessageType::ExecStdout => {
                                    if let Ok(out) = next.payload::<ExecStdout>() {
                                        let _ = stdout.write_all(&out.data).await;
                                    }
                                }
                                MessageType::ExecExited => {
                                    if let Ok(exited) = next.payload::<ExecExited>() {
                                        exit_code = exited.code;
                                    }
                                    should_break = true;
                                    break;
                                }
                                _ => {}
                            }
                        }
                    }

                    let _ = stdout.flush().await;

                    if should_break {
                        break;
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
/// The sandbox process creates the relay socket asynchronously during startup.
/// This function retries the connection with brief delays until it succeeds
/// or a timeout is reached.
async fn wait_for_relay(sock_path: &std::path::Path) -> MicrosandboxResult<AgentClient> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    let max_backoff = std::time::Duration::from_millis(10);
    let mut backoff = std::time::Duration::from_millis(1);

    loop {
        match AgentClient::connect(sock_path).await {
            Ok(client) => return Ok(client),
            Err(_) if tokio::time::Instant::now() < deadline => {
                // Keep early retries tight so relay readiness doesn't inherit a
                // coarse fixed delay on warm starts.
                tokio::time::sleep(backoff).await;
                backoff = std::cmp::min(backoff.saturating_mul(2), max_backoff);
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
    user: Option<String>,
    env: &[(String, String)],
    rlimits: &[Rlimit],
    tty: bool,
    rows: u16,
    cols: u16,
) -> ExecRequest {
    let merged = config::merge_env_pairs(&config.env, env);
    let mut env: Vec<String> = merged.iter().map(|(k, v)| format!("{k}={v}")).collect();

    // Inject TERM for TTY sessions if not already set.
    if tty && !env.iter().any(|e| e.starts_with("TERM=")) {
        env.push(format!("TERM={}", default_tty_term()));
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
        user: user.or_else(|| config.user.clone()),
        tty,
        rows,
        cols,
        rlimits,
    }
}

fn default_tty_term() -> String {
    select_tty_term(std::env::var("TERM").ok().as_deref())
}

fn select_tty_term(term: Option<&str>) -> String {
    match term {
        Some(term) if !term.trim().is_empty() && term != "dumb" => term.to_string(),
        _ => "xterm".to_string(),
    }
}

fn terminal_path_for_fd(fd: std::os::fd::RawFd) -> std::io::Result<std::path::PathBuf> {
    let mut buf = [0u8; 1024];
    let rc = unsafe { libc::ttyname_r(fd, buf.as_mut_ptr().cast(), buf.len()) };
    if rc != 0 {
        return Err(std::io::Error::from_raw_os_error(rc));
    }

    let end = buf
        .iter()
        .position(|&byte| byte == 0)
        .ok_or_else(|| std::io::Error::other("ttyname_r did not NUL-terminate"))?;

    let path = std::str::from_utf8(&buf[..end]).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "tty path is not valid UTF-8",
        )
    })?;

    Ok(std::path::PathBuf::from(path))
}

fn open_nonblocking_terminal_input(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    use std::os::fd::AsRawFd;

    let file = std::fs::File::open(path)?;
    let fd = file.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(file)
}

fn read_from_fd(fd: std::os::fd::RawFd, buf: &mut [u8]) -> std::io::Result<usize> {
    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    if n < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(n as usize)
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
// Functions: Reaper
//--------------------------------------------------------------------------------------------------

/// Reap all stale sandboxes in the global database.
///
/// Queries all sandboxes with status `Running` or `Draining`, checks whether
/// their process is still alive via `kill(pid, 0)`, and marks dead ones as
/// `Crashed`.
///
/// Designed to run once at startup as a fire-and-forget background task so
/// that crashes (SIGSEGV, SIGKILL, etc.) that prevented the sandbox process
/// from updating the database on exit are cleaned up without blocking the
/// main path.
pub async fn reap_stale_sandboxes() -> MicrosandboxResult<()> {
    let db = crate::db::init_global(Some(crate::config::config().database.max_connections)).await?;

    let stale = sandbox_entity::Entity::find()
        .filter(
            sandbox_entity::Column::Status.is_in([SandboxStatus::Running, SandboxStatus::Draining]),
        )
        .all(db)
        .await?;

    for sandbox in stale {
        // Best-effort: ignore per-sandbox errors so one bad record does not
        // prevent the rest from being reaped.
        let _ = reconcile_sandbox_runtime_state(db, sandbox).await;
    }

    Ok(())
}

/// Spawn a one-shot background reaper task.
///
/// The task queries the global database for sandboxes that claim to be
/// `Running` or `Draining` but whose process has already exited, and marks
/// them as `Crashed`. Errors are silently ignored so the caller's hot path
/// is never affected.
///
/// Safe to call multiple times — only the first invocation spawns a task.
pub fn spawn_reaper() {
    static SPAWNED: std::sync::Once = std::sync::Once::new();
    SPAWNED.call_once(|| {
        // Guard: tokio::spawn requires an active runtime. If called outside
        // one (e.g., from synchronous SDK setup code), silently skip rather
        // than panicking and poisoning the Once.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async {
                if let Err(e) = reap_stale_sandboxes().await {
                    tracing::debug!(error = %e, "background reaper failed");
                }
            });
        }
    });
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

    // No run record yet — the sandbox is still starting up (the child
    // process has not inserted its PID). Skip reconciliation to avoid
    // racing with create/start.
    let Some(run) = run else {
        return Ok(sandbox);
    };

    if run.pid.is_some_and(pid_is_alive) {
        return Ok(sandbox);
    }

    mark_sandbox_runtime_stale(db, sandbox.id, Some(run.id)).await?;

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
/// 2. OS keyring / credential store
/// 3. Global config `registries.auth` matched by registry hostname
/// 4. Docker credential store/config fallback
/// 5. Anonymous fallback
///
/// When `progress` is `Some`, uses `pull_with_sender()` to emit per-layer
/// progress events. The caller must consume the corresponding `PullProgressHandle`.
async fn pull_oci_image(
    reference: &str,
    pull_policy: microsandbox_image::PullPolicy,
    explicit_auth: Option<microsandbox_image::RegistryAuth>,
    progress: Option<microsandbox_image::PullProgressSender>,
) -> MicrosandboxResult<microsandbox_image::PullResult> {
    let global = crate::config::config();
    let cache = microsandbox_image::GlobalCache::new(&global.cache_dir())?;
    let platform = microsandbox_image::Platform::host_linux();
    let image_ref: microsandbox_image::Reference = reference.parse().map_err(|e| {
        crate::MicrosandboxError::InvalidConfig(format!("invalid image reference: {e}"))
    })?;
    let options = microsandbox_image::PullOptions {
        pull_policy,
        ..Default::default()
    };

    // Warm runs spend most of their time outside the guest, so avoid
    // constructing the registry client when the image is already complete
    // in the local cache.
    if let Some((result, metadata)) =
        microsandbox_image::Registry::pull_cached(&cache, &image_ref, &options)?
    {
        if let Some(sender) = progress {
            let reference: std::sync::Arc<str> = reference.to_string().into();
            sender.send(microsandbox_image::PullProgress::Resolving {
                reference: reference.clone(),
            });
            sender.send(microsandbox_image::PullProgress::Resolved {
                reference: reference.clone(),
                manifest_digest: metadata.manifest_digest.clone().into(),
                layer_count: metadata.layers.len(),
                total_download_bytes: metadata
                    .layers
                    .iter()
                    .filter_map(|layer| layer.size_bytes)
                    .reduce(|a, b| a + b),
            });
            sender.send(microsandbox_image::PullProgress::Complete {
                reference,
                layer_count: metadata.layers.len(),
            });
        }

        return Ok(result);
    }

    let auth = match explicit_auth {
        Some(auth) => auth,
        None => global.resolve_registry_auth(image_ref.registry())?,
    };

    let registry = microsandbox_image::Registry::with_auth(platform, cache, auth)?;

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
                "sandbox '{}' already exists; remove it, start the stopped sandbox, or recreate with .replace()",
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
            stop_sandbox_for_replacement(db, &model).await?;
        }

        sandbox_entity::Entity::delete_by_id(model.id)
            .exec(db)
            .await?;
    }

    remove_dir_if_exists(sandbox_dir)?;
    Ok(())
}

async fn stop_sandbox_for_replacement(
    db: &sea_orm::DatabaseConnection,
    sandbox: &sandbox_entity::Model,
) -> MicrosandboxResult<()> {
    let run = load_active_run(db, sandbox.id).await?;
    let pids: Vec<i32> = run
        .as_ref()
        .and_then(|model| model.pid)
        .filter(|pid| pid_is_alive(*pid))
        .into_iter()
        .collect();

    for pid in &pids {
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(*pid),
            nix::sys::signal::Signal::SIGTERM,
        )?;
    }

    wait_for_pids_to_exit(&pids, std::time::Duration::from_secs(30)).await;

    if pids.iter().any(|pid| pid_is_alive(*pid)) {
        return Err(crate::MicrosandboxError::SandboxStillRunning(format!(
            "cannot replace sandbox '{}': existing sandbox did not stop in time",
            sandbox.name
        )));
    }

    mark_sandbox_stopped_for_replacement(db, sandbox.id, run.as_ref().map(|model| model.id)).await
}

async fn mark_sandbox_stopped_for_replacement(
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
                Expr::value(run_entity::TerminationReason::Signal),
            )
            .col_expr(run_entity::Column::TerminatedAt, Expr::value(now))
            .filter(run_entity::Column::Id.eq(run_id))
            .exec(&txn)
            .await?;
    }

    sandbox_entity::Entity::update_many()
        .col_expr(
            sandbox_entity::Column::Status,
            Expr::value(SandboxStatus::Stopped),
        )
        .col_expr(sandbox_entity::Column::UpdatedAt, Expr::value(now))
        .filter(sandbox_entity::Column::Id.eq(sandbox_id))
        .exec(&txn)
        .await?;

    txn.commit().await?;
    Ok(())
}

async fn wait_for_pids_to_exit(pids: &[i32], timeout: std::time::Duration) {
    let start = std::time::Instant::now();
    let poll_interval = std::time::Duration::from_millis(50);

    loop {
        if pids.iter().all(|pid| !pid_is_alive(*pid)) {
            return;
        }

        if start.elapsed() >= timeout {
            return;
        }

        tokio::time::sleep(poll_interval).await;
    }
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
        os::fd::{AsRawFd, FromRawFd, OwnedFd},
        path::PathBuf,
        process::Command,
        time::{SystemTime, UNIX_EPOCH},
    };

    use microsandbox_db::entity::{
        image as image_entity, run as run_entity, sandbox_image as sandbox_image_entity,
    };
    use microsandbox_migration::{Migrator, MigratorTrait};
    use sea_orm::{ColumnTrait, ConnectOptions, Database, EntityTrait, QueryFilter, Set};
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
    fn test_default_tty_term_prefers_host_term() {
        assert_eq!(super::select_tty_term(Some("wezterm")), "wezterm");
    }

    #[test]
    fn test_default_tty_term_falls_back_from_dumb() {
        assert_eq!(super::select_tty_term(Some("dumb")), "xterm");
    }

    #[test]
    fn test_shared_tty_fd_flags_are_shared_across_dups() {
        let pty = nix::pty::openpty(None, None).unwrap();
        let shared_a = unsafe { OwnedFd::from_raw_fd(libc::dup(pty.slave.as_raw_fd())) };
        let shared_b = unsafe { OwnedFd::from_raw_fd(libc::dup(shared_a.as_raw_fd())) };

        let flags = unsafe { libc::fcntl(shared_a.as_raw_fd(), libc::F_GETFL) };
        assert_ne!(flags, -1);
        let ret = unsafe {
            libc::fcntl(
                shared_a.as_raw_fd(),
                libc::F_SETFL,
                flags | libc::O_NONBLOCK,
            )
        };
        assert_ne!(ret, -1);

        let other_flags = unsafe { libc::fcntl(shared_b.as_raw_fd(), libc::F_GETFL) };
        assert_ne!(other_flags, -1);
        assert_ne!(
            other_flags & libc::O_NONBLOCK,
            0,
            "dup'd tty fds should share O_NONBLOCK state"
        );
    }

    #[test]
    fn test_open_nonblocking_terminal_input_keeps_existing_tty_fds_blocking() {
        let pty = nix::pty::openpty(None, None).unwrap();
        let shared_a = unsafe { OwnedFd::from_raw_fd(libc::dup(pty.slave.as_raw_fd())) };
        let shared_b = unsafe { OwnedFd::from_raw_fd(libc::dup(shared_a.as_raw_fd())) };
        let tty_path = super::terminal_path_for_fd(pty.slave.as_raw_fd()).unwrap();

        let input = super::open_nonblocking_terminal_input(&tty_path).unwrap();

        let input_flags = unsafe { libc::fcntl(input.as_raw_fd(), libc::F_GETFL) };
        assert_ne!(input_flags, -1);
        assert_ne!(
            input_flags & libc::O_NONBLOCK,
            0,
            "re-opened tty input fd should be non-blocking"
        );

        let flags_a = unsafe { libc::fcntl(shared_a.as_raw_fd(), libc::F_GETFL) };
        let flags_b = unsafe { libc::fcntl(shared_b.as_raw_fd(), libc::F_GETFL) };
        assert_ne!(flags_a, -1);
        assert_ne!(flags_b, -1);
        assert_eq!(
            flags_a & libc::O_NONBLOCK,
            0,
            "existing tty fd should remain blocking"
        );
        assert_eq!(
            flags_b & libc::O_NONBLOCK,
            0,
            "dup'd tty fd should remain blocking"
        );
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
    async fn test_prepare_create_target_force_replaces_running_sandbox() {
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

        let child = Command::new("sleep").arg("30").spawn().unwrap();
        let live_pid = child.id() as i32;
        let waiter = std::thread::spawn(move || {
            let mut child = child;
            child.wait().unwrap()
        });
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

        prepare_create_target(&conn, &forced, &sandbox_dir)
            .await
            .unwrap();

        waiter.join().unwrap();

        assert!(!super::pid_is_alive(live_pid));
        assert!(!sandbox_dir.exists());
        assert!(
            super::sandbox_entity::Entity::find_by_id(sandbox_id)
                .one(&conn)
                .await
                .unwrap()
                .is_none()
        );
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

    /// Simulates the reaper sweep: queries all Running/Draining sandboxes and
    /// reconciles each. Verifies that only stale entries are reaped while
    /// live, stopped, crashed, and starting (no run record) sandboxes are
    /// left untouched.
    #[tokio::test]
    async fn test_reap_marks_only_dead_running_and_draining_sandboxes() {
        let temp = tempdir().unwrap();
        let db_path = temp.path().join("test.db");
        let db_url = format!("sqlite://{}?mode=rwc", db_path.display());
        let conn = Database::connect(ConnectOptions::new(&db_url))
            .await
            .unwrap();
        Migrator::up(&conn, None).await.unwrap();

        let dead = dead_pid();

        // --- Sandbox A: Running + dead PID → should become Crashed ---
        let cfg_a = SandboxConfig {
            name: "running-dead".into(),
            ..Default::default()
        };
        let id_a = insert_sandbox_record(&conn, &cfg_a).await.unwrap();
        run_entity::Entity::insert(run_entity::ActiveModel {
            sandbox_id: Set(id_a),
            pid: Set(Some(dead)),
            status: Set(run_entity::RunStatus::Running),
            ..Default::default()
        })
        .exec(&conn)
        .await
        .unwrap();

        // --- Sandbox B: Running + live PID → should stay Running ---
        let child = Command::new("sleep").arg("30").spawn().unwrap();
        let live_pid = child.id() as i32;
        let waiter = std::thread::spawn(move || {
            let mut child = child;
            child.wait().unwrap()
        });

        let cfg_b = SandboxConfig {
            name: "running-alive".into(),
            ..Default::default()
        };
        let id_b = insert_sandbox_record(&conn, &cfg_b).await.unwrap();
        run_entity::Entity::insert(run_entity::ActiveModel {
            sandbox_id: Set(id_b),
            pid: Set(Some(live_pid)),
            status: Set(run_entity::RunStatus::Running),
            ..Default::default()
        })
        .exec(&conn)
        .await
        .unwrap();

        // --- Sandbox C: Draining + dead PID → should become Crashed ---
        let cfg_c = SandboxConfig {
            name: "draining-dead".into(),
            ..Default::default()
        };
        let id_c = insert_sandbox_record(&conn, &cfg_c).await.unwrap();
        super::update_sandbox_status(&conn, id_c, SandboxStatus::Draining)
            .await
            .unwrap();
        run_entity::Entity::insert(run_entity::ActiveModel {
            sandbox_id: Set(id_c),
            pid: Set(Some(dead)),
            status: Set(run_entity::RunStatus::Running),
            ..Default::default()
        })
        .exec(&conn)
        .await
        .unwrap();

        // --- Sandbox D: Stopped → should stay Stopped ---
        let cfg_d = SandboxConfig {
            name: "stopped".into(),
            ..Default::default()
        };
        let id_d = insert_sandbox_record(&conn, &cfg_d).await.unwrap();
        super::update_sandbox_status(&conn, id_d, SandboxStatus::Stopped)
            .await
            .unwrap();

        // --- Sandbox E: Running + no run record (still starting) → should stay Running ---
        let cfg_e = SandboxConfig {
            name: "starting".into(),
            ..Default::default()
        };
        let id_e = insert_sandbox_record(&conn, &cfg_e).await.unwrap();

        // --- Reap: query all Running/Draining, reconcile each ---
        let stale = super::sandbox_entity::Entity::find()
            .filter(
                super::sandbox_entity::Column::Status
                    .is_in([SandboxStatus::Running, SandboxStatus::Draining]),
            )
            .all(&conn)
            .await
            .unwrap();

        for sandbox in stale {
            let _ = reconcile_sandbox_runtime_state(&conn, sandbox).await;
        }

        // --- Assertions ---
        let load = |id| {
            let conn = &conn;
            async move {
                super::sandbox_entity::Entity::find_by_id(id)
                    .one(conn)
                    .await
                    .unwrap()
                    .unwrap()
            }
        };

        assert_eq!(load(id_a).await.status, SandboxStatus::Crashed);
        assert_eq!(load(id_b).await.status, SandboxStatus::Running);
        assert_eq!(load(id_c).await.status, SandboxStatus::Crashed);
        assert_eq!(load(id_d).await.status, SandboxStatus::Stopped);
        assert_eq!(load(id_e).await.status, SandboxStatus::Running);

        // Cleanup the live process.
        unsafe { libc::kill(live_pid, libc::SIGKILL) };
        waiter.join().unwrap();
    }
}
