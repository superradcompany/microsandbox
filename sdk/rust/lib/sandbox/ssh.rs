//! SSH client and server helpers for sandboxes.

use std::collections::HashMap;
use std::io::Write;
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use microsandbox_protocol::{
    fs::{
        FS_CHUNK_SIZE, FsData, FsEntryInfo, FsOp, FsOpenOptions, FsRequest, FsResponse,
        FsResponseData, FsSetAttrs,
    },
    message::MessageType,
};
use microsandbox_types::EnvVar;
use russh::client::Msg as ClientMsg;
use russh::keys::{Algorithm, PrivateKey, PrivateKeyWithHashAlg, PublicKeyBase64, load_secret_key};
use russh::server::{Auth, Msg, Session};
use russh::{Channel, ChannelId, ChannelMsg, Sig};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::attach;
use crate::sandbox::exec::{ExecControl, ExecEvent, ExecOptions, ExecSink, StdinMode};
use crate::{MicrosandboxError, MicrosandboxResult, Sandbox, agent::AgentClient};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Default SSH listener host used by the CLI adapter.
pub const DEFAULT_SSH_HOST: &str = "127.0.0.1";

/// Default SSH listener port used by the CLI adapter.
pub const DEFAULT_SSH_PORT: u16 = 2222;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// SSH namespace for a sandbox.
#[derive(Clone)]
pub struct SandboxSsh {
    sandbox: Sandbox,
}

/// Builder for [`SshClientOptions`].
#[derive(Default)]
pub struct SshClientOptionsBuilder {
    options: SshClientOptions,
}

/// Options for a native SSH client connection.
pub struct SshClientOptions {
    user: String,
    term: String,
    sftp: bool,
}

/// Builder for [`SshExecOptions`].
#[derive(Default)]
pub struct SshExecOptionsBuilder {
    options: SshExecOptions,
}

/// Options for an SSH exec request.
#[derive(Default)]
pub struct SshExecOptions {
    tty: bool,
}

/// Builder for [`SshAttachOptions`].
#[derive(Default)]
pub struct SshAttachOptionsBuilder {
    options: SshAttachOptions,
}

/// Options for an interactive SSH attach session.
pub struct SshAttachOptions {
    term: String,
    detach_keys: Option<String>,
}

/// Output from an SSH exec request.
#[derive(Debug)]
pub struct SshOutput {
    /// Exit status code.
    pub status: i32,

    /// Captured stdout bytes.
    pub stdout: Bytes,

    /// Captured stderr bytes.
    pub stderr: Bytes,
}

/// Native in-process SSH client session.
pub struct SshClient {
    handle: russh::client::Handle<SshClientHandler>,
    term: String,
    server_task: Option<tokio::task::JoinHandle<MicrosandboxResult<()>>>,
    negotiated_version: u8,
}

/// High-level SFTP client session.
pub type SftpClient = russh_sftp::client::SftpSession;

/// Builder for [`SshServerOptions`].
#[derive(Default)]
pub struct SshServerOptionsBuilder {
    options: SshServerOptions,
}

/// SSH server options.
pub struct SshServerOptions {
    host_key_path: Option<PathBuf>,
    host_key: Option<PrivateKey>,
    authorized_keys_path: Option<PathBuf>,
    authorized_keys: Vec<String>,
    guest_user: Option<String>,
    sftp: bool,
}

/// Reusable SSH server endpoint for a sandbox.
#[derive(Clone)]
pub struct SshServer {
    config: Arc<russh::server::Config>,
    settings: SshSettings,
}

#[derive(Clone)]
struct SshSettings {
    sandbox: Sandbox,
    authorized_keys: Arc<Vec<String>>,
    guest_user: Option<String>,
    sftp: bool,
}

struct SshSession {
    settings: SshSettings,
    client: Option<Arc<AgentClient>>,
    user: Option<String>,
    channels: HashMap<ChannelId, ChannelState>,
}

enum ChannelState {
    Pending {
        channel: Option<Channel<Msg>>,
        pty: Option<PtyInfo>,
        env: Vec<EnvVar>,
    },
    Exec {
        control: ExecControl,
        stdin: Option<ExecSink>,
    },
    Sftp,
}

#[derive(Clone)]
struct PtyInfo {
    term: String,
    rows: u16,
    cols: u16,
}

struct SftpServerSession {
    client: Arc<AgentClient>,
    cwd: String,
    next_handle: u64,
    handles: HashMap<String, crate::sandbox::fs::FsHandle>,
}

/// Ordered duplex stream backed by this process's stdin and stdout.
pub struct SshStdioStream {
    stdin: tokio::io::Stdin,
    stdout: tokio::io::Stdout,
}

#[derive(Clone)]
struct SshClientHandler;

enum ExecCommand {
    Shell,
    Command(String),
}

//--------------------------------------------------------------------------------------------------
// Methods: Sandbox
//--------------------------------------------------------------------------------------------------

impl Sandbox {
    /// Return the SSH namespace for this sandbox.
    pub fn ssh(&self) -> SandboxSsh {
        SandboxSsh {
            sandbox: self.clone(),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: SandboxSsh
//--------------------------------------------------------------------------------------------------

impl SandboxSsh {
    /// Connect a native in-process SSH client to this sandbox.
    pub async fn connect(&self) -> MicrosandboxResult<SshClient> {
        self.connect_with(|opts| opts).await
    }

    /// Connect a native in-process SSH client to this sandbox.
    pub async fn open_client(&self) -> MicrosandboxResult<SshClient> {
        self.connect().await
    }

    /// Connect a native in-process SSH client with custom options.
    pub async fn connect_with(
        &self,
        f: impl FnOnce(SshClientOptionsBuilder) -> SshClientOptionsBuilder,
    ) -> MicrosandboxResult<SshClient> {
        let options = f(SshClientOptionsBuilder::default()).build();
        let (client_key, host_key) = {
            let mut rng = russh::keys::key::safe_rng();
            let client_key = PrivateKey::random(&mut rng, Algorithm::Ed25519)
                .map_err(|e| MicrosandboxError::Custom(format!("generate SSH client key: {e}")))?;
            let host_key = PrivateKey::random(&mut rng, Algorithm::Ed25519)
                .map_err(|e| MicrosandboxError::Custom(format!("generate SSH host key: {e}")))?;
            (client_key, host_key)
        };
        let authorized_key = client_key.public_key().public_key_base64();
        let user = options.user.clone();
        let term = options.term.clone();
        let sftp = options.sftp;
        let server = self
            .server_with(|opts| {
                opts.host_key(host_key)
                    .authorized_key(authorized_key)
                    .user(user.clone())
                    .sftp(sftp)
            })
            .await?;

        let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
        let server_task = tokio::spawn(async move { server.serve(server_stream).await });
        let mut client = match russh::client::connect_stream(
            Arc::new(russh::client::Config::default()),
            client_stream,
            SshClientHandler,
        )
        .await
        {
            Ok(client) => client,
            Err(error) => {
                server_task.abort();
                return Err(ssh_error("client handshake", error));
            }
        };
        let hash_alg = client
            .best_supported_rsa_hash()
            .await
            .map_err(|e| {
                server_task.abort();
                ssh_error("server signature algorithms", e)
            })?
            .flatten();
        let auth = client
            .authenticate_publickey(
                user,
                PrivateKeyWithHashAlg::new(Arc::new(client_key), hash_alg),
            )
            .await
            .map_err(|e| {
                server_task.abort();
                ssh_error("public-key authentication", e)
            })?;
        if !auth.success() {
            server_task.abort();
            return Err(MicrosandboxError::Custom(
                "SSH public-key authentication failed".into(),
            ));
        }

        Ok(SshClient {
            handle: client,
            term,
            server_task: Some(server_task),
            negotiated_version: self.sandbox.client().negotiated_version(),
        })
    }

    /// Connect a native in-process SSH client with custom options.
    pub async fn open_client_with(
        &self,
        f: impl FnOnce(SshClientOptionsBuilder) -> SshClientOptionsBuilder,
    ) -> MicrosandboxResult<SshClient> {
        self.connect_with(f).await
    }

    /// Prepare a reusable SSH server endpoint for this sandbox.
    pub async fn server(&self) -> MicrosandboxResult<SshServer> {
        self.server_with(|opts| opts).await
    }

    /// Prepare a reusable SSH server endpoint for this sandbox.
    pub async fn prepare_server(&self) -> MicrosandboxResult<SshServer> {
        self.server().await
    }

    /// Prepare a reusable SSH server endpoint with custom options.
    pub async fn server_with(
        &self,
        f: impl FnOnce(SshServerOptionsBuilder) -> SshServerOptionsBuilder,
    ) -> MicrosandboxResult<SshServer> {
        let local_backend =
            self.sandbox
                .backend()
                .as_local()
                .ok_or_else(|| MicrosandboxError::Unsupported {
                    feature: "Sandbox::ssh on cloud".into(),
                    available_when: "when cloud SSH proxying lands".into(),
                })?;
        let options = f(SshServerOptionsBuilder::default()).build();
        let authorized_keys = build_authorized_keys(&options, local_backend.config())?;
        let host_key = match options.host_key {
            Some(key) => key,
            None => {
                let (host_key_path, secure_parent) = match options.host_key_path {
                    Some(path) => (path, false),
                    None => (
                        default_host_key_path(local_backend, self.sandbox.name()),
                        true,
                    ),
                };
                load_or_create_host_key(&host_key_path, secure_parent)?
            }
        };
        let config = Arc::new(russh::server::Config {
            auth_rejection_time: Duration::from_secs(3),
            auth_rejection_time_initial: Some(Duration::from_millis(0)),
            keys: vec![host_key],
            ..Default::default()
        });
        let settings = SshSettings {
            sandbox: self.sandbox.clone(),
            authorized_keys: Arc::new(authorized_keys),
            guest_user: options.guest_user,
            sftp: options.sftp,
        };

        Ok(SshServer { config, settings })
    }

    /// Prepare a reusable SSH server endpoint with custom options.
    pub async fn prepare_server_with(
        &self,
        f: impl FnOnce(SshServerOptionsBuilder) -> SshServerOptionsBuilder,
    ) -> MicrosandboxResult<SshServer> {
        self.server_with(f).await
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: SshClientOptionsBuilder
//--------------------------------------------------------------------------------------------------

impl Default for SshClientOptions {
    fn default() -> Self {
        Self {
            user: "root".to_string(),
            term: default_ssh_term(),
            sftp: true,
        }
    }
}

impl SshClientOptionsBuilder {
    /// Set the SSH login user.
    pub fn user(mut self, user: impl Into<String>) -> Self {
        self.options.user = user.into();
        self
    }

    /// Set the terminal name requested for interactive SSH sessions.
    pub fn term(mut self, term: impl Into<String>) -> Self {
        self.options.term = term.into();
        self
    }

    /// Enable or disable SFTP on the internal server used by this client.
    pub fn sftp(mut self, enabled: bool) -> Self {
        self.options.sftp = enabled;
        self
    }

    /// Finalize the options.
    pub fn build(self) -> SshClientOptions {
        self.options
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: SshExecOptionsBuilder
//--------------------------------------------------------------------------------------------------

impl SshExecOptionsBuilder {
    /// Request a PTY for the SSH exec channel.
    pub fn tty(mut self, enabled: bool) -> Self {
        self.options.tty = enabled;
        self
    }

    /// Finalize the options.
    pub fn build(self) -> SshExecOptions {
        self.options
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: SshAttachOptionsBuilder
//--------------------------------------------------------------------------------------------------

impl Default for SshAttachOptions {
    fn default() -> Self {
        Self {
            term: default_ssh_term(),
            detach_keys: None,
        }
    }
}

impl SshAttachOptionsBuilder {
    /// Set the terminal name requested for the interactive shell.
    pub fn term(mut self, term: impl Into<String>) -> Self {
        self.options.term = term.into();
        self
    }

    /// Set the detach key sequence.
    pub fn detach_keys(mut self, keys: impl Into<String>) -> Self {
        self.options.detach_keys = Some(keys.into());
        self
    }

    /// Finalize the options.
    pub fn build(self) -> SshAttachOptions {
        self.options
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: SshClient
//--------------------------------------------------------------------------------------------------

impl SshClient {
    /// Run an SSH exec request and collect stdout, stderr, and exit status.
    pub async fn exec(&self, command: impl Into<String>) -> MicrosandboxResult<SshOutput> {
        self.exec_with(command, |opts| opts).await
    }

    /// Run an SSH exec request with custom options.
    pub async fn exec_with(
        &self,
        command: impl Into<String>,
        f: impl FnOnce(SshExecOptionsBuilder) -> SshExecOptionsBuilder,
    ) -> MicrosandboxResult<SshOutput> {
        let options = f(SshExecOptionsBuilder::default()).build();
        let mut channel = self
            .handle
            .channel_open_session()
            .await
            .map_err(|e| ssh_error("open session channel", e))?;
        if options.tty {
            channel
                .request_pty(true, &self.term, 80, 24, 0, 0, &[])
                .await
                .map_err(|e| ssh_error("request PTY", e))?;
            wait_channel_success(&mut channel, "request PTY").await?;
        }
        channel
            .exec(true, command.into())
            .await
            .map_err(|e| ssh_error("send exec request", e))?;
        wait_channel_success(&mut channel, "exec request").await?;

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut status = None;

        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
                ChannelMsg::ExtendedData { data, ext: 1 } => stderr.extend_from_slice(&data),
                ChannelMsg::ExtendedData { data, .. } => stderr.extend_from_slice(&data),
                ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status as i32),
                ChannelMsg::ExitSignal {
                    signal_name,
                    error_message,
                    ..
                } => {
                    let message = if error_message.is_empty() {
                        format!("process exited by signal {signal_name:?}")
                    } else {
                        error_message
                    };
                    stderr.extend_from_slice(message.as_bytes());
                    status = Some(128);
                }
                ChannelMsg::Close => break,
                ChannelMsg::Eof
                | ChannelMsg::Success
                | ChannelMsg::Failure
                | ChannelMsg::WindowAdjusted { .. }
                | ChannelMsg::XonXoff { .. } => {}
                ChannelMsg::Open { .. }
                | ChannelMsg::OpenFailure(_)
                | ChannelMsg::RequestPty { .. }
                | ChannelMsg::RequestShell { .. }
                | ChannelMsg::Exec { .. }
                | ChannelMsg::Signal { .. }
                | ChannelMsg::RequestSubsystem { .. }
                | ChannelMsg::RequestX11 { .. }
                | ChannelMsg::SetEnv { .. }
                | ChannelMsg::WindowChange { .. }
                | ChannelMsg::AgentForward { .. } => {}
                _ => {}
            }
        }

        Ok(SshOutput {
            status: status.unwrap_or(0),
            stdout: Bytes::from(stdout),
            stderr: Bytes::from(stderr),
        })
    }

    /// Attach the local terminal to an interactive SSH shell.
    pub async fn attach(&self) -> MicrosandboxResult<i32> {
        self.attach_with(|opts| opts).await
    }

    /// Attach the local terminal to an interactive SSH shell with custom options.
    pub async fn attach_with(
        &self,
        f: impl FnOnce(SshAttachOptionsBuilder) -> SshAttachOptionsBuilder,
    ) -> MicrosandboxResult<i32> {
        let options = f(SshAttachOptionsBuilder::default()).build();

        #[cfg(windows)]
        {
            let detach_keys = match &options.detach_keys {
                Some(spec) => attach::DetachKeys::parse(spec)?,
                None => attach::DetachKeys::default_keys(),
            };
            let (cols, rows) = attach::local::current_terminal_size().unwrap_or((80, 24));
            let mut channel = self
                .handle
                .channel_open_session()
                .await
                .map_err(|e| ssh_error("open session channel", e))?;
            channel
                .request_pty(
                    true,
                    &options.term,
                    u32::from(cols),
                    u32::from(rows),
                    0,
                    0,
                    &[],
                )
                .await
                .map_err(|e| ssh_error("request PTY", e))?;
            wait_channel_success(&mut channel, "request PTY").await?;
            channel
                .request_shell(true)
                .await
                .map_err(|e| ssh_error("request shell", e))?;
            wait_channel_success(&mut channel, "request shell").await?;

            let terminal_guard = attach::local::WindowsTerminalGuard::enter()?;
            let mut terminal_events =
                attach::local::WindowsTerminalEventPump::spawn_for_guard(&terminal_guard)?;
            let detach_seq = detach_keys.sequence();
            let mut match_pos = 0usize;
            let mut exit_code = 0i32;
            let (mut channel_rx, channel_tx) = channel.split();

            loop {
                tokio::select! {
                    Some(event) = terminal_events.recv() => {
                        match event {
                            attach::local::WindowsTerminalEvent::Input(data) => {
                                if attach::input_contains_detach_sequence(
                                    &data,
                                    detach_seq,
                                    &mut match_pos,
                                ) {
                                    break;
                                }

                                channel_tx
                                    .data_bytes(Bytes::from(data))
                                    .await
                                    .map_err(|e| ssh_error("write channel data", e))?;
                            }
                            attach::local::WindowsTerminalEvent::Resize { cols, rows } => {
                                let _ = channel_tx
                                    .window_change(u32::from(cols), u32::from(rows), 0, 0)
                                    .await;
                            }
                            attach::local::WindowsTerminalEvent::Error(error) => {
                                return Err(MicrosandboxError::Terminal(error));
                            }
                        }
                    }
                    msg = channel_rx.wait() => {
                        let Some(msg) = msg else {
                            break;
                        };
                        match msg {
                            ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. } => {
                                terminal_guard.write_output(&data)?;
                            }
                            ChannelMsg::ExitStatus { exit_status } => {
                                exit_code = exit_status as i32;
                            }
                            ChannelMsg::ExitSignal { .. } => {
                                exit_code = 128;
                            }
                            ChannelMsg::Close => break,
                            _ => {}
                        }
                    }
                }
            }

            Ok(exit_code)
        }

        #[cfg(unix)]
        {
            let detach_keys = match &options.detach_keys {
                Some(spec) => attach::DetachKeys::parse(spec)?,
                None => attach::DetachKeys::default_keys(),
            };
            let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));
            let mut channel = self
                .handle
                .channel_open_session()
                .await
                .map_err(|e| ssh_error("open session channel", e))?;
            channel
                .request_pty(
                    true,
                    &options.term,
                    u32::from(cols),
                    u32::from(rows),
                    0,
                    0,
                    &[],
                )
                .await
                .map_err(|e| ssh_error("request PTY", e))?;
            wait_channel_success(&mut channel, "request PTY").await?;
            channel
                .request_shell(true)
                .await
                .map_err(|e| ssh_error("request shell", e))?;
            wait_channel_success(&mut channel, "request shell").await?;

            crossterm::terminal::enable_raw_mode()
                .map_err(|e| MicrosandboxError::Terminal(e.to_string()))?;
            let _raw_guard = scopeguard::guard((), |_| {
                let _ = crossterm::terminal::disable_raw_mode();
            });

            let tty_input_path = terminal_path_for_fd(std::io::stdin().as_raw_fd())
                .map_err(|e| MicrosandboxError::Terminal(format!("resolve tty path: {e}")))?;
            let tty_input = open_nonblocking_terminal_input(&tty_input_path)
                .map_err(|e| MicrosandboxError::Terminal(format!("open tty input: {e}")))?;
            let stdin_async = tokio::io::unix::AsyncFd::new(tty_input)
                .map_err(|e| MicrosandboxError::Terminal(format!("async tty input: {e}")))?;
            let mut stdout = tokio::io::stdout();
            let mut sigwinch =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
                    .map_err(|e| MicrosandboxError::Runtime(format!("sigwinch: {e}")))?;
            let detach_seq = detach_keys.sequence();
            let mut match_pos = 0usize;
            let mut exit_code = 0i32;
            let (mut channel_rx, channel_tx) = channel.split();

            loop {
                tokio::select! {
                    result = stdin_async.readable() => {
                        let mut guard = match result {
                            Ok(guard) => guard,
                            Err(_) => break,
                        };
                        let mut input_buf = [0u8; 1024];
                        match guard.try_io(|inner| {
                            read_from_fd(inner.get_ref().as_raw_fd(), &mut input_buf)
                        }) {
                            Ok(Ok(0)) => {
                                let _ = channel_tx.eof().await;
                                break;
                            }
                            Ok(Ok(n)) => {
                                let data = &input_buf[..n];
                                let mut detached = false;
                                for &byte in data {
                                    if byte == detach_seq[match_pos] {
                                        match_pos += 1;
                                        if match_pos == detach_seq.len() {
                                            detached = true;
                                            break;
                                        }
                                    } else {
                                        match_pos = 0;
                                        if byte == detach_seq[0] {
                                            match_pos = 1;
                                        }
                                    }
                                }
                                if detached {
                                    break;
                                }
                                channel_tx
                                    .data_bytes(Bytes::copy_from_slice(data))
                                    .await
                                    .map_err(|e| ssh_error("write channel data", e))?;
                            }
                            Ok(Err(e)) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                            Ok(Err(_)) => break,
                            Err(_) => continue,
                        }
                    }
                    msg = channel_rx.wait() => {
                        let Some(msg) = msg else {
                            break;
                        };
                        match msg {
                            ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. } => {
                                use tokio::io::AsyncWriteExt;
                                stdout.write_all(&data).await?;
                                stdout.flush().await?;
                            }
                            ChannelMsg::ExitStatus { exit_status } => {
                                exit_code = exit_status as i32;
                            }
                            ChannelMsg::ExitSignal { .. } => {
                                exit_code = 128;
                            }
                            ChannelMsg::Close => break,
                            _ => {}
                        }
                    }
                    _ = sigwinch.recv() => {
                        if let Ok((new_cols, new_rows)) = crossterm::terminal::size() {
                            let _ = channel_tx
                                .window_change(u32::from(new_cols), u32::from(new_rows), 0, 0)
                                .await;
                        }
                    }
                }
            }

            Ok(exit_code)
        }
    }

    /// Open an SFTP client session over this SSH connection.
    pub async fn sftp(&self) -> MicrosandboxResult<SftpClient> {
        AgentClient::ensure_version_compat_for(MessageType::FsRequest, self.negotiated_version)?;

        let mut channel = self
            .handle
            .channel_open_session()
            .await
            .map_err(|e| ssh_error("open SFTP channel", e))?;
        channel
            .request_subsystem(true, "sftp")
            .await
            .map_err(|e| ssh_error("request SFTP subsystem", e))?;
        wait_channel_success(&mut channel, "SFTP subsystem").await?;
        russh_sftp::client::SftpSession::new(channel.into_stream())
            .await
            .map_err(|e| MicrosandboxError::Custom(format!("start SFTP client: {e}")))
    }

    /// Close this native SSH client session.
    pub async fn close(mut self) -> MicrosandboxResult<()> {
        let _ = self
            .handle
            .disconnect(russh::Disconnect::ByApplication, "closed", "")
            .await;
        if let Some(server_task) = self.server_task.take() {
            server_task.abort();
        }
        Ok(())
    }
}

impl Drop for SshClient {
    fn drop(&mut self) {
        if let Some(server_task) = self.server_task.take() {
            server_task.abort();
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: SshServerOptionsBuilder
//--------------------------------------------------------------------------------------------------

impl Default for SshServerOptions {
    fn default() -> Self {
        Self {
            host_key_path: None,
            host_key: None,
            authorized_keys_path: None,
            authorized_keys: Vec::new(),
            guest_user: None,
            sftp: true,
        }
    }
}

impl SshServerOptionsBuilder {
    /// Override the host private key path.
    pub fn host_key_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.options.host_key_path = Some(path.into());
        self
    }

    /// Use an in-memory host private key.
    pub fn host_key(mut self, key: PrivateKey) -> Self {
        self.options.host_key = Some(key);
        self
    }

    /// Override the authorized-keys path.
    pub fn authorized_keys_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.options.authorized_keys_path = Some(path.into());
        self
    }

    /// Add one in-memory authorized public key.
    pub fn authorized_key(mut self, key: impl Into<String>) -> Self {
        self.options.authorized_keys.push(key.into());
        self
    }

    /// Override the guest user used for exec requests.
    pub fn user(mut self, user: impl Into<String>) -> Self {
        self.options.guest_user = Some(user.into());
        self
    }

    /// Enable or disable SFTP.
    pub fn sftp(mut self, enabled: bool) -> Self {
        self.options.sftp = enabled;
        self
    }

    /// Finalize the options.
    pub fn build(self) -> SshServerOptions {
        self.options
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: SshServer
//--------------------------------------------------------------------------------------------------

impl SshServer {
    /// Serve one SSH connection over an ordered duplex stream.
    pub async fn serve<S>(&self, stream: S) -> MicrosandboxResult<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let session = russh::server::run_stream(
            self.config.clone(),
            stream,
            SshSession::new(self.settings.clone()),
        )
        .await
        .map_err(|e| ssh_error("server handshake", e))?;
        session
            .await
            .map_err(|e| MicrosandboxError::Custom(format!("SSH session failed: {e}")))?;
        Ok(())
    }

    /// Serve one SSH connection over an ordered duplex stream.
    pub async fn serve_connection<S>(&self, stream: S) -> MicrosandboxResult<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        self.serve(stream).await
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: SshSession
//--------------------------------------------------------------------------------------------------

impl SshSession {
    fn new(settings: SshSettings) -> Self {
        Self {
            settings,
            client: None,
            user: None,
            channels: HashMap::new(),
        }
    }

    async fn agent_client(&mut self) -> anyhow::Result<Arc<AgentClient>> {
        if let Some(client) = &self.client {
            return Ok(Arc::clone(client));
        }

        let local_backend = self.settings.sandbox.backend().as_local().ok_or_else(|| {
            MicrosandboxError::Unsupported {
                feature: "Sandbox::ssh on cloud".into(),
                available_when: "when cloud SSH proxying lands".into(),
            }
        })?;
        let client = Arc::new(
            crate::sandbox::fs::local::connect_agent(local_backend, self.settings.sandbox.name())
                .await?,
        );
        self.client = Some(Arc::clone(&client));
        Ok(client)
    }

    fn key_is_authorized(&self, public_key: &russh::keys::PublicKey) -> bool {
        let key = public_key.public_key_base64();
        self.settings
            .authorized_keys
            .iter()
            .any(|authorized| authorized == &key)
    }

    async fn start_exec(
        &mut self,
        channel: ChannelId,
        command: ExecCommand,
        session: &mut Session,
    ) -> anyhow::Result<()> {
        let Some(ChannelState::Pending { pty, env, .. }) = self.channels.remove(&channel) else {
            session.channel_failure(channel)?;
            return Ok(());
        };

        let shell = self
            .settings
            .sandbox
            .config()
            .spec
            .runtime
            .shell
            .as_deref()
            .unwrap_or("/bin/sh")
            .to_string();
        let (cmd, args) = match command {
            ExecCommand::Shell => (shell, Vec::new()),
            ExecCommand::Command(command) => (shell, vec!["-c".to_string(), command]),
        };
        let mut env = env;
        if let Some(pty) = &pty {
            env.push(EnvVar::new("TERM", pty.term.clone()));
        }
        let user = self
            .settings
            .guest_user
            .clone()
            .or_else(|| self.user.clone());
        let opts = ExecOptions {
            args,
            cwd: None,
            user,
            env,
            timeout: None,
            stdin: StdinMode::Pipe,
            tty: pty.is_some(),
            rlimits: Vec::new(),
        };
        let rows = pty.as_ref().map(|p| p.rows).unwrap_or(24);
        let cols = pty.as_ref().map(|p| p.cols).unwrap_or(80);
        let local_backend = self.settings.sandbox.backend().as_local().ok_or_else(|| {
            MicrosandboxError::Unsupported {
                feature: "Sandbox::ssh exec on cloud".into(),
                available_when: "when cloud SSH proxying lands".into(),
            }
        })?;
        let handle = crate::sandbox::exec::local::exec_stream_with_pty_size(
            local_backend,
            self.settings.sandbox.name(),
            self.settings.sandbox.config(),
            cmd,
            opts,
            rows,
            cols,
        )
        .await?;
        let (control, stdin, mut events) = handle.into_parts();
        let session_handle = session.handle();
        let pty_enabled = pty.is_some();

        tokio::spawn(async move {
            while let Some(event) = events.recv().await {
                match event {
                    ExecEvent::Started { .. } => {}
                    ExecEvent::Stdout(data) => {
                        let _ = session_handle.data(channel, data).await;
                    }
                    ExecEvent::Stderr(data) => {
                        if pty_enabled {
                            let _ = session_handle.data(channel, data).await;
                        } else {
                            let _ = session_handle.extended_data(channel, 1, data).await;
                        }
                    }
                    ExecEvent::Exited { code } => {
                        let _ = session_handle
                            .exit_status_request(channel, code.max(0) as u32)
                            .await;
                        let _ = session_handle.eof(channel).await;
                        let _ = session_handle.close(channel).await;
                        break;
                    }
                    ExecEvent::Failed(failed) => {
                        let message = Bytes::from(failed.message);
                        if pty_enabled {
                            let _ = session_handle.data(channel, message).await;
                        } else {
                            let _ = session_handle.extended_data(channel, 1, message).await;
                        }
                        let _ = session_handle.exit_status_request(channel, 127).await;
                        let _ = session_handle.eof(channel).await;
                        let _ = session_handle.close(channel).await;
                        break;
                    }
                    ExecEvent::StdinError(_) => {}
                }
            }
        });

        self.channels
            .insert(channel, ChannelState::Exec { control, stdin });
        session.channel_success(channel)?;
        Ok(())
    }
}

impl russh::server::Handler for SshSession {
    type Error = anyhow::Error;

    async fn auth_publickey_offered(
        &mut self,
        _user: &str,
        public_key: &russh::keys::PublicKey,
    ) -> Result<Auth, Self::Error> {
        if self.key_is_authorized(public_key) {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::reject())
        }
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &russh::keys::PublicKey,
    ) -> Result<Auth, Self::Error> {
        if self.key_is_authorized(public_key) {
            self.user = Some(user.to_string());
            Ok(Auth::Accept)
        } else {
            Ok(Auth::reject())
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        self.channels.insert(
            channel.id(),
            ChannelState::Pending {
                channel: Some(channel),
                pty: None,
                env: Vec::new(),
            },
        );
        Ok(true)
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        variable_name: &str,
        variable_value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(ChannelState::Pending { env, .. }) = self.channels.get_mut(&channel) {
            env.push(EnvVar::new(variable_name, variable_value));
            session.channel_success(channel)?;
        } else {
            session.channel_failure(channel)?;
        }
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(ChannelState::Pending { pty, .. }) = self.channels.get_mut(&channel) {
            *pty = Some(PtyInfo {
                term: term.to_string(),
                rows: row_height.min(u16::MAX as u32) as u16,
                cols: col_width.min(u16::MAX as u32) as u16,
            });
            session.channel_success(channel)?;
        } else {
            session.channel_failure(channel)?;
        }
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.start_exec(channel, ExecCommand::Shell, session).await
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let command = String::from_utf8_lossy(data).to_string();
        self.start_exec(channel, ExecCommand::Command(command), session)
            .await
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if name != "sftp" || !self.settings.sftp {
            session.channel_failure(channel)?;
            return Ok(());
        }

        let Some(ChannelState::Pending {
            channel: Some(channel_stream),
            ..
        }) = self.channels.remove(&channel)
        else {
            session.channel_failure(channel)?;
            return Ok(());
        };

        let client = self.agent_client().await?;
        if client.is_legacy_protocol() {
            // TODO(upgrade-0.6): Remove in 0.6.x or later once live-sandbox
            // compatibility for versions before 0.5 is no longer supported.
            session.channel_failure(channel)?;
            return Ok(());
        }

        let cwd = self
            .settings
            .sandbox
            .config()
            .spec
            .runtime
            .workdir
            .as_deref()
            .filter(|path| !path.is_empty() && path.starts_with('/'))
            .map(str::to_string)
            .clone()
            .unwrap_or_else(|| "/".to_string());
        let sftp = SftpServerSession {
            client,
            cwd,
            next_handle: 0,
            handles: HashMap::new(),
        };
        self.channels.insert(channel, ChannelState::Sftp);
        session.channel_success(channel)?;
        tokio::spawn(async move {
            russh_sftp::server::run(channel_stream.into_stream(), sftp).await;
        });
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(ChannelState::Exec {
            stdin: Some(stdin), ..
        }) = self.channels.get(&channel)
        {
            stdin.write(data).await?;
        }
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(ChannelState::Exec {
            stdin: Some(stdin), ..
        }) = self.channels.get(&channel)
        {
            let _ = stdin.close().await;
        }
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(ChannelState::Exec { control, stdin }) = self.channels.remove(&channel) {
            if let Some(stdin) = stdin {
                let _ = stdin.close().await;
            }
            let _ = control.kill().await;
        } else {
            self.channels.remove(&channel);
        }
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(ChannelState::Exec { control, .. }) = self.channels.get(&channel) {
            control
                .resize(
                    row_height.min(u16::MAX as u32) as u16,
                    col_width.min(u16::MAX as u32) as u16,
                )
                .await?;
            session.channel_success(channel)?;
        } else {
            session.channel_failure(channel)?;
        }
        Ok(())
    }

    async fn signal(
        &mut self,
        channel: ChannelId,
        signal: Sig,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(ChannelState::Exec { control, .. }) = self.channels.get(&channel)
            && let Some(signal) = signal_to_libc(signal)
        {
            control.signal(signal).await?;
        }
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl russh::client::Handler for SshClientHandler {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

impl SftpServerSession {
    fn normalize_path(&self, path: String) -> String {
        let cwd = if self.cwd.is_empty() {
            "/"
        } else {
            self.cwd.as_str()
        };

        if path.is_empty() || path == "." {
            return cwd.to_string();
        }
        if path.starts_with('/') {
            return path;
        }

        let cwd = cwd.trim_end_matches('/');
        if cwd.is_empty() {
            format!("/{path}")
        } else {
            format!("{cwd}/{path}")
        }
    }

    fn track_handle(&mut self, handle: crate::sandbox::fs::FsHandle) -> String {
        self.next_handle = self.next_handle.wrapping_add(1).max(1);
        let token = self.next_handle.to_string();
        self.handles.insert(token.clone(), handle);
        token
    }

    fn resolve_handle(
        &self,
        token: &str,
    ) -> Result<crate::sandbox::fs::FsHandle, russh_sftp::protocol::StatusCode> {
        self.handles
            .get(token)
            .copied()
            .ok_or(russh_sftp::protocol::StatusCode::Failure)
    }

    fn forget_handle(
        &mut self,
        token: &str,
    ) -> Result<crate::sandbox::fs::FsHandle, russh_sftp::protocol::StatusCode> {
        self.handles
            .remove(token)
            .ok_or(russh_sftp::protocol::StatusCode::Failure)
    }
}

impl Drop for SftpServerSession {
    fn drop(&mut self) {
        let client = Arc::clone(&self.client);
        let handles: Vec<_> = self.handles.drain().map(|(_, handle)| handle).collect();
        tokio::spawn(async move {
            for handle in handles {
                let _ = sftp_close_handle(&client, handle).await;
            }
        });
    }
}

impl russh_sftp::server::Handler for SftpServerSession {
    type Error = russh_sftp::protocol::StatusCode;

    fn unimplemented(&self) -> Self::Error {
        russh_sftp::protocol::StatusCode::OpUnsupported
    }

    async fn init(
        &mut self,
        _version: u32,
        _extensions: HashMap<String, String>,
    ) -> Result<russh_sftp::protocol::Version, Self::Error> {
        Ok(russh_sftp::protocol::Version::new())
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        pflags: russh_sftp::protocol::OpenFlags,
        attrs: russh_sftp::protocol::FileAttributes,
    ) -> Result<russh_sftp::protocol::Handle, Self::Error> {
        let path = self.normalize_path(filename);
        let options = open_flags_to_options(pflags, &attrs);
        let handle = sftp_open_file(&self.client, &path, options)
            .await
            .map_err(status_code)?;
        Ok(russh_sftp::protocol::Handle {
            id,
            handle: self.track_handle(handle),
        })
    }

    async fn close(
        &mut self,
        id: u32,
        handle: String,
    ) -> Result<russh_sftp::protocol::Status, Self::Error> {
        let handle = self.forget_handle(&handle)?;
        sftp_close_handle(&self.client, handle)
            .await
            .map_err(status_code)?;
        Ok(status(id, russh_sftp::protocol::StatusCode::Ok))
    }

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<russh_sftp::protocol::Data, Self::Error> {
        let handle = self.resolve_handle(&handle)?;
        let len = len.min(FS_CHUNK_SIZE as u32);
        let data = sftp_read_handle(&self.client, handle, offset, Some(len as u64))
            .await
            .map_err(status_code)?;
        if data.is_empty() {
            return Err(russh_sftp::protocol::StatusCode::Eof);
        }
        Ok(russh_sftp::protocol::Data {
            id,
            data: data.to_vec(),
        })
    }

    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<russh_sftp::protocol::Status, Self::Error> {
        let handle = self.resolve_handle(&handle)?;
        sftp_write_handle(&self.client, handle, offset, data)
            .await
            .map_err(status_code)?;
        Ok(status(id, russh_sftp::protocol::StatusCode::Ok))
    }

    async fn lstat(
        &mut self,
        id: u32,
        path: String,
    ) -> Result<russh_sftp::protocol::Attrs, Self::Error> {
        let path = self.normalize_path(path);
        let attrs = sftp_stat(&self.client, &path, false)
            .await
            .map_err(status_code)?;
        Ok(russh_sftp::protocol::Attrs {
            id,
            attrs: metadata_to_sftp_attrs(&attrs),
        })
    }

    async fn stat(
        &mut self,
        id: u32,
        path: String,
    ) -> Result<russh_sftp::protocol::Attrs, Self::Error> {
        let path = self.normalize_path(path);
        let attrs = sftp_stat(&self.client, &path, true)
            .await
            .map_err(status_code)?;
        Ok(russh_sftp::protocol::Attrs {
            id,
            attrs: metadata_to_sftp_attrs(&attrs),
        })
    }

    async fn fstat(
        &mut self,
        id: u32,
        handle: String,
    ) -> Result<russh_sftp::protocol::Attrs, Self::Error> {
        let handle = self.resolve_handle(&handle)?;
        let attrs = sftp_fstat(&self.client, handle)
            .await
            .map_err(status_code)?;
        Ok(russh_sftp::protocol::Attrs {
            id,
            attrs: metadata_to_sftp_attrs(&attrs),
        })
    }

    async fn setstat(
        &mut self,
        id: u32,
        path: String,
        attrs: russh_sftp::protocol::FileAttributes,
    ) -> Result<russh_sftp::protocol::Status, Self::Error> {
        let path = self.normalize_path(path);
        sftp_set_stat(&self.client, &path, true, attrs_to_set_attrs(&attrs))
            .await
            .map_err(status_code)?;
        Ok(status(id, russh_sftp::protocol::StatusCode::Ok))
    }

    async fn fsetstat(
        &mut self,
        id: u32,
        handle: String,
        attrs: russh_sftp::protocol::FileAttributes,
    ) -> Result<russh_sftp::protocol::Status, Self::Error> {
        let handle = self.resolve_handle(&handle)?;
        sftp_fset_stat(&self.client, handle, attrs_to_set_attrs(&attrs))
            .await
            .map_err(status_code)?;
        Ok(status(id, russh_sftp::protocol::StatusCode::Ok))
    }

    async fn opendir(
        &mut self,
        id: u32,
        path: String,
    ) -> Result<russh_sftp::protocol::Handle, Self::Error> {
        let path = self.normalize_path(path);
        let handle = sftp_open_dir(&self.client, &path)
            .await
            .map_err(status_code)?;
        Ok(russh_sftp::protocol::Handle {
            id,
            handle: self.track_handle(handle),
        })
    }

    async fn readdir(
        &mut self,
        id: u32,
        handle: String,
    ) -> Result<russh_sftp::protocol::Name, Self::Error> {
        let handle = self.resolve_handle(&handle)?;
        let entries = sftp_read_dir(&self.client, handle, None)
            .await
            .map_err(status_code)?;
        if entries.is_empty() {
            return Err(russh_sftp::protocol::StatusCode::Eof);
        }
        Ok(russh_sftp::protocol::Name {
            id,
            files: entries.into_iter().map(entry_to_sftp_file).collect(),
        })
    }

    async fn remove(
        &mut self,
        id: u32,
        filename: String,
    ) -> Result<russh_sftp::protocol::Status, Self::Error> {
        let path = self.normalize_path(filename);
        sftp_simple_op(&self.client, FsOp::Remove { path })
            .await
            .map_err(status_code)?;
        Ok(status(id, russh_sftp::protocol::StatusCode::Ok))
    }

    async fn mkdir(
        &mut self,
        id: u32,
        path: String,
        attrs: russh_sftp::protocol::FileAttributes,
    ) -> Result<russh_sftp::protocol::Status, Self::Error> {
        let path = self.normalize_path(path);
        sftp_simple_op(
            &self.client,
            FsOp::Mkdir {
                path: path.clone(),
                mode: attrs.permissions,
            },
        )
        .await
        .map_err(status_code)?;
        if attrs.permissions.is_some() {
            sftp_set_stat(&self.client, &path, true, attrs_to_set_attrs(&attrs))
                .await
                .map_err(status_code)?;
        }
        Ok(status(id, russh_sftp::protocol::StatusCode::Ok))
    }

    async fn rmdir(
        &mut self,
        id: u32,
        path: String,
    ) -> Result<russh_sftp::protocol::Status, Self::Error> {
        let path = self.normalize_path(path);
        sftp_simple_op(
            &self.client,
            FsOp::RemoveDir {
                path,
                recursive: false,
            },
        )
        .await
        .map_err(status_code)?;
        Ok(status(id, russh_sftp::protocol::StatusCode::Ok))
    }

    async fn realpath(
        &mut self,
        id: u32,
        path: String,
    ) -> Result<russh_sftp::protocol::Name, Self::Error> {
        let path = self.normalize_path(path);
        let path = sftp_path_op(&self.client, FsOp::RealPath { path })
            .await
            .map_err(status_code)?;
        Ok(russh_sftp::protocol::Name {
            id,
            files: vec![russh_sftp::protocol::File::dummy(path)],
        })
    }

    async fn rename(
        &mut self,
        id: u32,
        oldpath: String,
        newpath: String,
    ) -> Result<russh_sftp::protocol::Status, Self::Error> {
        let oldpath = self.normalize_path(oldpath);
        let newpath = self.normalize_path(newpath);
        sftp_simple_op(
            &self.client,
            FsOp::Rename {
                src: oldpath,
                dst: newpath,
            },
        )
        .await
        .map_err(status_code)?;
        Ok(status(id, russh_sftp::protocol::StatusCode::Ok))
    }

    async fn readlink(
        &mut self,
        id: u32,
        path: String,
    ) -> Result<russh_sftp::protocol::Name, Self::Error> {
        let path = self.normalize_path(path);
        let target = sftp_path_op(&self.client, FsOp::ReadLink { path })
            .await
            .map_err(status_code)?;
        Ok(russh_sftp::protocol::Name {
            id,
            files: vec![russh_sftp::protocol::File::dummy(target)],
        })
    }

    async fn symlink(
        &mut self,
        id: u32,
        linkpath: String,
        targetpath: String,
    ) -> Result<russh_sftp::protocol::Status, Self::Error> {
        let target = linkpath;
        let link_path = self.normalize_path(targetpath);
        sftp_simple_op(&self.client, FsOp::Symlink { target, link_path })
            .await
            .map_err(status_code)?;
        Ok(status(id, russh_sftp::protocol::StatusCode::Ok))
    }
}

impl SshStdioStream {
    /// Create a stdio SSH transport stream.
    pub fn new() -> Self {
        Self {
            stdin: tokio::io::stdin(),
            stdout: tokio::io::stdout(),
        }
    }
}

impl Default for SshStdioStream {
    fn default() -> Self {
        Self::new()
    }
}

impl AsyncRead for SshStdioStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.stdin).poll_read(cx, buf)
    }
}

impl AsyncWrite for SshStdioStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let this = self.get_mut();
        Pin::new(&mut this.stdout).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        let this = self.get_mut();
        Pin::new(&mut this.stdout).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let this = self.get_mut();
        Pin::new(&mut this.stdout).poll_shutdown(cx)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn build_authorized_keys(
    options: &SshServerOptions,
    config: &crate::config::LocalConfig,
) -> MicrosandboxResult<Vec<String>> {
    let mut keys = Vec::new();
    if let Some(path) = &options.authorized_keys_path {
        keys.extend(load_authorized_keys(path)?);
    } else if options.authorized_keys.is_empty() {
        keys.extend(load_authorized_keys(&default_authorized_keys_path(config))?);
    }
    for key in &options.authorized_keys {
        keys.push(parse_authorized_key(key)?);
    }
    if keys.is_empty() {
        return Err(MicrosandboxError::Custom(
            "SSH server has no authorized public keys".into(),
        ));
    }
    Ok(keys)
}

fn default_authorized_keys_path(config: &crate::config::LocalConfig) -> PathBuf {
    config.ssh_dir().join("authorized_keys")
}

fn default_host_key_path(
    local_backend: &crate::backend::LocalBackend,
    sandbox_name: &str,
) -> PathBuf {
    local_backend
        .sandboxes_dir()
        .join(sandbox_name)
        .join(microsandbox_utils::SSH_SUBDIR)
        .join("host_ed25519")
}

fn load_or_create_host_key(path: &Path, secure_parent: bool) -> MicrosandboxResult<PrivateKey> {
    if path.exists() {
        set_private_file_permissions(path)?;
        return load_secret_key(path, None)
            .map_err(|e| MicrosandboxError::Custom(format!("load SSH host key: {e}")));
    }

    if let Some(parent) = path.parent() {
        if secure_parent {
            create_secure_dir(parent)?;
        } else {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut rng = russh::keys::key::safe_rng();
    let key = PrivateKey::random(&mut rng, Algorithm::Ed25519)
        .map_err(|e| MicrosandboxError::Custom(format!("generate SSH host key: {e}")))?;
    let encoded = key
        .to_openssh(russh::keys::ssh_key::LineEnding::LF)
        .map_err(|e| MicrosandboxError::Custom(format!("encode SSH host key: {e}")))?;
    let mut open_options = std::fs::OpenOptions::new();
    open_options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open_options.mode(0o600);
    }
    let mut file = open_options.open(path)?;
    file.write_all(encoded.as_bytes())?;
    set_private_file_permissions(path)?;
    Ok(key)
}

fn load_authorized_keys(path: &Path) -> MicrosandboxResult<Vec<String>> {
    let content = std::fs::read_to_string(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            MicrosandboxError::Custom(format!(
                "SSH authorized keys not found at {}; add one with `msb ssh authorize --file ~/.ssh/id_ed25519.pub`",
                path.display()
            ))
        } else {
            MicrosandboxError::Io(error)
        }
    })?;

    let mut keys = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        keys.push(parse_authorized_key(line)?);
    }

    if keys.is_empty() {
        return Err(MicrosandboxError::Custom(format!(
            "SSH authorized keys file is empty at {}; add one with `msb ssh authorize --file ~/.ssh/id_ed25519.pub`",
            path.display()
        )));
    }

    Ok(keys)
}

fn parse_authorized_key(line: &str) -> MicrosandboxResult<String> {
    let mut parts = line.split_whitespace();
    let Some(first) = parts.next() else {
        return Err(MicrosandboxError::Custom("invalid authorized key".into()));
    };
    let key_part = if first.starts_with("ssh-") || first.starts_with("ecdsa-") {
        parts
            .next()
            .ok_or_else(|| MicrosandboxError::Custom("invalid authorized key".into()))?
    } else {
        first
    };
    let key = russh::keys::parse_public_key_base64(key_part)
        .map_err(|e| MicrosandboxError::Custom(format!("parse authorized key: {e}")))?;
    Ok(key.public_key_base64())
}

fn create_secure_dir(path: &Path) -> MicrosandboxResult<()> {
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn set_private_file_permissions(_path: &Path) -> MicrosandboxResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(_path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

async fn wait_channel_success(
    channel: &mut Channel<ClientMsg>,
    context: &str,
) -> MicrosandboxResult<()> {
    loop {
        match channel.wait().await {
            Some(ChannelMsg::Success) => return Ok(()),
            Some(ChannelMsg::Failure) => {
                return Err(MicrosandboxError::Custom(format!("SSH {context} failed")));
            }
            Some(ChannelMsg::Close) | None => {
                return Err(MicrosandboxError::Custom(format!(
                    "SSH channel closed during {context}"
                )));
            }
            Some(ChannelMsg::Data { .. })
            | Some(ChannelMsg::ExtendedData { .. })
            | Some(ChannelMsg::Eof)
            | Some(ChannelMsg::ExitStatus { .. })
            | Some(ChannelMsg::ExitSignal { .. })
            | Some(ChannelMsg::WindowAdjusted { .. })
            | Some(ChannelMsg::XonXoff { .. })
            | Some(ChannelMsg::Open { .. })
            | Some(ChannelMsg::OpenFailure(_))
            | Some(ChannelMsg::RequestPty { .. })
            | Some(ChannelMsg::RequestShell { .. })
            | Some(ChannelMsg::Exec { .. })
            | Some(ChannelMsg::Signal { .. })
            | Some(ChannelMsg::RequestSubsystem { .. })
            | Some(ChannelMsg::RequestX11 { .. })
            | Some(ChannelMsg::SetEnv { .. })
            | Some(ChannelMsg::WindowChange { .. })
            | Some(ChannelMsg::AgentForward { .. })
            | Some(_) => {}
        }
    }
}

#[cfg(unix)]
fn signal_to_libc(signal: Sig) -> Option<i32> {
    match signal {
        Sig::ABRT => Some(libc::SIGABRT),
        Sig::ALRM => Some(libc::SIGALRM),
        Sig::FPE => Some(libc::SIGFPE),
        Sig::HUP => Some(libc::SIGHUP),
        Sig::ILL => Some(libc::SIGILL),
        Sig::INT => Some(libc::SIGINT),
        Sig::KILL => Some(libc::SIGKILL),
        Sig::PIPE => Some(libc::SIGPIPE),
        Sig::QUIT => Some(libc::SIGQUIT),
        Sig::SEGV => Some(libc::SIGSEGV),
        Sig::TERM => Some(libc::SIGTERM),
        Sig::USR1 => Some(libc::SIGUSR1),
        Sig::Custom(_) => None,
    }
}

#[cfg(windows)]
fn signal_to_libc(signal: Sig) -> Option<i32> {
    match signal {
        Sig::ABRT => Some(6),
        Sig::ALRM => Some(14),
        Sig::FPE => Some(8),
        Sig::HUP => Some(1),
        Sig::ILL => Some(4),
        Sig::INT => Some(2),
        Sig::KILL => Some(9),
        Sig::PIPE => Some(13),
        Sig::QUIT => Some(3),
        Sig::SEGV => Some(11),
        Sig::TERM => Some(15),
        Sig::USR1 => Some(10),
        Sig::Custom(_) => None,
    }
}

async fn sftp_response(client: &AgentClient, op: FsOp) -> MicrosandboxResult<FsResponse> {
    let req = FsRequest { op };
    let resp_msg = client.request(MessageType::FsRequest, &req).await?;
    let resp: FsResponse = resp_msg.payload()?;
    if resp.ok {
        Ok(resp)
    } else {
        Err(MicrosandboxError::SandboxFsOps(
            resp.error.unwrap_or_else(|| "unknown error".into()),
        ))
    }
}

async fn sftp_simple_op(client: &AgentClient, op: FsOp) -> MicrosandboxResult<()> {
    sftp_response(client, op).await.map(|_| ())
}

async fn sftp_path_op(client: &AgentClient, op: FsOp) -> MicrosandboxResult<String> {
    match sftp_response(client, op).await?.data {
        Some(FsResponseData::Path(path)) => Ok(path),
        _ => Err(MicrosandboxError::SandboxFsOps(
            "unexpected response data for path operation".into(),
        )),
    }
}

async fn sftp_open_file(
    client: &AgentClient,
    path: &str,
    options: FsOpenOptions,
) -> MicrosandboxResult<crate::sandbox::fs::FsHandle> {
    sftp_handle_op(
        client,
        FsOp::OpenFile {
            path: path.to_string(),
            options,
        },
    )
    .await
}

async fn sftp_open_dir(
    client: &AgentClient,
    path: &str,
) -> MicrosandboxResult<crate::sandbox::fs::FsHandle> {
    sftp_handle_op(
        client,
        FsOp::OpenDir {
            path: path.to_string(),
        },
    )
    .await
}

async fn sftp_handle_op(
    client: &AgentClient,
    op: FsOp,
) -> MicrosandboxResult<crate::sandbox::fs::FsHandle> {
    match sftp_response(client, op).await?.data {
        Some(FsResponseData::Handle(handle)) => Ok(handle),
        _ => Err(MicrosandboxError::SandboxFsOps(
            "unexpected response data for handle operation".into(),
        )),
    }
}

async fn sftp_close_handle(
    client: &AgentClient,
    handle: crate::sandbox::fs::FsHandle,
) -> MicrosandboxResult<()> {
    sftp_simple_op(client, FsOp::CloseHandle { handle }).await
}

async fn sftp_read_handle(
    client: &AgentClient,
    handle: crate::sandbox::fs::FsHandle,
    offset: u64,
    len: Option<u64>,
) -> MicrosandboxResult<Bytes> {
    let req = FsRequest {
        op: FsOp::Read {
            handle,
            offset,
            len,
        },
    };
    let (_id, mut rx) = client.stream(MessageType::FsRequest, &req).await?;

    let mut data = Vec::new();
    while let Some(msg) = rx.recv().await {
        match msg.t {
            MessageType::FsData => {
                let chunk: FsData = msg.payload()?;
                data.extend_from_slice(&chunk.data);
            }
            MessageType::FsResponse => {
                let resp: FsResponse = msg.payload()?;
                if resp.ok {
                    return Ok(Bytes::from(data));
                }
                return Err(MicrosandboxError::SandboxFsOps(
                    resp.error.unwrap_or_else(|| "unknown error".into()),
                ));
            }
            _ => {}
        }
    }

    Err(MicrosandboxError::SandboxFsOps(
        "channel closed before read response".into(),
    ))
}

async fn sftp_write_handle(
    client: &AgentClient,
    handle: crate::sandbox::fs::FsHandle,
    offset: u64,
    data: Vec<u8>,
) -> MicrosandboxResult<()> {
    let req = FsRequest {
        op: FsOp::Write {
            handle,
            offset,
            len: Some(data.len() as u64),
        },
    };
    let (id, mut rx) = client.stream(MessageType::FsRequest, &req).await?;

    for chunk in data.chunks(FS_CHUNK_SIZE) {
        client
            .send(
                id,
                MessageType::FsData,
                &FsData {
                    data: chunk.to_vec(),
                },
            )
            .await?;
    }
    client
        .send(id, MessageType::FsData, &FsData { data: Vec::new() })
        .await?;

    while let Some(msg) = rx.recv().await {
        if msg.t == MessageType::FsResponse {
            let resp: FsResponse = msg.payload()?;
            if resp.ok {
                return Ok(());
            }
            return Err(MicrosandboxError::SandboxFsOps(
                resp.error.unwrap_or_else(|| "unknown error".into()),
            ));
        }
    }

    Err(MicrosandboxError::SandboxFsOps(
        "channel closed before write response".into(),
    ))
}

async fn sftp_stat(
    client: &AgentClient,
    path: &str,
    follow_symlink: bool,
) -> MicrosandboxResult<FsEntryInfo> {
    sftp_stat_op(
        client,
        FsOp::Stat {
            path: path.to_string(),
            follow_symlink,
        },
    )
    .await
}

async fn sftp_fstat(
    client: &AgentClient,
    handle: crate::sandbox::fs::FsHandle,
) -> MicrosandboxResult<FsEntryInfo> {
    sftp_stat_op(client, FsOp::FStat { handle }).await
}

async fn sftp_stat_op(client: &AgentClient, op: FsOp) -> MicrosandboxResult<FsEntryInfo> {
    match sftp_response(client, op).await?.data {
        Some(FsResponseData::Stat(info)) => Ok(info),
        _ => Err(MicrosandboxError::SandboxFsOps(
            "unexpected response data for stat operation".into(),
        )),
    }
}

async fn sftp_set_stat(
    client: &AgentClient,
    path: &str,
    follow_symlink: bool,
    attrs: FsSetAttrs,
) -> MicrosandboxResult<()> {
    sftp_simple_op(
        client,
        FsOp::SetStat {
            path: path.to_string(),
            follow_symlink,
            attrs,
        },
    )
    .await
}

async fn sftp_fset_stat(
    client: &AgentClient,
    handle: crate::sandbox::fs::FsHandle,
    attrs: FsSetAttrs,
) -> MicrosandboxResult<()> {
    sftp_simple_op(client, FsOp::FSetStat { handle, attrs }).await
}

async fn sftp_read_dir(
    client: &AgentClient,
    handle: crate::sandbox::fs::FsHandle,
    limit: Option<u32>,
) -> MicrosandboxResult<Vec<FsEntryInfo>> {
    match sftp_response(client, FsOp::ReadDir { handle, limit })
        .await?
        .data
    {
        Some(FsResponseData::List(entries)) => Ok(entries),
        _ => Err(MicrosandboxError::SandboxFsOps(
            "unexpected response data for readdir operation".into(),
        )),
    }
}

fn open_flags_to_options(
    flags: russh_sftp::protocol::OpenFlags,
    attrs: &russh_sftp::protocol::FileAttributes,
) -> FsOpenOptions {
    FsOpenOptions {
        read: flags.contains(russh_sftp::protocol::OpenFlags::READ),
        write: flags.contains(russh_sftp::protocol::OpenFlags::WRITE),
        append: flags.contains(russh_sftp::protocol::OpenFlags::APPEND),
        create: flags.contains(russh_sftp::protocol::OpenFlags::CREATE),
        truncate: flags.contains(russh_sftp::protocol::OpenFlags::TRUNCATE),
        create_new: flags.contains(russh_sftp::protocol::OpenFlags::EXCLUDE),
        mode: attrs.permissions,
    }
}

fn attrs_to_set_attrs(attrs: &russh_sftp::protocol::FileAttributes) -> FsSetAttrs {
    FsSetAttrs {
        mode: attrs.permissions,
        uid: attrs.uid,
        gid: attrs.gid,
        size: attrs.size,
        atime: attrs.atime.map(i64::from),
        mtime: attrs.mtime.map(i64::from),
    }
}

fn metadata_to_sftp_attrs(metadata: &FsEntryInfo) -> russh_sftp::protocol::FileAttributes {
    russh_sftp::protocol::FileAttributes {
        size: Some(metadata.size),
        uid: Some(metadata.uid),
        user: None,
        gid: Some(metadata.gid),
        group: None,
        permissions: Some(metadata.mode),
        atime: metadata.atime.map(|t| t.max(0) as u32),
        mtime: metadata
            .mtime
            .or(metadata.modified)
            .map(|t| t.max(0) as u32),
    }
}

fn entry_to_sftp_file(entry: FsEntryInfo) -> russh_sftp::protocol::File {
    let filename = entry
        .path
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(entry.path.as_str())
        .to_string();
    russh_sftp::protocol::File::new(
        filename,
        russh_sftp::protocol::FileAttributes {
            size: Some(entry.size),
            uid: Some(entry.uid),
            user: None,
            gid: Some(entry.gid),
            group: None,
            permissions: Some(entry.mode),
            atime: entry.atime.map(|t| t.max(0) as u32),
            mtime: entry.mtime.or(entry.modified).map(|t| t.max(0) as u32),
        },
    )
}

fn status(id: u32, status_code: russh_sftp::protocol::StatusCode) -> russh_sftp::protocol::Status {
    russh_sftp::protocol::Status {
        id,
        status_code,
        error_message: status_code.to_string(),
        language_tag: "en-US".to_string(),
    }
}

fn status_code(error: MicrosandboxError) -> russh_sftp::protocol::StatusCode {
    let message = error.to_string();
    if message.contains("No such file") || message.contains("not found") {
        russh_sftp::protocol::StatusCode::NoSuchFile
    } else if message.contains("Permission denied") || message.contains("permission denied") {
        russh_sftp::protocol::StatusCode::PermissionDenied
    } else {
        russh_sftp::protocol::StatusCode::Failure
    }
}

fn default_ssh_term() -> String {
    match std::env::var("TERM") {
        Ok(term) if !term.trim().is_empty() && term != "dumb" => term,
        _ => "xterm".to_string(),
    }
}

#[cfg(unix)]
#[cfg(unix)]
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

#[cfg(unix)]
#[cfg(unix)]
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

#[cfg(unix)]
#[cfg(unix)]
fn read_from_fd(fd: std::os::fd::RawFd, buf: &mut [u8]) -> std::io::Result<usize> {
    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    if n < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

fn ssh_error(context: &str, error: impl std::fmt::Display) -> MicrosandboxError {
    MicrosandboxError::Custom(format!("SSH {context}: {error}"))
}

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------
