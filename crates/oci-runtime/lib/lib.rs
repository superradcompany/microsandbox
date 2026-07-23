//! Standalone OCI runtime binary integration for Microsandbox.
#![cfg(target_os = "linux")]

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use chrono::Utc;
use microsandbox::sandbox::exec::{ExecControl, ExecEvent, ExecHandle};
use microsandbox::sandbox::{ExecOptionsBuilder, Sandbox, SandboxStatus};
use microsandbox_protocol::exec::ExecSignal;
use microsandbox_protocol::message::MessageType;
use microsandbox_runtime::oci::{
    OciBundle, OciOperation, OciProcess, OciState, OciStateStore, next_status,
    sandbox_name_for_container, validate_process,
};
use nix::sys::termios::{self, OutputFlags, SetArg};
use tokio::io::unix::AsyncFd;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const DEFAULT_EXEC_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const CONSOLE_RESIZE_POLL_INTERVAL: Duration = Duration::from_millis(250);
const MONITOR_SIGNAL_POLL_INTERVAL: Duration = Duration::from_millis(10);
const MONITOR_SIGNAL_REQUEST: &str = "signal.request";
const MONITOR_SIGNAL_TIMEOUT: Duration = Duration::from_secs(5);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Host-side OCI runtime implementation backed by Microsandbox.
#[derive(Debug, Clone)]
pub struct MicrosandboxOciRuntime {
    store: OciStateStore,
}

/// Options for `create`.
#[derive(Debug, Clone)]
pub struct CreateOptions {
    /// OCI container ID.
    pub id: String,

    /// OCI bundle directory.
    pub bundle: PathBuf,
}

/// Options for `exec`.
#[derive(Debug, Clone)]
pub struct ExecOptions {
    /// OCI container ID.
    pub id: String,

    /// OCI process descriptor path.
    pub process: PathBuf,

    /// Optional pid-file path requested by Docker/containerd.
    pub pid_file: Option<PathBuf>,
}

/// Options for `kill`.
#[derive(Debug, Clone)]
pub struct KillOptions {
    /// OCI container ID.
    pub id: String,

    /// Signal number or name.
    pub signal: String,

    /// Whether to signal all processes.
    pub all: bool,
}

/// Options for `delete`.
#[derive(Debug, Clone)]
pub struct DeleteOptions {
    /// OCI container ID.
    pub id: String,

    /// Force removal even if OCI state is not stopped.
    pub force: bool,
}

#[derive(Debug, Clone, Copy)]
struct StartedProcess {
    session_id: u32,
    guest_pid: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PtySize {
    rows: u16,
    cols: u16,
}

struct ConsoleBridge {
    fd: AsyncFd<OwnedFd>,
}

struct HostSignalForwarder {
    terminate: tokio::signal::unix::Signal,
    interrupt: tokio::signal::unix::Signal,
    hangup: tokio::signal::unix::Signal,
    quit: tokio::signal::unix::Signal,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl MicrosandboxOciRuntime {
    /// Create an OCI runtime wrapper using the supplied `--root` directory.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            store: OciStateStore::new(root),
        }
    }

    /// Create the Microsandbox-backed OCI container environment.
    pub async fn create(&self, options: CreateOptions) -> Result<()> {
        let bundle = OciBundle::load(&options.bundle)?;
        let mut state = self.store.create_created(&options.id, &bundle)?;

        let sandbox = create_sandbox_for_bundle(&options.id, &bundle).await?;
        let host_pid = resolve_created_sandbox_host_pid(&options.id, &sandbox).await;
        if let Some(pid) = host_pid {
            state.pid = Some(pid);
        }
        self.store.save(&state)?;

        sandbox.detach().await;
        Ok(())
    }

    /// Record the host process PID Docker/containerd should track for the OCI container.
    pub fn record_host_pid(&self, id: &str, pid: i32) -> Result<()> {
        let mut state = self.store.load(id)?;
        state.pid = Some(pid);
        self.store.save(&state)?;
        Ok(())
    }

    /// Return whether the OCI bundle asks for a fresh network namespace.
    pub fn requires_fresh_network_namespace(&self, id: &str) -> Result<bool> {
        let state = self.store.load(id)?;
        let bundle = OciBundle::load(&state.bundle)?;
        Ok(requires_fresh_network_namespace(&bundle))
    }

    /// Start the configured OCI init process.
    pub async fn start(&self, id: &str) -> Result<()> {
        let mut state = self.store.load(id)?;
        OciOperation::Start.validate(&state)?;

        let bundle = OciBundle::load(&state.bundle)?;
        let process = bundle
            .process()
            .ok_or_else(|| anyhow!("container `{id}` has no OCI process to start"))?;
        let sandbox = connect_sandbox(id).await?;
        let host_pid = state
            .pid
            .or(sandbox_host_pid_from_handle(id).await)
            .ok_or_else(|| anyhow!("container `{id}` has no Microsandbox host PID"))?;
        let (started, _handle) =
            start_process_stream(&sandbox, process, &bundle.rootfs_path()).await?;

        state.mark_running(
            host_pid,
            started.guest_pid,
            Some(started.session_id),
            Utc::now(),
        );
        self.store.save(&state)?;
        sandbox.detach().await;
        Ok(())
    }

    /// Run the OCI init process and keep monitoring it until exit.
    pub async fn monitor_init(&self, id: &str, console_slave: Option<PathBuf>) -> Result<i32> {
        let mut state = self.store.load(id)?;
        OciOperation::Start.validate(&state)?;
        let mut host_signals = HostSignalForwarder::new()?;
        let signal_request_path = self.store.container_dir(id)?.join(MONITOR_SIGNAL_REQUEST);

        let bundle = OciBundle::load(&state.bundle)?;
        let process = bundle
            .process()
            .ok_or_else(|| anyhow!("container `{id}` has no OCI process to monitor"))?;
        let sandbox = connect_sandbox(id).await?;
        let host_pid = state
            .pid
            .or(sandbox_host_pid_from_handle(id).await)
            .ok_or_else(|| anyhow!("container `{id}` has no Microsandbox host PID"))?;
        let (started, mut handle) =
            start_process_stream(&sandbox, process, &bundle.rootfs_path()).await?;

        state.mark_running(
            host_pid,
            started.guest_pid,
            Some(started.session_id),
            Utc::now(),
        );
        self.store.save(&state)?;

        let console = match console_slave {
            Some(path) => Some(open_console_bridge(&path)?),
            None => None,
        };
        let exit_code = monitor_process_exit(
            id,
            &mut handle,
            console.as_ref(),
            &mut host_signals,
            Some(&signal_request_path),
        )
        .await?;
        let mut state = self.store.load(id)?;
        state.mark_stopped(Some(exit_code), Utc::now());
        self.store.save(&state)?;
        stop_sandbox_after_init_exit(id).await?;
        sandbox.detach().await;
        Ok(exit_code)
    }

    /// Run an additional OCI process in a running container.
    pub async fn exec(&self, options: ExecOptions) -> Result<i32> {
        let state = self.store.load(&options.id)?;
        OciOperation::Exec.validate(&state)?;
        let mut host_signals = HostSignalForwarder::new()?;

        let process = load_process(&options.process)?;
        let bundle = OciBundle::load(&state.bundle)?;
        let sandbox = connect_sandbox(&options.id).await?;
        let (started, mut handle) =
            start_process_stream(&sandbox, &process, &bundle.rootfs_path()).await?;
        write_exec_pid_file(options.pid_file.as_deref(), &started)?;

        let exit_code =
            monitor_process_exit(&options.id, &mut handle, None, &mut host_signals, None).await?;
        sandbox.detach().await;
        Ok(exit_code)
    }

    /// Run an additional OCI process attached to an OCI console socket bridge.
    pub async fn exec_console(&self, options: ExecOptions, console_slave: PathBuf) -> Result<i32> {
        let state = self.store.load(&options.id)?;
        OciOperation::Exec.validate(&state)?;
        let mut host_signals = HostSignalForwarder::new()?;

        let process = load_process(&options.process)?;
        let bundle = OciBundle::load(&state.bundle)?;
        let sandbox = connect_sandbox(&options.id).await?;
        let (started, mut handle) =
            start_process_stream(&sandbox, &process, &bundle.rootfs_path()).await?;
        write_exec_pid_file(options.pid_file.as_deref(), &started)?;

        let console = open_console_bridge(&console_slave)?;
        let exit_code = monitor_process_exit(
            &options.id,
            &mut handle,
            Some(&console),
            &mut host_signals,
            None,
        )
        .await?;
        sandbox.detach().await;
        Ok(exit_code)
    }

    /// Send a signal to the OCI init process inside the guest.
    pub async fn kill(&self, options: KillOptions) -> Result<()> {
        let state = self.store.load(&options.id)?;
        OciOperation::Kill.validate(&state)?;

        if options.all {
            bail!("kill --all is not implemented by the Microsandbox OCI runtime yet");
        }

        let signal = parse_signal(&options.signal)?;
        self.request_monitor_signal(&options.id, signal).await?;
        Ok(())
    }

    /// Delete OCI and Microsandbox state.
    pub async fn delete(&self, options: DeleteOptions) -> Result<()> {
        let mut state = self.store.load(&options.id)?;
        if options.force && !state.status.is_terminal() {
            signal_init_process_if_known(&options.id, &state, libc::SIGKILL).await?;
            stop_sandbox_for_delete(&options.id).await?;
            state.mark_stopped(None, Utc::now());
            self.store.save(&state)?;
        } else {
            OciOperation::Delete.validate(&state)?;
        }

        if let Ok(handle) = Sandbox::get(&sandbox_name_for_container(&options.id)).await {
            let refreshed = handle.refresh().await.unwrap_or(handle);
            if !matches!(
                refreshed.status_snapshot(),
                SandboxStatus::Stopped | SandboxStatus::Crashed
            ) {
                bail!(
                    "cannot delete running Microsandbox sandbox `{}`",
                    refreshed.name()
                );
            }
            refreshed.remove().await?;
        }

        self.store.delete(&options.id)?;
        Ok(())
    }

    /// Return OCI state, refreshing terminal status from Microsandbox when possible.
    pub async fn state(&self, id: &str) -> Result<OciState> {
        let mut state = self.store.load(id)?;
        if let Ok(handle) = Sandbox::get(&sandbox_name_for_container(id)).await {
            if let Some(local) = handle.local()
                && state.pid.is_none()
            {
                state.pid = local.pid;
            }
            if matches!(
                handle.status_snapshot(),
                SandboxStatus::Stopped | SandboxStatus::Crashed
            ) && !state.status.is_terminal()
            {
                state.mark_stopped(None, Utc::now());
                self.store.save(&state)?;
            }
        }
        Ok(state)
    }

    /// Pause the OCI container if Microsandbox has a matching backend state.
    pub async fn pause(&self, id: &str) -> Result<()> {
        let state = self.store.load(id)?;
        let _ = next_status(OciOperation::Pause, &state)?;
        bail!("pause is not implemented by the Microsandbox OCI runtime yet")
    }

    /// Resume the OCI container if Microsandbox has a matching backend state.
    pub async fn resume(&self, id: &str) -> Result<()> {
        let state = self.store.load(id)?;
        let _ = next_status(OciOperation::Resume, &state)?;
        bail!("resume is not implemented by the Microsandbox OCI runtime yet")
    }

    async fn request_monitor_signal(&self, id: &str, signal: i32) -> Result<()> {
        let path = self.store.container_dir(id)?.join(MONITOR_SIGNAL_REQUEST);
        write_monitor_signal_request(&path, signal)?;

        let deadline = tokio::time::Instant::now() + MONITOR_SIGNAL_TIMEOUT;
        while path.exists() {
            if tokio::time::Instant::now() >= deadline {
                bail!("timed out waiting for OCI monitor to deliver signal {signal} for `{id}`");
            }
            tokio::time::sleep(MONITOR_SIGNAL_POLL_INTERVAL).await;
        }
        Ok(())
    }
}

impl HostSignalForwarder {
    fn new() -> Result<Self> {
        Ok(Self {
            terminate: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .context("install OCI monitor SIGTERM handler")?,
            interrupt: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                .context("install OCI monitor SIGINT handler")?,
            hangup: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
                .context("install OCI monitor SIGHUP handler")?,
            quit: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::quit())
                .context("install OCI monitor SIGQUIT handler")?,
        })
    }

    async fn recv(&mut self) -> i32 {
        tokio::select! {
            _ = self.terminate.recv() => libc::SIGTERM,
            _ = self.interrupt.recv() => libc::SIGINT,
            _ = self.hangup.recv() => libc::SIGHUP,
            _ = self.quit.recv() => libc::SIGQUIT,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn create_sandbox_for_bundle(id: &str, bundle: &OciBundle) -> Result<Sandbox> {
    let process = bundle.process();
    let mut builder = Sandbox::builder(sandbox_name_for_container(id))
        .image(bundle.rootfs_path())
        .detached(true)
        .label("oci.container.id", id)
        .label("oci.bundle", bundle.path.display().to_string());

    if let Some(process) = process {
        builder = builder.workdir(process.cwd().display().to_string());
        let user = process.user();
        if user.uid() != 0 || user.gid() != 0 {
            builder = builder.user(format!("{}:{}", user.uid(), user.gid()));
        }
        for (key, value) in env_pairs(process.env().as_deref().unwrap_or_default())? {
            builder = builder.env(key, value);
        }
    }

    for mount in bundle.mounts() {
        if is_runtime_managed_mount(mount.destination()) {
            continue;
        }

        match mount.typ().as_deref() {
            Some("bind") => {
                let Some(source) = mount.source().as_ref() else {
                    continue;
                };
                let destination = mount.destination().display().to_string();
                let source = absolutize_mount_source(&bundle.path, source);
                let readonly = mount
                    .options()
                    .as_deref()
                    .unwrap_or_default()
                    .iter()
                    .any(|opt| opt == "ro");
                builder = builder.volume(destination, |mount| {
                    let mount = mount.bind(source);
                    if readonly { mount.readonly() } else { mount }
                });
            }
            Some("tmpfs") => {
                let destination = mount.destination().display().to_string();
                builder = builder.volume(destination, |mount| mount.tmpfs());
            }
            _ => {}
        }
    }

    builder.create_detached().await.map_err(Into::into)
}

fn is_runtime_managed_mount(destination: &Path) -> bool {
    matches!(
        normalize_guest_path(destination).as_str(),
        "/dev" | "/dev/pts" | "/dev/ptmx" | "/dev/console" | "/proc" | "/sys" | "/sys/fs/cgroup"
    )
}

fn normalize_guest_path(path: &Path) -> String {
    let mut normalized = path.display().to_string();
    if normalized.is_empty() {
        return "/".to_string();
    }
    if !normalized.starts_with('/') {
        normalized.insert(0, '/');
    }
    while normalized.len() > 1 && normalized.ends_with('/') {
        normalized.pop();
    }
    normalized
}

async fn connect_sandbox(id: &str) -> Result<Sandbox> {
    let handle = Sandbox::get(&sandbox_name_for_container(id)).await?;
    match handle.status_snapshot() {
        SandboxStatus::Running | SandboxStatus::Draining => {
            handle.connect().await.map_err(Into::into)
        }
        SandboxStatus::Stopped | SandboxStatus::Crashed => {
            handle.start_detached().await.map_err(Into::into)
        }
        status => bail!("cannot connect to sandbox for container `{id}` while it is {status:?}"),
    }
}

async fn start_process_stream(
    sandbox: &Sandbox,
    process: &OciProcess,
    rootfs: &Path,
) -> Result<(StartedProcess, ExecHandle)> {
    let command = resolve_process_command(process, rootfs)?;
    let mut handle = sandbox
        .exec_stream_with(command, |exec| configure_exec(exec, process))
        .await?;
    let session_id = handle
        .id()
        .parse::<u32>()
        .context("parse Microsandbox exec session ID")?;

    while let Some(event) = handle.recv().await {
        match event {
            ExecEvent::Started { pid } => {
                if let Some(size) = process_console_size(process) {
                    handle
                        .resize(size.rows, size.cols)
                        .await
                        .context("resize OCI init PTY from process.consoleSize")?;
                }
                return Ok((
                    StartedProcess {
                        session_id,
                        guest_pid: Some(pid),
                    },
                    handle,
                ));
            }
            ExecEvent::Failed(payload) => {
                return Err(microsandbox::MicrosandboxError::ExecFailed(payload).into());
            }
            ExecEvent::Exited { code } => {
                bail!("OCI init process exited before start completed with code {code}")
            }
            ExecEvent::Stdout(_) | ExecEvent::Stderr(_) | ExecEvent::StdinError(_) => {}
        }
    }

    bail!("OCI init process stream ended before start completed")
}

async fn monitor_process_exit(
    id: &str,
    handle: &mut ExecHandle,
    console: Option<&ConsoleBridge>,
    host_signals: &mut HostSignalForwarder,
    signal_request_path: Option<&Path>,
) -> Result<i32> {
    if let Some(console) = console {
        return monitor_console_process_exit(
            id,
            handle,
            console,
            host_signals,
            signal_request_path,
        )
        .await;
    }

    let control = handle.control();
    let mut signal_poll = tokio::time::interval(MONITOR_SIGNAL_POLL_INTERVAL);
    loop {
        tokio::select! {
            signal = host_signals.recv() => {
                forward_host_signal(&control, signal).await?;
            }
            _ = signal_poll.tick(), if signal_request_path.is_some() => {
                deliver_monitor_signal_request(&control, signal_request_path.expect("guarded signal request path")).await?;
            }
            event = handle.recv() => {
                match event {
                    Some(ExecEvent::Exited { code }) => return Ok(code),
                    Some(ExecEvent::Failed(payload)) => {
                        return Err(microsandbox::MicrosandboxError::ExecFailed(payload).into());
                    }
                    Some(ExecEvent::Stdout(data)) => {
                        let mut stdout = std::io::stdout().lock();
                        stdout.write_all(&data).context("write OCI init stdout")?;
                        stdout.flush().context("flush OCI init stdout")?;
                    }
                    Some(ExecEvent::Stderr(data)) => {
                        let mut stderr = std::io::stderr().lock();
                        stderr.write_all(&data).context("write OCI init stderr")?;
                        stderr.flush().context("flush OCI init stderr")?;
                    }
                    Some(ExecEvent::Started { .. }) | Some(ExecEvent::StdinError(_)) => {}
                    None => bail!("OCI init process stream ended before exit event for `{id}`"),
                }
            }
        }
    }
}

async fn monitor_console_process_exit(
    id: &str,
    handle: &mut ExecHandle,
    console: &ConsoleBridge,
    host_signals: &mut HostSignalForwarder,
    signal_request_path: Option<&Path>,
) -> Result<i32> {
    let stdin = handle
        .take_stdin()
        .ok_or_else(|| anyhow!("container `{id}` requested an OCI console without piped stdin"))?;
    let control = handle.control();
    let mut last_size = None;
    sync_console_size(&control, console, &mut last_size).await?;
    let mut resize_poll = tokio::time::interval(CONSOLE_RESIZE_POLL_INTERVAL);
    let mut signal_poll = tokio::time::interval(MONITOR_SIGNAL_POLL_INTERVAL);
    let mut input = [0u8; 4096];

    loop {
        tokio::select! {
            signal = host_signals.recv() => {
                forward_host_signal(&control, signal).await?;
            }
            _ = signal_poll.tick(), if signal_request_path.is_some() => {
                deliver_monitor_signal_request(&control, signal_request_path.expect("guarded signal request path")).await?;
            }
            _ = resize_poll.tick() => {
                sync_console_size(&control, console, &mut last_size).await?;
            }
            read = read_console_input(console, &mut input) => {
                match read.context("read OCI console input")? {
                    0 => {
                        let _ = stdin.close().await;
                    }
                    n => {
                        stdin.write(&input[..n]).await.context("write OCI console input to guest")?;
                    }
                }
            }
            event = handle.recv() => {
                match event {
                    Some(ExecEvent::Exited { code }) => return Ok(code),
                    Some(ExecEvent::Failed(payload)) => {
                        return Err(microsandbox::MicrosandboxError::ExecFailed(payload).into());
                    }
                    Some(ExecEvent::Stdout(data)) | Some(ExecEvent::Stderr(data)) => {
                        write_console_output(console, &data).await.context("write OCI console output")?;
                    }
                    Some(ExecEvent::Started { .. }) | Some(ExecEvent::StdinError(_)) => {}
                    None => bail!("OCI init process stream ended before exit event for `{id}`"),
                }
            }
        }
    }
}

async fn forward_host_signal(control: &ExecControl, signal: i32) -> Result<()> {
    control
        .signal(signal)
        .await
        .with_context(|| format!("forward host signal {signal} to OCI process"))
}

async fn deliver_monitor_signal_request(control: &ExecControl, path: &Path) -> Result<()> {
    let Some(signal) = read_monitor_signal_request(path)? else {
        return Ok(());
    };
    forward_host_signal(control, signal).await?;
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| {
            format!(
                "acknowledge OCI monitor signal request `{}`",
                path.display()
            )
        }),
    }
}

fn write_monitor_signal_request(path: &Path, signal: i32) -> Result<()> {
    let tmp_path = path.with_extension("request.tmp");
    fs::write(&tmp_path, signal.to_string())
        .with_context(|| format!("write OCI monitor signal request `{}`", tmp_path.display()))?;
    fs::rename(&tmp_path, path)
        .with_context(|| format!("publish OCI monitor signal request `{}`", path.display()))
}

fn read_monitor_signal_request(path: &Path) -> Result<Option<i32>> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("read OCI monitor signal request `{}`", path.display()));
        }
    };
    let signal = contents
        .trim()
        .parse::<i32>()
        .with_context(|| format!("parse OCI monitor signal request `{}`", path.display()))?;
    Ok(Some(signal))
}

async fn sync_console_size(
    control: &ExecControl,
    console: &ConsoleBridge,
    last_size: &mut Option<PtySize>,
) -> Result<()> {
    let Some(size) = console_size_from_fd(console.fd.get_ref().as_raw_fd()) else {
        return Ok(());
    };
    if Some(size) == *last_size {
        return Ok(());
    }

    control
        .resize(size.rows, size.cols)
        .await
        .context("resize OCI console PTY in guest")?;
    *last_size = Some(size);
    Ok(())
}

fn open_console_bridge(path: &Path) -> Result<ConsoleBridge> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .with_context(|| format!("open OCI console slave `{}`", path.display()))?;
    let fd: OwnedFd = file.into();
    configure_console_slave(&fd).context("configure OCI console slave mode")?;
    set_nonblocking(fd.as_raw_fd()).context("set OCI console slave nonblocking")?;
    let fd = AsyncFd::new(fd).context("register OCI console slave with tokio")?;
    Ok(ConsoleBridge { fd })
}

fn configure_console_slave(fd: &OwnedFd) -> Result<()> {
    let mut attrs = termios::tcgetattr(fd).context("read OCI console termios")?;
    termios::cfmakeraw(&mut attrs);
    attrs
        .output_flags
        .insert(OutputFlags::OPOST | OutputFlags::ONLCR);
    termios::tcsetattr(fd, SetArg::TCSANOW, &attrs).context("set OCI console termios")?;
    Ok(())
}

fn process_console_size(process: &OciProcess) -> Option<PtySize> {
    let size = process.console_size()?;
    pty_size_from_rows_cols(size.height(), size.width())
}

fn console_size_from_fd(fd: i32) -> Option<PtySize> {
    let mut size = std::mem::MaybeUninit::<libc::winsize>::zeroed();
    if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, size.as_mut_ptr()) } < 0 {
        return None;
    }
    let size = unsafe { size.assume_init() };
    pty_size_from_rows_cols(u64::from(size.ws_row), u64::from(size.ws_col))
}

fn pty_size_from_rows_cols(rows: u64, cols: u64) -> Option<PtySize> {
    if rows == 0 || cols == 0 {
        return None;
    }
    Some(PtySize {
        rows: rows.min(u64::from(u16::MAX)) as u16,
        cols: cols.min(u64::from(u16::MAX)) as u16,
    })
}

async fn read_console_input(console: &ConsoleBridge, buf: &mut [u8]) -> std::io::Result<usize> {
    loop {
        let mut guard = console.fd.readable().await?;
        match guard.try_io(|inner| read_fd(inner.get_ref().as_raw_fd(), buf)) {
            Ok(result) => return result,
            Err(_) => continue,
        }
    }
}

async fn write_console_output(console: &ConsoleBridge, mut data: &[u8]) -> std::io::Result<()> {
    while !data.is_empty() {
        let mut guard = console.fd.writable().await?;
        match guard.try_io(|inner| write_fd(inner.get_ref().as_raw_fd(), data)) {
            Ok(Ok(0)) => {
                return Err(std::io::Error::new(
                    ErrorKind::WriteZero,
                    "console write returned zero",
                ));
            }
            Ok(Ok(n)) => data = &data[n..],
            Ok(Err(error)) if error.kind() == ErrorKind::Interrupted => continue,
            Ok(Err(error)) => return Err(error),
            Err(_) => continue,
        }
    }
    Ok(())
}

fn read_fd(fd: i32, buf: &mut [u8]) -> std::io::Result<usize> {
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n >= 0 {
            return Ok(n as usize);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == ErrorKind::Interrupted {
            continue;
        }
        return Err(error);
    }
}

fn write_fd(fd: i32, buf: &[u8]) -> std::io::Result<usize> {
    loop {
        let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        if n >= 0 {
            return Ok(n as usize);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == ErrorKind::Interrupted {
            continue;
        }
        return Err(error);
    }
}

fn set_nonblocking(fd: i32) -> std::io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

async fn signal_init_process(id: &str, state: &OciState, signal: i32) -> Result<()> {
    let session_id = state
        .microsandbox
        .as_ref()
        .and_then(|msb| msb.init_exec_session_id)
        .ok_or_else(|| anyhow!("container `{id}` has no OCI init exec session to signal"))?;
    let sandbox = connect_sandbox(id).await?;
    let payload = ExecSignal { signal };

    sandbox
        .client_arc()
        .send(session_id, MessageType::ExecSignal, &payload)
        .await
        .with_context(|| {
            format!("send signal {signal} to OCI init exec session {session_id} for `{id}`")
        })?;
    sandbox.detach().await;
    Ok(())
}

async fn signal_init_process_if_known(id: &str, state: &OciState, signal: i32) -> Result<()> {
    if state
        .microsandbox
        .as_ref()
        .and_then(|msb| msb.init_exec_session_id)
        .is_none()
    {
        return Ok(());
    }

    if let Err(error) = signal_init_process(id, state, signal).await {
        tracing::warn!(
            container_id = id,
            signal,
            error = %error,
            "failed to signal OCI init process during force delete; continuing with sandbox cleanup"
        );
    }
    Ok(())
}

async fn stop_sandbox_for_delete(id: &str) -> Result<()> {
    let name = sandbox_name_for_container(id);
    let Ok(handle) = Sandbox::get(&name).await else {
        return Ok(());
    };
    let refreshed = handle.refresh().await.unwrap_or(handle);
    if matches!(
        refreshed.status_snapshot(),
        SandboxStatus::Stopped | SandboxStatus::Crashed
    ) {
        return Ok(());
    }

    refreshed
        .stop()
        .await
        .with_context(|| format!("stop Microsandbox sandbox `{name}` during force delete"))
}

async fn stop_sandbox_after_init_exit(id: &str) -> Result<()> {
    let name = sandbox_name_for_container(id);
    let Ok(handle) = Sandbox::get(&name).await else {
        return Ok(());
    };
    let refreshed = handle.refresh().await.unwrap_or(handle);
    if matches!(
        refreshed.status_snapshot(),
        SandboxStatus::Stopped | SandboxStatus::Crashed
    ) {
        return Ok(());
    }

    refreshed
        .request_kill()
        .await
        .with_context(|| format!("request Microsandbox sandbox `{name}` stop after OCI init exit"))
}

fn resolve_process_command(process: &OciProcess, rootfs: &Path) -> Result<String> {
    let args = process_args(process)?;
    let command = &args[0];
    if command.contains('/') {
        return Ok(command.clone());
    }

    for entry in process_path_entries(process) {
        let guest_path = if entry.is_empty() || entry == "." {
            PathBuf::from(command)
        } else {
            Path::new(&entry).join(command)
        };
        let host_path = if guest_path.is_absolute() {
            rootfs.join(guest_path.strip_prefix("/").unwrap_or(&guest_path))
        } else {
            rootfs.join(&guest_path)
        };
        if host_path.is_file() {
            return Ok(guest_path_for_exec(&guest_path));
        }
    }

    Ok(command.clone())
}

fn process_path_entries(process: &OciProcess) -> Vec<String> {
    process
        .env()
        .as_deref()
        .unwrap_or_default()
        .iter()
        .find_map(|entry| entry.strip_prefix("PATH="))
        .unwrap_or(DEFAULT_EXEC_PATH)
        .split(':')
        .map(str::to_string)
        .collect()
}

fn guest_path_for_exec(path: &Path) -> String {
    if path.is_absolute() {
        path.display().to_string()
    } else {
        format!("/{}", path.display())
    }
}

fn configure_exec(mut exec: ExecOptionsBuilder, process: &OciProcess) -> ExecOptionsBuilder {
    let args = process.args().as_deref().unwrap_or_default();
    let terminal = process.terminal().unwrap_or(false);
    exec = exec
        .args(args.iter().skip(1).cloned())
        .cwd(process.cwd().display().to_string())
        .tty(terminal);
    if terminal {
        exec = exec.stdin_pipe();
    }
    let user = process.user();
    if user.uid() != 0 || user.gid() != 0 {
        exec = exec.user(format!("{}:{}", user.uid(), user.gid()));
    }
    for (key, value) in env_pairs_lossy(process.env().as_deref().unwrap_or_default()) {
        exec = exec.env(key, value);
    }
    exec
}

async fn sandbox_host_pid(sandbox: &Sandbox) -> Option<i32> {
    let local = sandbox.local()?;
    let handle = local.handle.as_ref()?;
    Some(handle.lock().await.pid() as i32)
}

async fn resolve_created_sandbox_host_pid(id: &str, sandbox: &Sandbox) -> Option<i32> {
    const PID_WAIT_ATTEMPTS: usize = 50;
    const PID_WAIT_INTERVAL: Duration = Duration::from_millis(20);

    if let Some(pid) = sandbox_host_pid(sandbox).await {
        return Some(pid);
    }

    for _ in 0..PID_WAIT_ATTEMPTS {
        if let Some(pid) = sandbox_host_pid_from_handle(id).await {
            return Some(pid);
        }
        tokio::time::sleep(PID_WAIT_INTERVAL).await;
    }

    None
}

async fn sandbox_host_pid_from_handle(id: &str) -> Option<i32> {
    let handle = Sandbox::get(&sandbox_name_for_container(id)).await.ok()?;
    handle.local().and_then(|local| local.pid)
}

fn load_process(path: &Path) -> Result<OciProcess> {
    let data = std::fs::read_to_string(path)
        .with_context(|| format!("read OCI process JSON `{}`", path.display()))?;
    let process: OciProcess = serde_json::from_str(&data)
        .with_context(|| format!("parse OCI process JSON `{}`", path.display()))?;
    validate_process(&process, path.parent().unwrap_or_else(|| Path::new(".")))
        .map_err(Into::into)
        .map(|()| process)
}

fn process_args(process: &OciProcess) -> Result<&[String]> {
    let args = process.args().as_deref().unwrap_or_default();
    if args.is_empty() {
        bail!("OCI process args must contain at least one entry");
    }
    Ok(args)
}

fn write_pid_file(path: &Path, pid: i32) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create pid-file directory `{}`", parent.display()))?;
    }
    std::fs::write(path, pid.to_string())
        .with_context(|| format!("write pid-file `{}`", path.display()))
}

fn write_exec_pid_file(path: Option<&Path>, started: &StartedProcess) -> Result<()> {
    let Some(path) = path else {
        return Ok(());
    };
    let pid = started
        .guest_pid
        .ok_or_else(|| anyhow!("exec process started without a guest PID for pid-file"))?;
    let pid = i32::try_from(pid).context("exec guest PID does not fit pid-file format")?;
    write_pid_file(path, pid)
}

fn env_pairs(env: &[String]) -> Result<Vec<(String, String)>> {
    env.iter()
        .map(|entry| {
            entry
                .split_once('=')
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .ok_or_else(|| anyhow!("OCI environment entry must be KEY=VALUE: `{entry}`"))
        })
        .collect()
}

fn env_pairs_lossy(env: &[String]) -> Vec<(String, String)> {
    env.iter()
        .filter_map(|entry| {
            entry
                .split_once('=')
                .map(|(key, value)| (key.to_string(), value.to_string()))
        })
        .collect()
}

fn absolutize_mount_source(bundle: &Path, source: &Path) -> PathBuf {
    if source.is_absolute() {
        source.to_path_buf()
    } else {
        bundle.join(source)
    }
}

fn requires_fresh_network_namespace(bundle: &OciBundle) -> bool {
    bundle
        .spec
        .linux()
        .as_ref()
        .and_then(|linux| linux.namespaces().as_ref())
        .is_some_and(|namespaces| {
            namespaces.iter().any(|namespace| {
                namespace.typ() == oci_spec::runtime::LinuxNamespaceType::Network
                    && namespace.path().is_none()
            })
        })
}

fn parse_signal(signal: &str) -> Result<i32> {
    if let Ok(number) = signal.parse::<i32>() {
        return Ok(number);
    }

    let normalized = signal
        .trim_start_matches('-')
        .trim_start_matches("SIG")
        .to_ascii_uppercase();
    match normalized.as_str() {
        "KILL" => Ok(libc::SIGKILL),
        "TERM" => Ok(libc::SIGTERM),
        "INT" => Ok(libc::SIGINT),
        "HUP" => Ok(libc::SIGHUP),
        "QUIT" => Ok(libc::SIGQUIT),
        _ => bail!("unsupported signal `{signal}`"),
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn parses_signal_names_and_numbers() {
        assert_eq!(parse_signal("0").expect("zero"), 0);
        assert_eq!(parse_signal("9").expect("number"), libc::SIGKILL);
        assert_eq!(parse_signal("SIGTERM").expect("sigterm"), libc::SIGTERM);
        assert_eq!(parse_signal("TERM").expect("term"), libc::SIGTERM);
        assert!(parse_signal("SIGBOGUS").is_err());
    }

    #[test]
    fn monitor_signal_request_round_trips() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join(MONITOR_SIGNAL_REQUEST);

        write_monitor_signal_request(&path, libc::SIGTERM).expect("write signal request");

        assert_eq!(
            read_monitor_signal_request(&path).expect("read signal request"),
            Some(libc::SIGTERM)
        );
    }

    #[test]
    fn rejects_invalid_env_entries() {
        assert!(env_pairs(&["PATH=/bin".to_string()]).is_ok());
        assert!(env_pairs(&["PATH".to_string()]).is_err());
    }

    #[test]
    fn resolves_relative_mount_source_against_bundle() {
        assert_eq!(
            absolutize_mount_source(Path::new("/bundle"), Path::new("data")),
            PathBuf::from("/bundle/data")
        );
        assert_eq!(
            absolutize_mount_source(Path::new("/bundle"), Path::new("/host/data")),
            PathBuf::from("/host/data")
        );
    }

    #[test]
    fn write_pid_file_creates_parent_directory() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("nested").join("init.pid");

        write_pid_file(&path, 1234).expect("write pid file");

        let content = std::fs::read_to_string(path).expect("read pid file");
        assert_eq!(content, "1234");
    }

    #[test]
    fn write_exec_pid_file_uses_guest_pid() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("exec.pid");
        let started = StartedProcess {
            session_id: 7,
            guest_pid: Some(4321),
        };

        write_exec_pid_file(Some(&path), &started).expect("write exec pid file");

        let content = std::fs::read_to_string(path).expect("read exec pid file");
        assert_eq!(content, "4321");
    }

    #[test]
    fn write_exec_pid_file_rejects_missing_guest_pid() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("exec.pid");
        let started = StartedProcess {
            session_id: 7,
            guest_pid: None,
        };

        let error = write_exec_pid_file(Some(&path), &started).expect_err("missing guest pid");

        assert!(error.to_string().contains("without a guest PID"));
    }

    #[test]
    fn configure_console_slave_sets_raw_no_echo_mode() {
        use nix::fcntl::OFlag;
        use nix::pty::{grantpt, posix_openpt, ptsname_r, unlockpt};
        use nix::sys::termios::{LocalFlags, OutputFlags};

        let master = posix_openpt(OFlag::O_RDWR | OFlag::O_NOCTTY).expect("open pty master");
        grantpt(&master).expect("grant pty");
        unlockpt(&master).expect("unlock pty");
        let slave_path = ptsname_r(&master).expect("pty slave path");
        let slave = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(slave_path)
            .expect("open pty slave");
        let fd: OwnedFd = slave.into();

        configure_console_slave(&fd).expect("configure console slave");

        let attrs = termios::tcgetattr(&fd).expect("read termios");
        assert!(!attrs.local_flags.contains(LocalFlags::ECHO));
        assert!(!attrs.local_flags.contains(LocalFlags::ICANON));
        assert!(!attrs.local_flags.contains(LocalFlags::ISIG));
        assert!(attrs.output_flags.contains(OutputFlags::OPOST));
        assert!(attrs.output_flags.contains(OutputFlags::ONLCR));
    }

    #[test]
    fn configure_console_slave_translates_newline_for_master() {
        use nix::fcntl::OFlag;
        use nix::pty::{grantpt, posix_openpt, ptsname_r, unlockpt};

        let master = posix_openpt(OFlag::O_RDWR | OFlag::O_NOCTTY).expect("open pty master");
        grantpt(&master).expect("grant pty");
        unlockpt(&master).expect("unlock pty");
        let slave_path = ptsname_r(&master).expect("pty slave path");
        let slave = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(slave_path)
            .expect("open pty slave");
        let fd: OwnedFd = slave.into();

        configure_console_slave(&fd).expect("configure console slave");
        write_fd(fd.as_raw_fd(), b"\n").expect("write newline to slave");

        let mut buf = [0u8; 8];
        let n = read_fd(master.as_raw_fd(), &mut buf).expect("read newline from master");
        assert_eq!(&buf[..n], b"\r\n");
    }

    #[test]
    fn console_size_from_fd_reads_pty_window_size() {
        use nix::fcntl::OFlag;
        use nix::pty::{grantpt, posix_openpt, ptsname_r, unlockpt};

        let master = posix_openpt(OFlag::O_RDWR | OFlag::O_NOCTTY).expect("open pty master");
        grantpt(&master).expect("grant pty");
        unlockpt(&master).expect("unlock pty");
        let slave_path = ptsname_r(&master).expect("pty slave path");
        let slave = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(slave_path)
            .expect("open pty slave");
        let fd: OwnedFd = slave.into();
        let size = libc::winsize {
            ws_row: 42,
            ws_col: 132,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };

        assert_eq!(
            unsafe { libc::ioctl(fd.as_raw_fd(), libc::TIOCSWINSZ, &size) },
            0
        );

        assert_eq!(
            console_size_from_fd(fd.as_raw_fd()),
            Some(PtySize {
                rows: 42,
                cols: 132
            })
        );
    }

    #[test]
    fn pty_size_ignores_zero_and_clamps_large_values() {
        assert_eq!(pty_size_from_rows_cols(0, 80), None);
        assert_eq!(pty_size_from_rows_cols(24, 0), None);
        assert_eq!(
            pty_size_from_rows_cols(u64::MAX, u64::MAX),
            Some(PtySize {
                rows: u16::MAX,
                cols: u16::MAX,
            })
        );
    }

    #[test]
    fn detects_fresh_oci_network_namespace() {
        let temp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(temp.path().join("rootfs")).expect("rootfs");
        std::fs::write(
            temp.path().join("config.json"),
            r#"{
                "ociVersion": "1.2.0",
                "root": { "path": "rootfs" },
                "process": {
                    "user": { "uid": 0, "gid": 0 },
                    "cwd": "/",
                    "args": ["/bin/sh"]
                },
                "linux": {
                    "namespaces": [{ "type": "network" }]
                }
            }"#,
        )
        .expect("config");

        let bundle = OciBundle::load(temp.path()).expect("load bundle");

        assert!(requires_fresh_network_namespace(&bundle));
    }

    #[test]
    fn terminal_process_uses_tty_and_piped_stdin() {
        let temp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(temp.path().join("rootfs")).expect("rootfs");
        std::fs::write(
            temp.path().join("config.json"),
            r#"{
                "ociVersion": "1.2.0",
                "root": { "path": "rootfs" },
                "process": {
                    "terminal": true,
                    "user": { "uid": 0, "gid": 0 },
                    "cwd": "/",
                    "args": ["/bin/sh"]
                }
            }"#,
        )
        .expect("config");
        let bundle = OciBundle::load(temp.path()).expect("load bundle");
        let process = bundle.process().expect("process");

        let options = configure_exec(ExecOptionsBuilder::default(), process)
            .build()
            .expect("exec options");

        assert!(options.tty);
        assert!(matches!(
            options.stdin,
            microsandbox::sandbox::exec::StdinMode::Pipe
        ));
    }

    #[test]
    fn reads_process_console_size_from_oci_config() {
        let temp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(temp.path().join("rootfs")).expect("rootfs");
        std::fs::write(
            temp.path().join("config.json"),
            r#"{
                "ociVersion": "1.2.0",
                "root": { "path": "rootfs" },
                "process": {
                    "terminal": true,
                    "consoleSize": { "height": 45, "width": 160 },
                    "user": { "uid": 0, "gid": 0 },
                    "cwd": "/",
                    "args": ["/bin/sh"]
                }
            }"#,
        )
        .expect("config");
        let bundle = OciBundle::load(temp.path()).expect("load bundle");
        let process = bundle.process().expect("process");

        assert_eq!(
            process_console_size(process),
            Some(PtySize {
                rows: 45,
                cols: 160
            })
        );
    }

    #[test]
    fn skips_runtime_managed_oci_mounts() {
        for destination in [
            "/dev",
            "/dev/",
            "/dev/pts",
            "/dev/ptmx",
            "/dev/console",
            "/proc",
            "/sys",
            "/sys/fs/cgroup",
        ] {
            assert!(
                is_runtime_managed_mount(Path::new(destination)),
                "{destination} should be runtime-managed"
            );
        }

        for destination in ["/dev/shm", "/etc/hosts", "/etc/resolv.conf", "/tmp"] {
            assert!(
                !is_runtime_managed_mount(Path::new(destination)),
                "{destination} should be forwarded from the OCI bundle"
            );
        }
    }

    #[test]
    fn resolves_bare_process_command_from_rootfs_path() {
        let temp = tempfile::tempdir().expect("tempdir");
        let bash = temp
            .path()
            .join("rootfs")
            .join("usr")
            .join("bin")
            .join("bash");
        std::fs::create_dir_all(bash.parent().expect("parent")).expect("bin dir");
        std::fs::write(&bash, b"").expect("bash");
        std::fs::write(
            temp.path().join("config.json"),
            r#"{
                "ociVersion": "1.2.0",
                "root": { "path": "rootfs" },
                "process": {
                    "user": { "uid": 0, "gid": 0 },
                    "cwd": "/",
                    "args": ["bash"]
                }
            }"#,
        )
        .expect("config");
        let bundle = OciBundle::load(temp.path()).expect("load bundle");

        let command =
            resolve_process_command(bundle.process().expect("process"), &bundle.rootfs_path())
                .expect("resolve command");

        assert_eq!(command, "/usr/bin/bash");
    }

    #[test]
    fn leaves_explicit_process_command_unchanged() {
        let temp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(temp.path().join("rootfs")).expect("rootfs");
        std::fs::write(
            temp.path().join("config.json"),
            r#"{
                "ociVersion": "1.2.0",
                "root": { "path": "rootfs" },
                "process": {
                    "user": { "uid": 0, "gid": 0 },
                    "cwd": "/",
                    "args": ["/custom/bash"]
                }
            }"#,
        )
        .expect("config");
        let bundle = OciBundle::load(temp.path()).expect("load bundle");

        let command =
            resolve_process_command(bundle.process().expect("process"), &bundle.rootfs_path())
                .expect("resolve command");

        assert_eq!(command, "/custom/bash");
    }
}
