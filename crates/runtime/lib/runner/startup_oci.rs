//! Feature-gated startup workload execution and OCI lifecycle handoff.

use std::io::{ErrorKind, Write};
#[cfg(unix)]
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;

use microsandbox_agent_client::{
    AgentClient, ClientResult, ErrorKind as ClientErrorKind, OutputAcknowledgements, TypedMessage,
};
#[cfg(feature = "net")]
use microsandbox_network::network::NetworkActivationHandle;
use microsandbox_protocol::{
    exec::{
        ExecExited, ExecFailed, ExecLimits, ExecOutputAck, ExecRequest, ExecResize, ExecSignal,
        ExecStderr, ExecStdin, ExecStdinAck, ExecStdout,
    },
    isolation::IsolatedExecRequest,
    message::MessageType,
};
#[cfg(unix)]
use tokio::io::unix::AsyncFd;

use crate::vm::StartupCommand;
use crate::{RuntimeError, RuntimeResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Terminal status for the startup workload exec session.
pub(crate) enum StartupCommandExit {
    /// The command ran and exited with the contained status code.
    Exited(i32),

    /// agentd could not spawn the command.
    Failed(ExecFailed),
}

/// Optional host stdio handles used for OCI startup command forwarding.
pub(crate) struct StartupStdio {
    /// Input owned by this workload rather than the VMM console.
    pub(crate) stdin: Option<std::fs::File>,
    /// Original host stdout captured before runtime log redirection.
    pub(crate) stdout: std::fs::File,

    /// Original host stderr captured before runtime log redirection.
    pub(crate) stderr: std::fs::File,
}

#[cfg(unix)]
pub(crate) type StartupConsole = OwnedFd;

#[cfg(not(unix))]
pub(crate) struct StartupConsole;

#[cfg(unix)]
struct StartupConsoleBridge {
    fd: AsyncFd<OwnedFd>,
}

#[cfg(not(unix))]
struct StartupConsoleBridge;

enum StartupInput {
    #[cfg(unix)]
    Pipe(StartupConsoleBridge),
    File(tokio::fs::File),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PtySize {
    rows: u16,
    cols: u16,
}

/// Input allowance shared by pipe and terminal forwarding for one startup session.
struct StartupInputWindow {
    policy: Option<ExecLimits>,
    sent: u64,
    consumed: u64,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl StartupInputWindow {
    fn capacity(&self, buffer_size: usize) -> usize {
        self.policy.map_or(buffer_size, |policy| {
            let remaining = u64::from(policy.input_limit) - (self.sent - self.consumed);
            buffer_size
                .min(policy.stdin_chunk_size as usize)
                .min(remaining as usize)
        })
    }

    fn sent(&mut self, bytes: usize) -> RuntimeResult<()> {
        self.sent = self
            .sent
            .checked_add(bytes as u64)
            .ok_or_else(|| RuntimeError::Custom("startup stdin counter overflow".into()))?;
        Ok(())
    }

    fn acknowledge(&mut self, consumed: u64) -> RuntimeResult<()> {
        if consumed < self.consumed || consumed > self.sent {
            return Err(RuntimeError::Custom(
                "invalid startup stdin acknowledgement".into(),
            ));
        }
        self.consumed = consumed;
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) async fn run_startup_command(
    agent_sock_path: &Path,
    command: StartupCommand,
    mut stdio: Option<StartupStdio>,
    console: Option<StartupConsole>,
    #[cfg(feature = "net")] network_activation: Option<NetworkActivationHandle>,
) -> RuntimeResult<StartupCommandExit> {
    let error_path = command.session_id_path.as_deref().map(startup_error_path);
    let exit_path = command.session_id_path.as_deref().map(startup_exit_path);
    let result = run_startup_command_inner(
        agent_sock_path,
        command,
        &mut stdio,
        console,
        #[cfg(feature = "net")]
        network_activation,
    )
    .await;

    match &result {
        Err(error) => {
            if let Some(path) = error_path.as_deref() {
                let _ = write_startup_error(path, &error.to_string());
            }
            if let Some(path) = exit_path.as_deref() {
                let _ = write_startup_exit(path, 1);
            }
        }
        Ok(StartupCommandExit::Failed(failed)) => {
            if let Some(path) = error_path.as_deref() {
                let _ = write_startup_error(path, &failed.message);
            }
            if let Some(path) = exit_path.as_deref() {
                let _ = write_startup_exit(path, 127);
            }
        }
        Ok(StartupCommandExit::Exited(code)) => {
            if let Some(path) = exit_path.as_deref() {
                write_startup_exit(path, *code)?;
            }
        }
    }

    result
}

async fn run_startup_command_inner(
    agent_sock_path: &Path,
    command: StartupCommand,
    stdio: &mut Option<StartupStdio>,
    console: Option<StartupConsole>,
    #[cfg(feature = "net")] network_activation: Option<NetworkActivationHandle>,
) -> RuntimeResult<StartupCommandExit> {
    let mut session_id_path = command.session_id_path;
    let signal_path = command.signal_path.clone();
    let uses_console = console.is_some();
    let mut stdin = stdio
        .as_mut()
        .and_then(|stdio| stdio.stdin.take())
        .map(startup_input)
        .transpose()?;
    let mut started = false;
    // Keep the inherited PTY slave open during OCI `create`. containerd owns
    // the master and waits for a live slave before it invokes OCI `start`.
    let mut console = open_startup_console(console)?;
    if let Some(start_signal_path) = command.start_signal_path.as_ref() {
        wait_for_start_signal(start_signal_path).await?;
    }
    #[cfg(feature = "net")]
    if let Some(network_activation) = network_activation {
        #[cfg(target_os = "linux")]
        let connected = super::network_oci::namespace_has_network_interface()?;
        #[cfg(not(target_os = "linux"))]
        let connected = true;
        tracing::info!(connected, "checked OCI network namespace before startup");
        if connected {
            network_activation.activate();
        }
    }
    let mut console_input_closed = console.is_none();
    let tty = command.tty || console.is_some();
    let rows = nonzero_tty_size(command.rows, 24);
    let cols = nonzero_tty_size(command.cols, 80);

    let client = AgentClient::connect(agent_sock_path)
        .await
        .map_err(|err| RuntimeError::Custom(format!("startup command connect: {err}")))?;

    let request = ExecRequest {
        security: command.security,
        cmd: command.cmd,
        args: command.args,
        env: command.env,
        cwd: command.cwd,
        user: command.user,
        tty,
        rows,
        cols,
        rlimits: Vec::new(),
    };

    let isolated = command.isolation.map(|isolation| IsolatedExecRequest {
        process: request.clone(),
        isolation,
    });
    if isolated
        .as_ref()
        .is_some_and(|request| request.isolation.user.is_some())
        && client.ready().agent.workload_user_namespace != Some(true)
    {
        return Err(RuntimeError::Custom(
            "guest agent does not support OCI user namespaces; update agentd".into(),
        ));
    }
    let stream = match &isolated {
        Some(request) => {
            client
                .stream(TypedMessage::new(MessageType::ExecIsolated, request))
                .await
        }
        None => {
            client
                .stream(TypedMessage::new(MessageType::ExecRequest, &request))
                .await
        }
    };
    let stream =
        stream.map_err(|err| RuntimeError::Custom(format!("startup command dispatch: {err}")))?;
    let id = stream.id();
    let policy = client
        .ready()
        .agent
        .exec_limits
        .filter(|_| client.ready().supports(MessageType::ExecOutputAck));
    if let Some(policy) = policy {
        policy
            .validate()
            .map_err(|error| RuntimeError::Custom(error.into()))?;
    }
    let mut input_window = StartupInputWindow {
        policy,
        sent: 0,
        consumed: 0,
    };
    let (sender, mut stream) = stream.into_parts();
    let acknowledgements = OutputAcknowledgements::default();
    let consumed_output = acknowledgements.consumed.clone();
    let mut output_ack = ExecOutputAck::default();
    let worker = tokio::spawn(acknowledgements.run(move |ack| {
        let sender = sender.clone();
        async move {
            sender
                .send(TypedMessage::new(MessageType::ExecOutputAck, &ack))
                .await
        }
    }));
    let mut worker = tokio_util::task::AbortOnDropHandle::new(worker);
    let mut initial_stdin = initial_startup_stdin(uses_console || stdin.is_some());
    let mut resize_poll = tokio::time::interval(std::time::Duration::from_millis(250));
    let mut signal_poll = tokio::time::interval(std::time::Duration::from_millis(20));
    let mut input = [0u8; 4096];
    let mut stdin_buf = [0u8; 4096];

    loop {
        let input_capacity = input_window.capacity(input.len());
        tokio::select! {
            result = &mut worker => {
                return Err(RuntimeError::Custom(format!("startup output acknowledgement: {result:?}")));
            }
            read = read_startup_input(&mut stdin, &mut stdin_buf[..input_capacity]), if started && stdin.is_some() && input_capacity > 0 => {
                let n = read.map_err(|error| RuntimeError::Custom(format!("startup stdin: {error}")))?;
                let result = client.send(id, TypedMessage::new(MessageType::ExecStdin,
                    &ExecStdin { data: stdin_buf[..n].to_vec() })).await;
                check_initial_stdin_delivery(result)?;
                input_window.sent(n)?;
                if n == 0 { stdin = None; }
            }
            _ = signal_poll.tick(), if signal_path.is_some() => {
                if let Some(signal) = take_signal_request(signal_path.as_deref().unwrap())? {
                    let payload = ExecSignal { signal };
                    client
                        .send(
                            id,
                            TypedMessage::new(MessageType::ExecSignal, &payload),
                        )
                        .await
                        .map_err(|err| RuntimeError::Custom(format!(
                            "startup command signal {signal}: {err}"
                        )))?;
                }
            }
            _ = resize_poll.tick(), if console.is_some() => {
                if let Some(size) = startup_console_size(console.as_ref()) {
                    let payload = ExecResize { rows: size.rows, cols: size.cols };
                    let _ = client
                        .send(id, TypedMessage::new(MessageType::ExecResize, &payload))
                        .await;
                }
            }
            read = read_optional_startup_console_input(console.as_ref(), &mut input[..input_capacity]),
                if started && console.is_some() && !console_input_closed && input_capacity > 0 =>
            {
                match read {
                    Ok(0) => {
                        console_input_closed = true;
                        let payload = ExecStdin { data: Vec::new() };
                        let _ = client
                            .send(id, TypedMessage::new(MessageType::ExecStdin, &payload))
                            .await;
                    }
                    Ok(n) => {
                        let payload = ExecStdin { data: input[..n].to_vec() };
                        if client
                            .send(id, TypedMessage::new(MessageType::ExecStdin, &payload))
                            .await
                            .is_err()
                        {
                            console_input_closed = true;
                        } else {
                            input_window.sent(n)?;
                        }
                    }
                    Err(error) if is_console_disconnect(&error) => {
                        console_input_closed = true;
                        console = None;
                        let payload = ExecStdin { data: Vec::new() };
                        let _ = client
                            .send(id, TypedMessage::new(MessageType::ExecStdin, &payload))
                            .await;
                    }
                    Err(error) => {
                        return Err(RuntimeError::Custom(format!(
                            "startup command console input: {error}"
                        )));
                    }
                }
            }
            message = stream.recv() => {
                let Some(message) = message.map_err(|err| {
                    RuntimeError::Custom(format!("startup command stream: {err}"))
                })? else {
                    return Err(RuntimeError::Custom(
                        "startup command stream ended before terminal event".into(),
                    ));
                };
                match MessageType::from_wire_str(&message.t) {
                    Some(MessageType::ExecStarted) => {
                        started = true;
                        if let Some(path) = session_id_path.take() {
                            write_session_id(&path, id)?;
                        }
                        if let Some(payload) = initial_stdin.take() {
                            let result = client
                                .send(
                                    id,
                                    TypedMessage::new(MessageType::ExecStdin, &payload),
                                )
                                .await;
                            check_initial_stdin_delivery(result)?;
                        }
                    }
                    Some(MessageType::ExecStdout) => {
                        let stdout = message.payload::<ExecStdout>().map_err(|err| {
                            RuntimeError::Custom(format!("startup command stdout: {err}"))
                        })?;
                        write_startup_output(
                            console.as_ref(),
                            if uses_console { None } else { stdio.as_mut() },
                            true,
                            &stdout.data,
                        )
                        .await?;
                        if policy.is_some() {
                            output_ack.consume(stdout.data.len()).ok_or_else(|| RuntimeError::Custom("startup output counter overflow".into()))?;
                            consumed_output.send_replace(output_ack.clone());
                        }
                    }
                    Some(MessageType::ExecStderr) => {
                        let stderr = message.payload::<ExecStderr>().map_err(|err| {
                            RuntimeError::Custom(format!("startup command stderr: {err}"))
                        })?;
                        write_startup_output(
                            console.as_ref(),
                            if uses_console { None } else { stdio.as_mut() },
                            false,
                            &stderr.data,
                        )
                        .await?;
                        if policy.is_some() {
                            output_ack.consume(stderr.data.len()).ok_or_else(|| RuntimeError::Custom("startup output counter overflow".into()))?;
                            consumed_output.send_replace(output_ack.clone());
                        }
                    }
                    Some(MessageType::ExecStdinAck) => {
                        let ack = message.payload::<ExecStdinAck>().map_err(|err| RuntimeError::Custom(format!("startup stdin acknowledgement: {err}")))?;
                        input_window.acknowledge(ack.consumed)?;
                    }
                    Some(MessageType::ExecStdinError) => {
                        stdin = None;
                        console_input_closed = true;
                    }
                    Some(MessageType::ExecExited) => {
                        let exited = message.payload::<ExecExited>().map_err(|err| {
                            RuntimeError::Custom(format!("startup command exit: {err}"))
                        })?;
                        return Ok(StartupCommandExit::Exited(exited.code));
                    }
                    Some(MessageType::ExecFailed) => {
                        let failed = message.payload::<ExecFailed>().map_err(|err| {
                            RuntimeError::Custom(format!("startup command failure: {err}"))
                        })?;
                        return Ok(StartupCommandExit::Failed(failed));
                    }
                    _ => {}
                }
            }
        }
    }
}

fn initial_startup_stdin(uses_console: bool) -> Option<ExecStdin> {
    (!uses_console).then(|| ExecStdin { data: Vec::new() })
}

#[cfg(unix)]
pub(crate) fn open_startup_stdin(fd: i32) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(format!("/proc/self/fd/{fd}"))
}

fn startup_input(file: std::fs::File) -> RuntimeResult<StartupInput> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        if file.metadata()?.file_type().is_fifo() {
            // SAFETY: the owned descriptor stays open and unchanged until AsyncFd is dropped.
            let fd =
                unsafe { AsyncFd::register(OwnedFd::from(file)) }.map_err(std::io::Error::from)?;
            return Ok(StartupInput::Pipe(StartupConsoleBridge { fd }));
        }
    }
    Ok(StartupInput::File(tokio::fs::File::from_std(file)))
}

async fn read_startup_input(
    input: &mut Option<StartupInput>,
    buf: &mut [u8],
) -> std::io::Result<usize> {
    use tokio::io::AsyncReadExt;
    match input {
        #[cfg(unix)]
        Some(StartupInput::Pipe(pipe)) => read_startup_console_input(pipe, buf).await,
        Some(StartupInput::File(file)) => file.read(buf).await,
        None => std::future::pending().await,
    }
}

#[cfg(unix)]
fn open_startup_console(
    console: Option<StartupConsole>,
) -> RuntimeResult<Option<StartupConsoleBridge>> {
    let Some(fd) = console else {
        return Ok(None);
    };
    set_nonblocking(fd.as_raw_fd())?;
    // SAFETY: AsyncFd owns this descriptor; no raw close or replacement is performed.
    let fd = unsafe { AsyncFd::register(fd) }.map_err(std::io::Error::from)?;
    Ok(Some(StartupConsoleBridge { fd }))
}

#[cfg(not(unix))]
fn open_startup_console(
    _console: Option<StartupConsole>,
) -> RuntimeResult<Option<StartupConsoleBridge>> {
    Ok(None)
}

fn nonzero_tty_size(size: u16, default: u16) -> u16 {
    if size == 0 { default } else { size }
}

async fn write_startup_output(
    console: Option<&StartupConsoleBridge>,
    stdio: Option<&mut StartupStdio>,
    stdout: bool,
    data: &[u8],
) -> RuntimeResult<()> {
    if let Some(console) = console {
        match write_startup_console_output(console, data).await {
            Ok(()) => return Ok(()),
            Err(error) if is_console_disconnect(&error) => return Ok(()),
            Err(error) => return Err(error.into()),
        }
    }

    let Some(stdio) = stdio else {
        return Ok(());
    };
    if stdout {
        stdio.stdout.write_all(data)?;
        stdio.stdout.flush()?;
    } else {
        stdio.stderr.write_all(data)?;
        stdio.stderr.flush()?;
    }
    Ok(())
}

#[cfg(unix)]
async fn read_startup_console_input(
    console: &StartupConsoleBridge,
    buf: &mut [u8],
) -> std::io::Result<usize> {
    loop {
        let mut guard = console.fd.readable().await?;
        match guard.try_io(|inner| read_fd(inner.get_ref().as_raw_fd(), buf)) {
            Ok(result) => return result,
            Err(_) => continue,
        }
    }
}

async fn read_optional_startup_console_input(
    console: Option<&StartupConsoleBridge>,
    buf: &mut [u8],
) -> std::io::Result<usize> {
    match console {
        Some(console) => read_startup_console_input(console, buf).await,
        None => std::future::pending().await,
    }
}

#[cfg(not(unix))]
async fn read_startup_console_input(
    _console: &StartupConsoleBridge,
    _buf: &mut [u8],
) -> std::io::Result<usize> {
    std::future::pending().await
}

#[cfg(unix)]
async fn write_startup_console_output(
    console: &StartupConsoleBridge,
    mut data: &[u8],
) -> std::io::Result<()> {
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

#[cfg(not(unix))]
async fn write_startup_console_output(
    _console: &StartupConsoleBridge,
    _data: &[u8],
) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn startup_console_size(console: Option<&StartupConsoleBridge>) -> Option<PtySize> {
    console.and_then(|console| console_size_from_fd(console.fd.get_ref().as_raw_fd()))
}

#[cfg(not(unix))]
fn startup_console_size(_console: Option<&StartupConsoleBridge>) -> Option<PtySize> {
    None
}

fn is_console_disconnect(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::BrokenPipe | ErrorKind::ConnectionReset | ErrorKind::UnexpectedEof
    ) || error.raw_os_error() == Some(libc::EIO)
}

#[cfg(unix)]
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

#[cfg(unix)]
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

#[cfg(unix)]
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

#[cfg(unix)]
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

fn check_initial_stdin_delivery(result: ClientResult<()>) -> RuntimeResult<()> {
    match result {
        // A fast process may already have a terminal event buffered in the receiver.
        // Continue draining that stream so its output and exit status are preserved.
        Ok(())
        | Err(microsandbox_agent_client::ClientError {
            kind: ClientErrorKind::StreamClosed,
            ..
        }) => Ok(()),
        Err(error) => Err(RuntimeError::Custom(format!(
            "startup command close stdin: {error}"
        ))),
    }
}

fn write_session_id(path: &Path, id: u32) -> RuntimeResult<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp_path = path.with_extension("tmp");
    std::fs::write(&tmp_path, id.to_string())?;
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

fn startup_error_path(session_id_path: &Path) -> std::path::PathBuf {
    let file_name = session_id_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("startup");
    session_id_path.with_file_name(format!("{file_name}.error"))
}

fn startup_exit_path(session_id_path: &Path) -> std::path::PathBuf {
    let file_name = session_id_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("startup");
    session_id_path.with_file_name(format!("{file_name}.exit"))
}

fn write_startup_exit(path: &Path, code: i32) -> RuntimeResult<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp_path = path.with_extension("exit.tmp");
    std::fs::write(&tmp_path, code.to_string())?;
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

fn write_startup_error(path: &Path, message: &str) -> RuntimeResult<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp_path = path.with_extension("error.tmp");
    std::fs::write(&tmp_path, message)?;
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

async fn wait_for_start_signal(path: &Path) -> RuntimeResult<()> {
    let mut interval = tokio::time::interval(std::time::Duration::from_millis(20));
    loop {
        interval.tick().await;
        match tokio::fs::try_exists(path).await {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(err) => {
                return Err(RuntimeError::Custom(format!(
                    "startup command start signal {}: {err}",
                    path.display()
                )));
            }
        }
    }
}

fn take_signal_request(path: &Path) -> RuntimeResult<Option<i32>> {
    let raw = match std::fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    std::fs::remove_file(path)?;
    let signal = raw.trim().parse::<i32>().map_err(|error| {
        RuntimeError::Custom(format!(
            "startup command signal request {}: {error}",
            path.display()
        ))
    })?;
    Ok(Some(signal))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::io::{Seek, Write};
    use std::path::Path;

    use microsandbox_agent_client::{ClientError, ErrorKind};
    #[cfg(unix)]
    use microsandbox_protocol::{
        codec,
        core::Ready,
        exec::{ExecExited, ExecOutputAck, ExecStarted, ExecStdin, ExecStdinAck, ExecStdout},
        message::{Message, MessageType},
    };
    #[cfg(unix)]
    use tokio::io::AsyncWriteExt;
    #[cfg(unix)]
    use tokio::net::UnixListener;

    #[cfg(unix)]
    #[tokio::test]
    async fn startup_forwards_multiple_input_windows_and_acknowledges_output() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("agent.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let policy = super::ExecLimits::default();
        let bytes = vec![b'x'; policy.input_limit as usize * 3];
        let expected = bytes.len();
        let mut input = tempfile::tempfile().unwrap();
        input.write_all(&bytes).unwrap();
        input.rewind().unwrap();
        let output = tempfile::tempfile().unwrap();
        let stdio = super::StartupStdio {
            stdin: Some(input),
            stdout: output.try_clone().unwrap(),
            stderr: output,
        };
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(&1u32.to_be_bytes()).await.unwrap();
            socket.write_all(&100u32.to_be_bytes()).await.unwrap();
            let ready = Message::with_payload(
                MessageType::Ready,
                0,
                &Ready {
                    exec_limits: Some(policy),
                    ..Default::default()
                },
            )
            .unwrap();
            codec::write_message(&mut socket, &ready).await.unwrap();
            let request = codec::read_message(&mut socket).await.unwrap();
            assert_eq!(request.t, MessageType::ExecIsolated);
            let id = request.id;
            let started =
                Message::with_payload(MessageType::ExecStarted, id, &ExecStarted { pid: 1 })
                    .unwrap();
            codec::write_message(&mut socket, &started).await.unwrap();
            let mut received = 0u64;
            loop {
                let message = codec::read_message(&mut socket).await.unwrap();
                assert_eq!(message.t, MessageType::ExecStdin);
                let data = message.payload::<ExecStdin>().unwrap().data;
                if data.is_empty() {
                    break;
                }
                assert!(data.len() <= policy.stdin_chunk_size as usize);
                assert!(data.iter().all(|byte| *byte == b'x'));
                received += data.len() as u64;
                if received.is_multiple_of(u64::from(policy.input_limit)) {
                    let ack = Message::with_payload(
                        MessageType::ExecStdinAck,
                        id,
                        &ExecStdinAck { consumed: received },
                    )
                    .unwrap();
                    codec::write_message(&mut socket, &ack).await.unwrap();
                }
            }
            assert_eq!(received, expected as u64);
            let mut consumed = ExecOutputAck::default();
            // Send more than one output window, requiring consumption acknowledgements.
            for _ in 0..80 {
                let data = vec![b'y'; policy.output_chunk_size as usize];
                consumed.consume(data.len()).unwrap();
                let stdout =
                    Message::with_payload(MessageType::ExecStdout, id, &ExecStdout { data })
                        .unwrap();
                codec::write_message(&mut socket, &stdout).await.unwrap();
                let ack = codec::read_message(&mut socket).await.unwrap();
                assert_eq!(ack.t, MessageType::ExecOutputAck);
                assert_eq!(
                    ack.payload::<ExecOutputAck>().unwrap().consumed,
                    consumed.consumed
                );
            }
            let exited =
                Message::with_payload(MessageType::ExecExited, id, &ExecExited { code: 42 })
                    .unwrap();
            codec::write_message(&mut socket, &exited).await.unwrap();
        });
        let command = serde_json::from_value(serde_json::json!({
            "cmd": "cat", "args": [], "env": [], "cwd": null, "user": null, "isolation": {}
        }))
        .unwrap();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            super::run_startup_command(
                &path,
                command,
                Some(stdio),
                None,
                #[cfg(feature = "net")]
                None,
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(matches!(result, super::StartupCommandExit::Exited(42)));
        server.await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn user_namespace_request_is_not_sent_to_an_older_agent() {
        for supported in [None, Some(false)] {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("agent.sock");
            let listener = UnixListener::bind(&path).unwrap();
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                socket.write_all(&1u32.to_be_bytes()).await.unwrap();
                socket.write_all(&100u32.to_be_bytes()).await.unwrap();
                let ready = Message::with_payload(
                    MessageType::Ready,
                    0,
                    &Ready {
                        workload_user_namespace: supported,
                        ..Default::default()
                    },
                )
                .unwrap();
                codec::write_message(&mut socket, &ready).await.unwrap();
                assert!(
                    codec::read_message(&mut socket).await.is_err(),
                    "unsupported peer must not receive an execution request"
                );
            });
            let command = serde_json::from_value(serde_json::json!({
                "cmd": "true", "args": [], "env": [], "cwd": null, "user": null,
                "isolation": {"pid":true, "mount":true, "user": {
                    "uid_mappings":[{"container_id":0,"guest_id":0,"size":1}],
                    "gid_mappings":[{"container_id":0,"guest_id":0,"size":1}]
                }}
            }))
            .unwrap();
            let result = super::run_startup_command(
                &path,
                command,
                None,
                None,
                #[cfg(feature = "net")]
                None,
            )
            .await;
            let error = result
                .err()
                .expect("older agent must reject user namespaces");
            assert!(error.to_string().contains("update agentd"));
            tokio::time::timeout(std::time::Duration::from_secs(5), server)
                .await
                .unwrap()
                .unwrap();
        }
    }

    #[test]
    fn startup_input_waits_for_acknowledgements_and_respects_chunk_size() {
        let mut window = super::StartupInputWindow {
            policy: Some(super::ExecLimits {
                input_limit: 8,
                stdin_chunk_size: 4,
                ..Default::default()
            }),
            sent: 0,
            consumed: 0,
        };
        assert_eq!(window.capacity(4096), 4);
        window.sent(8).unwrap();
        assert_eq!(window.capacity(4096), 0);
        window.acknowledge(3).unwrap();
        assert_eq!(window.capacity(4096), 3);
        window.acknowledge(3).unwrap();
        assert_eq!(window.capacity(4096), 3);
        assert!(window.acknowledge(2).is_err());
        assert!(window.acknowledge(9).is_err());
        window.acknowledge(8).unwrap();
        assert_eq!(window.capacity(4096), 4);
    }

    #[test]
    fn startup_input_without_policy_retains_legacy_capacity() {
        let mut window = super::StartupInputWindow {
            policy: None,
            sent: 0,
            consumed: 0,
        };
        window.sent(65536).unwrap();
        assert_eq!(window.capacity(4096), 4096);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn inherited_pipe_delivers_bytes_then_eof_without_changing_parent_flags() {
        use std::io::Write;
        use std::os::fd::AsRawFd;
        let (reader, writer) = nix::unistd::pipe().unwrap();
        let flags = unsafe { libc::fcntl(reader.as_raw_fd(), libc::F_GETFL) };
        let file = super::open_startup_stdin(reader.as_raw_fd()).unwrap();
        let mut input = Some(super::startup_input(file).unwrap());
        let mut buf = [0; 32];
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(20),
                super::read_startup_input(&mut input, &mut buf)
            )
            .await
            .is_err()
        );
        let mut writer = std::fs::File::from(writer);
        writer.write_all(b"INPUT_OK\n").unwrap();
        drop(writer);
        let n = super::read_startup_input(&mut input, &mut buf)
            .await
            .unwrap();
        assert_eq!(&buf[..n], b"INPUT_OK\n");
        assert_eq!(
            super::read_startup_input(&mut input, &mut buf)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            unsafe { libc::fcntl(reader.as_raw_fd(), libc::F_GETFL) },
            flags
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn null_startup_input_reaches_eof() {
        let mut input =
            Some(super::startup_input(std::fs::File::open("/dev/null").unwrap()).unwrap());
        assert_eq!(
            super::read_startup_input(&mut input, &mut [0; 8])
                .await
                .unwrap(),
            0
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn inherited_regular_file_delivers_bytes_then_eof() {
        use std::io::{Seek, Write};
        use std::os::fd::AsRawFd;
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(b"FILE_OK").unwrap();
        file.rewind().unwrap();
        let mut input = Some(
            super::startup_input(super::open_startup_stdin(file.as_raw_fd()).unwrap()).unwrap(),
        );
        let mut buf = [0; 32];
        let n = super::read_startup_input(&mut input, &mut buf)
            .await
            .unwrap();
        assert_eq!(&buf[..n], b"FILE_OK");
        assert_eq!(
            super::read_startup_input(&mut input, &mut buf)
                .await
                .unwrap(),
            0
        );
    }

    #[test]
    fn stdin_eof_racing_with_exit_keeps_receiving_terminal_event() {
        assert!(super::check_initial_stdin_delivery(Ok(())).is_ok());
        assert!(
            super::check_initial_stdin_delivery(Err(ClientError::new(ErrorKind::StreamClosed,)))
                .is_ok()
        );
    }

    #[test]
    fn stdin_eof_transport_errors_remain_fatal() {
        for kind in [
            ErrorKind::Timeout,
            ErrorKind::Io(std::io::ErrorKind::BrokenPipe),
        ] {
            let error = super::check_initial_stdin_delivery(Err(ClientError::new(kind)))
                .expect_err("transport failure must remain visible");
            assert!(error.to_string().contains("startup command close stdin"));
        }
    }

    #[test]
    fn takes_signal_request_once() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("init.signal");
        std::fs::write(&path, "15").expect("write signal request");

        assert_eq!(
            super::take_signal_request(&path).expect("take request"),
            Some(15)
        );
        assert_eq!(
            super::take_signal_request(&path).expect("request consumed"),
            None
        );
    }

    #[test]
    fn derives_and_writes_startup_exit_path() {
        let temp = tempfile::tempdir().expect("tempdir");
        let session = temp.path().join("init.session");
        let exit = super::startup_exit_path(&session);

        assert_eq!(exit, temp.path().join("init.session.exit"));
        super::write_startup_exit(&exit, 143).expect("write exit status");
        assert_eq!(
            std::fs::read_to_string(exit).expect("read exit status"),
            "143"
        );
        assert_eq!(
            super::startup_exit_path(Path::new("session")),
            Path::new("session.exit")
        );
    }

    #[test]
    fn non_console_startup_closes_stdin_but_console_keeps_it_open() {
        let stdin = super::initial_startup_stdin(false).expect("non-console EOF");
        assert!(stdin.data.is_empty());
        assert!(super::initial_startup_stdin(true).is_none());
    }

    #[tokio::test]
    async fn optional_console_input_waits_when_console_is_absent() {
        let mut buf = [0u8; 1];
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(10),
            super::read_optional_startup_console_input(None, &mut buf),
        )
        .await;

        assert!(result.is_err());
    }
}
