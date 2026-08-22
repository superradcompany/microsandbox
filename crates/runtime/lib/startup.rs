//! Startup workload execution for detached `msb run -- CMD`.

use std::io::{ErrorKind, Write};
#[cfg(unix)]
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;

use microsandbox_agent_client::AgentClient;
use microsandbox_protocol::{
    exec::{
        ExecExited, ExecFailed, ExecRequest, ExecResize, ExecSignal, ExecStderr, ExecStdin,
        ExecStdout,
    },
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PtySize {
    rows: u16,
    cols: u16,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) async fn run_startup_command(
    agent_sock_path: &Path,
    command: StartupCommand,
    mut stdio: Option<StartupStdio>,
    console: Option<StartupConsole>,
) -> RuntimeResult<StartupCommandExit> {
    let error_path = command.session_id_path.as_deref().map(startup_error_path);
    let exit_path = command.session_id_path.as_deref().map(startup_exit_path);
    let result = run_startup_command_inner(agent_sock_path, command, &mut stdio, console).await;

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
) -> RuntimeResult<StartupCommandExit> {
    let mut session_id_path = command.session_id_path;
    let signal_path = command.signal_path.clone();
    let uses_console = console.is_some();
    // Keep the inherited PTY slave open during OCI `create`. containerd owns
    // the master and waits for a live slave before it invokes OCI `start`.
    let mut console = open_startup_console(console)?;
    if let Some(start_signal_path) = command.start_signal_path.as_ref() {
        wait_for_start_signal(start_signal_path).await?;
    }
    let mut console_input_closed = console.is_none();
    let tty = command.tty || console.is_some();
    let rows = nonzero_tty_size(command.rows, 24);
    let cols = nonzero_tty_size(command.cols, 80);

    let client = AgentClient::connect(agent_sock_path)
        .await
        .map_err(|err| RuntimeError::Custom(format!("startup command connect: {err}")))?;

    let request = ExecRequest {
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

    let (id, mut rx) = client
        .stream(MessageType::ExecRequest, &request)
        .await
        .map_err(|err| RuntimeError::Custom(format!("startup command dispatch: {err}")))?;
    let mut initial_stdin = initial_startup_stdin(uses_console);
    let mut resize_poll = tokio::time::interval(std::time::Duration::from_millis(250));
    let mut signal_poll = tokio::time::interval(std::time::Duration::from_millis(20));
    let mut input = [0u8; 4096];

    loop {
        tokio::select! {
            _ = signal_poll.tick(), if signal_path.is_some() => {
                if let Some(signal) = take_signal_request(signal_path.as_deref().unwrap())? {
                    let payload = ExecSignal { signal };
                    client
                        .send(id, MessageType::ExecSignal, &payload)
                        .await
                        .map_err(|err| RuntimeError::Custom(format!(
                            "startup command signal {signal}: {err}"
                        )))?;
                }
            }
            _ = resize_poll.tick(), if console.is_some() => {
                if let Some(size) = startup_console_size(console.as_ref()) {
                    let payload = ExecResize { rows: size.rows, cols: size.cols };
                    let _ = client.send(id, MessageType::ExecResize, &payload).await;
                }
            }
            read = read_optional_startup_console_input(console.as_ref(), &mut input),
                if console.is_some() && !console_input_closed =>
            {
                match read {
                    Ok(0) => {
                        console_input_closed = true;
                        let payload = ExecStdin { data: Vec::new() };
                        let _ = client.send(id, MessageType::ExecStdin, &payload).await;
                    }
                    Ok(n) => {
                        let payload = ExecStdin { data: input[..n].to_vec() };
                        if client.send(id, MessageType::ExecStdin, &payload).await.is_err() {
                            console_input_closed = true;
                        }
                    }
                    Err(error) if is_console_disconnect(&error) => {
                        console_input_closed = true;
                        console = None;
                        let payload = ExecStdin { data: Vec::new() };
                        let _ = client.send(id, MessageType::ExecStdin, &payload).await;
                    }
                    Err(error) => {
                        return Err(RuntimeError::Custom(format!(
                            "startup command console input: {error}"
                        )));
                    }
                }
            }
            message = rx.recv() => {
                let Some(message) = message else {
                    return Err(RuntimeError::Custom(
                        "startup command stream ended before terminal event".into(),
                    ));
                };
                match message.t {
                    MessageType::ExecStarted => {
                        if let Some(path) = session_id_path.take() {
                            write_session_id(&path, id)?;
                        }
                        if let Some(payload) = initial_stdin.take() {
                            client
                                .send(id, MessageType::ExecStdin, &payload)
                                .await
                                .map_err(|err| RuntimeError::Custom(format!(
                                    "startup command close stdin: {err}"
                                )))?;
                        }
                    }
                    MessageType::ExecStdout => {
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
                    }
                    MessageType::ExecStderr => {
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
                    }
                    MessageType::ExecExited => {
                        let exited = message.payload::<ExecExited>().map_err(|err| {
                            RuntimeError::Custom(format!("startup command exit: {err}"))
                        })?;
                        return Ok(StartupCommandExit::Exited(exited.code));
                    }
                    MessageType::ExecFailed => {
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
fn open_startup_console(
    console: Option<StartupConsole>,
) -> RuntimeResult<Option<StartupConsoleBridge>> {
    let Some(fd) = console else {
        return Ok(None);
    };
    set_nonblocking(fd.as_raw_fd())?;
    let fd = AsyncFd::new(fd)?;
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
    use std::path::Path;

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
