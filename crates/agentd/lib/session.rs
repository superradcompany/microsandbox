//! Exec session management: spawning processes with PTY or pipe I/O.

use std::{
    ffi::CString,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    process::Stdio,
};

use nix::{
    pty::openpty,
    sys::signal::{Signal, kill},
    unistd::Pid,
};
use tokio::{
    io::{AsyncReadExt, unix::AsyncFd},
    process::{Child, Command},
    sync::mpsc,
};

use microsandbox_protocol::exec::ExecRequest;

use crate::error::{AgentdError, AgentdResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// An active exec session handle for sending input to a running process.
///
/// Output reading is handled by a background task that sends events
/// via the `mpsc` channel provided at spawn time.
pub struct ExecSession {
    /// The PID of the spawned process.
    pid: i32,

    /// The PTY master fd (only for PTY mode, used for writing and resize).
    pty_master: Option<OwnedFd>,

    /// The child's stdin (only for pipe mode).
    stdin: Option<tokio::process::ChildStdin>,
}

/// Output from a session that the agent loop should forward to the host.
pub enum SessionOutput {
    /// Data from stdout (or PTY master).
    Stdout(Vec<u8>),

    /// Data from stderr (pipe mode only).
    Stderr(Vec<u8>),

    /// The process has exited with the given code.
    Exited(i32),

    /// Pre-encoded frame bytes to write directly to the serial output buffer.
    ///
    /// Used by filesystem streaming operations that encode their own
    /// `FsData`/`FsResponse` messages.
    Raw(Vec<u8>),
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ExecSession {
    /// Spawns a new exec session.
    ///
    /// If `req.tty` is true, uses a PTY. Otherwise, uses piped stdin/stdout/stderr.
    /// A background task is spawned to read output and send events via `tx`.
    pub fn spawn(
        id: u32,
        req: &ExecRequest,
        tx: mpsc::UnboundedSender<(u32, SessionOutput)>,
    ) -> AgentdResult<Self> {
        if req.tty {
            Self::spawn_pty(id, req, tx)
        } else {
            Self::spawn_pipe(id, req, tx)
        }
    }

    /// Returns the PID of the spawned process (as u32 for the protocol).
    pub fn pid(&self) -> u32 {
        self.pid as u32
    }

    /// Writes data to the process's stdin (or PTY master).
    pub async fn write_stdin(&self, data: &[u8]) -> AgentdResult<()> {
        if let Some(ref master) = self.pty_master {
            blocking_write_fd(master.as_raw_fd(), data).await
        } else if let Some(ref stdin) = self.stdin {
            blocking_write_fd(stdin.as_raw_fd(), data).await
        } else {
            Ok(())
        }
    }

    /// Resizes the PTY (only applicable for TTY sessions).
    pub fn resize(&self, rows: u16, cols: u16) -> AgentdResult<()> {
        if let Some(ref master) = self.pty_master {
            let ws = libc::winsize {
                ws_row: rows,
                ws_col: cols,
                ws_xpixel: 0,
                ws_ypixel: 0,
            };
            let ret = unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCSWINSZ, &ws) };
            if ret < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        Ok(())
    }

    /// Sends a signal to the spawned process.
    pub fn send_signal(&self, signal: i32) -> AgentdResult<()> {
        let sig = Signal::try_from(signal)
            .map_err(|e| AgentdError::ExecSession(format!("invalid signal {signal}: {e}")))?;
        kill(Pid::from_raw(self.pid), sig)?;
        Ok(())
    }

    /// Closes the process's stdin.
    ///
    /// For pipe mode, drops the `ChildStdin` handle which closes the fd.
    /// For PTY mode, this is a no-op (the PTY master stays open for output).
    pub fn close_stdin(&mut self) {
        self.stdin.take();
    }
}

impl ExecSession {
    /// Spawns a process with a PTY.
    fn spawn_pty(
        id: u32,
        req: &ExecRequest,
        tx: mpsc::UnboundedSender<(u32, SessionOutput)>,
    ) -> AgentdResult<Self> {
        let pty = openpty(None, None)?;

        // Set initial window size.
        let ws = libc::winsize {
            ws_row: req.rows,
            ws_col: req.cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let ret = unsafe { libc::ioctl(pty.master.as_raw_fd(), libc::TIOCSWINSZ, &ws) };
        if ret < 0 {
            return Err(std::io::Error::last_os_error().into());
        }

        let slave_fd = pty.slave.as_raw_fd();

        // Pre-build all strings before fork to avoid allocating in the child.
        let c_cmd = CString::new(req.cmd.as_str())
            .map_err(|e| AgentdError::ExecSession(format!("invalid command: {e}")))?;
        let mut c_args: Vec<CString> = vec![c_cmd.clone()];
        for arg in &req.args {
            c_args.push(
                CString::new(arg.as_str())
                    .map_err(|e| AgentdError::ExecSession(format!("invalid arg: {e}")))?,
            );
        }

        // Build argv pointer array (null-terminated).
        let argv_ptrs: Vec<*const libc::c_char> = c_args
            .iter()
            .map(|s| s.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();

        // Pre-parse environment variables into CStrings.
        let c_env: Vec<(CString, CString)> = req
            .env
            .iter()
            .filter_map(|var| {
                let (key, val) = var.split_once('=')?;
                let k = CString::new(key).ok()?;
                let v = CString::new(val).ok()?;
                Some((k, v))
            })
            .collect();

        // Pre-build cwd CString.
        let c_cwd = req
            .cwd
            .as_ref()
            .map(|dir| CString::new(dir.as_str()))
            .transpose()
            .map_err(|e| AgentdError::ExecSession(format!("invalid cwd: {e}")))?;

        // Pre-parse rlimits before fork (no allocations in child).
        let parsed_rlimits = parse_rlimits(req);

        // Fork.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(std::io::Error::last_os_error().into());
        }

        #[allow(unreachable_code)]
        if pid == 0 {
            // Child process — only async-signal-safe operations from here.
            drop(pty.master);

            // Create new session.
            if unsafe { libc::setsid() } < 0 {
                unsafe { libc::_exit(1) };
            }

            // Set controlling terminal.
            if unsafe { libc::ioctl(slave_fd, libc::TIOCSCTTY.into(), 0) } < 0 {
                unsafe { libc::_exit(1) };
            }

            // Dup slave to stdin/stdout/stderr.
            unsafe {
                if libc::dup2(slave_fd, 0) < 0 {
                    libc::_exit(1);
                }
                if libc::dup2(slave_fd, 1) < 0 {
                    libc::_exit(1);
                }
                if libc::dup2(slave_fd, 2) < 0 {
                    libc::_exit(1);
                }
                if slave_fd > 2 {
                    libc::close(slave_fd);
                }
            }

            // Set environment variables using pre-built CStrings.
            for (key, val) in &c_env {
                unsafe {
                    libc::setenv(key.as_ptr(), val.as_ptr(), 1);
                }
            }

            // Set working directory.
            if let Some(ref dir) = c_cwd {
                unsafe {
                    libc::chdir(dir.as_ptr());
                }
            }

            // Apply resource limits.
            for (resource, limit) in &parsed_rlimits {
                if unsafe { libc::setrlimit(*resource as _, limit) } != 0 {
                    unsafe { libc::_exit(1) };
                }
            }

            // execvp — on success this never returns.
            unsafe {
                libc::execvp(argv_ptrs[0], argv_ptrs.as_ptr());
            }

            // If execvp returns, it failed.
            unsafe { libc::_exit(127) };
        }

        // Parent process.
        drop(pty.slave);

        // Dup the master fd for the reader task.
        let reader_fd = unsafe { libc::dup(pty.master.as_raw_fd()) };
        if reader_fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let reader_fd = unsafe { OwnedFd::from_raw_fd(reader_fd) };

        // Spawn background reader task.
        tokio::spawn(pty_reader_task(id, pid, reader_fd, tx));

        Ok(Self {
            pid,
            pty_master: Some(pty.master),
            stdin: None,
        })
    }

    /// Spawns a process with piped stdio.
    fn spawn_pipe(
        id: u32,
        req: &ExecRequest,
        tx: mpsc::UnboundedSender<(u32, SessionOutput)>,
    ) -> AgentdResult<Self> {
        let mut cmd = Command::new(&req.cmd);
        cmd.args(&req.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        for var in &req.env {
            if let Some((key, val)) = var.split_once('=') {
                cmd.env(key, val);
            }
        }

        if let Some(ref dir) = req.cwd {
            cmd.current_dir(dir);
        }

        // Apply resource limits in the child before exec.
        let parsed_rlimits = parse_rlimits(req);
        if !parsed_rlimits.is_empty() {
            unsafe {
                cmd.pre_exec(move || {
                    for (resource, limit) in &parsed_rlimits {
                        if libc::setrlimit(*resource as _, limit) != 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                    }
                    Ok(())
                });
            }
        }

        let mut child = cmd.spawn()?;
        let pid = child.id().unwrap_or(0) as i32;
        let stdin = child.stdin.take();
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();

        // Spawn background reader task.
        tokio::spawn(pipe_reader_task(id, child, stdout, stderr, tx));

        Ok(Self {
            pid,
            pty_master: None,
            stdin,
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Parses a resource limit name into the corresponding `RLIMIT_*` constant.
///
/// Uses raw constants for Linux-specific limits that aren't in libc's cross-platform API.
fn parse_rlimit_resource(name: &str) -> Option<libc::c_int> {
    // Linux x86_64 RLIMIT_* values for resources not exposed by libc on all platforms.
    const RLIMIT_LOCKS: libc::c_int = 10;
    const RLIMIT_SIGPENDING: libc::c_int = 11;
    const RLIMIT_MSGQUEUE: libc::c_int = 12;
    const RLIMIT_NICE: libc::c_int = 13;
    const RLIMIT_RTPRIO: libc::c_int = 14;
    const RLIMIT_RTTIME: libc::c_int = 15;

    match name {
        "cpu" => Some(libc::RLIMIT_CPU as _),
        "fsize" => Some(libc::RLIMIT_FSIZE as _),
        "data" => Some(libc::RLIMIT_DATA as _),
        "stack" => Some(libc::RLIMIT_STACK as _),
        "core" => Some(libc::RLIMIT_CORE as _),
        "rss" => Some(libc::RLIMIT_RSS as _),
        "nproc" => Some(libc::RLIMIT_NPROC as _),
        "nofile" => Some(libc::RLIMIT_NOFILE as _),
        "memlock" => Some(libc::RLIMIT_MEMLOCK as _),
        "as" => Some(libc::RLIMIT_AS as _),
        "locks" => Some(RLIMIT_LOCKS),
        "sigpending" => Some(RLIMIT_SIGPENDING),
        "msgqueue" => Some(RLIMIT_MSGQUEUE),
        "nice" => Some(RLIMIT_NICE),
        "rtprio" => Some(RLIMIT_RTPRIO),
        "rttime" => Some(RLIMIT_RTTIME),
        _ => None,
    }
}

/// Pre-parses rlimits from the exec request into `(resource_id, rlimit)` tuples
/// that can be applied in the child process via `setrlimit()`.
fn parse_rlimits(req: &ExecRequest) -> Vec<(libc::c_int, libc::rlimit)> {
    req.rlimits
        .iter()
        .filter_map(|rl| {
            let resource = parse_rlimit_resource(&rl.resource)?;
            Some((
                resource,
                libc::rlimit {
                    rlim_cur: rl.soft,
                    rlim_max: rl.hard,
                },
            ))
        })
        .collect()
}

/// Writes data to a raw fd using a blocking task, handling short writes.
async fn blocking_write_fd(fd: RawFd, data: &[u8]) -> AgentdResult<()> {
    let data = data.to_vec();
    tokio::task::spawn_blocking(move || {
        let mut written = 0;
        while written < data.len() {
            let ptr = unsafe { data.as_ptr().add(written) as *const libc::c_void };
            let ret = unsafe { libc::write(fd, ptr, data.len() - written) };
            if ret < 0 {
                return Err(AgentdError::Io(std::io::Error::last_os_error()));
            }
            written += ret as usize;
        }
        Ok(())
    })
    .await
    .map_err(|e| AgentdError::ExecSession(format!("stdin write join error: {e}")))?
}

/// Background task that reads from a PTY master fd and sends output events.
async fn pty_reader_task(
    id: u32,
    pid: i32,
    master_fd: OwnedFd,
    tx: mpsc::UnboundedSender<(u32, SessionOutput)>,
) {
    // Set non-blocking for async I/O.
    let raw = master_fd.as_raw_fd();
    let flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
    if flags >= 0 {
        unsafe { libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    }

    let Ok(async_fd) = AsyncFd::new(master_fd) else {
        let code = wait_for_pid(pid).await;
        let _ = tx.send((id, SessionOutput::Exited(code)));
        return;
    };

    loop {
        let Ok(mut guard) = async_fd.readable().await else {
            break;
        };

        let fd = async_fd.as_raw_fd();
        let mut buf = [0u8; 4096];
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };

        if n > 0 {
            let _ = tx.send((id, SessionOutput::Stdout(buf[..n as usize].to_vec())));
            guard.clear_ready();
        } else if n == 0 {
            break;
        } else {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EAGAIN)
                || err.raw_os_error() == Some(libc::EWOULDBLOCK)
            {
                guard.clear_ready();
                continue;
            }
            // EIO or other error — PTY slave closed.
            break;
        }
    }

    let code = wait_for_pid(pid).await;
    let _ = tx.send((id, SessionOutput::Exited(code)));
}

/// Background task that reads from piped stdout/stderr and sends output events.
async fn pipe_reader_task(
    id: u32,
    mut child: Child,
    stdout: Option<tokio::process::ChildStdout>,
    stderr: Option<tokio::process::ChildStderr>,
    tx: mpsc::UnboundedSender<(u32, SessionOutput)>,
) {
    let mut stdout = stdout;
    let mut stderr = stderr;
    let mut stdout_eof = stdout.is_none();
    let mut stderr_eof = stderr.is_none();

    while !stdout_eof || !stderr_eof {
        let mut stdout_buf = [0u8; 4096];
        let mut stderr_buf = [0u8; 4096];

        tokio::select! {
            result = async {
                match stdout.as_mut() {
                    Some(out) => out.read(&mut stdout_buf).await,
                    None => std::future::pending().await,
                }
            }, if !stdout_eof => {
                match result {
                    Ok(0) | Err(_) => {
                        stdout = None;
                        stdout_eof = true;
                    }
                    Ok(n) => {
                        let _ = tx.send((id, SessionOutput::Stdout(stdout_buf[..n].to_vec())));
                    }
                }
            }
            result = async {
                match stderr.as_mut() {
                    Some(err) => err.read(&mut stderr_buf).await,
                    None => std::future::pending().await,
                }
            }, if !stderr_eof => {
                match result {
                    Ok(0) | Err(_) => {
                        stderr = None;
                        stderr_eof = true;
                    }
                    Ok(n) => {
                        let _ = tx.send((id, SessionOutput::Stderr(stderr_buf[..n].to_vec())));
                    }
                }
            }
        }
    }

    // Both streams are done — wait for process exit.
    let code = match child.wait().await {
        Ok(status) => status.code().unwrap_or(-1),
        Err(_) => -1,
    };

    let _ = tx.send((id, SessionOutput::Exited(code)));
}

/// Waits for a process to exit by PID and returns the exit code.
async fn wait_for_pid(pid: i32) -> i32 {
    tokio::task::spawn_blocking(move || {
        let mut status: i32 = 0;
        unsafe {
            libc::waitpid(pid, &mut status, 0);
        }
        if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            -1
        }
    })
    .await
    .unwrap_or(-1)
}
