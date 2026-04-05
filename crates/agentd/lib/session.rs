//! Exec session management: spawning processes with PTY or pipe I/O.

use std::{
    ffi::{CStr, CString},
    mem::MaybeUninit,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    process::Stdio,
};

use nix::{
    pty::openpty,
    sys::signal::{Signal, kill},
    unistd::Pid,
};
use tokio::{
    io::AsyncReadExt,
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

struct ResolvedUser {
    uid: libc::uid_t,
    gid: libc::gid_t,
    initgroups_user: Option<CString>,
    home_dir: Option<CString>,
}

struct PasswdEntry {
    name: String,
    uid: libc::uid_t,
    gid: libc::gid_t,
    home_dir: Option<String>,
}

struct GroupEntry {
    gid: libc::gid_t,
}

struct ExecErrorPipe {
    read_end: OwnedFd,
    write_end: OwnedFd,
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
        let err_pipe = new_exec_error_pipe()?;

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

        let resolved_user = resolve_requested_user(req)?;
        let default_home = default_home_dir(req, resolved_user.as_ref()).map(CStr::to_owned);
        let home_key = default_home
            .as_ref()
            .map(|_| {
                CString::new("HOME")
                    .map_err(|e| AgentdError::ExecSession(format!("invalid home env key: {e}")))
            })
            .transpose()?;

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
            drop(err_pipe.read_end);

            // Create new session.
            if unsafe { libc::setsid() } < 0 {
                unsafe { libc::_exit(1) };
            }

            // Set controlling terminal.
            if unsafe { libc::ioctl(slave_fd, libc::TIOCSCTTY, 0) } < 0 {
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

            if let Some(ref user) = resolved_user
                && apply_resolved_user(user).is_err()
            {
                unsafe { libc::_exit(1) };
            }

            if let (Some(key), Some(home)) = (&home_key, &default_home) {
                unsafe {
                    libc::setenv(key.as_ptr(), home.as_ptr(), 1);
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
            write_exec_error_and_exit(err_pipe.write_end.as_raw_fd());
        }

        // Parent process.
        drop(pty.slave);
        drop(err_pipe.write_end);

        if let Some(exec_errno) = read_exec_error(err_pipe.read_end.as_raw_fd())? {
            let _ = wait_for_exec_failure_child(pid);
            return Err(AgentdError::ExecSession(format!(
                "spawn pty cmd={} args={:?} cwd={:?}: {}",
                req.cmd,
                req.args,
                req.cwd,
                std::io::Error::from_raw_os_error(exec_errno)
            )));
        }

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

        let resolved_user = resolve_requested_user(req)?;
        if let Some(home) = default_home_dir(req, resolved_user.as_ref()) {
            cmd.env("HOME", home.to_string_lossy().into_owned());
        }

        // Apply resource limits in the child before exec.
        let parsed_rlimits = parse_rlimits(req);
        if resolved_user.is_some() || !parsed_rlimits.is_empty() {
            unsafe {
                cmd.pre_exec(move || {
                    if let Some(ref user) = resolved_user {
                        apply_resolved_user(user).map_err(agentd_to_io_error)?;
                    }
                    for (resource, limit) in &parsed_rlimits {
                        if libc::setrlimit(*resource as _, limit) != 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                    }
                    Ok(())
                });
            }
        }

        let mut child = cmd.spawn().map_err(|err| {
            AgentdError::ExecSession(format!(
                "spawn pipe cmd={} args={:?} cwd={:?}: {}",
                req.cmd, req.args, req.cwd, err
            ))
        })?;
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

fn new_exec_error_pipe() -> AgentdResult<ExecErrorPipe> {
    let mut fds = [0; 2];
    let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    Ok(ExecErrorPipe {
        read_end: unsafe { OwnedFd::from_raw_fd(fds[0]) },
        write_end: unsafe { OwnedFd::from_raw_fd(fds[1]) },
    })
}

fn write_exec_error_and_exit(err_fd: RawFd) -> ! {
    let errno = unsafe { *libc::__errno_location() };
    let bytes = errno.to_ne_bytes();
    let _ = unsafe { libc::write(err_fd, bytes.as_ptr() as *const libc::c_void, bytes.len()) };
    unsafe { libc::_exit(127) }
}

fn read_exec_error(err_fd: RawFd) -> AgentdResult<Option<i32>> {
    let mut buf = [0u8; std::mem::size_of::<i32>()];
    let n = unsafe { libc::read(err_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    if n < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if n == 0 {
        return Ok(None);
    }
    if n as usize != buf.len() {
        return Err(AgentdError::ExecSession(format!(
            "short exec error report: expected {} bytes, got {n}",
            buf.len()
        )));
    }
    Ok(Some(i32::from_ne_bytes(buf)))
}

fn wait_for_exec_failure_child(pid: i32) -> AgentdResult<()> {
    let ret = unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn resolve_requested_user(req: &ExecRequest) -> AgentdResult<Option<ResolvedUser>> {
    let requested = req
        .user
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .or_else(|| {
            std::env::var(microsandbox_protocol::ENV_USER)
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        });

    requested.as_deref().map(resolve_user_spec).transpose()
}

fn resolve_user_spec(spec: &str) -> AgentdResult<ResolvedUser> {
    let (user_part, group_part) = match spec.split_once(':') {
        Some((user, group)) => (user.trim(), Some(group.trim())),
        None => (spec.trim(), None),
    };

    if user_part.is_empty() {
        return Err(AgentdError::ExecSession("user spec has empty user".into()));
    }

    let passwd = if let Ok(uid) = parse_id(user_part) {
        lookup_passwd_by_uid(uid)?
    } else {
        lookup_passwd_by_name(user_part)?
            .ok_or_else(|| AgentdError::ExecSession(format!("guest user not found: {user_part}")))?
            .into()
    };

    let (uid, passwd_entry) = match passwd {
        ResolvedUserLookup::Known(entry) => (entry.uid, Some(entry)),
        ResolvedUserLookup::Numeric(uid) => (uid, None),
    };

    let gid = match group_part {
        Some("") => {
            return Err(AgentdError::ExecSession("user spec has empty group".into()));
        }
        Some(group) => resolve_group_spec(group)?,
        None => passwd_entry
            .as_ref()
            .map(|entry| entry.gid)
            .unwrap_or_else(|| unsafe { libc::getgid() }),
    };

    let initgroups_user = passwd_entry
        .as_ref()
        .map(|entry| CString::new(entry.name.as_str()))
        .transpose()
        .map_err(|e| AgentdError::ExecSession(format!("invalid guest user name: {e}")))?;

    Ok(ResolvedUser {
        uid,
        gid,
        initgroups_user,
        home_dir: passwd_entry
            .as_ref()
            .and_then(|entry| entry.home_dir.as_deref())
            .map(CString::new)
            .transpose()
            .map_err(|e| AgentdError::ExecSession(format!("invalid guest home directory: {e}")))?,
    })
}

enum ResolvedUserLookup {
    Known(PasswdEntry),
    Numeric(libc::uid_t),
}

impl From<PasswdEntry> for ResolvedUserLookup {
    fn from(value: PasswdEntry) -> Self {
        Self::Known(value)
    }
}

fn resolve_group_spec(spec: &str) -> AgentdResult<libc::gid_t> {
    if let Ok(gid) = parse_id(spec) {
        return Ok(gid);
    }

    lookup_group_by_name(spec)?
        .map(|entry| entry.gid)
        .ok_or_else(|| AgentdError::ExecSession(format!("guest group not found: {spec}")))
}

fn parse_id(value: &str) -> Result<u32, std::num::ParseIntError> {
    value.parse::<u32>()
}

fn lookup_passwd_by_name(name: &str) -> AgentdResult<Option<PasswdEntry>> {
    let name = CString::new(name)
        .map_err(|e| AgentdError::ExecSession(format!("invalid guest user name: {e}")))?;
    let mut pwd = MaybeUninit::<libc::passwd>::uninit();
    let mut result = std::ptr::null_mut();
    let mut buf = vec![0u8; lookup_buffer_len()];
    let rc = unsafe {
        libc::getpwnam_r(
            name.as_ptr(),
            pwd.as_mut_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 {
        return Err(AgentdError::ExecSession(format!(
            "failed to resolve guest user {name:?}: {}",
            std::io::Error::from_raw_os_error(rc)
        )));
    }
    if result.is_null() {
        return Ok(None);
    }

    let pwd = unsafe { pwd.assume_init() };
    let name = unsafe { CStr::from_ptr(pwd.pw_name) }
        .to_string_lossy()
        .into_owned();
    let home_dir = unsafe { CStr::from_ptr(pwd.pw_dir) }
        .to_string_lossy()
        .into_owned();
    Ok(Some(PasswdEntry {
        name,
        uid: pwd.pw_uid,
        gid: pwd.pw_gid,
        home_dir: (!home_dir.is_empty()).then_some(home_dir),
    }))
}

fn lookup_passwd_by_uid(uid: libc::uid_t) -> AgentdResult<ResolvedUserLookup> {
    let mut pwd = MaybeUninit::<libc::passwd>::uninit();
    let mut result = std::ptr::null_mut();
    let mut buf = vec![0u8; lookup_buffer_len()];
    let rc = unsafe {
        libc::getpwuid_r(
            uid,
            pwd.as_mut_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 {
        return Err(AgentdError::ExecSession(format!(
            "failed to resolve guest uid {uid}: {}",
            std::io::Error::from_raw_os_error(rc)
        )));
    }
    if result.is_null() {
        return Ok(ResolvedUserLookup::Numeric(uid));
    }

    let pwd = unsafe { pwd.assume_init() };
    let name = unsafe { CStr::from_ptr(pwd.pw_name) }
        .to_string_lossy()
        .into_owned();
    let home_dir = unsafe { CStr::from_ptr(pwd.pw_dir) }
        .to_string_lossy()
        .into_owned();
    Ok(ResolvedUserLookup::Known(PasswdEntry {
        name,
        uid: pwd.pw_uid,
        gid: pwd.pw_gid,
        home_dir: (!home_dir.is_empty()).then_some(home_dir),
    }))
}

fn lookup_group_by_name(name: &str) -> AgentdResult<Option<GroupEntry>> {
    let name = CString::new(name)
        .map_err(|e| AgentdError::ExecSession(format!("invalid guest group name: {e}")))?;
    let mut grp = MaybeUninit::<libc::group>::uninit();
    let mut result = std::ptr::null_mut();
    let mut buf = vec![0u8; lookup_buffer_len()];
    let rc = unsafe {
        libc::getgrnam_r(
            name.as_ptr(),
            grp.as_mut_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 {
        return Err(AgentdError::ExecSession(format!(
            "failed to resolve guest group {name:?}: {}",
            std::io::Error::from_raw_os_error(rc)
        )));
    }
    if result.is_null() {
        return Ok(None);
    }

    let grp = unsafe { grp.assume_init() };
    Ok(Some(GroupEntry { gid: grp.gr_gid }))
}

fn lookup_buffer_len() -> usize {
    let size = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    if size > 0 { size as usize } else { 16 * 1024 }
}

fn apply_resolved_user(user: &ResolvedUser) -> AgentdResult<()> {
    if let Some(ref name) = user.initgroups_user {
        if unsafe { libc::initgroups(name.as_ptr(), user.gid) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    } else if unsafe { libc::setgroups(0, std::ptr::null()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    if unsafe { libc::setgid(user.gid) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if unsafe { libc::setuid(user.uid) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    Ok(())
}

fn default_home_dir<'a>(req: &ExecRequest, user: Option<&'a ResolvedUser>) -> Option<&'a CStr> {
    if env_contains_key(&req.env, "HOME") {
        return None;
    }

    user.and_then(|user| user.home_dir.as_deref())
}

fn env_contains_key(env: &[String], key: &str) -> bool {
    env.iter().any(|entry| {
        entry
            .split_once('=')
            .map(|(entry_key, _)| entry_key == key)
            .unwrap_or(false)
    })
}

fn agentd_to_io_error(err: AgentdError) -> std::io::Error {
    std::io::Error::other(err.to_string())
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
    let tx_output = tx.clone();
    let read_result = tokio::task::spawn_blocking(move || {
        // PTY masters are safer with a dedicated blocking read loop than with
        // edge-driven readiness. Fast writers followed by process exit can
        // strand the tail behind a missed wakeup/HUP transition.
        let raw = master_fd.as_raw_fd();
        let flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
        if flags >= 0 {
            unsafe { libc::fcntl(raw, libc::F_SETFL, flags & !libc::O_NONBLOCK) };
        }

        loop {
            let mut buf = [0u8; 4096];
            let n = unsafe { libc::read(raw, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };

            if n > 0 {
                if tx_output
                    .send((id, SessionOutput::Stdout(buf[..n as usize].to_vec())))
                    .is_err()
                {
                    break;
                }
                continue;
            }

            if n == 0 {
                break;
            }

            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::EIO) => break,
                _ => break,
            }
        }
    })
    .await;

    let _ = read_result;

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

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::time::timeout;

    use microsandbox_protocol::exec::ExecRequest;

    use super::*;

    #[tokio::test]
    async fn test_pty_reader_drains_ready_fd() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let req = ExecRequest {
            cmd: "/bin/sh".to_string(),
            args: vec![
                "-c".to_string(),
                "i=0; while [ $i -lt 1024 ]; do printf AAAA; i=$((i+1)); done; printf SECOND; sleep 1; printf '<END>\\n'; sleep 1; exit 0"
                    .to_string(),
            ],
            env: vec!["PATH=/usr/local/bin:/usr/bin:/bin".to_string()],
            cwd: None,
            user: None,
            tty: true,
            rows: 24,
            cols: 80,
            rlimits: Vec::new(),
        };

        let session = ExecSession::spawn(7, &req, tx).expect("spawn pty session");
        let mut stdout = Vec::new();
        let mut exit = None;

        let recv_result = timeout(Duration::from_secs(5), async {
            while let Some((id, output)) = rx.recv().await {
                assert_eq!(id, 7);
                match output {
                    SessionOutput::Stdout(data) => stdout.extend_from_slice(&data),
                    SessionOutput::Exited(code) => {
                        exit = Some(code);
                        break;
                    }
                    SessionOutput::Stderr(_) | SessionOutput::Raw(_) => {}
                }
            }
        })
        .await;

        if recv_result.is_err() {
            let _ = session.send_signal(libc::SIGKILL);
            panic!("timed out waiting for PTY output");
        }

        assert_eq!(exit, Some(0));

        let second = stdout
            .windows(b"SECOND".len())
            .position(|window| window == b"SECOND");
        let end = stdout
            .windows(b"<END>".len())
            .position(|window| window == b"<END>");

        assert!(
            matches!((second, end), (Some(second), Some(end)) if second < end),
            "expected immediate PTY write to arrive before later output; got {:?}",
            String::from_utf8_lossy(&stdout),
        );
    }

    #[test]
    fn test_resolve_user_spec_for_current_uid_gid() {
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        let resolved = resolve_user_spec(&format!("{uid}:{gid}")).expect("resolve numeric user");
        assert_eq!(resolved.uid, uid);
        assert_eq!(resolved.gid, gid);
    }

    #[test]
    fn test_request_user_overrides_env_default() {
        unsafe {
            std::env::set_var(microsandbox_protocol::ENV_USER, "0:0");
        }

        let req = ExecRequest {
            cmd: "/bin/true".to_string(),
            args: Vec::new(),
            env: Vec::new(),
            cwd: None,
            user: Some("1:1".to_string()),
            tty: false,
            rows: 24,
            cols: 80,
            rlimits: Vec::new(),
        };

        let resolved = resolve_requested_user(&req).expect("resolve requested user");
        assert_eq!(resolved.unwrap().uid, 1);

        unsafe {
            std::env::remove_var(microsandbox_protocol::ENV_USER);
        }
    }

    #[test]
    fn test_default_home_dir_uses_resolved_user_home() {
        let req = ExecRequest {
            cmd: "/bin/true".to_string(),
            args: Vec::new(),
            env: Vec::new(),
            cwd: None,
            user: None,
            tty: false,
            rows: 24,
            cols: 80,
            rlimits: Vec::new(),
        };
        let user = ResolvedUser {
            uid: 1000,
            gid: 1000,
            initgroups_user: None,
            home_dir: Some(CString::new("/home/tester").unwrap()),
        };

        assert_eq!(
            default_home_dir(&req, Some(&user)).map(CStr::to_string_lossy),
            Some("/home/tester".into()),
        );
    }

    #[test]
    fn test_default_home_dir_respects_explicit_home_env() {
        let req = ExecRequest {
            cmd: "/bin/true".to_string(),
            args: Vec::new(),
            env: vec!["HOME=/tmp/custom".to_string()],
            cwd: None,
            user: None,
            tty: false,
            rows: 24,
            cols: 80,
            rlimits: Vec::new(),
        };
        let user = ResolvedUser {
            uid: 1000,
            gid: 1000,
            initgroups_user: None,
            home_dir: Some(CString::new("/home/tester").unwrap()),
        };

        assert!(default_home_dir(&req, Some(&user)).is_none());
    }

    #[tokio::test]
    async fn test_spawn_pipe_error_does_not_include_probe_details() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let req = ExecRequest {
            cmd: "/definitely/not/a/real/binary".to_string(),
            args: Vec::new(),
            env: Vec::new(),
            cwd: None,
            user: None,
            tty: false,
            rows: 24,
            cols: 80,
            rlimits: Vec::new(),
        };

        let err = ExecSession::spawn(9, &req, tx).expect_err("spawn should fail");
        let message = err.to_string();

        assert!(message.contains("spawn pipe"));
        assert!(!message.contains("symlink_metadata="));
        assert!(!message.contains("metadata="));
        assert!(!message.contains("magic="));
        assert!(!message.contains("path_probe="));
        assert!(!message.contains("cwd_probe="));
        assert!(!message.contains("target_probe="));
    }
}
