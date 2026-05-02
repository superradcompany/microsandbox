//! PID 1 handoff to a guest init.
//!
//! After [`init::init`] returns, agentd may be configured to hand off
//! PID 1 to a user-supplied init binary (typically `systemd`, but any
//! init works). This module implements the fork+exec dance:
//!
//! - **Parent** keeps PID 1 (execve preserves it), execs the target
//!   init, and is supervised by the kernel as the new PID 1.
//! - **Child** continues as a normal grandchild process and runs the
//!   agent loop, serving host requests over virtio-serial.
//!
//! The handoff happens before any tokio runtime is built and before
//! virtio-serial is opened, keeping the fork single-threaded and
//! free of duplicated runtime state.
//!
//! [`init::init`]: crate::init::init
//!
//! ### Performance constraint
//!
//! The fork point relies on agentd's RSS being tiny (<5MB) so
//! copy-on-write page-table duplication is cheap (~1µs/page). If
//! agentd ever grows large in-memory caches before this point, fork
//! cost scales linearly with mapped memory. Keep init::init light and
//! don't move the fork point later.

use std::ffi::{CString, OsString};
use std::fs::OpenOptions;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::process;

use nix::sys::signal::{SigSet, SigmaskHow, Signal, sigprocmask};
use nix::unistd::{ForkResult, fork};

use crate::config::HandoffInit;
use crate::error::{AgentdError, AgentdResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Post-handoff agentd stderr log path.
///
/// Without this redirect, agentd and the new init both write to the VM
/// serial console and their output interleaves. The directory is
/// created in `init::init` (see `create_run_dir`).
const POST_HANDOFF_STDERR: &str = "/run/microsandbox/agentd.log";

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Forks and execs the configured init binary, returning to the caller
/// only in the child process.
///
/// In the **parent** (which becomes the new PID 1), this function calls
/// `execve` and never returns on success. On execve failure, it writes
/// to the console and exits non-zero — the kernel panics PID 1, the
/// VMM exits, and the host hits its connect timeout. The pre-flight
/// check below makes this rare.
///
/// In the **child**, this function redirects stderr to a log file and
/// returns `Ok(())`, after which the caller falls through to the
/// runtime build and the agent loop.
pub fn do_handoff(spec: HandoffInit) -> AgentdResult<()> {
    preflight(&spec.program)?;

    let argv = build_argv(&spec.program, &spec.argv);
    let envp = build_envp(&spec.env);
    let program_c = path_to_cstring(&spec.program)?;

    // SAFETY: `fork()` in a single-threaded process with no opened
    // serial fds and no async runtime. The agent loop has not started
    // yet; tls/init writes are complete; only stdin/stdout/stderr are
    // inherited from the kernel.
    match unsafe { fork() }? {
        ForkResult::Parent { .. } => {
            // We are now the new PID 1's pre-image. Restore default
            // signal disposition + clear blocked mask before exec so
            // the new init starts with kernel defaults.
            reset_signals();
            // SAFETY: arrays are NUL-terminated; pointers live until
            // execve consumes them or returns with an error.
            let err = nix::unistd::execve(&program_c, &argv, &envp).unwrap_err();
            // Past this point, exec has failed. Write a diagnostic to
            // the kernel console and exit non-zero so the kernel
            // panics PID 1 and the VMM tears the guest down.
            let _ = writeln!(
                std::io::stderr(),
                "agentd: execve({}) failed: {err}",
                spec.program.display()
            );
            process::exit(127);
        }
        ForkResult::Child => {
            redirect_child_stderr();
            Ok(())
        }
    }
}

/// Verifies the init binary exists and is executable. Runs in the
/// parent (pre-fork) so failures surface via the normal init-failure
/// path rather than a kernel panic on PID 1 exit.
fn preflight(program: &Path) -> AgentdResult<()> {
    let metadata = std::fs::metadata(program).map_err(|e| {
        AgentdError::Init(format!(
            "handoff init binary not found at {}: {e}",
            program.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(AgentdError::Init(format!(
            "handoff init path is not a regular file: {}",
            program.display()
        )));
    }
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o111 == 0 {
        return Err(AgentdError::Init(format!(
            "handoff init binary is not executable: {}",
            program.display()
        )));
    }
    Ok(())
}

/// Builds the C argv list for execve.
///
/// `argv[0]` is the program path itself; supplemental args follow.
fn build_argv(program: &Path, supplemental: &[OsString]) -> Vec<CString> {
    let mut out = Vec::with_capacity(1 + supplemental.len());
    out.push(path_to_cstring_lossy(program));
    for arg in supplemental {
        out.push(osstring_to_cstring_lossy(arg.clone()));
    }
    out
}

/// Builds the C envp list: inherited env + spec.env, with later
/// entries overriding earlier ones by key.
fn build_envp(extras: &[(OsString, OsString)]) -> Vec<CString> {
    use std::collections::BTreeMap;

    let mut env: BTreeMap<OsString, OsString> = std::env::vars_os().collect();

    // Strip our own boot params from the inherited env so the new
    // init doesn't see stale MSB_* values that referred to agentd's
    // boot, not its own runtime.
    for var in [
        microsandbox_protocol::ENV_HANDOFF_INIT,
        microsandbox_protocol::ENV_HANDOFF_INIT_ARGS,
        microsandbox_protocol::ENV_HANDOFF_INIT_ENV,
    ] {
        env.remove(&OsString::from(var));
    }

    for (k, v) in extras {
        env.insert(k.clone(), v.clone());
    }

    env.into_iter()
        .map(|(k, v)| {
            let mut bytes = k.into_vec();
            bytes.push(b'=');
            bytes.extend(v.into_vec());
            CString::new(bytes).unwrap_or_else(|_| {
                // NUL byte in env value — drop it. CString::new only
                // fails on interior NULs which can't appear in valid
                // env vars; treat as a defensive default.
                CString::new("").unwrap()
            })
        })
        .collect()
}

/// Converts a `Path` to a `CString` for execve, returning a config
/// error on interior NUL.
fn path_to_cstring(path: &Path) -> AgentdResult<CString> {
    CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| {
        AgentdError::Config(format!("init path contains NUL byte: {}", path.display()))
    })
}

/// Converts a `Path` to a `CString` for argv, replacing interior NULs
/// with `?`. Used past the pre-flight check, where the path has
/// already been validated.
fn path_to_cstring_lossy(path: &Path) -> CString {
    let bytes: Vec<u8> = path
        .as_os_str()
        .as_encoded_bytes()
        .iter()
        .copied()
        .map(|b| if b == 0 { b'?' } else { b })
        .collect();
    CString::new(bytes).expect("NUL stripped above")
}

fn osstring_to_cstring_lossy(s: OsString) -> CString {
    let bytes: Vec<u8> = s
        .into_vec()
        .into_iter()
        .map(|b| if b == 0 { b'?' } else { b })
        .collect();
    CString::new(bytes).expect("NUL stripped above")
}

/// Resets all signal dispositions to SIG_DFL and clears the blocked
/// signal mask so the new init starts with kernel defaults.
fn reset_signals() {
    use nix::sys::signal::{SigHandler, sigaction};
    let dfl = nix::sys::signal::SigAction::new(
        SigHandler::SigDfl,
        nix::sys::signal::SaFlags::empty(),
        SigSet::empty(),
    );
    for signum in 1..=31 {
        // SIGKILL (9) and SIGSTOP (19) cannot be reset, but
        // sigaction returns EINVAL silently — ignore.
        let Ok(sig) = Signal::try_from(signum) else {
            continue;
        };
        // SAFETY: setting SIG_DFL is always safe.
        let _ = unsafe { sigaction(sig, &dfl) };
    }
    let empty = SigSet::empty();
    let _ = sigprocmask(SigmaskHow::SIG_SETMASK, Some(&empty), None);
}

/// Redirects the child's stderr to the post-handoff log file. Best
/// effort — a failure here just leaves stderr pointing at the serial
/// console (interleaved with the new init's output). The agent loop
/// keeps working either way.
fn redirect_child_stderr() {
    let Ok(file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(POST_HANDOFF_STDERR)
    else {
        return;
    };
    // SAFETY: dup2 onto stderr (fd=2) is well-defined; the source fd
    // is owned by `file` until the function returns.
    unsafe {
        libc::dup2(file.as_raw_fd(), libc::STDERR_FILENO);
    }
}

/// Returns true when the current process is PID 1 in its PID
/// namespace. After handoff, agentd is no longer PID 1, and any code
/// path that relied on that (e.g. `reboot()`) needs to take a different
/// route.
pub fn is_pid_1() -> bool {
    nix::unistd::getpid().as_raw() == 1
}

/// Sends `SIGRTMIN+4` to PID 1 to request shutdown.
///
/// systemd interprets this as "start poweroff.target". Other inits
/// typically default-handle it as "exit cleanly," which causes the
/// kernel to panic on PID 1 exit and triggers VMM shutdown.
///
/// `SIGRTMIN` is a function on Linux (glibc reserves the first few
/// RT signals for libc internals), so the value is computed at
/// runtime via `libc::SIGRTMIN()`.
pub fn signal_init_shutdown() -> AgentdResult<()> {
    let sig = libc::SIGRTMIN() + 4;
    // SAFETY: kill(2) is signal-safe and pid=1 is always valid.
    let ret = unsafe { libc::kill(1, sig) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

/// Sends `SIGTERM` to PID 1 as a sysvinit-friendly shutdown fallback.
pub fn signal_init_term() -> AgentdResult<()> {
    let ret = unsafe { libc::kill(1, libc::SIGTERM) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

/// Convert a `PathBuf` to a `String` for diagnostic messages where
/// non-UTF8 paths are unlikely.
#[allow(dead_code)]
fn pathbuf_display(p: &PathBuf) -> String {
    p.display().to_string()
}
