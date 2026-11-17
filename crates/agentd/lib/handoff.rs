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
//! The handoff happens before any tokio runtime is built. The already-open
//! virtio-console descriptor is close-on-exec, so the new PID 1 does not
//! inherit it while the agent child keeps serving the host connection.
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
use std::fs::{Metadata, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::process;
use std::time::Duration;

use nix::sys::signal::{SigSet, SigmaskHow, Signal, sigprocmask};
use nix::unistd::{ForkResult, fork, setsid};

use microsandbox_protocol::{HANDOFF_INIT_AUTO, HANDOFF_INIT_AUTO_CANDIDATES};

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

/// Status file that reports which signals PID 1 handles.
const INIT_STATUS_PATH: &str = "/proc/1/status";

/// Link to the program running as PID 1.
const INIT_EXE_PATH: &str = "/proc/1/exe";

/// File name of the multi-call binary that provides BusyBox init.
const BUSYBOX_NAME: &str = "busybox";

/// Delay between repeats of a shutdown request PID 1 could not yet receive.
const INIT_SHUTDOWN_RETRY_INTERVAL: Duration = Duration::from_millis(100);

/// How many times to repeat a shutdown request PID 1 could not yet receive.
const INIT_SHUTDOWN_RETRIES: u32 = 50;

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
    let cmd = resolve_cmd(&spec.cmd)?;
    preflight(&cmd)?;
    if let Some(ref cwd) = spec.cwd {
        preflight_cwd(cwd)?;
    }

    let argv = build_argv(&cmd, &spec.argv);
    let envp = build_envp(&spec.env);
    let cmd_c = path_to_cstring(&cmd)?;

    // SAFETY: `fork()` runs while agentd is still single-threaded and before
    // any async runtime exists. The console fd is close-on-exec in the parent
    // and intentionally retained by the child for the agent loop.
    match unsafe { fork() }? {
        ForkResult::Parent { .. } => {
            // We are now the new PID 1's pre-image. Restore default
            // signal disposition + clear blocked mask before exec so
            // the new init starts with kernel defaults.
            reset_signals();
            if let Some(ref cwd) = spec.cwd
                && let Err(err) = nix::unistd::chdir(cwd)
            {
                let _ = writeln!(
                    std::io::stderr(),
                    "agentd: chdir({}) before handoff failed: {err}",
                    cwd.display()
                );
                process::exit(126);
            }
            // SAFETY: arrays are NUL-terminated; pointers live until
            // execve consumes them or returns with an error.
            let err = nix::unistd::execve(&cmd_c, &argv, &envp).unwrap_err();
            // Past this point, exec has failed. Write a diagnostic to
            // the kernel console and exit non-zero so the kernel
            // panics PID 1 and the VMM tears the guest down.
            let _ = writeln!(
                std::io::stderr(),
                "agentd: execve({}) failed: {err}",
                cmd.display()
            );
            process::exit(127);
        }
        ForkResult::Child => {
            isolate_child_from_init()?;
            redirect_child_stderr();
            Ok(())
        }
    }
}

/// Resolves the user-supplied cmd, expanding the `auto` sentinel
/// into the first executable regular file from
/// [`HANDOFF_INIT_AUTO_CANDIDATES`].
///
/// Non-`auto` paths are returned unchanged; downstream `preflight`
/// validates them.
fn resolve_cmd(cmd: &Path) -> AgentdResult<PathBuf> {
    if cmd != Path::new(HANDOFF_INIT_AUTO) {
        return Ok(cmd.to_path_buf());
    }

    resolve_auto_cmd(HANDOFF_INIT_AUTO_CANDIDATES)
}

fn resolve_auto_cmd(candidates: &[&str]) -> AgentdResult<PathBuf> {
    for candidate in candidates {
        let p = Path::new(candidate);
        if init_candidate_is_executable_file(p) {
            return Ok(p.to_path_buf());
        }
    }

    Err(AgentdError::Init(format!(
        "{HANDOFF_INIT_AUTO}: no init binary found, checked: {}",
        candidates.join(", ")
    )))
}

/// Verifies the init binary exists and is executable. Runs in the
/// parent (pre-fork) so failures surface via the normal init-failure
/// path rather than a kernel panic on PID 1 exit.
fn preflight(cmd: &Path) -> AgentdResult<()> {
    let metadata = std::fs::metadata(cmd).map_err(|e| {
        AgentdError::Init(format!(
            "handoff init binary not found at {}: {e}",
            cmd.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(AgentdError::Init(format!(
            "handoff init path is not a regular file: {}",
            cmd.display()
        )));
    }
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o111 == 0 {
        return Err(AgentdError::Init(format!(
            "handoff init binary is not executable: {}",
            cmd.display()
        )));
    }
    Ok(())
}

fn preflight_cwd(cwd: &Path) -> AgentdResult<()> {
    let metadata = std::fs::metadata(cwd).map_err(|e| {
        AgentdError::Init(format!(
            "handoff init cwd not found at {}: {e}",
            cwd.display()
        ))
    })?;
    if !metadata.is_dir() {
        return Err(AgentdError::Init(format!(
            "handoff init cwd is not a directory: {}",
            cwd.display()
        )));
    }
    Ok(())
}

fn init_candidate_is_executable_file(path: &Path) -> bool {
    std::fs::metadata(path)
        .map(|metadata| metadata_is_executable_file(&metadata))
        .unwrap_or(false)
}

fn metadata_is_executable_file(metadata: &Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;

    metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
}

/// Builds the C argv list for execve.
///
/// `argv[0]` is the cmd path itself; supplemental args follow.
/// argv values come from the host SDK's validated wire format and from
/// the cmd path which `path_to_cstring` already screens for NUL, so
/// the [`CString::new`] calls here are infallible in practice. Any
/// NUL-bearing value is silently skipped rather than corrupting argv.
fn build_argv(cmd: &Path, supplemental: &[OsString]) -> Vec<CString> {
    let mut out = Vec::with_capacity(1 + supplemental.len());
    if let Ok(c) = CString::new(cmd.as_os_str().as_encoded_bytes()) {
        out.push(c);
    }
    for arg in supplemental {
        if let Ok(c) = CString::new(arg.as_bytes()) {
            out.push(c);
        }
    }
    out
}

/// Builds the C envp list: inherited env + spec.env, with later
/// entries overriding earlier ones by key. Order is unspecified
/// (execve doesn't care).
///
/// Entries whose `KEY=VALUE` encoding contains a NUL byte are skipped
/// rather than substituted — a malformed entry would confuse the new
/// init in subtle ways.
fn build_envp(extras: &[(OsString, OsString)]) -> Vec<CString> {
    use std::collections::HashMap;

    let mut env: HashMap<OsString, OsString> = std::env::vars_os().collect();

    for (k, v) in extras {
        env.insert(k.clone(), v.clone());
    }

    env.into_iter()
        .filter_map(|(k, v)| {
            let mut bytes = k.into_vec();
            bytes.push(b'=');
            bytes.extend(v.into_vec());
            CString::new(bytes).ok()
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

/// Moves the surviving agentd process into a new session so init
/// systems that manage their original session/process group do not
/// accidentally signal the agent relay.
fn isolate_child_from_init() -> AgentdResult<()> {
    setsid().map_err(|e| AgentdError::Init(format!("failed to isolate agentd session: {e}")))?;
    Ok(())
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

/// Asks PID 1 to shut down with a signal it can receive.
///
/// The kernel drops signals PID 1 neither handles nor blocks, so the request has to match
/// the init. systemd powers off on `SIGRTMIN+4`, BusyBox init on `SIGUSR2`, and other inits
/// conventionally treat `SIGTERM` as the shutdown request. Inits that collect signals with
/// `sigwait`, such as tini, receive the default signal and pass it to their child.
///
/// A short-lived workload can finish while the init is still starting, before it can
/// receive anything. The same request is repeated in the background until the init shows it
/// can receive it, or the retries run out. Repeating never escalates: the init still owns
/// the shutdown.
///
/// `SIGRTMIN` is a function on Linux (glibc reserves the first few
/// RT signals for libc internals), so the value is computed at
/// runtime via `libc::SIGRTMIN()`.
pub fn request_init_shutdown() -> AgentdResult<()> {
    if send_init_shutdown_signal()? {
        return Ok(());
    }

    std::thread::Builder::new()
        .name("init-shutdown".into())
        .spawn(|| {
            for _ in 0..INIT_SHUTDOWN_RETRIES {
                std::thread::sleep(INIT_SHUTDOWN_RETRY_INTERVAL);
                if !matches!(send_init_shutdown_signal(), Ok(false)) {
                    return;
                }
            }
        })?;

    Ok(())
}

/// Sends the shutdown request once. Returns whether PID 1 showed it can receive the signal.
fn send_init_shutdown_signal() -> AgentdResult<bool> {
    let handled = std::fs::read_to_string(INIT_STATUS_PATH)
        .ok()
        .and_then(|status| parse_handled_signals(&status));
    let init_is_busybox = std::fs::read_link(INIT_EXE_PATH)
        .is_ok_and(|exe| exe.file_name() == Some(BUSYBOX_NAME.as_ref()));
    let sig = select_init_shutdown_signal(handled, init_is_busybox, libc::SIGRTMIN() + 4);

    // SAFETY: kill(2) is signal-safe and pid=1 is always valid.
    let ret = unsafe { libc::kill(1, sig) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    Ok(handled.is_some_and(|mask| handles_signal(mask, sig)))
}

/// Reads the signals a process catches or blocks from `/proc/<pid>/status` text.
fn parse_handled_signals(status: &str) -> Option<u64> {
    let mask = |field: &str| {
        let value = status.lines().find_map(|line| line.strip_prefix(field))?;
        u64::from_str_radix(value.trim(), 16).ok()
    };

    Some(mask("SigCgt:")? | mask("SigBlk:")?)
}

/// Whether a signal mask includes `signal`. Bit zero of the mask is signal 1.
fn handles_signal(handled: u64, signal: libc::c_int) -> bool {
    (1..=64).contains(&signal) && handled & (1 << (signal - 1)) != 0
}

/// Chooses the shutdown request for PID 1.
///
/// BusyBox init is matched by name because `/proc` hides the signals it is waiting for in
/// `sigtimedwait`. Anything else unknown keeps the default request.
fn select_init_shutdown_signal(
    handled: Option<u64>,
    init_is_busybox: bool,
    default_signal: libc::c_int,
) -> libc::c_int {
    let handles = |signal| handled.is_some_and(|mask| handles_signal(mask, signal));

    if handles(default_signal) {
        default_signal
    } else if init_is_busybox {
        libc::SIGUSR2
    } else if handles(libc::SIGTERM) {
        libc::SIGTERM
    } else {
        default_signal
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "microsandbox-agentd-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp test dir");
        dir
    }

    const RT_SHUTDOWN: libc::c_int = 39;

    fn mask(signals: &[libc::c_int]) -> u64 {
        signals
            .iter()
            .fold(0, |mask, signal| mask | 1 << (signal - 1))
    }

    #[test]
    fn parses_handled_signals_from_proc_status() {
        // Taken from a running systemd, which blocks its shutdown signals and reads them from
        // a signalfd, so they appear in SigBlk rather than SigCgt.
        let status = "Name:\tsystemd\nSigBlk:\t7fe3c0fe28014a03\nSigCgt:\t00000000000004ec\n";

        let handled = parse_handled_signals(status).unwrap();

        assert!(handles_signal(handled, RT_SHUTDOWN));
        assert!(handles_signal(handled, libc::SIGTERM));
        assert!(!handles_signal(handled, libc::SIGSTOP));
    }

    #[test]
    fn rejects_unreadable_proc_status() {
        assert_eq!(parse_handled_signals("Name:\tinit\n"), None);
        assert_eq!(parse_handled_signals("SigBlk:\t0\n"), None);
        assert_eq!(
            parse_handled_signals("SigBlk:\t0\nSigCgt:\tnot-hex\n"),
            None
        );
    }

    #[test]
    fn a_starting_init_cannot_receive_shutdown_signals() {
        let status = "SigBlk:\t0000000000000000\nSigCgt:\t0000000000000000\n";

        let handled = parse_handled_signals(status).unwrap();

        assert!(!handles_signal(handled, RT_SHUTDOWN));
        assert_eq!(
            select_init_shutdown_signal(Some(handled), false, RT_SHUTDOWN),
            RT_SHUTDOWN
        );
    }

    #[test]
    fn rejects_out_of_range_signals() {
        assert!(!handles_signal(u64::MAX, 0));
        assert!(!handles_signal(u64::MAX, 65));
    }

    #[test]
    fn shutdown_keeps_the_default_signal_for_inits_that_handle_it() {
        let handled = mask(&[libc::SIGTERM, libc::SIGUSR2, RT_SHUTDOWN]);

        assert_eq!(
            select_init_shutdown_signal(Some(handled), false, RT_SHUTDOWN),
            RT_SHUTDOWN
        );
        assert_eq!(
            select_init_shutdown_signal(Some(handled), true, RT_SHUTDOWN),
            RT_SHUTDOWN
        );
    }

    #[test]
    fn shutdown_uses_poweroff_signal_for_busybox_init() {
        // Taken from a running BusyBox init, which only installs a handler for SIGTSTP.
        let handled = mask(&[libc::SIGTSTP]);

        assert_eq!(
            select_init_shutdown_signal(Some(handled), true, RT_SHUTDOWN),
            libc::SIGUSR2
        );
        assert_eq!(
            select_init_shutdown_signal(None, true, RT_SHUTDOWN),
            libc::SIGUSR2
        );
    }

    #[test]
    fn shutdown_uses_sigterm_for_other_inits_that_handle_it() {
        let handled = mask(&[libc::SIGTERM, libc::SIGUSR2]);

        assert_eq!(
            select_init_shutdown_signal(Some(handled), false, RT_SHUTDOWN),
            libc::SIGTERM
        );
    }

    #[test]
    fn shutdown_keeps_the_default_signal_when_init_handlers_are_unknown() {
        assert_eq!(
            select_init_shutdown_signal(None, false, RT_SHUTDOWN),
            RT_SHUTDOWN
        );
        assert_eq!(
            select_init_shutdown_signal(Some(0), false, RT_SHUTDOWN),
            RT_SHUTDOWN
        );
    }

    #[test]
    fn resolve_cmd_passes_explicit_path_through() {
        let p = Path::new("/lib/systemd/systemd");
        let resolved = resolve_cmd(p).unwrap();
        assert_eq!(resolved, PathBuf::from("/lib/systemd/systemd"));
    }

    #[test]
    fn resolve_cmd_passes_through_non_existent_explicit_paths() {
        // Resolution intentionally doesn't `stat` non-`auto` paths;
        // `preflight` is responsible for that. This keeps the resolver
        // testable without a real filesystem layout.
        let p = Path::new("/no/such/init");
        let resolved = resolve_cmd(p).unwrap();
        assert_eq!(resolved, PathBuf::from("/no/such/init"));
    }

    #[test]
    fn resolve_cmd_auto_returns_first_existing_candidate_or_errors() {
        // Whichever happens on the host running the test: at least one
        // of the candidates likely exists on a real Linux box, but the
        // test box may also be macOS where none do. Either branch is
        // a valid outcome — assert only that the API behaves correctly.
        match resolve_cmd(Path::new(HANDOFF_INIT_AUTO)) {
            Ok(p) => {
                assert!(
                    HANDOFF_INIT_AUTO_CANDIDATES
                        .iter()
                        .any(|c| Path::new(c) == p),
                    "resolved path {p:?} not in candidate list"
                );
                assert!(p.exists(), "resolved path must exist");
            }
            Err(AgentdError::Init(msg)) => {
                assert!(msg.contains("no init binary found"));
                for c in HANDOFF_INIT_AUTO_CANDIDATES {
                    assert!(msg.contains(c), "error should list {c}");
                }
            }
            Err(e) => panic!("unexpected error variant: {e}"),
        }
    }

    #[test]
    fn resolve_auto_cmd_skips_non_executable_candidates() {
        use std::os::unix::fs::PermissionsExt;

        let dir = unique_test_dir("auto-skip");
        let non_executable = dir.join("sbin-init");
        let executable = dir.join("systemd");

        std::fs::write(&non_executable, b"not executable").expect("write non-executable");
        std::fs::set_permissions(&non_executable, std::fs::Permissions::from_mode(0o644))
            .expect("chmod non-executable");
        std::fs::write(&executable, b"#!/bin/sh\n").expect("write executable");
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755))
            .expect("chmod executable");

        let candidates = [
            non_executable.to_str().expect("utf-8 temp path"),
            executable.to_str().expect("utf-8 temp path"),
        ];
        let resolved = resolve_auto_cmd(&candidates).expect("resolve executable candidate");

        assert_eq!(resolved, executable);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
