//! Sandbox socket discovery, launch endpoints, and artifact cleanup.

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};

use microsandbox_runtime::ipc::SandboxSocketPaths;
#[cfg(windows)]
use windows_sys::Win32::Foundation::HANDLE;
#[cfg(windows)]
use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;

use crate::MicrosandboxResult;
use crate::backend::LocalBackend;
use crate::runtime::launch_contract::LaunchContract;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// What a client-side open of the agent pipe name revealed.
#[cfg(windows)]
enum AgentPipeProbe {
    /// No server instance exists — the name is free to bind.
    Free,

    /// A live server holds the name. The serving PID is best-effort.
    Served { server_pid: Option<u32> },
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl LocalBackend {
    pub(crate) fn agent_socket_paths(&self, name: &str) -> Vec<PathBuf> {
        agent_socket_paths_in(
            &self.config().run_dir(),
            &self.config().sandboxes_dir(),
            name,
        )
    }

    /// Pre-v0.6.9 runtimes derive control paths by replacing the agent extension.
    /// Give them the flat endpoint whose control name discovery already recognizes.
    pub(crate) fn launch_agent_socket_path(
        &self,
        name: &str,
        contract: LaunchContract,
    ) -> MicrosandboxResult<PathBuf> {
        #[cfg(unix)]
        if contract.patch < 9 {
            let paths = SandboxSocketPaths::in_sandboxes_dir(
                &self.config().run_dir(),
                &self.sandboxes_dir(),
                name,
            );
            return select_socket_path(vec![paths.runtime.legacy_agent, paths.fallback_agent]);
        }
        #[cfg(not(unix))]
        let _ = contract;
        self.resolve_agent_socket_path(name)
    }

    /// Pick the first explicit-backend socket path usable on this platform.
    pub(crate) fn resolve_agent_socket_path(&self, name: &str) -> MicrosandboxResult<PathBuf> {
        #[cfg(unix)]
        let candidates = vec![microsandbox_runtime::ipc::canonical_agent_endpoint(
            &self.config().run_dir(),
            name,
        )];
        #[cfg(not(unix))]
        let candidates = self.agent_socket_paths(name);
        select_socket_path(candidates)
    }

    /// Remove every Unix runtime socket artifact deterministically owned by a sandbox.
    pub(crate) fn remove_socket_artifacts(&self, name: &str) -> MicrosandboxResult<()> {
        remove_socket_artifacts_at(
            &self.config().run_dir(),
            &self.config().sandboxes_dir(),
            name,
        )
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Return agent socket paths for the default backend, or the default home when it is cloud.
pub(crate) fn default_agent_socket_paths(name: &str) -> Vec<PathBuf> {
    let backend = crate::backend::default_backend();
    if let Some(local) = backend.as_local() {
        return local.agent_socket_paths(name);
    }

    let home = microsandbox_utils::resolve_home();
    agent_socket_paths_in(
        &home.join(microsandbox_utils::RUN_SUBDIR),
        &home.join(microsandbox_utils::SANDBOXES_SUBDIR),
        name,
    )
}

fn agent_socket_paths_in(run_dir: &Path, sandboxes_dir: &Path, name: &str) -> Vec<PathBuf> {
    // New clients prefer the canonical per-sandbox endpoint, then the flat
    // legacy path used by older runtimes, and finally the pre-hash in-sandbox
    // fallback retained for unusually deep homes. Windows named pipes did not
    // change layout, so the canonical endpoint is the only candidate there.
    #[cfg(unix)]
    let candidates = {
        let paths = SandboxSocketPaths::in_sandboxes_dir(run_dir, sandboxes_dir, name);
        vec![
            paths.runtime.agent,
            paths.runtime.legacy_agent,
            paths.fallback_agent,
        ]
    };
    #[cfg(not(unix))]
    let candidates = {
        let _ = sandboxes_dir;
        vec![microsandbox_runtime::ipc::canonical_agent_endpoint(
            run_dir, name,
        )]
    };

    candidates
}

/// Pick the first socket path usable on this platform.
pub(crate) fn resolve_agent_socket_path(name: &str) -> MicrosandboxResult<PathBuf> {
    let candidates = default_agent_socket_paths(name);

    #[cfg(unix)]
    if let Some(existing) = first_existing_socket_path(&candidates) {
        return Ok(existing);
    }

    select_socket_path(candidates)
}

#[cfg(unix)]
fn first_existing_socket_path(candidates: &[PathBuf]) -> Option<PathBuf> {
    candidates.iter().find(|path| path.exists()).cloned()
}

#[cfg(unix)]
fn select_socket_path(candidates: Vec<PathBuf>) -> MicrosandboxResult<PathBuf> {
    for path in &candidates {
        if microsandbox_runtime::ipc::validate_socket_pair(path).is_ok() {
            return Ok(path.clone());
        }
    }

    let shortest = candidates
        .iter()
        .flat_map(|path| {
            [
                path.as_os_str().as_bytes().len(),
                microsandbox_runtime::ipc::control_socket_path_for(path)
                    .as_os_str()
                    .as_bytes()
                    .len(),
            ]
        })
        .min()
        .unwrap_or(0);

    Err(crate::MicrosandboxError::InvalidConfig(format!(
        "sandbox runtime socket path is too long: shortest derived path is {shortest} bytes, \
         but Unix socket paths on this platform must be shorter than {} bytes; set \
         MSB_HOME to a shorter directory",
        unsafe { std::mem::zeroed::<libc::sockaddr_un>() }
            .sun_path
            .len()
    )))
}

#[cfg(not(unix))]
fn select_socket_path(candidates: Vec<PathBuf>) -> MicrosandboxResult<PathBuf> {
    // Named pipes have no `sun_path`-style length limit, so the primary
    // candidate is always usable.
    candidates.into_iter().next().ok_or_else(|| {
        crate::MicrosandboxError::InvalidConfig(
            "no agent relay socket candidates were derived".to_string(),
        )
    })
}

/// Fail the spawn when another process already serves this sandbox's agent
/// pipe, naming the stale PID so the operator can terminate it.
///
/// Unix sockets are files the new runtime simply unlinks and rebinds; Windows
/// named pipes have no such steal path — the child's `first_pipe_instance`
/// bind would fail deep in boot, and agent clients would keep silently
/// reaching the stale server in the meantime.
#[cfg(windows)]
pub(super) async fn ensure_agent_pipe_unclaimed(
    pipe_path: &Path,
    sandbox_name: &str,
) -> MicrosandboxResult<()> {
    // A just-stopped runtime closes its pipe within moments of its DB row
    // going terminal; retry briefly so stop→start (restart) flows don't trip
    // on ordinary teardown.
    const PROBE_ATTEMPTS: u32 = 10;
    const PROBE_INTERVAL: std::time::Duration = std::time::Duration::from_millis(200);

    let mut last_seen_pid = None;
    for attempt in 0..PROBE_ATTEMPTS {
        match probe_agent_pipe_server(pipe_path) {
            Ok(AgentPipeProbe::Free) => return Ok(()),
            Ok(AgentPipeProbe::Served { server_pid }) => last_seen_pid = server_pid,
            Err(err) => {
                // Unexpected probe failure must not block the spawn — if the
                // name really is taken, the child's first-instance bind fails
                // loudly on its own.
                tracing::debug!(
                    error = %err,
                    pipe = %pipe_path.display(),
                    "agent pipe probe failed; proceeding with spawn"
                );
                return Ok(());
            }
        }
        if attempt + 1 < PROBE_ATTEMPTS {
            tokio::time::sleep(PROBE_INTERVAL).await;
        }
    }

    let pid_note = match last_seen_pid {
        Some(pid) => format!(" (pid {pid})"),
        None => String::new(),
    };
    Err(crate::MicrosandboxError::Runtime(format!(
        "agent pipe {} for sandbox '{sandbox_name}' is already being served by a stale sandbox \
         process{pid_note}; terminate that process and retry",
        pipe_path.display()
    )))
}

#[cfg(windows)]
fn probe_agent_pipe_server(pipe_path: &Path) -> std::io::Result<AgentPipeProbe> {
    const ERROR_PIPE_BUSY: i32 = 231;

    match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(pipe_path)
    {
        Ok(client) => {
            let mut pid = 0u32;
            let ok =
                unsafe { GetNamedPipeServerProcessId(client.as_raw_handle() as HANDLE, &mut pid) };
            Ok(AgentPipeProbe::Served {
                server_pid: (ok != 0).then_some(pid),
            })
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(AgentPipeProbe::Free),
        // Every instance being busy still proves a live server.
        Err(err) if err.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
            Ok(AgentPipeProbe::Served { server_pid: None })
        }
        Err(err) => Err(err),
    }
}

/// Remove runtime socket artifacts using explicit storage roots.
pub(crate) fn remove_socket_artifacts_at(
    run_dir: &Path,
    sandboxes_dir: &Path,
    name: &str,
) -> MicrosandboxResult<()> {
    SandboxSocketPaths::in_sandboxes_dir(run_dir, sandboxes_dir, name).remove_artifacts()?;

    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use microsandbox_runtime::ipc::RuntimeSocketPaths;
    use tempfile::tempdir;

    use crate::backend::LocalBackend;

    #[tokio::test]
    async fn test_agent_socket_candidates_follow_explicit_local_backend_paths() {
        let temp = tempdir().unwrap();
        let home = temp.path().join("msb-home");
        let backend = LocalBackend::builder()
            .config_path(home.join("config.json"))
            .managed_config_path(home.join("managed.json"))
            .home(&home)
            .build()
            .await
            .unwrap();

        let candidates = backend.agent_socket_paths("sdk-socket-test");

        #[cfg(unix)]
        {
            assert_eq!(candidates.len(), 3);
            assert!(candidates[0].starts_with(backend.config().run_dir().join("sandboxes")));
            assert_eq!(candidates[0].file_name().unwrap(), "agent.sock");
            assert!(candidates[1].starts_with(backend.config().run_dir().join("agent")));
            assert_eq!(
                candidates[2],
                backend
                    .config()
                    .sandboxes_dir()
                    .join("sdk-socket-test")
                    .join("runtime")
                    .join("agent.sock")
            );
        }
        #[cfg(windows)]
        {
            assert_eq!(candidates.len(), 1);
            assert!(
                candidates[0]
                    .to_string_lossy()
                    .starts_with(r"\\.\pipe\msb-agent-")
            );
        }
    }

    #[tokio::test]
    async fn test_agent_socket_resolution_uses_explicit_local_backend_paths() {
        // Root the backend home under a short directory so the derived AF_UNIX
        // socket path stays within the platform `sun_path` limit (104 bytes on
        // macOS). The default system temp dir on macOS lives under
        // `/var/folders/...`, long enough to overflow that limit and make
        // resolution fail spuriously. Windows uses named pipes (no length
        // limit), so the default temp dir is fine there.
        #[cfg(unix)]
        let temp = tempfile::Builder::new()
            .prefix("msb")
            .tempdir_in("/tmp")
            .unwrap();
        #[cfg(not(unix))]
        let temp = tempfile::Builder::new().prefix("msb").tempdir().unwrap();
        let home = temp.path().join("msb-home");
        let backend = LocalBackend::builder()
            .config_path(home.join("config.json"))
            .managed_config_path(home.join("managed.json"))
            .home(&home)
            .build()
            .await
            .unwrap();

        let resolved = backend
            .resolve_agent_socket_path("sdk-socket-test")
            .unwrap();

        #[cfg(unix)]
        assert!(resolved.starts_with(backend.config().run_dir().join("sandboxes")));
        #[cfg(windows)]
        assert!(
            resolved
                .to_string_lossy()
                .starts_with(r"\\.\pipe\msb-agent-")
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_new_client_selects_old_runtime_socket_when_canonical_is_absent() {
        let temp = tempfile::Builder::new()
            .prefix("msb-compat")
            .tempdir_in("/tmp")
            .unwrap();
        let run_dir = temp.path().join("run");
        let sandboxes_dir = temp.path().join("sandboxes");
        let paths = RuntimeSocketPaths::new(&run_dir, "old-runtime");
        std::fs::create_dir_all(paths.legacy_agent.parent().unwrap()).unwrap();
        let _listener = std::os::unix::net::UnixListener::bind(&paths.legacy_agent).unwrap();

        let candidates = super::agent_socket_paths_in(&run_dir, &sandboxes_dir, "old-runtime");
        let selected = super::first_existing_socket_path(&candidates).unwrap();

        assert_eq!(selected, paths.legacy_agent);
        std::os::unix::net::UnixStream::connect(selected).unwrap();
    }
}
