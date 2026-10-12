//! Host-side per-sandbox IPC endpoint paths and lifecycle cleanup.

#[cfg(unix)]
use std::ffi::{CStr, CString};
use std::fmt::{self, Write as _};
#[cfg(any(unix, windows))]
use std::fs::File;
#[cfg(unix)]
use std::fs::{DirBuilder, OpenOptions};
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::time::Duration;

use sha2::{Digest, Sha256};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Bytes of SHA-256 used by the canonical per-sandbox socket directory.
pub const CANONICAL_SOCKET_HASH_BYTES: usize = 12;

/// Bytes of SHA-256 used by the legacy flat agent socket names.
pub const LEGACY_SOCKET_HASH_BYTES: usize = 16;

/// Total budget shared by every endpoint check in one liveness probe.
#[cfg(unix)]
const ENDPOINT_PROBE_BUDGET: Duration = Duration::from_millis(50);

/// Delay before retrying a connect that found the listener queue full.
#[cfg(unix)]
const ENDPOINT_PROBE_RETRY_DELAY: Duration = Duration::from_millis(5);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Run-directory socket paths for one sandbox; empty on Windows, which uses named pipes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeSocketPaths {
    #[cfg(unix)]
    run_dir: PathBuf,
    /// Canonical directory containing the sandbox's runtime sockets.
    #[cfg(unix)]
    pub canonical_dir: PathBuf,
    /// Canonical agent relay socket.
    #[cfg(unix)]
    pub agent: PathBuf,
    /// Canonical host-control socket.
    #[cfg(unix)]
    pub control: PathBuf,
    /// Legacy flat agent socket path used by older clients.
    #[cfg(unix)]
    pub legacy_agent: PathBuf,
    /// Legacy flat control socket path used by older clients.
    #[cfg(unix)]
    pub legacy_control: PathBuf,
}

/// All runtime endpoints for a sandbox, including its historical storage paths.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxSocketPaths {
    /// Canonical and flat legacy endpoints in the host run directory.
    pub runtime: RuntimeSocketPaths,
    /// Historical agent endpoint inside the sandbox storage directory.
    #[cfg(unix)]
    pub fallback_agent: PathBuf,
    /// Historical control endpoint inside the sandbox storage directory.
    #[cfg(unix)]
    pub fallback_control: PathBuf,
}

/// Cross-process ownership guard for one sandbox's runtime lifecycle.
///
/// On Unix the guard is an advisory `flock` held by the underlying open file
/// description. Launchers may duplicate the descriptor into the sandbox
/// process; closing the launcher's copy then preserves ownership in the child
/// until it exits, including after `SIGKILL`. On Windows the sandbox process
/// acquires a `LockFileEx` byte-range lock itself and retains this file for its
/// entire runtime generation.
///
/// Availability fences this lock, not every other inherited descriptor: Unix process-exit
/// cleanup can release it before deferred disk/KVM teardown finishes. Callers that need disks
/// reusable must also observe the appropriate disk ownership guards.
pub struct SandboxLifecycleGuard {
    #[cfg(unix)]
    file: File,
    #[cfg(windows)]
    _file: File,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RuntimeSocketPaths {
    /// Derive the canonical and flat legacy paths within a host run directory.
    pub fn new(run_dir: &Path, name: &str) -> Self {
        #[cfg(unix)]
        {
            let digest = Sha256::digest(name.as_bytes());
            let canonical_id = encode_hash(&digest, CANONICAL_SOCKET_HASH_BYTES);
            let legacy_id = encode_hash(&digest, LEGACY_SOCKET_HASH_BYTES);
            let canonical_dir = run_dir.join("sandboxes").join(canonical_id);
            let agent = canonical_dir.join("agent.sock");
            let control = control_socket_path_for(&agent);
            let legacy_agent = run_dir.join("agent").join(format!("{legacy_id}.sock"));
            let legacy_control = control_socket_path_for(&legacy_agent);

            Self {
                run_dir: run_dir.to_path_buf(),
                canonical_dir,
                agent,
                control,
                legacy_agent,
                legacy_control,
            }
        }
        #[cfg(not(unix))]
        {
            let _ = (run_dir, name);
            Self {}
        }
    }

    /// Iterate over every socket endpoint, excluding its containing directory.
    #[cfg(unix)]
    pub fn endpoints(&self) -> impl Iterator<Item = &Path> {
        let Self {
            run_dir: _,
            canonical_dir: _,
            agent,
            control,
            legacy_agent,
            legacy_control,
        } = self;
        [
            agent.as_path(),
            control.as_path(),
            legacy_agent.as_path(),
            legacy_control.as_path(),
        ]
        .into_iter()
    }

    /// Prepare the canonical socket directory when `agent_sock` uses that layout.
    #[cfg(unix)]
    pub fn prepare_canonical_directory(&self, agent_sock: &Path) -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt;

        if agent_sock != self.agent {
            return Ok(());
        }

        let parent = self.canonical_dir.parent().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "canonical socket directory has no parent: {}",
                    self.canonical_dir.display()
                ),
            )
        })?;
        std::fs::create_dir_all(parent)?;
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        match builder.create(&self.canonical_dir) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let metadata = std::fs::symlink_metadata(&self.canonical_dir)?;
                if !metadata.is_dir() || metadata.file_type().is_symlink() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        format!(
                            "canonical socket path is not a directory: {}",
                            self.canonical_dir.display()
                        ),
                    ));
                }
            }
            Err(error) => return Err(error),
        }
        std::fs::set_permissions(&self.canonical_dir, std::fs::Permissions::from_mode(0o700))
    }

    /// Publish the legacy agent symlink for an already-bound runtime endpoint.
    #[cfg(unix)]
    pub fn publish_legacy_agent_link(&self, agent_sock: &Path) -> std::io::Result<()> {
        if agent_sock == self.legacy_agent {
            // An older launcher asks the new runtime to bind the compatibility
            // path directly. The endpoint already satisfies that client contract.
            return Ok(());
        }
        validate_compatibility_path(&self.legacy_agent)?;
        publish_compatibility_link(&self.run_dir, &self.legacy_agent, agent_sock)
    }

    /// Publish the legacy control symlink for an already-bound runtime endpoint.
    #[cfg(unix)]
    pub fn publish_legacy_control_link(&self, control_sock: &Path) -> std::io::Result<()> {
        if control_sock == self.legacy_control {
            return Ok(());
        }
        validate_compatibility_path(&self.legacy_control)?;
        publish_compatibility_link(&self.run_dir, &self.legacy_control, control_sock)
    }

    /// Remove canonical and flat compatibility artifacts, attempting both after an error.
    /// Does nothing on Windows, where named pipes leave no socket files.
    pub fn remove_artifacts(&self) -> std::io::Result<()> {
        #[cfg(unix)]
        {
            let legacy_result = self.remove_legacy_artifacts();
            let canonical_result = self.remove_canonical_artifacts();
            legacy_result.and(canonical_result)
        }
        #[cfg(not(unix))]
        {
            Ok(())
        }
    }

    /// Remove only the canonical socket directory and its endpoints.
    /// Does nothing on Windows.
    pub fn remove_canonical_artifacts(&self) -> std::io::Result<()> {
        #[cfg(unix)]
        {
            let Some(run) = open_directory(&self.run_dir)? else {
                return Ok(());
            };
            let Some(sandboxes) = open_owned_child_directory(&run, c"sandboxes", &self.run_dir)?
            else {
                return Ok(());
            };
            let hash = c_path_name(&self.canonical_dir)?;
            let canonical = match open_child_directory(&sandboxes, &hash) {
                Ok(Some(directory)) => directory,
                Ok(None) => return Ok(()),
                Err(error)
                    if matches!(
                        error.raw_os_error(),
                        Some(libc::ELOOP) | Some(libc::ENOTDIR)
                    ) =>
                {
                    // The hash entry is not a directory. Remove that exact entry via
                    // the already-open parent without following a possible symlink.
                    return unlinkat_if_exists(&sandboxes, &hash, 0);
                }
                Err(error) => return Err(error),
            };

            let control_result = unlinkat_if_exists(&canonical, c"control.sock", 0);
            let agent_result = unlinkat_if_exists(&canonical, c"agent.sock", 0);
            control_result.and(agent_result)?;
            unlinkat_if_exists(&sandboxes, &hash, libc::AT_REMOVEDIR)
        }
        #[cfg(not(unix))]
        {
            Ok(())
        }
    }

    /// Remove the flat compatibility endpoints.
    #[cfg(unix)]
    fn remove_legacy_artifacts(&self) -> std::io::Result<()> {
        let Some(run) = open_directory(&self.run_dir)? else {
            return Ok(());
        };
        let Some(agent) = open_owned_child_directory(&run, c"agent", &self.run_dir)? else {
            return Ok(());
        };

        let control = c_path_name(&self.legacy_control)?;
        let relay = c_path_name(&self.legacy_agent)?;
        let control_result = unlinkat_if_exists(&agent, &control, 0);
        let relay_result = unlinkat_if_exists(&agent, &relay, 0);
        control_result.and(relay_result)
    }
}

impl SandboxSocketPaths {
    /// Derive all endpoints using the host run directory and this sandbox's storage directory.
    pub fn new(run_dir: &Path, sandbox_dir: &Path, name: &str) -> Self {
        let runtime = RuntimeSocketPaths::new(run_dir, name);
        #[cfg(not(unix))]
        let _ = sandbox_dir;
        #[cfg(unix)]
        let fallback_agent = sandbox_dir.join("runtime").join("agent.sock");
        #[cfg(unix)]
        let fallback_control = control_socket_path_for(&fallback_agent);
        Self {
            runtime,
            #[cfg(unix)]
            fallback_agent,
            #[cfg(unix)]
            fallback_control,
        }
    }

    /// Derive all endpoints for the sandbox stored under `sandboxes_dir` as `name`.
    pub fn in_sandboxes_dir(run_dir: &Path, sandboxes_dir: &Path, name: &str) -> Self {
        Self::new(run_dir, &sandboxes_dir.join(name), name)
    }

    /// Iterate over all current and historical endpoints in preference order.
    #[cfg(unix)]
    pub fn endpoints(&self) -> impl Iterator<Item = &Path> {
        // No `..`: adding a field requires explicitly updating endpoint enumeration.
        let Self {
            runtime,
            fallback_agent,
            fallback_control,
        } = self;
        runtime
            .endpoints()
            .chain([fallback_agent.as_path(), fallback_control.as_path()])
    }

    /// Remove current and historical socket artifacts, attempting both after an error.
    /// Does nothing on Windows, where named pipes leave no socket files.
    pub fn remove_artifacts(&self) -> std::io::Result<()> {
        let runtime_result = self.runtime.remove_artifacts();
        #[cfg(unix)]
        let fallback_result = remove_socket_pair(&self.fallback_agent);
        #[cfg(not(unix))]
        let fallback_result = Ok(());
        runtime_result.and(fallback_result)
    }

    /// Whether any endpoint may still belong to a live runtime.
    ///
    /// Call while holding launcher and lifecycle ownership. Older Unix runtimes predate those locks, so probe before reaping a start without a run record.
    ///
    /// Every endpoint check shares one 50 ms budget. A timeout returns `true` so callers preserve the status and artifacts for a later retry. Uncertain I/O errors are propagated.
    #[cfg(unix)]
    pub async fn may_be_live(&self) -> std::io::Result<bool> {
        let probe = async {
            for path in self.endpoints() {
                if endpoint_answers(path).await? {
                    return Ok(true);
                }
            }

            Ok(false)
        };

        match tokio::time::timeout(ENDPOINT_PROBE_BUDGET, probe).await {
            Ok(result) => result,
            Err(_) => {
                tracing::debug!(
                    endpoint_dir = %self.runtime.canonical_dir.display(),
                    "runtime endpoint probe timed out; retaining start"
                );
                Ok(true)
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl fmt::Debug for SandboxLifecycleGuard {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SandboxLifecycleGuard")
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Derive the canonical agent endpoint for a sandbox name.
pub fn canonical_agent_endpoint(run_dir: &Path, name: &str) -> PathBuf {
    #[cfg(unix)]
    {
        RuntimeSocketPaths::new(run_dir, name).agent
    }

    #[cfg(windows)]
    {
        let _ = run_dir;
        PathBuf::from(format!(
            r"\\.\pipe\msb-agent-{}",
            socket_hash(name, LEGACY_SOCKET_HASH_BYTES)
        ))
    }
}

/// Derive the stable lifecycle-lock path for one sandbox name.
pub fn lifecycle_lock_path(run_dir: &Path, name: &str) -> PathBuf {
    let digest = Sha256::digest(name.as_bytes());
    let id = encode_hash(&digest, LEGACY_SOCKET_HASH_BYTES);
    run_dir.join("locks").join(format!("{id}.lock"))
}

/// Acquire exclusive lifecycle ownership, waiting for a current owner to exit.
pub fn acquire_lifecycle_guard(
    run_dir: &Path,
    name: &str,
) -> std::io::Result<SandboxLifecycleGuard> {
    #[cfg(unix)]
    {
        acquire_lifecycle_guard_unix(run_dir, name, false)?.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                format!("sandbox {name:?} lifecycle is currently owned"),
            )
        })
    }

    #[cfg(windows)]
    {
        let path = lifecycle_lock_path(run_dir, name);
        let parent = path.parent().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("lifecycle lock has no parent: {}", path.display()),
            )
        })?;
        std::fs::create_dir_all(parent)?;
        let file = microsandbox_utils::process_lock::open_lock_file(&path)?;
        microsandbox_utils::process_lock::lock_exclusive(&file)?;
        Ok(SandboxLifecycleGuard { _file: file })
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = (run_dir, name);
        Ok(SandboxLifecycleGuard {})
    }
}

/// Stable namespace shared by launchers and read-time recovery.
pub fn sandbox_transition_lock_path(run_dir: &Path, name: &str) -> PathBuf {
    let digest = Sha256::digest(name.as_bytes());
    run_dir
        .join("creation-locks")
        .join(format!("{}.lock", hex::encode(&digest[..16])))
}

/// Claim a name transition without waiting; a live creator must never be reaped as abandoned.
pub fn try_acquire_transition_guard(run_dir: &Path, name: &str) -> std::io::Result<Option<File>> {
    let path = sandbox_transition_lock_path(run_dir, name);
    std::fs::create_dir_all(path.parent().expect("transition path has parent"))?;
    let file = microsandbox_utils::process_lock::open_lock_file(&path)?;
    if microsandbox_utils::process_lock::try_lock_exclusive(&file)? {
        Ok(Some(file))
    } else {
        Ok(None)
    }
}

/// Stable capture-publication ownership, outside the removable source directory.
pub fn snapshot_lineage_lock_path(run_dir: &Path, name: &str) -> PathBuf {
    lifecycle_lock_path(run_dir, name).with_extension("snapshot-lineage.lock")
}

/// Claim source publication ownership without waiting, including from a runtime exit observer.
pub fn try_acquire_snapshot_lineage_guard(
    run_dir: &Path,
    name: &str,
) -> std::io::Result<Option<File>> {
    let path = snapshot_lineage_lock_path(run_dir, name);
    std::fs::create_dir_all(path.parent().expect("lineage lock path has parent"))?;
    let file = microsandbox_utils::process_lock::open_lock_file(&path)?;
    if microsandbox_utils::process_lock::try_lock_exclusive(&file)? {
        Ok(Some(file))
    } else {
        Ok(None)
    }
}

/// Try to acquire exclusive lifecycle ownership without blocking.
pub fn try_acquire_lifecycle_guard(
    run_dir: &Path,
    name: &str,
) -> std::io::Result<Option<SandboxLifecycleGuard>> {
    #[cfg(unix)]
    {
        acquire_lifecycle_guard_unix(run_dir, name, true)
    }

    #[cfg(windows)]
    {
        let path = lifecycle_lock_path(run_dir, name);
        let parent = path.parent().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("lifecycle lock has no parent: {}", path.display()),
            )
        })?;
        std::fs::create_dir_all(parent)?;
        let file = microsandbox_utils::process_lock::open_lock_file(&path)?;
        if microsandbox_utils::process_lock::try_lock_exclusive(&file)? {
            Ok(Some(SandboxLifecycleGuard { _file: file }))
        } else {
            Ok(None)
        }
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = (run_dir, name);
        Ok(Some(SandboxLifecycleGuard {}))
    }
}

#[cfg(unix)]
impl SandboxLifecycleGuard {
    /// Adopt a descriptor that already owns the sandbox lifecycle lock.
    ///
    /// This is used only for the descriptor inherited from the SDK launcher.
    pub fn from_inherited_file(file: File) -> Self {
        Self { file }
    }

    /// Return the descriptor to duplicate into a sandbox child process.
    pub fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

/// Derive the control endpoint belonging to an agent endpoint.
pub fn control_socket_path_for(agent_sock: &Path) -> PathBuf {
    #[cfg(unix)]
    if is_canonical_agent_socket(agent_sock) {
        return agent_sock.with_file_name("control.sock");
    }

    agent_sock.with_extension(crate::control::CONTROL_SOCKET_EXTENSION)
}

/// Return whether a Unix socket path fits the platform `sockaddr_un` field.
#[cfg(unix)]
pub fn socket_path_fits(path: &Path) -> bool {
    socket_path_len(path) < unix_socket_path_capacity()
}

/// Validate both endpoints in an agent/control socket pair.
#[cfg(unix)]
pub fn validate_socket_pair(agent_sock: &Path) -> std::io::Result<()> {
    let control_sock = control_socket_path_for(agent_sock);
    for path in [agent_sock, control_sock.as_path()] {
        if !socket_path_fits(path) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "Unix socket path is too long: {} bytes at {}; paths must be shorter than {} bytes",
                    socket_path_len(path),
                    path.display(),
                    unix_socket_path_capacity()
                ),
            ));
        }
    }
    Ok(())
}

/// Remove one agent/control socket pair, treating missing files as success.
pub fn remove_socket_pair(agent_sock: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        if is_canonical_agent_socket(agent_sock) {
            return remove_canonical_socket_pair(agent_sock);
        }
        if is_legacy_agent_socket(agent_sock) {
            return remove_legacy_socket_pair(agent_sock);
        }

        let control_sock = control_socket_path_for(agent_sock);
        let control_result = remove_file_if_exists(&control_sock);
        let agent_result = remove_file_if_exists(agent_sock);
        control_result.and(agent_result)
    }

    #[cfg(windows)]
    {
        let _ = agent_sock;
        Ok(())
    }
}

#[cfg(unix)]
fn publish_compatibility_link(run_dir: &Path, link: &Path, target: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::symlink;

    let parent = link.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("compatibility link has no parent: {}", link.display()),
        )
    })?;
    std::fs::create_dir_all(parent)?;

    // Prefer a relative target for endpoints under the same run directory so
    // compatibility links do not bake the absolute MSB_HOME into the tree.
    let link_target = target
        .strip_prefix(run_dir)
        .map(|relative| PathBuf::from("..").join(relative))
        .unwrap_or_else(|_| target.to_path_buf());

    match symlink(&link_target, link) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if std::fs::symlink_metadata(link)?.file_type().is_symlink()
                && std::fs::read_link(link)? == link_target
            {
                return Ok(());
            }

            // Publication is deliberately no-replace. Lifecycle cleanup owns
            // stale files; startup must never unlink a possibly-live legacy
            // endpoint merely because the sandbox name matches.
            Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!(
                    "legacy runtime endpoint already exists at {}",
                    link.display()
                ),
            ))
        }
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn acquire_lifecycle_guard_unix(
    run_dir: &Path,
    name: &str,
    nonblocking: bool,
) -> std::io::Result<Option<SandboxLifecycleGuard>> {
    let path = lifecycle_lock_path(run_dir, name);
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("lifecycle lock has no parent: {}", path.display()),
        )
    })?;
    std::fs::create_dir_all(parent)?;
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)?;
    let operation = libc::LOCK_EX | if nonblocking { libc::LOCK_NB } else { 0 };
    if unsafe { libc::flock(file.as_raw_fd(), operation) } == 0 {
        return Ok(Some(SandboxLifecycleGuard { file }));
    }

    let error = std::io::Error::last_os_error();
    if nonblocking && error.kind() == std::io::ErrorKind::WouldBlock {
        return Ok(None);
    }
    Err(error)
}

#[cfg(unix)]
fn validate_compatibility_path(path: &Path) -> std::io::Result<()> {
    if socket_path_fits(path) {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "legacy Unix socket path is too long: {} bytes at {}; paths must be shorter than {} bytes",
                socket_path_len(path),
                path.display(),
                unix_socket_path_capacity()
            ),
        ))
    }
}

#[cfg(windows)]
fn socket_hash(name: &str, bytes: usize) -> String {
    encode_hash(&Sha256::digest(name.as_bytes()), bytes)
}

fn encode_hash(digest: &[u8], bytes: usize) -> String {
    let mut hash = String::with_capacity(bytes * 2);
    for byte in digest.iter().take(bytes) {
        let _ = write!(hash, "{byte:02x}");
    }
    hash
}

#[cfg(unix)]
fn is_canonical_agent_socket(path: &Path) -> bool {
    let Some(id) = path
        .parent()
        .and_then(Path::file_name)
        .and_then(|id| id.to_str())
    else {
        return false;
    };

    path.file_name().is_some_and(|name| name == "agent.sock")
        && path
            .parent()
            .and_then(Path::parent)
            .and_then(Path::file_name)
            .is_some_and(|name| name == "sandboxes")
        && id.len() == CANONICAL_SOCKET_HASH_BYTES * 2
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(unix)]
fn is_legacy_agent_socket(path: &Path) -> bool {
    let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
        return false;
    };

    path.parent()
        .and_then(Path::file_name)
        .is_some_and(|name| name == "agent")
        && path
            .extension()
            .is_some_and(|extension| extension == "sock")
        && stem.len() == LEGACY_SOCKET_HASH_BYTES * 2
        && stem
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(unix)]
fn remove_file_if_exists(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn remove_canonical_socket_pair(agent_sock: &Path) -> std::io::Result<()> {
    let canonical_path = agent_sock.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "canonical socket has no directory: {}",
                agent_sock.display()
            ),
        )
    })?;
    let run_dir = canonical_path
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "canonical socket has no run directory: {}",
                    agent_sock.display()
                ),
            )
        })?;
    let Some(run) = open_directory(run_dir)? else {
        return Ok(());
    };
    let Some(sandboxes) = open_owned_child_directory(&run, c"sandboxes", run_dir)? else {
        return Ok(());
    };
    let hash = c_path_name(canonical_path)?;
    let Some(canonical) =
        open_owned_child_directory(&sandboxes, &hash, &run_dir.join("sandboxes"))?
    else {
        return Ok(());
    };

    let control_result = unlinkat_if_exists(&canonical, c"control.sock", 0);
    let agent_result = unlinkat_if_exists(&canonical, c"agent.sock", 0);
    control_result.and(agent_result)
}

#[cfg(unix)]
fn remove_legacy_socket_pair(agent_sock: &Path) -> std::io::Result<()> {
    let agent_path = agent_sock.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("legacy socket has no directory: {}", agent_sock.display()),
        )
    })?;
    let run_dir = agent_path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "legacy socket has no run directory: {}",
                agent_sock.display()
            ),
        )
    })?;
    let Some(run) = open_directory(run_dir)? else {
        return Ok(());
    };
    let Some(agent) = open_owned_child_directory(&run, c"agent", run_dir)? else {
        return Ok(());
    };

    let control = c_path_name(&control_socket_path_for(agent_sock))?;
    let relay = c_path_name(agent_sock)?;
    let control_result = unlinkat_if_exists(&agent, &control, 0);
    let relay_result = unlinkat_if_exists(&agent, &relay, 0);
    control_result.and(relay_result)
}

#[cfg(unix)]
fn open_directory(path: &Path) -> std::io::Result<Option<File>> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC);
    match options.open(path) {
        Ok(directory) => Ok(Some(directory)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn open_owned_child_directory(
    parent: &File,
    name: &CStr,
    run_dir: &Path,
) -> std::io::Result<Option<File>> {
    match open_child_directory(parent, name) {
        Ok(directory) => Ok(directory),
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(libc::ELOOP) | Some(libc::ENOTDIR)
            ) =>
        {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "runtime IPC directory is not an owned directory: {}",
                    run_dir
                        .join(std::ffi::OsStr::from_bytes(name.to_bytes()))
                        .display()
                ),
            ))
        }
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn open_child_directory(parent: &File, name: &CStr) -> std::io::Result<Option<File>> {
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd >= 0 {
        return Ok(Some(unsafe { File::from_raw_fd(fd) }));
    }

    let error = std::io::Error::last_os_error();
    if error.kind() == std::io::ErrorKind::NotFound {
        Ok(None)
    } else {
        Err(error)
    }
}

#[cfg(unix)]
fn unlinkat_if_exists(parent: &File, name: &CStr, flags: i32) -> std::io::Result<()> {
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), flags) } == 0 {
        return Ok(());
    }

    let error = std::io::Error::last_os_error();
    if error.kind() == std::io::ErrorKind::NotFound {
        Ok(())
    } else {
        Err(error)
    }
}

#[cfg(unix)]
fn c_path_name(path: &Path) -> std::io::Result<CString> {
    let name = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("runtime IPC path has no file name: {}", path.display()),
        )
    })?;
    CString::new(name.as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("runtime IPC file name contains NUL: {}", path.display()),
        )
    })
}

/// Whether a live runtime answers at one endpoint path.
///
/// Absent, malformed and unaddressable paths answer `false`: nothing can
/// be listening there. A full listener queue is retried instead, so a busy
/// runtime still counts as live; the caller's deadline bounds those retries.
#[cfg(unix)]
async fn endpoint_answers(path: &Path) -> std::io::Result<bool> {
    use std::io::ErrorKind;

    // Files can exist here even when the path cannot address a Unix socket.
    if !socket_path_fits(path) {
        return Ok(false);
    }

    if let Err(error) = tokio::fs::symlink_metadata(path).await {
        // No endpoint can be reached through a malformed directory entry.
        // Cleanup can remove the entry without following it.
        if error.kind() == ErrorKind::NotFound
            || matches!(error.raw_os_error(), Some(libc::ENOTDIR | libc::ELOOP))
        {
            return Ok(false);
        }

        return Err(endpoint_error("inspect", path, error));
    }

    loop {
        match tokio::net::UnixStream::connect(path).await {
            Ok(_) => return Ok(true),
            // Linux reports a full listener queue as EAGAIN rather than a
            // pending connection. Yield and retry within the same budget.
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                tokio::time::sleep(ENDPOINT_PROBE_RETRY_DELAY).await;
            }
            // Nothing is accepting here, so the artifact is a leftover.
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::ConnectionRefused | ErrorKind::NotFound
                ) || matches!(
                    error.raw_os_error(),
                    Some(libc::ENOTSOCK | libc::EPROTOTYPE | libc::ELOOP | libc::ENOTDIR)
                ) =>
            {
                return Ok(false);
            }
            Err(error) => return Err(endpoint_error("connect to", path, error)),
        }
    }
}

/// Name the failing operation and endpoint while keeping the original error kind.
#[cfg(unix)]
fn endpoint_error(operation: &str, path: &Path, error: std::io::Error) -> std::io::Error {
    std::io::Error::new(
        error.kind(),
        format!("{operation} runtime endpoint {}: {error}", path.display()),
    )
}

#[cfg(unix)]
fn socket_path_len(path: &Path) -> usize {
    use std::os::unix::ffi::OsStrExt;

    path.as_os_str().as_bytes().len()
}

#[cfg(unix)]
fn unix_socket_path_capacity() -> usize {
    let storage = unsafe { std::mem::zeroed::<libc::sockaddr_un>() };
    storage.sun_path.len()
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Keep a task runnable so Tokio does not advance the paused clock while
    // real filesystem work runs on the blocking pool. Only deadline tests advance time.
    #[cfg(unix)]
    async fn probe_without_advancing_clock(paths: &SandboxSocketPaths) -> std::io::Result<bool> {
        let probe = paths.may_be_live();
        tokio::pin!(probe);
        let started = std::time::Instant::now();
        loop {
            assert!(
                started.elapsed() < std::time::Duration::from_secs(5),
                "endpoint probe stalled with the clock paused"
            );
            tokio::select! {
                biased;
                result = &mut probe => return result,
                () = tokio::task::yield_now() => {}
            }
        }
    }

    #[cfg(unix)]
    #[tokio::test(start_paused = true)]
    async fn endpoint_probe_covers_current_and_legacy_paths() {
        let home = tempfile::tempdir_in("/tmp").unwrap();
        let run_dir = home.path().join("run");
        let sandbox_dir = home.path().join("sandbox");
        let paths = RuntimeSocketPaths::new(&run_dir, "worker");
        let probe_paths = SandboxSocketPaths::new(&run_dir, &sandbox_dir, "worker");
        let fallback = sandbox_dir.join("runtime/agent.sock");
        for path in [
            paths.agent,
            paths.control,
            paths.legacy_agent,
            paths.legacy_control,
            control_socket_path_for(&fallback),
            fallback,
        ] {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
            assert!(probe_without_advancing_clock(&probe_paths).await.unwrap());
            listener.set_nonblocking(true).unwrap();
            listener.accept().unwrap();
            drop(listener);
            assert!(!probe_without_advancing_clock(&probe_paths).await.unwrap());
            std::fs::remove_file(&path).unwrap();
            std::fs::write(&path, b"stale artifact").unwrap();
            assert!(!probe_without_advancing_clock(&probe_paths).await.unwrap());
            std::fs::remove_file(&path).unwrap();
            // Final symlinks pass symlink_metadata; connect must reject their targets.
            std::os::unix::fs::symlink(&path, &path).unwrap();
            assert!(!probe_without_advancing_clock(&probe_paths).await.unwrap());
            std::fs::remove_file(&path).unwrap();
            let non_directory = home.path().join("not-a-directory");
            std::fs::write(&non_directory, b"file").unwrap();
            std::os::unix::fs::symlink(non_directory.join("agent.sock"), &path).unwrap();
            assert!(!probe_without_advancing_clock(&probe_paths).await.unwrap());
            std::fs::remove_file(&path).unwrap();
        }

        // A malformed canonical directory must not prevent legacy recovery.
        let canonical_dir = &probe_paths.runtime.canonical_dir;
        std::fs::remove_dir(canonical_dir).unwrap();
        std::fs::write(canonical_dir, b"stale directory entry").unwrap();
        assert!(!probe_without_advancing_clock(&probe_paths).await.unwrap());
        std::fs::remove_file(canonical_dir).unwrap();
        std::os::unix::fs::symlink(canonical_dir, canonical_dir).unwrap();
        assert!(!probe_without_advancing_clock(&probe_paths).await.unwrap());
        probe_paths.remove_artifacts().unwrap();
        assert!(std::fs::symlink_metadata(canonical_dir).is_err());
    }

    #[cfg(unix)]
    #[tokio::test(start_paused = true)]
    async fn endpoint_probe_skips_overlong_paths_and_checks_reachable_fallback() {
        let home = tempfile::tempdir_in("/tmp").unwrap();
        let run_dir = home.path().join("x".repeat(128));
        let paths = SandboxSocketPaths::new(&run_dir, home.path(), "worker");
        std::fs::create_dir_all(&paths.runtime.canonical_dir).unwrap();
        std::fs::write(&paths.runtime.agent, b"stale artifact").unwrap();
        assert!(!probe_without_advancing_clock(&paths).await.unwrap());

        std::fs::create_dir_all(paths.fallback_agent.parent().unwrap()).unwrap();
        let listener = std::os::unix::net::UnixListener::bind(&paths.fallback_agent).unwrap();
        assert!(probe_without_advancing_clock(&paths).await.unwrap());
        listener.set_nonblocking(true).unwrap();
        listener.accept().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn endpoint_probe_timeout_retains_an_uncertain_owner() {
        // The overall deadline is a caller-facing latency contract, so state it
        // independently of the production constant. Widening the budget must
        // fail here rather than silently lengthening this test's wait.
        const EXPECTED_BUDGET: Duration = Duration::from_millis(50);

        let home = tempfile::tempdir_in("/tmp").unwrap();
        let paths = SandboxSocketPaths::new(home.path(), home.path(), "worker");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .start_paused(true)
            .build()
            .unwrap();
        let (release, wait) = std::sync::mpsc::channel();
        let (ready, started) = std::sync::mpsc::channel();
        let blocker = runtime.spawn_blocking(move || {
            ready.send(()).unwrap();
            let _ = wait.recv();
        });
        started.recv().unwrap();
        // A busy filesystem pool delays metadata past the probe's deadline.
        // The caller must return conservatively without waiting for that work.
        let result = runtime.block_on(async {
            let probe = paths.may_be_live();
            tokio::pin!(probe);
            tokio::select! {
                biased;
                result = &mut probe => panic!("probe completed before deadline: {result:?}"),
                () = tokio::task::yield_now() => {}
            }
            tokio::time::advance(EXPECTED_BUDGET).await;
            // The budget has elapsed, so the next poll must already be ready.
            // Never await the probe here: a paused clock auto-advances while
            // idle and would hide a deadline longer than the contract.
            tokio::select! {
                biased;
                result = &mut probe => result,
                () = tokio::task::yield_now() => {
                    panic!("probe still pending after {EXPECTED_BUDGET:?}")
                }
            }
        });
        release.send(()).unwrap();
        runtime.block_on(blocker).unwrap();
        assert!(result.unwrap());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn endpoint_probe_bounds_a_full_listener_queue() {
        let home = tempfile::tempdir_in("/tmp").unwrap();
        let paths = SandboxSocketPaths::new(home.path(), home.path(), "worker");
        let path = &paths.runtime.legacy_agent;
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let listener = std::os::unix::net::UnixListener::bind(path).unwrap();
        // Reduce the real listener backlog so the next connection gets EAGAIN.
        assert_eq!(unsafe { libc::listen(listener.as_raw_fd(), 0) }, 0);
        let _queued = tokio::net::UnixStream::connect(path).await.unwrap();
        assert_eq!(
            tokio::net::UnixStream::connect(path)
                .await
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::WouldBlock,
        );
        let result =
            tokio::time::timeout(std::time::Duration::from_secs(1), paths.may_be_live()).await;
        assert!(result.unwrap().unwrap());
        assert!(path.exists());
        // Free one slot while the next probe is retrying. Verify a new connection
        // actually arrives, so a timeout cannot masquerade as a successful retry.
        listener.set_nonblocking(true).unwrap();
        let drain = async {
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
            listener.accept().unwrap();
        };
        let (result, ()) = tokio::join!(paths.may_be_live(), drain);
        assert!(result.unwrap());
        listener
            .accept()
            .expect("the probe must connect after queue space opens");
        drop(listener);
        tokio::time::pause();
        assert!(!probe_without_advancing_clock(&paths).await.unwrap());
    }

    #[test]
    #[cfg(unix)]
    fn derives_canonical_and_legacy_hashes_from_one_name() {
        let paths = RuntimeSocketPaths::new(Path::new("/tmp/msb/run"), "worker");

        assert_eq!(
            paths.agent,
            Path::new("/tmp/msb/run/sandboxes/87eba76e7f3164534045ba92/agent.sock")
        );
        assert_eq!(
            paths.control,
            Path::new("/tmp/msb/run/sandboxes/87eba76e7f3164534045ba92/control.sock")
        );
        assert_eq!(
            paths.legacy_agent,
            Path::new("/tmp/msb/run/agent/87eba76e7f3164534045ba922e7770fb.sock")
        );
        assert_eq!(
            paths.legacy_control,
            Path::new("/tmp/msb/run/agent/87eba76e7f3164534045ba922e7770fb.control.sock")
        );
        assert_eq!(control_socket_path_for(&paths.agent), paths.control);
        assert_eq!(
            control_socket_path_for(Path::new("/tmp/msb/sandboxes/worker/runtime/agent.sock")),
            Path::new("/tmp/msb/sandboxes/worker/runtime/agent.control.sock")
        );
    }

    #[test]
    #[cfg(unix)]
    fn derives_hashes_from_utf8_name_bytes() {
        let paths = RuntimeSocketPaths::new(Path::new("/tmp/msb/run"), "工作");

        assert_eq!(
            paths.agent,
            Path::new("/tmp/msb/run/sandboxes/bc62d1b6b936c78dbbd0bbe5/agent.sock")
        );
        assert_eq!(
            paths.legacy_agent,
            Path::new("/tmp/msb/run/agent/bc62d1b6b936c78dbbd0bbe5572e32d0.sock")
        );
    }

    #[test]
    fn lifecycle_guard_is_exclusive_and_reusable() {
        let temp = tempfile::tempdir().unwrap();
        let run_dir = temp.path().join("run");
        let owner = acquire_lifecycle_guard(&run_dir, "worker").unwrap();

        assert!(
            try_acquire_lifecycle_guard(&run_dir, "worker")
                .unwrap()
                .is_none(),
            "a second file handle must not acquire an owned runtime generation"
        );
        drop(owner);
        assert!(
            try_acquire_lifecycle_guard(&run_dir, "worker")
                .unwrap()
                .is_some(),
            "dropping the runtime owner must release lifecycle ownership"
        );
    }

    #[test]
    #[cfg(unix)]
    fn lifecycle_guard_remains_owned_by_an_inherited_descriptor() {
        use std::os::fd::FromRawFd;

        let temp = tempfile::Builder::new()
            .prefix("msb-lifecycle")
            .tempdir_in("/tmp")
            .unwrap();
        let run_dir = temp.path().join("run");
        let launcher = acquire_lifecycle_guard(&run_dir, "worker").unwrap();
        let inherited_fd = unsafe { libc::dup(launcher.as_raw_fd()) };
        assert!(inherited_fd >= 0);
        let inherited =
            SandboxLifecycleGuard::from_inherited_file(unsafe { File::from_raw_fd(inherited_fd) });

        assert!(
            try_acquire_lifecycle_guard(&run_dir, "worker")
                .unwrap()
                .is_none()
        );
        drop(launcher);
        assert!(
            try_acquire_lifecycle_guard(&run_dir, "worker")
                .unwrap()
                .is_none(),
            "closing the launcher copy must not unlock the child copy"
        );
        drop(inherited);
        assert!(
            try_acquire_lifecycle_guard(&run_dir, "worker")
                .unwrap()
                .is_some()
        );
    }

    #[test]
    #[cfg(unix)]
    fn validates_the_control_endpoint_at_the_unix_path_boundary() {
        let capacity = unix_socket_path_capacity();
        let accepted = PathBuf::from(format!(
            "/{}.sock",
            "a".repeat(capacity - "/.control.sock".len() - 1)
        ));
        let rejected = PathBuf::from(format!(
            "/{}.sock",
            "a".repeat(capacity - "/.control.sock".len())
        ));

        assert_eq!(
            socket_path_len(&control_socket_path_for(&accepted)),
            capacity - 1
        );
        assert!(validate_socket_pair(&accepted).is_ok());
        assert_eq!(
            socket_path_len(&control_socket_path_for(&rejected)),
            capacity
        );
        assert_eq!(
            validate_socket_pair(&rejected).unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
    }

    #[test]
    #[cfg(unix)]
    fn compatibility_links_reach_canonical_unix_sockets() {
        let temp = tempfile::Builder::new()
            .prefix("msb-ipc")
            .tempdir_in("/tmp")
            .unwrap();
        let run_dir = temp.path().join("run");
        let paths = RuntimeSocketPaths::new(&run_dir, "compat");
        std::fs::create_dir_all(&paths.canonical_dir).unwrap();
        let _agent = std::os::unix::net::UnixListener::bind(&paths.agent).unwrap();
        let _control = std::os::unix::net::UnixListener::bind(&paths.control).unwrap();

        paths.publish_legacy_agent_link(&paths.agent).unwrap();
        paths.publish_legacy_control_link(&paths.control).unwrap();

        assert_eq!(
            std::fs::read_link(&paths.legacy_agent).unwrap(),
            Path::new("../sandboxes")
                .join(paths.canonical_dir.file_name().unwrap())
                .join("agent.sock")
        );
        assert_eq!(
            std::fs::read_link(&paths.legacy_control).unwrap(),
            Path::new("../sandboxes")
                .join(paths.canonical_dir.file_name().unwrap())
                .join("control.sock")
        );
        std::os::unix::net::UnixStream::connect(&paths.legacy_agent).unwrap();
        std::os::unix::net::UnixStream::connect(&paths.legacy_control).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn compatibility_publication_never_replaces_a_live_legacy_socket() {
        let temp = tempfile::Builder::new()
            .prefix("msb-ipc")
            .tempdir_in("/tmp")
            .unwrap();
        let run_dir = temp.path().join("run");
        let paths = RuntimeSocketPaths::new(&run_dir, "collision");
        std::fs::create_dir_all(&paths.canonical_dir).unwrap();
        std::fs::create_dir_all(paths.legacy_agent.parent().unwrap()).unwrap();
        let _canonical = std::os::unix::net::UnixListener::bind(&paths.agent).unwrap();
        let _legacy = std::os::unix::net::UnixListener::bind(&paths.legacy_agent).unwrap();

        let error = paths.publish_legacy_agent_link(&paths.agent).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        std::os::unix::net::UnixStream::connect(&paths.legacy_agent).unwrap();
        assert!(
            !std::fs::symlink_metadata(&paths.legacy_agent)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    #[cfg(unix)]
    fn new_runtime_accepts_legacy_paths_supplied_by_an_old_launcher() {
        let temp = tempfile::Builder::new()
            .prefix("msb-ipc")
            .tempdir_in("/tmp")
            .unwrap();
        let run_dir = temp.path().join("run");
        let paths = RuntimeSocketPaths::new(&run_dir, "old-launcher");
        std::fs::create_dir_all(paths.legacy_agent.parent().unwrap()).unwrap();
        let _agent = std::os::unix::net::UnixListener::bind(&paths.legacy_agent).unwrap();
        let _control = std::os::unix::net::UnixListener::bind(&paths.legacy_control).unwrap();

        paths
            .publish_legacy_agent_link(&paths.legacy_agent)
            .unwrap();
        paths
            .publish_legacy_control_link(&paths.legacy_control)
            .unwrap();

        assert!(
            !std::fs::symlink_metadata(&paths.legacy_agent)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(
            !std::fs::symlink_metadata(&paths.legacy_control)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        std::os::unix::net::UnixStream::connect(&paths.legacy_agent).unwrap();
        std::os::unix::net::UnixStream::connect(&paths.legacy_control).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn sandbox_cleanup_removes_canonical_and_compatibility_artifacts() {
        let temp = tempfile::Builder::new()
            .prefix("msb-ipc")
            .tempdir_in("/tmp")
            .unwrap();
        let run_dir = temp.path().join("run");
        let paths = RuntimeSocketPaths::new(&run_dir, "cleanup");
        std::fs::create_dir_all(&paths.canonical_dir).unwrap();
        let agent = std::os::unix::net::UnixListener::bind(&paths.agent).unwrap();
        let control = std::os::unix::net::UnixListener::bind(&paths.control).unwrap();
        paths.publish_legacy_agent_link(&paths.agent).unwrap();
        paths.publish_legacy_control_link(&paths.control).unwrap();

        paths.remove_artifacts().unwrap();

        assert!(!paths.agent.exists());
        assert!(!paths.control.exists());
        assert!(std::fs::symlink_metadata(&paths.legacy_agent).is_err());
        assert!(std::fs::symlink_metadata(&paths.legacy_control).is_err());
        assert!(!paths.canonical_dir.exists());

        drop((agent, control));
        paths.remove_artifacts().unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn sandbox_cleanup_does_not_follow_a_canonical_directory_symlink() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::Builder::new()
            .prefix("msb-ipc")
            .tempdir_in("/tmp")
            .unwrap();
        let run_dir = temp.path().join("run");
        let paths = RuntimeSocketPaths::new(&run_dir, "symlink");
        let external = temp.path().join("external");
        std::fs::create_dir_all(paths.canonical_dir.parent().unwrap()).unwrap();
        std::fs::create_dir_all(&external).unwrap();
        std::fs::write(external.join("agent.sock"), b"do not remove").unwrap();
        symlink(&external, &paths.canonical_dir).unwrap();

        paths.remove_artifacts().unwrap();

        assert!(external.join("agent.sock").exists());
        assert!(std::fs::symlink_metadata(&paths.canonical_dir).is_err());
    }

    #[test]
    #[cfg(unix)]
    fn sandbox_cleanup_does_not_follow_owned_parent_symlinks() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::Builder::new()
            .prefix("msb-ipc")
            .tempdir_in("/tmp")
            .unwrap();
        let run_dir = temp.path().join("run");
        let paths = RuntimeSocketPaths::new(&run_dir, "parent-symlinks");
        let external_agent = temp.path().join("external-agent");
        let external_sandboxes = temp.path().join("external-sandboxes");
        let external_canonical = external_sandboxes.join(
            paths
                .canonical_dir
                .file_name()
                .expect("canonical directory has a hash name"),
        );
        std::fs::create_dir_all(&run_dir).unwrap();
        std::fs::create_dir_all(&external_agent).unwrap();
        std::fs::create_dir_all(&external_canonical).unwrap();
        let legacy_agent = external_agent.join(paths.legacy_agent.file_name().unwrap());
        let legacy_control = external_agent.join(paths.legacy_control.file_name().unwrap());
        let canonical_agent = external_canonical.join("agent.sock");
        let canonical_control = external_canonical.join("control.sock");
        let _listeners = [
            std::os::unix::net::UnixListener::bind(&legacy_agent).unwrap(),
            std::os::unix::net::UnixListener::bind(&legacy_control).unwrap(),
            std::os::unix::net::UnixListener::bind(&canonical_agent).unwrap(),
            std::os::unix::net::UnixListener::bind(&canonical_control).unwrap(),
        ];
        symlink(&external_agent, run_dir.join("agent")).unwrap();
        symlink(&external_sandboxes, run_dir.join("sandboxes")).unwrap();

        assert_eq!(
            remove_socket_pair(&paths.agent).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
        assert_eq!(
            remove_socket_pair(&paths.legacy_agent).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
        let error = paths.remove_artifacts().unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        for endpoint in [
            legacy_agent,
            legacy_control,
            canonical_agent,
            canonical_control,
        ] {
            assert!(endpoint.exists(), "cleanup followed parent to {endpoint:?}");
        }
    }
}
