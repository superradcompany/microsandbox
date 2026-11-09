//! Inspect independent recovery captures with an isolated, trusted guest reader.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use microsandbox_protocol::storage_preview as wire;
use microsandbox_runtime::checkpoint::migration::{self, CandidateSummary, RecoveryPreview};
use microsandbox_types::{
    DiskImageFormat, MountOptions, OwnedVolumeStorage, SecurityProfile, VolumeMount,
};
use tokio::sync::Mutex;

use super::storage_recovery::{guard_target_storage, with_locked_storage, with_target_locks};
use super::{
    RootDisk, RootfsSource, SandboxBuilder, StorageRecovery, StorageRecoveryOptions,
    StorageRecoverySelection,
};
use crate::backend::{Backend, BackendSelectionSource};
use crate::config::layers::BackendConfig;
use crate::runtime::{
    launch_contract,
    protected_state::{self, StoragePreparation},
};
use crate::sandbox::exec::ExecEvent;
use crate::{LocalBackend, MicrosandboxError, MicrosandboxResult, Sandbox, SandboxConfig};

#[path = "storage_preview_lower.rs"]
mod lower;
pub use wire::StoragePreviewEntry;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A private set of recovery views scoped to one catalog generation and configuration.
#[doc(hidden)]
pub struct StoragePreview {
    name: String,
    backend: Arc<dyn Backend>,
    maintenance: bool,
    candidates: Vec<CandidateSummary>,
    mounts: BTreeMap<String, String>,
    files: Arc<SessionFiles>,
}

struct SessionFiles {
    // Drop private images and their handles before removing their parent on Windows.
    captures: Mutex<RecoveryPreview>,
    lower: Mutex<Option<lower::CapturedLower>>,
    parent: tempfile::TempDir,
    layered: bool,
    manifest: Option<String>,
    cache: PathBuf,
    sources: BackendConfig,
    runtime: crate::setup::ResolvedRuntime,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Sandbox {
    /// Capture all eligible alternatives without changing the target. Inspect any configured
    /// disk independently, then explicitly confirm a complete choice or drop the session.
    #[doc(hidden)]
    pub async fn preview_storage(
        name: &str,
        options: StorageRecoveryOptions,
    ) -> MicrosandboxResult<StoragePreview> {
        if !options.selections.is_empty() {
            return Err(MicrosandboxError::InvalidConfig(
                "choose candidate IDs when confirming the captured views".into(),
            ));
        }
        let backend = crate::backend::default_backend();
        with_target_locks(backend.clone(), name, async |local| {
            let runtime = crate::setup::resolve_runtime(local.config())?;
            launch_contract::require_storage_reader(&runtime.msb_path).await?;
            let parent = migration::private_preview_parent().map_err(unavailable)?;
            let (config, captures) = capture_readonly(local, name, &options, parent.path()).await?;
            let candidates = captures.candidates().to_vec();
            let layered = matches!(
                &config.spec.image,
                RootfsSource::Oci(source) if !matches!(source.root_disk, Some(RootDisk::Flat { .. }))
            );
            let files = SessionFiles {
                captures: Mutex::new(captures),
                lower: Mutex::new(None),
                parent,
                layered,
                manifest: config.manifest_digest.clone(),
                cache: local.config().cache_dir(),
                sources: local.config_sources().clone(),
                runtime,
            };
            Ok(StoragePreview {
                name: name.to_owned(),
                backend: backend.clone(),
                maintenance: options.legacy_writers_stopped,
                candidates,
                mounts: guest_mounts(&config),
                files: Arc::new(files),
            })
        })
        .await
    }
}

impl StoragePreview {
    /// Immutable summaries of the full captured candidate set.
    pub fn candidates(&self) -> &[CandidateSummary] {
        &self.candidates
    }

    /// Guest mount path from the original host configuration for this disk role.
    pub fn guest_mount(&self, disk_id: &str) -> Option<&str> {
        self.mounts.get(disk_id).map(String::as_str)
    }

    /// List the complete bounded directory. Symlinks are reported without being followed.
    pub async fn list(
        &mut self,
        disk_id: &str,
        candidate_id: &str,
        path: &str,
    ) -> MicrosandboxResult<Vec<StoragePreviewEntry>> {
        let bytes = self.query(disk_id, candidate_id, "list", path).await?;
        let entries: Vec<StoragePreviewEntry> =
            serde_json::from_slice(&bytes).map_err(unavailable)?;
        if entries.len() > wire::MAX_ENTRIES
            || entries.iter().any(|e| {
                e.name.is_empty()
                    || e.name.len() > 255
                    || e.name.contains(['/', '\0'])
                    || !matches!(e.kind.as_str(), "file" | "directory" | "symlink" | "other")
            })
        {
            return Err(unavailable("invalid guest directory reply"));
        }
        Ok(entries)
    }

    /// Read one entire regular file up to 64 KiB. Only a proven missing guest path returns ENOENT.
    pub async fn read(
        &mut self,
        disk_id: &str,
        candidate_id: &str,
        path: &str,
    ) -> MicrosandboxResult<Vec<u8>> {
        self.query(disk_id, candidate_id, "read", path).await
    }

    /// Apply the operator's choice after reacquiring the target and revalidating the captured bytes.
    pub async fn confirm(
        self,
        selections: Vec<StorageRecoverySelection>,
    ) -> MicrosandboxResult<StorageRecovery> {
        if selections.is_empty() {
            return Err(MicrosandboxError::InvalidConfig(
                "select a captured view for every disk before confirming".into(),
            ));
        }
        let options = StorageRecoveryOptions {
            selections,
            accept_selected_view: true,
            legacy_writers_stopped: self.maintenance,
        };
        with_locked_storage(
            self.backend.clone(),
            &self.name,
            async |local, config, storage| {
                let captured = self.files.captures.lock().await;
                let lower = self.files.lower.lock().await;
                if let Some(lower) = lower.as_ref() {
                    lower.verify()?;
                }
                protected_state::prepare_storage(
                    local,
                    config,
                    storage,
                    StoragePreparation::Existing,
                    &options,
                    Some(&captured),
                )
                .await?;
                Ok(StorageRecovery {
                    name: self.name.clone(),
                    ready: true,
                    originals_retained: true,
                })
            },
        )
        .await
    }

    async fn query(
        &self,
        disk_id: &str,
        candidate_id: &str,
        operation: &'static str,
        path: &str,
    ) -> MicrosandboxResult<Vec<u8>> {
        if !self
            .candidates
            .iter()
            .any(|c| c.id == candidate_id && c.disk_id == disk_id)
        {
            return Err(unavailable(
                "candidate does not belong to this captured disk",
            ));
        }
        if !path.starts_with('/')
            || path.len() > 4096
            || path.contains('\0')
            || path.split('/').any(|component| component == "..")
        {
            return Err(MicrosandboxError::InvalidConfig(
                "expected an absolute guest path of at most 4096 bytes without parent traversal"
                    .into(),
            ));
        }
        // The owned task retains capture and helper-home ownership if the UI cancels its read.
        // A helper can never outlive its sources or be reused for a different user's query.
        let files = self.files.clone();
        let (disk_id, candidate_id, path) =
            (disk_id.to_owned(), candidate_id.to_owned(), path.to_owned());
        tokio::spawn(async move { run_query(files, disk_id, candidate_id, operation, path).await })
            .await
            .map_err(unavailable)?
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn guest_mounts(config: &SandboxConfig) -> BTreeMap<String, String> {
    let mut mounts = BTreeMap::from([("root".into(), "/".into())]);
    for mount in &config.spec.mounts {
        if let VolumeMount::Owned {
            guest,
            storage: OwnedVolumeStorage::Disk { .. },
            ..
        } = mount
        {
            mounts.insert(
                microsandbox_types::owned_volume_mount_id(guest),
                guest.clone(),
            );
        }
    }
    mounts
}

/// Called with exclusive target transition/lineage/lifecycle ownership. Reading through the
/// released-schema catalog keeps cancelling a browse compatible with the original CLI.
pub(crate) async fn capture_readonly(
    local: &LocalBackend,
    name: &str,
    options: &StorageRecoveryOptions,
    parent: &std::path::Path,
) -> MicrosandboxResult<(SandboxConfig, RecoveryPreview)> {
    let mut db = crate::setup::open_catalog(local.config()).await?;
    let (id, stored, config) = crate::setup::preview_target(&mut db, name).await?;
    let storage = guard_target_storage(local, name, &config).await?;
    let runtime = storage.join("runtime");
    if microsandbox_runtime::checkpoint::layout::require_ready(&runtime).is_ok() {
        return Err(unavailable("protected storage is already ready"));
    }
    protected_state::require_maintenance(options)?;
    let mut bindings = protected_state::bindings(&config, storage.path(), id, &stored)?;
    let _related = crate::runtime::storage_aliases::resolve_with_catalog(
        local,
        id,
        &mut bindings,
        Some(&mut db),
    )
    .await?;
    let (current, raw, current_config) = crate::setup::preview_target(&mut db, name).await?;
    if id != current
        || raw != stored
        || serde_json::to_value(&current_config)? != serde_json::to_value(&config)?
    {
        return Err(unavailable(
            "selected catalog configuration changed before private capture",
        ));
    }
    let capture = protected_state::filesystem_work(name, || {
        migration::capture_preview(&runtime, &bindings, parent)
    })?;
    Ok((config, capture))
}

fn unavailable(error: impl std::fmt::Display) -> MicrosandboxError {
    MicrosandboxError::Runtime(format!("recovery filesystem view unavailable: {error}"))
}

fn read_only_disk(
    host: PathBuf,
    guest: &str,
    format: DiskImageFormat,
    filesystem: &str,
) -> VolumeMount {
    VolumeMount::DiskImage {
        host,
        guest: guest.to_owned(),
        format,
        fstype: Some(filesystem.to_owned()),
        options: MountOptions {
            readonly: true,
            noexec: true,
            nodev: true,
            nosuid: true,
            ..Default::default()
        },
    }
}

async fn run_query(
    files: Arc<SessionFiles>,
    disk: String,
    id: String,
    operation: &str,
    path: String,
) -> MicrosandboxResult<Vec<u8>> {
    let images = files.clone();
    let merged = disk == "root" && files.layered;
    let (image, lower) = tokio::task::spawn_blocking(move || -> MicrosandboxResult<_> {
        let image = images
            .captures
            .blocking_lock()
            .materialize(&disk, &id)
            .map_err(|e| unavailable(format!("materializing private disk: {e}")))?;
        let lower = if merged {
            let mut lower = images.lower.blocking_lock();
            if lower.is_none() {
                let digest = images
                    .manifest
                    .as_deref()
                    .ok_or_else(|| unavailable("the sandbox has no saved OCI manifest digest"))?;
                *lower = Some(lower::CapturedLower::capture(
                    &images.cache,
                    digest,
                    images.parent.path(),
                )?);
            }
            lower.as_ref().map(|v| v.disk.clone())
        } else {
            None
        };
        Ok((image, lower))
    })
    .await
    .map_err(unavailable)??;
    let temp = migration::private_reader_home().map_err(unavailable)?;
    // macOS's normal temporary root starts with the /var system alias. Pass canonical private
    // paths to the strict bind-root validator instead of enabling symlink traversal for it.
    let scratch = reader_path(temp.path())?;
    let home = scratch.join("h");
    let root = scratch.join("root");
    seed_reader_root(&root)?;
    let private_config = files.sources.recovery_reader(&home, &files.runtime)?;
    let local = LocalBackend::from_backend_config(
        private_config,
        BackendSelectionSource::Programmatic,
        None,
    );
    // Bind-root readers never pull an image or provision a disk in this fresh home. Create
    // the collection only; protected state still reserves the named sandbox exclusively.
    std::fs::create_dir_all(local.sandboxes_dir())
        .map_err(|e| unavailable(format!("preparing the private sandbox directory: {e}")))?;
    let mut config = SandboxConfig::default();
    config.spec.name = "storage-reader".into();
    config.spec.image = RootfsSource::Bind {
        path: root,
        follow_root_symlinks: false,
    };
    config.spec.network.enabled = false;
    config.spec.security_profile = SecurityProfile::Restricted;
    config.spec.lifecycle.max_duration_secs = Some(60);
    config.spec.mounts.push(read_only_disk(
        reader_path(&image)?,
        wire::DATA,
        DiskImageFormat::Raw,
        "ext4",
    ));
    if let Some(lower) = lower {
        config.spec.mounts.push(read_only_disk(
            reader_path(&lower)?,
            wire::LOWER,
            DiskImageFormat::Vmdk,
            "erofs",
        ));
    }
    config.storage_reader = Some(merged);
    let effective =
        SandboxBuilder::from(config.clone()).finish_local(local.config_sources(), None)?;
    // Managed policy can restrict the reader. Never let it introduce another root, executable,
    // secret, mount or network connection into a process that receives the captured bytes.
    if effective.storage_reader != Some(merged) || !same_authority(&effective, &config)? {
        return Err(unavailable(
            "managed sandbox policy is incompatible with an isolated read-only reader",
        ));
    }
    let backend: Arc<dyn Backend> = Arc::new(local);
    let vm = crate::backend::with_backend(backend, Sandbox::create(config))
        .await
        .map_err(|e| unavailable(format!("starting isolated reader VM: {e}")))?;
    let result = async {
        let handshake = exchange(&vm, &["handshake"], 256)
            .await
            .map_err(|e| unavailable(format!("probing the embedded reader: {e}")))?;
        if handshake.0 != 0 || handshake.1 != wire::HANDSHAKE.as_bytes() {
            return Err(unavailable(
                "upgrade required: the embedded guest reader protocol is unsupported",
            ));
        }
        let limit = if operation == "read" {
            wire::MAX_FILE
        } else {
            1024 * 1024
        };
        let (status, bytes, stderr) = exchange(
            &vm,
            &[if merged { "merged" } else { "disk" }, operation, &path],
            limit,
        )
        .await
        .map_err(|e| unavailable(format!("querying the mounted guest view: {e}")))?;
        match status {
            0 => Ok(bytes),
            wire::ABSENT => Err(MicrosandboxError::Io(std::io::Error::from(
                std::io::ErrorKind::NotFound,
            ))),
            _ => Err(unavailable(format!(
                "guest reader refused this path ({})",
                String::from_utf8_lossy(&stderr).escape_default()
            ))),
        }
    }
    .await;
    if vm.stop_with_timeout(Duration::from_secs(5)).await.is_err() {
        vm.kill_with_timeout(Duration::from_secs(10))
            .await
            .map_err(|e| unavailable(format!("stopping the private reader VM: {e}")))?;
    }
    result
}

fn same_authority(a: &SandboxConfig, b: &SandboxConfig) -> MicrosandboxResult<bool> {
    let spec = |s: &SandboxConfig| {
        serde_json::json!([
            s.spec.image,
            s.spec.mounts,
            s.spec.network,
            s.spec.vsock,
            s.spec.patches,
            s.spec.init,
            s.spec.env,
            s.spec.runtime.scripts,
            s.spec.runtime.entrypoint,
            s.spec.runtime.cmd,
            s.spec.runtime.user,
            s.spec.security_profile
        ])
    };
    Ok(a.registry_auth.is_none() && spec(a) == spec(b))
}

/// Restricted guest exec resolves UID/GID through the guest account database. Supply only
/// these fixed identities in our fresh root; neither host nor candidate accounts are copied.
fn seed_reader_root(root: &std::path::Path) -> MicrosandboxResult<()> {
    std::fs::create_dir(root).map_err(unavailable)?;
    let etc = root.join("etc");
    std::fs::create_dir(&etc).map_err(unavailable)?;
    std::fs::write(
        etc.join("passwd"),
        b"root:x:0:0:private storage reader:/:/bin/false\n",
    )
    .map_err(unavailable)?;
    std::fs::write(etc.join("group"), b"root:x:0:\n").map_err(unavailable)?;
    Ok(())
}

/// Use the canonical private object with the local-drive spelling accepted by the normal
/// Windows runtime disk grammar. Never strip an arbitrary device or UNC prefix.
fn reader_path(path: &std::path::Path) -> MicrosandboxResult<PathBuf> {
    let canonical = std::fs::canonicalize(path).map_err(unavailable)?;
    #[cfg(windows)]
    {
        use std::path::{Component, Prefix};
        let mut components = canonical.components();
        let Some(Component::Prefix(prefix)) = components.next() else {
            return Err(unavailable("private reader requires a local drive"));
        };
        if let Prefix::VerbatimDisk(letter) = prefix.kind() {
            if components.next() != Some(Component::RootDir) {
                return Err(unavailable("invalid private reader drive path"));
            }
            let mut standard = PathBuf::from(format!("{}:\\", char::from(letter)));
            for component in components {
                let Component::Normal(name) = component else {
                    return Err(unavailable("invalid private reader path component"));
                };
                standard.push(name);
            }
            if std::fs::canonicalize(&standard).map_err(unavailable)? != canonical {
                return Err(unavailable(
                    "private reader path changes under drive normalization",
                ));
            }
            return Ok(standard);
        }
        if !matches!(prefix.kind(), Prefix::Disk(_)) {
            return Err(unavailable("private reader requires a local drive"));
        }
    }
    Ok(canonical)
}

async fn exchange(
    vm: &Sandbox,
    args: &[&str],
    limit: usize,
) -> MicrosandboxResult<(i32, Vec<u8>, Vec<u8>)> {
    let mut handle = vm
        // PID 1 is the exact embedded agent in this VM. Its kernel-pinned executable remains
        // accessible after the bootstrap root is switched out for the empty scratch root.
        .exec_stream_with("/proc/1/exe", |opts| {
            opts.arg(wire::READER_ARG)
                .args(args.iter().copied())
                .cwd("/")
                .stdin_null()
                .timeout(Duration::from_secs(10))
        })
        .await
        .map_err(unavailable)?;
    tokio::time::timeout(Duration::from_secs(15), async {
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        while let Some(event) = handle.recv().await {
            let (target, bytes, bound) = match event {
                ExecEvent::Stdout(bytes) => (&mut stdout, bytes, limit),
                ExecEvent::Stderr(bytes) => (&mut stderr, bytes, 4096),
                ExecEvent::Exited { code } => return Ok((code, stdout, stderr)),
                ExecEvent::Started { .. } => continue,
                ExecEvent::Failed(failure) => {
                    return Err(unavailable(format!(
                        "trusted reader execution failed ({:?}, errno {:?}): {}",
                        failure.kind,
                        failure.errno,
                        failure
                            .message
                            .chars()
                            .take(240)
                            .collect::<String>()
                            .escape_default()
                    )));
                }
                ExecEvent::StdinError(error) => {
                    return Err(unavailable(format!(
                        "trusted reader input failed (errno {:?}): {}",
                        error.errno,
                        error
                            .message
                            .chars()
                            .take(240)
                            .collect::<String>()
                            .escape_default()
                    )));
                }
            };
            if bytes.len() > bound - target.len() {
                return Err(unavailable("guest reply exceeds the inspection limit"));
            }
            target.extend_from_slice(&bytes);
        }
        Err(unavailable("guest reader disconnected"))
    })
    .await
    .map_err(unavailable)?
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{GlobalConfigPatch, PathsConfigPatch};
    use crate::setup::RuntimeOrigin;

    #[cfg(unix)]
    #[tokio::test]
    async fn storage_preview_runtime_without_embedded_reader_fails_before_catalog_or_capture() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let exe = temp.path().join("msb");
        let firmware = temp.path().join("firmware");
        std::fs::write(&exe,b"#!/bin/sh\nprintf '%s\\n' '{\"protocols\":[2],\"protected_guest_state\":true,\"storage_reader\":false}'\n").unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(&firmware, b"unused").unwrap();
        let home = temp.path().join("home");
        let config = BackendConfig::new(
            GlobalConfigPatch::new()
                .home(home.clone())
                .paths(PathsConfigPatch::new().msb(exe).libkrunfw(firmware)),
            Default::default(),
        );
        let backend: Arc<dyn Backend> = Arc::new(LocalBackend::from_backend_config(
            config,
            BackendSelectionSource::Programmatic,
            None,
        ));
        let error = crate::backend::with_backend(
            backend,
            Sandbox::preview_storage("target", Default::default()),
        )
        .await
        .err()
        .expect("old embedded agent accepted");
        assert!(
            error
                .to_string()
                .contains("embedded storage recovery reader")
                && error.to_string().contains("upgrade"),
            "{error}"
        );
        assert!(!home.join(microsandbox_utils::DB_SUBDIR).exists());
        assert!(!home.join(microsandbox_utils::SANDBOXES_SUBDIR).exists());
    }

    #[cfg(unix)]
    #[test]
    fn storage_preview_reader_sockets_fit_with_long_tmpdir() {
        const CHILD: &str = "MSB_TEST_LONG_READER_TEMPDIR";
        if std::env::var_os(CHILD).is_none() {
            let temp = migration::private_preview_parent().unwrap();
            let long = temp.path().join("a".repeat(130));
            std::fs::create_dir(&long).unwrap();
            let status=std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact","sandbox::storage_preview::tests::storage_preview_reader_sockets_fit_with_long_tmpdir"])
                .env(CHILD,"1").env("TMPDIR",long).status().unwrap();
            assert!(status.success());
            return;
        }
        let name = "storage-reader";
        let capture = migration::private_preview_parent().unwrap();
        let long = microsandbox_runtime::ipc::canonical_agent_endpoint(
            &capture.path().join("reader/home/run"),
            name,
        );
        assert!(microsandbox_runtime::ipc::validate_socket_pair(&long).is_err());
        let home = migration::private_reader_home().unwrap();
        let short = microsandbox_runtime::ipc::canonical_agent_endpoint(
            &std::fs::canonicalize(home.path()).unwrap().join("h/run"),
            name,
        );
        microsandbox_runtime::ipc::validate_socket_pair(&short).unwrap();
    }

    #[test]
    fn storage_preview_preserves_process_local_reader_and_rejects_managed_redirection() {
        let parent = tempfile::tempdir().unwrap();
        let scratch = reader_path(parent.path()).unwrap();
        std::fs::create_dir(scratch.join("empty")).unwrap();
        std::fs::write(scratch.join("disk"), [0; 512]).unwrap();
        let home = scratch.join("home");
        let runtime = crate::setup::ResolvedRuntime {
            msb_path: parent.path().join("msb"),
            libkrunfw_path: parent.path().join("fw"),
            origin: RuntimeOrigin::Configuration,
        };
        let sources = BackendConfig::new(
            GlobalConfigPatch::new().home(parent.path().join("user-home")),
            Default::default(),
        );
        let private = sources.recovery_reader(&home, &runtime).unwrap();
        assert_eq!(private.resolved_config().home(), home);
        let mut config = SandboxConfig::default();
        config.spec.name = "storage-reader".into();
        config.storage_reader = Some(false);
        config.spec.image = RootfsSource::Bind {
            path: scratch.join("empty"),
            follow_root_symlinks: false,
        };
        config.spec.network.enabled = false;
        config.spec.security_profile = SecurityProfile::Restricted;
        config.spec.mounts.push(read_only_disk(
            scratch.join("disk"),
            wire::DATA,
            DiskImageFormat::Raw,
            "ext4",
        ));
        let effective = SandboxBuilder::from(config.clone())
            .finish_local(&private, None)
            .unwrap();
        assert_eq!(effective.storage_reader, Some(false));
        assert!(same_authority(&effective, &config).unwrap());
        assert!(
            !serde_json::to_string(&config)
                .unwrap()
                .contains("storage_reader")
        );
        let policy = GlobalConfigPatch::new()
            .paths(PathsConfigPatch::new().cache(parent.path().join("shared")));
        assert!(
            BackendConfig::new(Default::default(), policy)
                .recovery_reader(&home, &runtime)
                .is_err()
        );
    }
}
