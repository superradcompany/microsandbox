//! Durable identity and byte ownership for explicit initial-boot cleanup.

use std::collections::HashSet;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use microsandbox_utils::{private_file, process_lock};
use sea_orm::{ColumnTrait, ConnectionTrait, DatabaseBackend, EntityTrait, QueryFilter, Statement};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::backend::LocalBackend;
use crate::backend::local::creation::CreationStorage;
use crate::db::entity::sandbox;
use crate::sandbox::{RootDisk, Sandbox, SandboxConfig};
use crate::{MicrosandboxError, MicrosandboxResult, Operation};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

pub(crate) const TOKEN_LABEL: &str = "msb.initial_boot_attempt";
const MAX_MARKER_BYTES: u64 = 8 * 1024 * 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Phase {
    Prepared,
    Creating,
    Published,
    Cleaning,
    Cleaned,
    Superseded,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Marker {
    token: String,
    phase: Phase,
    sandbox_id: Option<i32>,
    config: Option<SandboxConfig>,
    directory: Option<(u64, u64)>,
}

/// Proof that the exact initial-boot attempt was fenced and its owned state durably removed.
/// This is evidence at this operation's completion, not permission to delete a later attempt.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FailedBootCleanupReceipt {
    /// Sandbox name covered by this operation.
    pub name: String,
    /// Caller token recorded before boot.
    pub token: String,
    /// Exact catalog identity, when reservation reached the catalog.
    pub sandbox_id: Option<i32>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Sandbox {
    /// Clean one failed initial boot on a local Unix backend.
    ///
    /// The create builder must have carried `initial_boot_attempt(token)`. Keep that token
    /// durably before invoking create. This operation refuses published, live, unidentified,
    /// and replacement owners. It never sends a signal or treats a missing catalog row as proof.
    /// Stop the exact failed runtime first if it still owns its lifecycle lock. Do not use a
    /// tolerant remove before this call: it would discard the ownership evidence.
    pub async fn cleanup_failed_initial_boot(
        name: &str,
        token: &str,
    ) -> MicrosandboxResult<FailedBootCleanupReceipt> {
        let backend = crate::backend::default_backend();
        let local = backend
            .as_local()
            .ok_or_else(|| MicrosandboxError::local_only(Operation::SandboxRemove))?;
        cleanup(local, name, token).await
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn token(config: &SandboxConfig) -> Option<&str> {
    config.spec.labels.get(TOKEN_LABEL).map(String::as_str)
}

pub(crate) fn validate_token(value: &str) -> MicrosandboxResult<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(invalid(
            "initial boot token must contain 1 through 128 letters, digits, dashes or underscores",
        ));
    }
    Ok(())
}

fn invalid(message: &str) -> MicrosandboxError {
    MicrosandboxError::InvalidConfig(message.into())
}

fn directory(sandbox: &Path) -> MicrosandboxResult<PathBuf> {
    Ok(sandbox
        .parent()
        .ok_or_else(|| invalid("sandbox storage has no parent"))?
        .join(".initial-boot"))
}

fn verify_directory(root: &Path) -> MicrosandboxResult<bool> {
    match std::fs::symlink_metadata(root) {
        Ok(metadata) if metadata.is_dir() => {
            private_file::verify(&File::open(root)?)?;
            Ok(true)
        }
        Ok(_) => Err(invalid(
            "initial boot journal must be a real private directory",
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn ensure_directory(sandbox: &Path) -> MicrosandboxResult<()> {
    let root = directory(sandbox)?;
    if !verify_directory(&root)? {
        let parent = root.parent().expect("journal parent");
        private_file::create_private_dir_all(parent)?;
        match private_file::create_private_directory(&root) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                verify_directory(&root)?;
            }
            Err(error) => return Err(error.into()),
        }
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn member(sandbox: &Path, extension: &str) -> MicrosandboxResult<PathBuf> {
    let name = sandbox
        .file_name()
        .ok_or_else(|| invalid("sandbox storage has no name"))?;
    let hash = hex::encode(Sha256::digest(name.as_encoded_bytes()));
    Ok(directory(sandbox)?.join(format!("{hash}.{extension}")))
}

fn read(sandbox: &Path) -> MicrosandboxResult<Option<Marker>> {
    if !verify_directory(&directory(sandbox)?)? {
        return Ok(None);
    }
    let path = member(sandbox, "json")?;
    let mut file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    private_file::verify(&file)?;
    if !file.metadata()?.is_file() || file.metadata()?.len() > MAX_MARKER_BYTES {
        return Err(invalid("invalid initial boot journal"));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_MARKER_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_MARKER_BYTES {
        return Err(invalid("oversized initial boot journal"));
    }
    Ok(Some(serde_json::from_slice(&bytes)?))
}

fn write(sandbox: &Path, marker: &Marker) -> MicrosandboxResult<()> {
    ensure_directory(sandbox)?;
    let path = member(sandbox, "json")?;
    let parent = path.parent().expect("journal parent");
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    private_file::harden(temp.as_file(), false)?;
    serde_json::to_writer(&mut temp, marker)?;
    temp.flush()?;
    temp.as_file().sync_all()?;
    temp.persist(&path).map_err(|error| error.error)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

/// Stable byte-ownership inode outside the removable sandbox. Never unlink or replace it.
pub(crate) fn byte_lock_path(sandbox: &Path) -> MicrosandboxResult<PathBuf> {
    ensure_directory(sandbox)?;
    let path = member(sandbox, "bytes")?;
    process_lock::open_lock_file(&path)?.sync_all()?;
    File::open(path.parent().expect("lock parent"))?.sync_all()?;
    Ok(path)
}

/// Prepare before image resolution, while no VM or deterministic disk may exist.
pub(crate) async fn prepare(
    local: &LocalBackend,
    name: &str,
    token: &str,
) -> MicrosandboxResult<()> {
    crate::sandbox::validate_sandbox_name(name)?;
    validate_token(token)?;
    let run = local.config().run_dir();
    let _transition = LocalBackend::acquire_sandbox_transition_guard(&run, name).await?;
    let _lifecycle =
        crate::runtime::acquire_sandbox_lifecycle_guard(&run, name, Duration::from_secs(5)).await?;
    let _creation = CreationStorage::acquire(local, name)?;
    let target = local.sandboxes_dir().join(name);
    let db = local.db().await?;
    if sandbox::Entity::find()
        .filter(sandbox::Column::Name.eq(name))
        .one(db.write())
        .await?
        .is_some()
        || target.try_exists()?
    {
        return Err(invalid(
            "initial boot requires an absent sandbox and storage directory",
        ));
    }
    if let Some(previous) = read(&target)?
        && (previous.token == token
            || !matches!(
                previous.phase,
                Phase::Cleaned | Phase::Published | Phase::Superseded
            ))
    {
        return Err(invalid(
            "initial boot token was already used or another attempt remains unresolved",
        ));
    }
    let fence = process_lock::open_existing_lock_file(&byte_lock_path(&target)?)?;
    if !process_lock::try_lock_exclusive(&fence)? {
        return Err(invalid("prior initial boot still owns disk bytes"));
    }
    write(
        &target,
        &Marker {
            token: token.into(),
            phase: Phase::Prepared,
            sandbox_id: None,
            config: None,
            directory: None,
        },
    )
}

/// Called under name transition before any create can replace or materialize storage.
pub(crate) fn authorize(local: &LocalBackend, config: &SandboxConfig) -> MicrosandboxResult<()> {
    let target = local.sandboxes_dir().join(&config.spec.name);
    let Some(mut marker) = read(&target)? else {
        return if token(config).is_some() {
            Err(invalid("initial boot has no prepared journal"))
        } else {
            Ok(())
        };
    };
    match marker.phase {
        Phase::Prepared if token(config) == Some(marker.token.as_str()) => {
            if !matches!(config.spec.image, crate::sandbox::RootfsSource::Oci(_))
                || config.replace_existing
                || config.snapshot_parent.is_some()
                || config.snapshot_archive_source.is_some()
                || config.snapshot_upper_source.is_some()
                || config.checkpoint_restore.is_some()
                || config.branch_source.is_some()
                || !matches!(
                    config.spec.image.oci_root_disk(),
                    None | Some(RootDisk::Managed { .. } | RootDisk::Flat { .. })
                )
            {
                return Err(invalid(
                    "initial boot cleanup supports only new managed or flat OCI disks",
                ));
            }
            if config.spec.mounts.iter().any(|mount| {
                matches!(
                    mount,
                    microsandbox_types::VolumeMount::Named { .. }
                        | microsandbox_types::VolumeMount::DiskImage { .. }
                )
            }) {
                return Err(invalid(
                    "initial boot cleanup cannot own named or external disk mounts",
                ));
            }
            marker.phase = Phase::Creating;
            marker.config = Some(config.clone());
            write(&target, &marker)
        }
        Phase::Cleaned | Phase::Published | Phase::Superseded if token(config).is_none() => {
            marker.phase = Phase::Superseded;
            write(&target, &marker)
        }
        _ => Err(invalid(
            "sandbox name belongs to an unresolved or different initial boot attempt",
        )),
    }
}

/// Persist the exact catalog owner before its deterministic directory can exist.
pub(crate) fn bind(
    local: &LocalBackend,
    config: &SandboxConfig,
    id: i32,
) -> MicrosandboxResult<()> {
    if token(config).is_none() {
        return Ok(());
    }
    let target = local.sandboxes_dir().join(&config.spec.name);
    let mut marker = read(&target)?.ok_or_else(|| invalid("initial boot journal disappeared"))?;
    if marker.phase != Phase::Creating || token(config) != Some(marker.token.as_str()) {
        return Err(invalid("initial boot ownership changed"));
    }
    marker.sandbox_id = Some(id);
    marker.config = Some(config.clone());
    if let Ok(metadata) = std::fs::symlink_metadata(&target) {
        if !metadata.is_dir() {
            return Err(invalid("initial boot storage is not a real directory"));
        }
        marker.directory = Some((metadata.dev(), metadata.ino()));
    }
    write(&target, &marker)
}

/// A successful or unknown publication can never produce a failed-initial-boot receipt.
pub(crate) fn published(local: &LocalBackend, config: &SandboxConfig) -> MicrosandboxResult<()> {
    if token(config).is_none() {
        return Ok(());
    }
    let target = local.sandboxes_dir().join(&config.spec.name);
    let mut marker = read(&target)?.ok_or_else(|| invalid("initial boot journal disappeared"))?;
    if marker.phase != Phase::Creating || token(config) != Some(marker.token.as_str()) {
        return Err(invalid("initial boot ownership changed"));
    }
    marker.phase = Phase::Published;
    marker.config = None;
    write(&target, &marker)
}

/// Other removal paths must retain evidence for this operation.
pub(crate) fn require_untracked(local: &LocalBackend, name: &str) -> MicrosandboxResult<()> {
    if read(&local.sandboxes_dir().join(name))?.is_some_and(|marker| {
        matches!(
            marker.phase,
            Phase::Prepared | Phase::Creating | Phase::Cleaning
        )
    }) {
        return Err(invalid(
            "initial boot cleanup is pending; use cleanup_failed_initial_boot with its exact token",
        ));
    }
    Ok(())
}

/// Acquire every byte fence before any unlink. No disk path or stable marker is fabricated
/// when it is missing; the retained attempt-wide fence also covers already absent rows/files.
fn fence_bytes(target: &Path, config: Option<&SandboxConfig>) -> MicrosandboxResult<Vec<File>> {
    let path = member(target, "bytes")?;
    let file = process_lock::open_existing_lock_file(&path)?;
    if !process_lock::try_lock_exclusive(&file)? {
        return Err(invalid("initial boot still owns disk bytes"));
    }
    let mut fences = vec![file];
    if let Some(config) = config {
        fences.extend(
            crate::runtime::owned_volumes::try_acquire_disk_guards(target, &config.spec.mounts)?
                .ok_or_else(|| invalid("owned disk bytes remain held"))?,
        );
    }
    let mut disk_inodes = HashSet::new();
    let mut pending = vec![target.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let entries = match std::fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        for entry in entries {
            let entry = entry?;
            let kind = entry.file_type()?;
            if kind.is_dir() && entry.file_name() != "guest-state" {
                pending.push(entry.path());
            }
            if kind.is_file()
                && entry
                    .path()
                    .extension()
                    .is_some_and(|ext| matches!(ext.to_str(), Some("raw" | "ext4" | "qcow2")))
            {
                let file = std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                    .open(entry.path())?;
                let metadata = file.metadata()?;
                if !disk_inodes.insert((metadata.dev(), metadata.ino())) {
                    continue;
                }
                if !process_lock::try_lock_exclusive(&file)? {
                    return Err(invalid("initial boot disk file bytes remain held"));
                }
                fences.push(file);
            }
        }
    }
    Ok(fences)
}

async fn cleanup(
    local: &LocalBackend,
    name: &str,
    expected: &str,
) -> MicrosandboxResult<FailedBootCleanupReceipt> {
    crate::sandbox::validate_sandbox_name(name)?;
    validate_token(expected)?;
    let run = local.config().run_dir();
    let _transition = LocalBackend::acquire_sandbox_transition_guard(&run, name).await?;
    let _lineage = crate::snapshot::lineage::lock_source(&run, name).await?;
    let _lifecycle =
        crate::runtime::acquire_sandbox_lifecycle_guard(&run, name, Duration::from_secs(5)).await?;
    let _creation = CreationStorage::acquire(local, name)?;
    let target = local.sandboxes_dir().join(name);
    let mut marker = read(&target)?.ok_or_else(|| {
        invalid("initial boot ownership is unidentified; no cleanup receipt can be issued")
    })?;
    if marker.token != expected
        || !matches!(
            marker.phase,
            Phase::Prepared | Phase::Creating | Phase::Cleaning | Phase::Cleaned
        )
    {
        return Err(invalid(
            "initial boot token is stale, published, or belongs to another execution",
        ));
    }
    let db = local.db().await?;
    let row = sandbox::Entity::find()
        .filter(sandbox::Column::Name.eq(name))
        .one(db.write())
        .await?;
    if let Some(row) = &row {
        let config: SandboxConfig = serde_json::from_str(&row.config)?;
        if marker.phase == Phase::Cleaned
            || token(&config) != Some(expected)
            || marker.sandbox_id.is_some_and(|id| id != row.id)
        {
            return Err(invalid("initial boot catalog identity changed"));
        }
        // A marker published before SDK success is authoritative even when an ephemeral row
        // disappeared. Conversely, a terminal/absent row alone never grants cleanup authority.
        if row.status == crate::sandbox::SandboxStatus::Running
            || row.status == crate::sandbox::SandboxStatus::Draining
        {
            return Err(invalid("initial boot runtime outcome is live or unknown"));
        }
        marker.sandbox_id = Some(row.id);
    }
    if let Ok(metadata) = std::fs::symlink_metadata(&target) {
        if marker.phase == Phase::Cleaned {
            return Err(invalid(
                "storage appeared after the initial boot was cleaned",
            ));
        }
        if row.is_none() && marker.directory.is_none() {
            return Err(invalid("initial boot storage has no recorded identity"));
        }
        if !metadata.is_dir() {
            return Err(invalid("initial boot storage is not a real directory"));
        }
        let identity = (metadata.dev(), metadata.ino());
        if marker
            .directory
            .is_some_and(|previous| previous != identity)
        {
            return Err(invalid("initial boot directory identity changed"));
        }
        marker.directory = Some(identity);
    }
    let fences = fence_bytes(&target, marker.config.as_ref())?;
    marker.phase = Phase::Cleaning;
    write(&target, &marker)?;
    // All locks and byte descriptors stay in this future through filesystem deletion and the
    // catalog commit. No detached unlink worker can outlive their ownership on cancellation.
    let sockets = microsandbox_runtime::ipc::SandboxSocketPaths::new(&run, &target, name);
    if sockets.may_be_live().await? {
        return Err(invalid(
            "initial boot still has a live or unidentified runtime endpoint",
        ));
    }
    local.remove_socket_artifacts(name)?;
    for parent in [
        run.as_path(),
        sockets
            .runtime
            .canonical_dir
            .parent()
            .expect("socket parent"),
    ] {
        match File::open(parent) {
            Ok(directory) => directory.sync_all()?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    crate::sandbox::remove_dir_if_exists(&target)?;
    File::open(local.sandboxes_dir())?.sync_all()?;
    if let Some(id) = marker.sandbox_id {
        db.write()
            .transaction(|txn| async move {
                txn.execute_raw(Statement::from_sql_and_values(
                    DatabaseBackend::Sqlite,
                    "UPDATE sandbox SET creation_state = NULL WHERE id = ?",
                    [id.into()],
                ))
                .await?;
                sandbox::Entity::delete_by_id(id).exec(&txn).await?;
                Ok::<_, MicrosandboxError>((txn, ()))
            })
            .await?;
    }
    // The writer query fences pending SQLite work before the durable cleaned marker is written.
    if sandbox::Entity::find()
        .filter(sandbox::Column::Name.eq(name))
        .one(db.write())
        .await?
        .is_some()
    {
        return Err(invalid("initial boot catalog ownership remains"));
    }
    let checkpoint = db
        .write()
        .query_one_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "PRAGMA wal_checkpoint(FULL)".to_string(),
        ))
        .await?
        .ok_or_else(|| invalid("catalog durability checkpoint returned no result"))?;
    if checkpoint.try_get::<i64>("", "busy")? != 0 {
        return Err(invalid(
            "catalog durability checkpoint is still busy; retry cleanup",
        ));
    }
    let catalog = local
        .config()
        .home()
        .join(microsandbox_utils::DB_SUBDIR)
        .join(microsandbox_utils::DB_FILENAME);
    File::open(&catalog)?.sync_all()?;
    File::open(catalog.parent().expect("catalog parent"))?.sync_all()?;
    marker.phase = Phase::Cleaned;
    marker.config = None;
    write(&target, &marker)?;
    drop(fences);
    Ok(FailedBootCleanupReceipt {
        name: name.into(),
        token: expected.into(),
        sandbox_id: marker.sandbox_id,
    })
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use sea_orm::{ConnectionTrait, Set};

    use crate::backend::Backend;
    use crate::sandbox::{SandboxBuilder, SandboxStatus};

    use super::*;

    struct Fixture {
        _home: tempfile::TempDir,
        backend: Arc<LocalBackend>,
        config: SandboxConfig,
        id: i32,
        target: PathBuf,
    }

    impl Fixture {
        async fn new() -> Self {
            let home = tempfile::tempdir_in("/tmp").unwrap();
            let backend = Arc::new(
                crate::test_support::local_backend_builder(home.path().join("home"))
                    .build()
                    .await
                    .unwrap(),
            );
            let config = SandboxBuilder::new("initial")
                .image_with(|image| {
                    image
                        .oci("alpine")
                        .root_disk_with(|disk| disk.flat().size(256u32))
                })
                .volume("/data", |mount| {
                    mount.owned_with(|owned| owned.disk().size(1u32))
                })
                .initial_boot_attempt("attempt-a")
                .finish(None, None)
                .unwrap();
            prepare(&backend, "initial", "attempt-a").await.unwrap();
            authorize(&backend, &config).unwrap();
            let id = sandbox::Entity::insert(sandbox::ActiveModel {
                name: Set("initial".into()),
                status: Set(SandboxStatus::Stopped),
                ephemeral: Set(false),
                config: Set(serde_json::to_string(&config).unwrap()),
                ..Default::default()
            })
            .exec(backend.db().await.unwrap().write())
            .await
            .unwrap()
            .last_insert_id;
            bind(&backend, &config, id).unwrap();
            let target = backend.sandboxes_dir().join("initial");
            std::fs::create_dir_all(&target).unwrap();
            std::fs::write(target.join("rootfs.raw"), b"private root bytes").unwrap();
            let owned = crate::runtime::owned_volumes::backing_path(
                &target,
                "/data",
                &microsandbox_types::OwnedVolumeStorage::Disk { capacity_mib: 1 },
            );
            std::fs::create_dir_all(owned.parent().unwrap()).unwrap();
            std::fs::write(&owned, b"private volume bytes").unwrap();
            crate::runtime::owned_volumes::disk_lock_path(&target, "/data").unwrap();
            bind(&backend, &config, id).unwrap();
            Self {
                _home: home,
                backend,
                config,
                id,
                target,
            }
        }

        async fn cleanup(&self, token: &str) -> MicrosandboxResult<FailedBootCleanupReceipt> {
            let backend: Arc<dyn Backend> = self.backend.clone();
            crate::with_backend(
                backend,
                Sandbox::cleanup_failed_initial_boot("initial", token),
            )
            .await
        }
    }

    #[tokio::test]
    async fn missing_catalog_never_bypasses_stable_or_actual_disk_byte_fences() {
        let fixture = Fixture::new().await;
        sandbox::Entity::delete_by_id(fixture.id)
            .exec(fixture.backend.db().await.unwrap().write())
            .await
            .unwrap();
        let stable =
            process_lock::open_existing_lock_file(&byte_lock_path(&fixture.target).unwrap())
                .unwrap();
        process_lock::lock_exclusive(&stable).unwrap();
        assert!(
            fixture
                .cleanup("attempt-a")
                .await
                .unwrap_err()
                .to_string()
                .contains("still owns disk bytes")
        );
        assert_eq!(
            std::fs::read(fixture.target.join("rootfs.raw")).unwrap(),
            b"private root bytes"
        );
        let unlinked_disk = File::open(fixture.target.join("rootfs.raw")).unwrap();
        std::fs::remove_file(fixture.target.join("rootfs.raw")).unwrap();
        assert_eq!(unlinked_disk.metadata().unwrap().nlink(), 0);
        // The retained runtime-wide byte fence catches an unlinked disk inode too;
        // an existence check or a fresh open of the disk filename would miss it.
        assert!(
            fixture
                .cleanup("attempt-a")
                .await
                .unwrap_err()
                .to_string()
                .contains("still owns disk bytes")
        );
        drop(unlinked_disk);
        drop(stable);
        std::fs::write(fixture.target.join("rootfs.raw"), b"private root bytes").unwrap();

        let owned = crate::runtime::owned_volumes::try_acquire_disk_guards(
            &fixture.target,
            &fixture.config.spec.mounts,
        )
        .unwrap()
        .unwrap();
        assert!(
            fixture
                .cleanup("attempt-a")
                .await
                .unwrap_err()
                .to_string()
                .contains("owned disk bytes remain held")
        );
        assert!(fixture.target.join("rootfs.raw").exists());
        drop(owned);

        let disk = File::open(fixture.target.join("rootfs.raw")).unwrap();
        process_lock::lock_shared(&disk).unwrap();
        assert!(
            fixture
                .cleanup("attempt-a")
                .await
                .unwrap_err()
                .to_string()
                .contains("disk file bytes remain held")
        );
        // In particular, removal must not unlink the inode while its last byte holder survives.
        assert!(fixture.target.join("rootfs.raw").exists());
        drop(disk);
        let receipt = fixture.cleanup("attempt-a").await.unwrap();
        assert_eq!(receipt.sandbox_id, Some(fixture.id));
        assert!(!fixture.target.exists());
        fixture.cleanup("attempt-a").await.unwrap();

        prepare(&fixture.backend, "initial", "attempt-b")
            .await
            .unwrap();
        assert!(fixture.cleanup("attempt-a").await.is_err());
        fixture.cleanup("attempt-b").await.unwrap();
    }

    #[tokio::test]
    async fn cleanup_refuses_live_creation_new_identity_and_unidentified_absence() {
        let fixture = Fixture::new().await;
        assert!(fixture.cleanup("another-attempt").await.is_err());
        assert!(require_untracked(&fixture.backend, "initial").is_err());
        let creation = CreationStorage::acquire(&fixture.backend, "initial").unwrap();
        assert!(
            fixture
                .cleanup("attempt-a")
                .await
                .unwrap_err()
                .to_string()
                .contains("preparation is still finishing")
        );
        drop(creation);
        let lifecycle = microsandbox_runtime::ipc::try_acquire_lifecycle_guard(
            &fixture.backend.config().run_dir(),
            "initial",
        )
        .unwrap()
        .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(40), fixture.cleanup("attempt-a"))
                .await
                .is_err()
        );
        drop(lifecycle);
        let db = fixture.backend.db().await.unwrap();
        sandbox::Entity::delete_by_id(fixture.id)
            .exec(db.write())
            .await
            .unwrap();
        sandbox::Entity::insert(sandbox::ActiveModel {
            name: Set("initial".into()),
            status: Set(SandboxStatus::Stopped),
            ephemeral: Set(false),
            config: Set(serde_json::to_string(&fixture.config).unwrap()),
            ..Default::default()
        })
        .exec(db.write())
        .await
        .unwrap();
        assert!(
            fixture
                .cleanup("attempt-a")
                .await
                .unwrap_err()
                .to_string()
                .contains("catalog identity changed")
        );
        assert!(fixture.target.join("rootfs.raw").exists());

        let backend: Arc<dyn Backend> = fixture.backend.clone();
        let error = crate::with_backend(
            backend,
            Sandbox::cleanup_failed_initial_boot("unknown", "unknown-token"),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("ownership is unidentified"));

        sandbox::Entity::delete_many()
            .exec(db.write())
            .await
            .unwrap();
        let preserved = fixture.target.with_extension("original");
        std::fs::rename(&fixture.target, &preserved).unwrap();
        std::fs::create_dir(&fixture.target).unwrap();
        std::fs::write(fixture.target.join("rootfs.raw"), b"new unidentified owner").unwrap();
        assert!(
            fixture
                .cleanup("attempt-a")
                .await
                .unwrap_err()
                .to_string()
                .contains("directory identity changed")
        );
        assert_eq!(
            std::fs::read(fixture.target.join("rootfs.raw")).unwrap(),
            b"new unidentified owner"
        );
        assert!(preserved.join("rootfs.raw").exists());
    }

    #[tokio::test]
    async fn interrupted_catalog_cleanup_retries_the_recorded_attempt_without_reopening_bytes() {
        let fixture = Fixture::new().await;
        let db = fixture.backend.db().await.unwrap();
        db.write().execute_unprepared("CREATE TRIGGER interrupt_cleanup BEFORE DELETE ON sandbox BEGIN SELECT RAISE(ABORT, 'interrupt cleanup'); END").await.unwrap();
        assert!(fixture.cleanup("attempt-a").await.is_err());
        assert!(!fixture.target.exists());
        assert_eq!(
            read(&fixture.target).unwrap().unwrap().phase,
            Phase::Cleaning
        );
        assert!(
            sandbox::Entity::find_by_id(fixture.id)
                .one(db.read())
                .await
                .unwrap()
                .is_some()
        );
        db.write()
            .execute_unprepared("DROP TRIGGER interrupt_cleanup")
            .await
            .unwrap();
        fixture.cleanup("attempt-a").await.unwrap();
        assert!(
            sandbox::Entity::find_by_id(fixture.id)
                .one(db.read())
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            read(&fixture.target).unwrap().unwrap().phase,
            Phase::Cleaned
        );
    }

    #[tokio::test]
    async fn competing_create_cannot_claim_a_prepared_attempt() {
        let home = tempfile::tempdir_in("/tmp").unwrap();
        let backend = Arc::new(
            crate::test_support::local_backend_builder(home.path().join("home"))
                .build()
                .await
                .unwrap(),
        );
        prepare(&backend, "competing", "initial-a").await.unwrap();
        let root = home.path().join("rootfs");
        std::fs::create_dir(&root).unwrap();
        let target = backend.sandboxes_dir().join("competing");
        let backend_dyn: Arc<dyn Backend> = backend.clone();
        let result = crate::with_backend(
            backend_dyn,
            SandboxBuilder::new("competing")
                .image(root)
                .create_detached(),
        )
        .await;
        let error = match result {
            Ok(_) => panic!("competing create claimed an unresolved initial boot"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("unresolved or different initial boot"),
            "{error}"
        );
        assert!(!target.exists());
        assert_eq!(read(&target).unwrap().unwrap().phase, Phase::Prepared);
        let backend_dyn: Arc<dyn Backend> = backend;
        crate::with_backend(
            backend_dyn,
            Sandbox::cleanup_failed_initial_boot("competing", "initial-a"),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn published_or_unknown_vm_outcomes_never_produce_failed_boot_receipts() {
        let fixture = Fixture::new().await;
        published(&fixture.backend, &fixture.config).unwrap();
        sandbox::Entity::delete_by_id(fixture.id)
            .exec(fixture.backend.db().await.unwrap().write())
            .await
            .unwrap();
        std::fs::remove_dir_all(&fixture.target).unwrap();
        assert!(
            fixture
                .cleanup("attempt-a")
                .await
                .unwrap_err()
                .to_string()
                .contains("stale, published")
        );
    }
}
