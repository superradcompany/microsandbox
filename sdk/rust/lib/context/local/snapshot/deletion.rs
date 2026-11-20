//! Atomic snapshot retirement and recovery of interrupted directory cleanup.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};

#[cfg(windows)]
use cap_primitives::fs::_WindowsByHandle;
use cap_primitives::fs::{FollowSymlinks, open_dir_nofollow};
use cap_std::fs::Dir;
#[cfg(any(unix, windows))]
use cap_std::fs::MetadataExt;
use microsandbox_image::storage_lease::StorageLease;
use microsandbox_runtime::ipc::SandboxLifecycleGuard;
use microsandbox_utils::process_lock;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use sha2::{Digest, Sha256};

use crate::context::LocalContext;
use crate::db::entity::{run, sandbox, snapshot};
use crate::sandbox::validate_sandbox_name;
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// The caller holds the source's exclusive lease (and group lock when grouped). Readers
/// see either a complete artifact or no artifact; recursive cleanup never uses its live name.
pub(super) fn quarantine(source: &Path) -> MicrosandboxResult<()> {
    let parent = source
        .parent()
        .ok_or_else(|| std::io::Error::other("snapshot has no parent"))?;
    let (path, lock) = prepare_retirement(parent, source.file_name().unwrap())?;
    let root = parent.join(".snapshot-deletions");
    std::fs::rename(source, path.join("payload")).map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!("move snapshot into deletion quarantine: {error}"),
        )
    })?;
    sync_dir(parent)?;
    sync_dir(&path)?;
    std::fs::remove_dir_all(path.join("payload")).map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!("remove quarantined snapshot: {error}"),
        )
    })?;
    // Keep the intent until catalog deletion has committed. Recovery may finish the row
    // removal if the process dies between retiring the directory and updating the index.
    drop(lock);
    sync_dir(&root)?;
    Ok(())
}

/// Create a recoverable catalog-retirement receipt without changing the live member.
/// The returned lock must span publication. A complete-generation publisher places this
/// record in its private view, making the absent member and recovery intent visible together.
pub(super) fn prepare_retirement(
    parent: &Path,
    name: &std::ffi::OsStr,
) -> MicrosandboxResult<(PathBuf, File)> {
    let name_path = Path::new(name);
    if name_path.components().count() != 1
        || !matches!(name_path.components().next(), Some(Component::Normal(_)))
    {
        return Err(std::io::Error::other("invalid snapshot retirement name").into());
    }
    let root = parent.join(".snapshot-deletions");
    std::fs::create_dir_all(&root)?;
    if !std::fs::symlink_metadata(&root)?.file_type().is_dir() {
        return Err(
            std::io::Error::other("snapshot deletion directory is not a real directory").into(),
        );
    }
    let coordination = coordinate(&root)?;
    let path = root.join(format!("delete-{:032x}", rand::random::<u128>()));
    std::fs::create_dir(&path)?;
    let lock = process_lock::open_lock_file(&path.join("active.lock"))?;
    process_lock::lock_exclusive(&lock)?;
    let record = path.join("source.json");
    let temporary = path.join("source.json.part");
    let mut file = File::create(&temporary)?;
    file.write_all(&serde_json::to_vec(&PathBuf::from(name))?)?;
    file.sync_all()?;
    drop(file);

    std::fs::rename(&temporary, &record)?;
    sync_dir(&path)?;
    sync_dir(&root)?;
    drop(coordination);
    Ok((path, lock))
}

/// Recovery never removes a new artifact at the original name. Only an absent source permits
/// deletion of its stale catalog row. The exact entry lease spans that check and row deletion.
pub(super) async fn recover_parent(local: &LocalContext, parent: &Path) -> MicrosandboxResult<()> {
    super::group::recover_histories(local, parent).await?;

    // Recovery creates namespace leases and retires journal paths too. It must
    // enter before those operations, otherwise a group exchange could move its
    // journal while the worker is still using the old pathname. Busy recovery is
    // deferred; never wait on admission while catalog initialization owns locks.
    let writer = if super::group::is_group(parent) {
        let Some(writer) = super::writer::WriterLease::try_acquire(parent)? else {
            return Ok(());
        };
        Some(writer)
    } else {
        None
    };
    recover_parent_owned(local, parent, writer).await
}

/// A whole-history remover already owns admission; do not skip its final recovery pass.
pub(super) async fn recover_parent_admitted(
    local: &LocalContext,
    parent: &Path,
    writer: super::writer::WriterLease,
) -> MicrosandboxResult<()> {
    writer.validate(parent)?;
    recover_parent_owned(local, parent, Some(writer)).await
}

async fn recover_parent_owned(
    local: &LocalContext,
    parent: &Path,
    writer: Option<super::writer::WriterLease>,
) -> MicrosandboxResult<()> {
    if let Some(admission) = writer.clone() {
        let directory = parent.to_path_buf();
        tokio::task::spawn_blocking(move || {
            let _admission = admission;
            super::group::recover_retired(&directory)
        })
        .await
        .map_err(|error| {
            MicrosandboxError::Custom(format!("group generation recovery: {error}"))
        })??;
    }
    let root = parent.join(".snapshot-deletions");
    match std::fs::symlink_metadata(&root) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
        Ok(_) => {
            return Err(std::io::Error::other(
                "snapshot deletion directory is not a real directory",
            )
            .into());
        }
    }
    let entries = match std::fs::read_dir(&root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_dir()
            || !entry.file_name().to_string_lossy().starts_with("delete-")
        {
            continue;
        }
        let coordination = coordinate(&root)?;
        let lock = match process_lock::open_existing_lock_file(&entry.path().join("active.lock")) {
            Ok(lock) => lock,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match process_lock::create_new_lock_file(&entry.path().join("active.lock")) {
                    Ok(lock) => lock,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(error) => return Err(error.into()),
                }
            }
            Err(error) => return Err(error.into()),
        };
        if !process_lock::try_lock_exclusive(&lock)? {
            continue;
        }
        drop(coordination);
        let record = match std::fs::read(entry.path().join("source.json")) {
            Ok(record) => record,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                discard(&entry.path())?;
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        let name: PathBuf = match serde_json::from_slice(&record) {
            Ok(name) => name,
            Err(error) => {
                // Older writers could leave a partial record before moving the source.
                // Without a valid name, never discard a quarantined payload or an index row.
                match std::fs::symlink_metadata(entry.path().join("payload")) {
                    Err(missing) if missing.kind() == std::io::ErrorKind::NotFound => {
                        discard(&entry.path())?;
                        continue;
                    }
                    Err(error) => return Err(error.into()),
                    Ok(_) => {
                        return Err(MicrosandboxError::SnapshotIntegrity(format!(
                            "cannot read snapshot deletion record {}: {error}; quarantined payload retained at {}; inspect the journal before retrying",
                            entry.path().join("source.json").display(),
                            entry.path().join("payload").display(),
                        )));
                    }
                }
            }
        };
        if name.components().count() != 1
            || !matches!(name.components().next(), Some(Component::Normal(_)))
        {
            return Err(std::io::Error::other("invalid snapshot deletion record").into());
        }
        let source = parent.join(name);
        let Some(lease) = StorageLease::try_exclusive(&source)? else {
            continue;
        };
        match std::fs::symlink_metadata(&source) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // The receipt may have arrived in a complete-directory exchange whose
                // publisher died before flushing the group's parent. Confirm that view
                // is durable before releasing its catalog/image roots.
                sync_dir(parent)?;
                if let Some(container) = parent.parent() {
                    sync_dir(container)?;
                }
                // Current rows use the resolved address; older catalogs can retain
                // the original spelling through a symlinked parent.
                let canonical_key = StorageLease::key(&source)?.display().to_string();
                let original_key = source.display().to_string();
                snapshot::Entity::delete_many()
                    .filter(snapshot::Column::ArtifactPath.is_in([canonical_key, original_key]))
                    .exec(local.db().await?.write())
                    .await?;
                super::store::recompute_children(local.db().await?.write()).await?;
            }
            Err(error) => return Err(error.into()),
            Ok(_) => {} // Publication or a crash before retirement left a valid live name.
        }
        let path = entry.path();
        let worker_writer = writer.clone();
        tokio::task::spawn_blocking(move || {
            let _guards = (lease, lock, worker_writer);
            discard(&path)
        })
        .await
        .map_err(|error| {
            MicrosandboxError::Custom(format!("snapshot cleanup recovery: {error}"))
        })??;
    }
    Ok(())
}

/// Release unused objects only after excluding both runtime activity and capture publication.
/// Captures can still be publishing after their VM exits, so the lifecycle lock alone is
/// insufficient. The existing transition -> lineage -> lifecycle order also fences restarts.
pub(crate) async fn release_store_objects(
    local: &LocalContext,
    source: &str,
) -> MicrosandboxResult<()> {
    if validate_sandbox_name(source).is_err() {
        return Ok(());
    }
    let db = local.db().await?;
    let run_dir = local.config().run_dir();
    let Some(transition) =
        microsandbox_runtime::ipc::try_acquire_transition_guard(&run_dir, source)?
    else {
        return Ok(());
    };
    let Some(lineage) =
        microsandbox_runtime::ipc::try_acquire_snapshot_lineage_guard(&run_dir, source)?
    else {
        return Ok(());
    };
    let Some(lifecycle) = SandboxLifecycleGuard::try_acquire(&run_dir, source)? else {
        return Ok(());
    };
    let Some(registered) = sandbox::Entity::find()
        .filter(sandbox::Column::Name.eq(source))
        .one(db.read())
        .await?
    else {
        return Ok(());
    };
    if registered.status.has_active_runtime_state() {
        return Ok(());
    }
    // Older Windows runtimes do not own the modern lifecycle lock. Retain their store
    // whenever a recorded active process is alive rather than treating a free lock as exit.
    let active_runs = run::Entity::find()
        .filter(run::Column::SandboxId.eq(registered.id))
        .filter(run::Column::Status.eq(run::RunStatus::Running))
        .all(db.read())
        .await?;
    if active_runs
        .iter()
        .any(|run| run.pid.is_none_or(LocalContext::pid_is_alive))
    {
        return Ok(());
    }
    let sandboxes = local.sandboxes_dir();
    let source = source.to_owned();
    tokio::task::spawn_blocking(move || -> MicrosandboxResult<()> {
        // Cancellation of the async caller must not release guards during the filesystem scan.
        let _guards = (transition, lineage, lifecycle);
        match release_stopped_store(&sandboxes, &source) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            result => result.map_err(Into::into),
        }
    })
    .await
    .map_err(|error| MicrosandboxError::Custom(format!("checkpoint object release: {error}")))?
}

/// Every child is opened relative to an admitted directory, without following symlinks or
/// Windows reparse points. A corrupt store must never redirect cleanup into another host tree.
fn release_stopped_store(sandboxes: &Path, source: &str) -> io::Result<()> {
    let mut parent =
        Dir::open_ambient_dir(sandboxes, cap_std::ambient_authority())?.into_std_file();
    for name in [source, "checkpoint-store", "objects", "sha256"] {
        parent = open_dir_nofollow(&parent, Path::new(name))?;
    }
    let store = Dir::from_std_file(parent);
    let shards = store.entries()?;
    let store = store.into_std_file();
    for shard in shards {
        let shard = shard?;
        if !is_hex(&shard.file_name().to_string_lossy(), 2) || !shard.file_type()?.is_dir() {
            continue;
        }
        let shard = Dir::from_std_file(open_dir_nofollow(&store, Path::new(&shard.file_name()))?);
        let objects = shard.entries()?;
        let shard = shard.into_std_file();
        for object in objects {
            let object = object?;
            if is_hex(&object.file_name().to_string_lossy(), 64) {
                release_unlinked(&shard, Path::new(&object.file_name()))?;
            }
        }
    }
    Ok(())
}

/// Never erase a receipt skipped because another process still owns its active lock.
/// Called under the group publication lock after admitted recovery has completed.
pub(super) fn require_no_pending(parent: &Path) -> MicrosandboxResult<()> {
    let root = parent.join(".snapshot-deletions");
    match std::fs::symlink_metadata(&root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => {
            return Err(MicrosandboxError::SnapshotIntegrity(
                "snapshot deletion directory is not a real directory".into(),
            ));
        }
    }
    for entry in std::fs::read_dir(root)? {
        if entry?.file_name().to_string_lossy().starts_with("delete-") {
            return Err(MicrosandboxError::SnapshotIntegrity(
                "snapshot group still has pending member cleanup; retry removal after recovery"
                    .into(),
            ));
        }
    }
    Ok(())
}

/// Remember external parents before retiring the last indexed member. These small
/// pointers are coordination records, not a recursive search through arbitrary host data.
pub(super) fn register_parent(local: &LocalContext, parent: &Path) -> std::io::Result<()> {
    let parent = parent.canonicalize()?;
    let root = local.cache_dir().join(".snapshot-deletion-parents");
    std::fs::create_dir_all(&root)?;
    if !std::fs::symlink_metadata(&root)?.file_type().is_dir() {
        return Err(std::io::Error::other("invalid snapshot recovery registry"));
    }
    let bytes = serde_json::to_vec(&parent).map_err(std::io::Error::other)?;
    let key = hex::encode(Sha256::digest(&bytes));
    let mut temporary = tempfile::NamedTempFile::new_in(&root)?;
    temporary.write_all(&bytes)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(root.join(format!("{key}.json")))
        .map_err(|error| error.error)?;
    sync_dir(&root)
}

pub(crate) fn recovery_parents(local: &LocalContext) -> std::io::Result<BTreeSet<PathBuf>> {
    let managed = local.snapshots_dir();
    let mut parents = BTreeSet::from([managed.clone()]);
    if managed.exists() {
        for entry in std::fs::read_dir(&managed)? {
            let entry = entry?;
            // Private/retired generations carry group.json too. Only the live
            // group may recover their receipts under its stable writer key.
            if !entry
                .file_name()
                .to_string_lossy()
                .starts_with(".group-generation-")
                && entry.file_type()?.is_dir()
                && entry.path().join(super::group::GROUP_FILENAME).is_file()
            {
                parents.insert(entry.path());
            }
        }
    }
    let root = local.cache_dir().join(".snapshot-deletion-parents");
    if root.exists() {
        if !std::fs::symlink_metadata(&root)?.file_type().is_dir() {
            return Err(std::io::Error::other("invalid snapshot recovery registry"));
        }
        for entry in std::fs::read_dir(root)? {
            let entry = entry?;
            if entry.path().extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            if !entry.file_type()?.is_file() {
                return Err(std::io::Error::other("invalid snapshot recovery pointer"));
            }
            let parent: PathBuf = serde_json::from_slice(&std::fs::read(entry.path())?)
                .map_err(std::io::Error::other)?;
            if !parent.is_absolute() {
                return Err(std::io::Error::other(
                    "snapshot recovery parent must be absolute",
                ));
            }
            parents.insert(parent);
        }
    }
    Ok(parents)
}

fn release_unlinked(directory: &File, name: &Path) -> io::Result<()> {
    // Windows directory enumeration does not provide the link count. A no-follow,
    // handle-relative stat obtains it on both platforms through the existing cap APIs.
    let metadata = match cap_primitives::fs::stat(directory, name, FollowSymlinks::No) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    #[cfg(unix)]
    let unlinked = metadata.nlink() == 1;
    #[cfg(windows)]
    let unlinked = _WindowsByHandle::number_of_links(&metadata) == Some(1)
        && metadata.file_attributes() & 0x400 == 0;
    #[cfg(not(any(unix, windows)))]
    let unlinked = false;
    if !metadata.is_file() || !unlinked {
        return Ok(());
    }
    match cap_primitives::fs::remove_file(directory, name) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

fn is_hex(name: &str, length: usize) -> bool {
    name.len() == length && name.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn coordinate(root: &Path) -> std::io::Result<File> {
    let file = process_lock::open_lock_file(&root.join("coordination.lock"))?;
    process_lock::lock_exclusive(&file)?;
    Ok(file)
}

fn discard(path: &Path) -> std::io::Result<()> {
    let _coordination = coordinate(path.parent().unwrap())?;
    // Payload first, records last: no interruption can hide retained payload from recovery.
    match std::fs::symlink_metadata(path.join("payload")) {
        Ok(metadata) if metadata.file_type().is_dir() => {
            std::fs::remove_dir_all(path.join("payload"))?
        }
        Ok(_) => {
            return Err(std::io::Error::other(
                "snapshot quarantine payload is not a directory",
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    sync_dir(path)?;
    for name in ["source.json.part", "source.json", "active.lock"] {
        match std::fs::remove_file(path.join(name)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        sync_dir(path)?;
    }
    std::fs::remove_dir(path)?;
    sync_dir(path.parent().unwrap())
}

fn sync_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    async fn store_fixture() -> (
        tempfile::TempDir,
        LocalContext,
        microsandbox_image::checkpoint::LocalObjectStore,
        i32,
    ) {
        use sea_orm::{ActiveModelTrait, Set};
        let home = tempfile::tempdir().unwrap();
        let local = crate::test_support::local_backend_builder(home.path())
            .build()
            .unwrap();
        let model = sandbox::ActiveModel {
            name: Set("box".into()),
            config: Set("{}".into()),
            status: Set(crate::sandbox::SandboxStatus::Stopped),
            ephemeral: Set(false),
            ..Default::default()
        }
        .insert(local.db().await.unwrap().write())
        .await
        .unwrap();
        let store = microsandbox_image::checkpoint::LocalObjectStore::open(
            local.sandboxes_dir().join("box/checkpoint-store"),
        )
        .unwrap();
        (home, local, store, model.id)
    }

    #[tokio::test]
    async fn checkpoint_store_reclaims_orphans_and_preserves_snapshots_and_recovery_captures() {
        let (_home, local, store, _) = store_fixture().await;
        let orphan = store.object_path(&store.put_bytes(b"orphan").unwrap());
        let shared = store.object_path(&store.put_bytes(b"snapshot").unwrap());
        let recovery = store.object_path(&store.put_bytes(b"recovery").unwrap());
        let snapshot_link = local.sandboxes_dir().join("retained-snapshot-object");
        std::fs::hard_link(&shared, &snapshot_link).unwrap();
        let capture = local.sandboxes_dir().join("box/checkpoints/checkpoint_old");
        std::fs::create_dir_all(&capture).unwrap();
        let recovery_link = capture.join("recovery-object");
        std::fs::hard_link(&recovery, &recovery_link).unwrap();
        let independent_copy = local.sandboxes_dir().join("copied-snapshot-object");
        std::fs::copy(&orphan, &independent_copy).unwrap();
        let unknown = orphan.parent().unwrap().join("unrecognized-file");
        std::fs::write(&unknown, b"retain").unwrap();

        release_store_objects(&local, "box").await.unwrap();

        assert!(!orphan.exists());
        assert!(shared.exists() && recovery.exists() && unknown.exists());
        assert_eq!(std::fs::read(recovery_link).unwrap(), b"recovery");
        assert_eq!(std::fs::read(snapshot_link).unwrap(), b"snapshot");
        assert_eq!(std::fs::read(independent_copy).unwrap(), b"orphan");
        // A later pass becomes eligible only once the protected capture link is gone.
        std::fs::remove_dir_all(capture).unwrap();
        release_store_objects(&local, "box").await.unwrap();
        assert!(!recovery.exists());
    }

    #[tokio::test]
    async fn checkpoint_store_defers_for_transition_capture_and_runtime_owners() {
        let (_home, local, store, _) = store_fixture().await;
        let orphan = store.object_path(&store.put_bytes(b"orphan").unwrap());
        let run_dir = local.config().run_dir();
        let transition = microsandbox_runtime::ipc::try_acquire_transition_guard(&run_dir, "box")
            .unwrap()
            .unwrap();
        release_store_objects(&local, "box").await.unwrap();
        assert!(orphan.exists());
        drop(transition);
        let capture = super::super::lineage::lock_source(&run_dir, "box")
            .await
            .unwrap();
        release_store_objects(&local, "box").await.unwrap();
        assert!(orphan.exists());
        drop(capture);
        let runtime = SandboxLifecycleGuard::try_acquire(&run_dir, "box")
            .unwrap()
            .unwrap();
        release_store_objects(&local, "box").await.unwrap();
        assert!(orphan.exists());
        drop(runtime);
        release_store_objects(&local, "box").await.unwrap();
        assert!(!orphan.exists());
    }

    #[tokio::test]
    async fn checkpoint_store_preserves_a_live_legacy_process_without_a_lifecycle_lock() {
        use sea_orm::{ActiveModelTrait, Set};
        let (_home, local, store, id) = store_fixture().await;
        let orphan = store.object_path(&store.put_bytes(b"orphan").unwrap());
        let active = run::ActiveModel {
            sandbox_id: Set(id),
            pid: Set(Some(std::process::id() as i32)),
            status: Set(run::RunStatus::Running),
            ..Default::default()
        }
        .insert(local.db().await.unwrap().write())
        .await
        .unwrap();
        release_store_objects(&local, "box").await.unwrap();
        assert!(orphan.exists());
        run::Entity::delete_by_id(active.id)
            .exec(local.db().await.unwrap().write())
            .await
            .unwrap();
        release_store_objects(&local, "box").await.unwrap();
        assert!(!orphan.exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn checkpoint_store_never_follows_symlinked_directories_or_objects() {
        use std::os::unix::fs::symlink;
        let (home, local, store, _) = store_fixture().await;
        let orphan = store.object_path(&store.put_bytes(b"orphan").unwrap());
        let sandbox = local.sandboxes_dir().join("box");
        // Move each admitted subtree out, then substitute a symlink. No outside file may be deleted.
        for relative in [
            "checkpoint-store/objects/sha256",
            "checkpoint-store/objects",
            "checkpoint-store",
        ] {
            let path = sandbox.join(relative);
            let outside = home.path().join("outside");
            std::fs::rename(&path, &outside).unwrap();
            symlink(&outside, &path).unwrap();
            assert!(release_store_objects(&local, "box").await.is_err());
            assert!(orphan.exists());
            std::fs::remove_file(&path).unwrap();
            std::fs::rename(&outside, &path).unwrap();
        }
        let outside = home.path().join("outside-object");
        std::fs::write(&outside, b"outside").unwrap();
        let alias = orphan.parent().unwrap().join("a".repeat(64));
        symlink(&outside, &alias).unwrap();
        release_store_objects(&local, "box").await.unwrap();
        assert_eq!(std::fs::read(&outside).unwrap(), b"outside");
        assert!(alias.symlink_metadata().unwrap().file_type().is_symlink());
        assert!(!orphan.exists());
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn checkpoint_store_never_follows_windows_directory_junctions() {
        let (home, local, store, _) = store_fixture().await;
        let object = store.object_path(&store.put_bytes(b"outside object").unwrap());
        let root = local.sandboxes_dir().join("box/checkpoint-store");
        let outside = home.path().join("outside");
        std::fs::rename(&root, &outside).unwrap();
        let created = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&root)
            .arg(&outside)
            .output()
            .unwrap();
        assert!(
            created.status.success(),
            "{}",
            String::from_utf8_lossy(&created.stderr)
        );

        assert!(release_store_objects(&local, "box").await.is_err());
        assert_eq!(std::fs::read(&object).unwrap(), b"outside object");
        // Remove the junction itself so TempDir cleanup never needs to inspect its target.
        std::fs::remove_dir(&root).unwrap();
        std::fs::rename(&outside, &root).unwrap();
    }

    #[tokio::test]
    async fn discovery_never_recovers_a_private_generation_as_a_live_group() {
        let home = tempfile::tempdir().unwrap();
        let local = crate::test_support::local_backend_builder(home.path())
            .build()
            .unwrap();
        let group = super::super::group::ensure(&local.snapshots_dir(), Some("history"))
            .await
            .unwrap();
        let private = local.snapshots_dir().join(".group-generation-interrupted");
        std::fs::create_dir(&private).unwrap();
        std::fs::copy(
            group.join(super::super::group::GROUP_FILENAME),
            private.join(super::super::group::GROUP_FILENAME),
        )
        .unwrap();
        let parents = recovery_parents(&local).unwrap();
        assert!(parents.contains(&group));
        assert!(!parents.contains(&private));
    }

    #[tokio::test]
    async fn group_recovery_defers_namespace_and_journal_mutation_until_writer_finishes() {
        let home = tempfile::tempdir().unwrap();
        let local = crate::test_support::local_backend_builder(home.path())
            .build()
            .unwrap();
        local.db().await.unwrap();
        let group = super::super::group::ensure(&local.snapshots_dir(), Some("history"))
            .await
            .unwrap();
        let journal = group.join(".snapshot-deletions/delete-interrupted");
        std::fs::create_dir_all(journal.join("payload")).unwrap();
        std::fs::write(journal.join("source.json"), b"\"retired\"").unwrap();
        std::fs::write(journal.join("payload/marker"), b"retained").unwrap();
        let admission = super::super::writer::WriterLease::acquire(&group)
            .await
            .unwrap();

        recover_parent(&local, &group).await.unwrap();
        assert!(journal.join("payload/marker").is_file());
        assert!(!group.join(".msb-leases").exists());

        drop(admission);
        recover_parent(&local, &group).await.unwrap();
        assert!(!journal.exists());
        assert!(group.join(super::super::group::GROUP_FILENAME).is_file());
    }
}
