//! Atomic snapshot retirement and recovery of interrupted directory cleanup.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use microsandbox_image::storage_lease::StorageLease;
use microsandbox_utils::process_lock;
use sea_orm::EntityTrait;
use sha2::{Digest, Sha256};

use crate::backend::LocalBackend;
use crate::db::entity::snapshot;
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
    file.write_all(&serde_json::to_vec(&PathBuf::from(
        source.file_name().unwrap(),
    ))?)?;
    file.sync_all()?;
    drop(file);

    std::fs::rename(&temporary, &record)?;
    sync_dir(&path)?;
    sync_dir(&root)?;
    std::fs::rename(source, path.join("payload")).map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!("move snapshot into deletion quarantine: {error}"),
        )
    })?;
    sync_dir(parent)?;
    sync_dir(&path)?;
    drop(coordination);
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

/// Recovery never removes a new artifact at the original name. Only an absent source permits
/// deletion of its stale catalog row. The exact entry lease spans that check and row deletion.
pub(super) async fn recover_parent(local: &LocalBackend, parent: &Path) -> MicrosandboxResult<()> {
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
                snapshot::Entity::delete_by_id(
                    super::store::canonical_path(&source).display().to_string(),
                )
                .exec(local.db().await?.write())
                .await?;
                super::store::recompute_children(local.db().await?.write()).await?;
            }
            Err(error) => return Err(error.into()),
            Ok(_) => {} // Publication or a crash before retirement left a valid live name.
        }
        let path = entry.path();
        tokio::task::spawn_blocking(move || {
            let _guards = (lease, lock);
            discard(&path)
        })
        .await
        .map_err(|error| {
            MicrosandboxError::Custom(format!("snapshot cleanup recovery: {error}"))
        })??;
    }
    Ok(())
}

/// Remember external parents before retiring the last indexed member. These small
/// pointers are coordination records, not a recursive search through arbitrary host data.
pub(super) fn register_parent(local: &LocalBackend, parent: &Path) -> std::io::Result<()> {
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

pub(crate) fn recovery_parents(local: &LocalBackend) -> std::io::Result<BTreeSet<PathBuf>> {
    let managed = local.snapshots_dir();
    let mut parents = BTreeSet::from([managed.clone()]);
    if managed.exists() {
        for entry in std::fs::read_dir(&managed)? {
            let entry = entry?;
            if entry.file_type()?.is_dir()
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
