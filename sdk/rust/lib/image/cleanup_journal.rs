//! Recoverable image unlink intents. Hard links retain the exact admitted inode, so recovery
//! cannot unlink a new publication at the same name after an interrupted cleanup.

use std::fs::File;
use std::path::{Component, Path, PathBuf};

use microsandbox_image::{
    GlobalCache, Reference,
    storage_lease::{StorageLease, same_file},
};
use microsandbox_utils::process_lock;
use sea_orm::EntityTrait;

use crate::MicrosandboxResult;
use crate::backend::LocalBackend;
use crate::db::entity::{image_ref, layer, manifest, snapshot};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub(super) struct Journal {
    path: PathBuf,
    root: PathBuf,
    files: Vec<PathBuf>,
    _lock: File,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Journal {
    /// Call with exclusive entry leases held, before committing removal of catalog ownership.
    pub(super) fn prepare(root: &Path, files: &[PathBuf]) -> MicrosandboxResult<Option<Self>> {
        if files.is_empty() {
            return Ok(None);
        }
        let directory = root.join(".image-deletions");
        std::fs::create_dir_all(&directory)?;
        if !std::fs::symlink_metadata(&directory)?.file_type().is_dir() {
            return Err(std::io::Error::other(
                "image deletion journal directory is not a real directory",
            )
            .into());
        }
        let _coordination = coordinate(&directory)?;
        let stage = tempfile::Builder::new()
            .prefix(".prepare-")
            .tempdir_in(&directory)?;
        let lock = process_lock::open_lock_file(&stage.path().join("active.lock"))?;
        process_lock::lock_exclusive(&lock)?;
        let mut retained = Vec::new();
        for path in files {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| std::io::Error::other("cleanup path is outside cache"))?;
            validate_relative(relative)?;
            match std::fs::symlink_metadata(path) {
                Ok(metadata) if metadata.file_type().is_file() => {}
                Ok(_) => {
                    return Err(std::io::Error::other(
                        "cache cleanup target is not a regular file",
                    )
                    .into());
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            }
            let pinned = stage.path().join(retained.len().to_string());
            std::fs::hard_link(path, &pinned)?;
            retained.push(relative.to_path_buf());
        }
        let record = stage.path().join("files.json");
        std::fs::write(&record, serde_json::to_vec(&retained)?)?;
        File::open(&record)?.sync_all()?;
        sync_dir(stage.path())?;
        let path = directory.join(format!("delete-{:032x}", rand::random::<u128>()));
        std::fs::rename(stage.path(), &path)?;
        sync_dir(&directory)?;
        Ok(Some(Self {
            path,
            root: root.to_path_buf(),
            files: retained,
            _lock: lock,
        }))
    }

    /// Remove only admitted generations; keep the journal on any I/O failure for retry.
    /// The caller either owns all entry leases or invokes recovery's per-entry revalidation.
    pub(super) fn finish(self) -> MicrosandboxResult<Vec<(PathBuf, u64)>> {
        let mut removed = Vec::new();
        for (index, relative) in self.files.iter().enumerate() {
            let path = self.root.join(relative);
            let pinned = self.path.join(index.to_string());
            match same_file(&path, &pinned) {
                Ok(true) => {
                    let size = std::fs::metadata(&pinned)?.len();
                    std::fs::remove_file(&path)?;
                    sync_dir(path.parent().unwrap())?;
                    removed.push((path, size));
                }
                Ok(false) => {} // A later publisher owns the name now.
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        self.discard()?;
        Ok(removed)
    }

    fn discard(self) -> MicrosandboxResult<()> {
        // Keep the lock held through removal. Recovery opens existing lock files only;
        // directory names are unique and never reused.
        let _coordination = coordinate(self.path.parent().unwrap())?;
        discard_directory(&self.path)?;
        drop(self._lock);
        sync_dir(self.path.parent().unwrap())?;
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) async fn recover(local: &LocalBackend) -> MicrosandboxResult<()> {
    let cache = GlobalCache::new(&local.cache_dir())?;
    let root = local.cache_dir();
    let directory = root.join(".image-deletions");
    match std::fs::symlink_metadata(&directory) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
        Ok(_) => {
            return Err(std::io::Error::other(
                "image deletion journal directory is not a real directory",
            )
            .into());
        }
    }
    let entries = match std::fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let preparing = name.starts_with(".prepare-");
        if (!preparing && !name.starts_with("delete-")) || !entry.file_type()?.is_dir() {
            continue;
        }
        let coordination = coordinate(&directory)?;
        let lock = match process_lock::open_existing_lock_file(&entry.path().join("active.lock")) {
            Ok(lock) => lock,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // Creation and disposal hold the parent coordinator. With it held, a
                // missing active lock cannot be a live creator waiting to install it.
                discard_directory(&entry.path())?;
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        if !process_lock::try_lock_exclusive(&lock)? {
            continue;
        }
        drop(coordination);
        if preparing {
            // The catalog transaction cannot commit until this directory is published.
            // A crashed preparation owns only extra hard links, never the source entries.
            let _coordination = coordinate(&directory)?;
            discard_directory(&entry.path())?;
            drop(lock);
            sync_dir(&directory)?;
            continue;
        }
        let record = match std::fs::read(entry.path().join("files.json")) {
            Ok(record) => record,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let _coordination = coordinate(&directory)?;
                discard_directory(&entry.path())?;
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        let files: Vec<PathBuf> = serde_json::from_slice(&record)?;
        for relative in &files {
            validate_relative(relative)?;
        }
        // Publication owns shared entry leases through its transaction. Once exclusive leases
        // are held, this catalog snapshot cannot be invalidated by a participating publisher.
        let db = local.db().await?.read();
        let mut busy = false;
        // Recover each independent entry with a fresh ownership query while holding its
        // exclusive lease. A previous generation may have journaled arbitrarily many files.
        for (index, relative) in files.iter().enumerate() {
            let path = root.join(relative);
            let pinned = entry.path().join(index.to_string());
            let Some(_lease) = StorageLease::try_exclusive(&path)? else {
                busy = true;
                continue;
            };
            // Requery after admission so a publisher cannot race the ownership decision.
            let owned = match relative
                .components()
                .next()
                .and_then(|part| part.as_os_str().to_str())
            {
                Some("manifests") => {
                    let named = image_ref::Entity::find()
                        .all(db)
                        .await?
                        .into_iter()
                        .any(|row| {
                            row.reference
                                .parse::<Reference>()
                                .ok()
                                .is_some_and(|reference| {
                                    cache.image_metadata_path(&reference) == path
                                })
                        });
                    let snapshots = snapshot::Entity::find().all(db).await?;
                    let snapshot_named = snapshots.iter().any(|row| {
                        row.image_ref
                            .parse::<Reference>()
                            .ok()
                            .is_some_and(|reference| cache.image_metadata_path(&reference) == path)
                    });
                    let bytes = match std::fs::read(&pinned) {
                        Ok(bytes) => bytes,
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
                        Err(error) => return Err(error.into()),
                    };
                    let metadata =
                        serde_json::from_slice::<microsandbox_image::CachedImageMetadata>(&bytes)
                            .ok();
                    let mut retained_generation = metadata.as_ref().is_some_and(|metadata| {
                        snapshots
                            .iter()
                            .any(|row| row.image_manifest_digest == metadata.manifest_digest)
                    });
                    if !retained_generation && let Some(metadata) = metadata {
                        let roots = microsandbox_db::catalog::rootfs_query(db)
                            .await?
                            .all(db)
                            .await?;
                        let manifests = manifest::Entity::find().all(db).await?;
                        retained_generation = manifests.iter().any(|manifest| {
                            manifest.digest == metadata.manifest_digest
                                && roots
                                    .iter()
                                    .any(|root| root.manifest_id == Some(manifest.id))
                        });
                    }
                    named || snapshot_named || retained_generation
                }
                Some("layers") => layer::Entity::find().all(db).await?.into_iter().any(|row| {
                    row.diff_id
                        .parse()
                        .ok()
                        .is_some_and(|digest| cache.layer_erofs_path(&digest) == path)
                }),
                _ => manifest::Entity::find()
                    .all(db)
                    .await?
                    .into_iter()
                    .any(|row| {
                        row.digest.parse().ok().is_some_and(|digest| {
                            cache.fsmeta_erofs_path(&digest) == path
                                || cache.vmdk_path(&digest) == path
                        })
                    }),
            };
            if !owned {
                match same_file(&path, &pinned) {
                    Ok(true) => {
                        std::fs::remove_file(&path)?;
                        sync_dir(path.parent().unwrap())?;
                    }
                    Ok(false) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
            match std::fs::remove_file(&pinned) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        if !busy {
            let _coordination = coordinate(&directory)?;
            discard_directory(&entry.path())?;
            sync_dir(&directory)?;
        }
        drop(lock);
    }
    Ok(())
}

/// Serializes only journal creation/disposal, never image work or catalog transactions.
fn coordinate(directory: &Path) -> std::io::Result<File> {
    let lock = process_lock::open_lock_file(&directory.join("coordination.lock"))?;
    process_lock::lock_exclusive(&lock)?;
    Ok(lock)
}

fn discard_directory(path: &Path) -> std::io::Result<()> {
    let entries = match std::fs::read_dir(path) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    // Drop extra hard links first. A crash after removing the record or lock can then
    // leave only an empty shell, and recovery also tolerates older unordered disposal.
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        if name == "files.json" || name == "active.lock" {
            continue;
        }
        if name
            .to_str()
            .is_none_or(|name| name.parse::<usize>().is_err())
            || !entry.file_type()?.is_file()
        {
            return Err(std::io::Error::other("unexpected image journal member"));
        }
        remove_if_present(&entry.path())?;
    }
    sync_dir(path)?;
    remove_if_present(&path.join("files.json"))?;
    sync_dir(path)?;
    remove_if_present(&path.join("active.lock"))?;
    std::fs::remove_dir(path)
}

fn remove_if_present(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn validate_relative(path: &Path) -> MicrosandboxResult<()> {
    let components = path.components().collect::<Vec<_>>();
    if components.len() != 2
        || !components
            .iter()
            .all(|part| matches!(part, Component::Normal(_)))
        || !matches!(
            components[0].as_os_str().to_str(),
            Some("manifests" | "layers" | "fsmeta" | "vmdk")
        )
    {
        return Err(std::io::Error::other("invalid cache deletion journal path").into());
    }
    let extension = path.extension().and_then(|part| part.to_str());
    let expected = match components[0].as_os_str().to_str() {
        Some("manifests") => "json",
        Some("layers" | "fsmeta") => "erofs",
        Some("vmdk") => "vmdk",
        _ => unreachable!("validated above"),
    };
    if extension != Some(expected) {
        return Err(
            std::io::Error::other("deletion journal cannot target coordination files").into(),
        );
    }
    Ok(())
}

fn sync_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}
