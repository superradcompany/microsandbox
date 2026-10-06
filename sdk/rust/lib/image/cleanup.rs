//! Image deletion coordinates with file readers and publishers through catalog commit.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use microsandbox_image::{Digest, GlobalCache, Reference, storage_lease::StorageLease};
use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter};

use super::{
    ImagePruneReport,
    cleanup_journal::{self, Journal},
};
use crate::backend::LocalBackend;
use crate::db::entity::{image_ref, layer, manifest, manifest_layer, snapshot};
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Default)]
struct Cleanup {
    files: Vec<PathBuf>,
    // These MUST outlive both the transaction and disk cleanup. Acquiring them only after
    // commit allows a publisher to recreate the same path in the intervening window.
    leases: HashMap<PathBuf, StorageLease>,
    more: bool,
    skipped: HashSet<PathBuf>,
    journal: Option<Journal>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) async fn prune(local: &LocalBackend) -> MicrosandboxResult<ImagePruneReport> {
    delete(local, None).await
}

pub(super) async fn remove(
    local: &LocalBackend,
    reference: &str,
    force: bool,
) -> MicrosandboxResult<()> {
    delete(local, Some((reference.to_owned(), force))).await?;
    Ok(())
}

async fn delete(
    local: &LocalBackend,
    selected: Option<(String, bool)>,
) -> MicrosandboxResult<ImagePruneReport> {
    crate::backend::local::snapshot::publication::recover(local).await?;
    cleanup_journal::recover(local).await?;
    let pools = local.db().await?;
    // Freeze the scope of an explicit removal, not the mutable catalog contents. Every
    // batch rechecks owners inside its write transaction before removing an object.
    let mut selected_manifests = HashSet::new();
    let mut selected_layers = HashSet::new();
    if let Some((name, _)) = &selected {
        let reference = image_ref::Entity::find()
            .filter(image_ref::Column::Reference.eq(name))
            .one(pools.read())
            .await?
            .ok_or_else(|| MicrosandboxError::ImageNotFound(name.clone()))?;
        selected_manifests.insert(reference.manifest_id);
        selected_layers.extend(
            manifest_layer::Entity::find()
                .filter(manifest_layer::Column::ManifestId.eq(reference.manifest_id))
                .all(pools.read())
                .await?
                .into_iter()
                .map(|row| row.layer_id),
        );
    }
    let mut total = ImagePruneReport::default();
    let mut skipped = HashSet::new();
    loop {
        let (report, more, next_skipped) = delete_batch(
            local,
            selected.clone(),
            selected_manifests.clone(),
            selected_layers.clone(),
            skipped,
        )
        .await?;
        total.image_refs_removed += report.image_refs_removed;
        total.manifests_removed += report.manifests_removed;
        total.layers_removed += report.layers_removed;
        total.fsmeta_removed += report.fsmeta_removed;
        total.vmdk_removed += report.vmdk_removed;
        total.skipped_in_use += report.skipped_in_use;
        if let Some(bytes) = report.bytes_reclaimed {
            total.bytes_reclaimed = Some(total.bytes_reclaimed.unwrap_or(0).saturating_add(bytes));
        }
        if !more {
            return Ok(total);
        }
        skipped = next_skipped;
    }
}

async fn delete_batch(
    local: &LocalBackend,
    selected: Option<(String, bool)>,
    selected_manifests: HashSet<i32>,
    selected_layers: HashSet<i32>,
    skipped: HashSet<PathBuf>,
) -> MicrosandboxResult<(ImagePruneReport, bool, HashSet<PathBuf>)> {
    let cache = GlobalCache::new(&local.cache_dir())?;
    let pools = local.db().await?;
    let (mut report, cleanup) = pools
        .write()
        .transaction(|txn| {
            let selected = selected.clone();
            let cache = cache.clone();
            let selected_manifests = selected_manifests.clone();
            let selected_layers = selected_layers.clone();
            let skipped = skipped.clone();
            async move {
                let sandbox_refs = microsandbox_db::catalog::rootfs_query(&txn)
                    .await?
                    .all(&txn)
                    .await?
                    .into_iter()
                    .filter_map(|root| root.manifest_id)
                    .collect::<HashSet<_>>();
                let snapshot_refs = snapshot::Entity::find()
                    .all(&txn)
                    .await?
                    .into_iter()
                    .map(|row| row.image_manifest_digest)
                    .collect::<HashSet<_>>();
                let mut report = ImagePruneReport::default();
                let mut cleanup = Cleanup {
                    skipped,
                    ..Default::default()
                };
                let references = image_ref::Entity::find()
                    .find_also_related(manifest::Entity)
                    .all(&txn)
                    .await?;
                let retained_ids = references
                    .iter()
                    .filter_map(|(_, manifest)| manifest.as_ref())
                    .filter(|manifest| {
                        sandbox_refs.contains(&manifest.id)
                            || snapshot_refs.contains(&manifest.digest)
                    })
                    .map(|manifest| manifest.id)
                    .collect::<HashSet<_>>();
                let retained_paths = references
                    .iter()
                    .filter(|(reference, _)| retained_ids.contains(&reference.manifest_id))
                    .filter_map(|(reference, _)| reference.reference.parse::<Reference>().ok())
                    .map(|reference| cache.image_metadata_path(&reference))
                    .collect::<HashSet<_>>();
                for (reference, manifest) in references {
                    if let Some((name, _)) = &selected
                        && &reference.reference != name
                    {
                        continue;
                    }
                    let Some(manifest) = manifest else {
                        continue;
                    };
                    if selected.is_some() && !selected_manifests.contains(&manifest.id) {
                        return Err(MicrosandboxError::ImageInUse(
                            "image reference changed during removal; retry".into(),
                        ));
                    }
                    let retained = sandbox_refs.contains(&manifest.id)
                        || snapshot_refs.contains(&manifest.digest);
                    if retained {
                        match &selected {
                            None => continue,
                            Some((_, false)) => {
                                return Err(MicrosandboxError::ImageInUse(
                                    "sandbox or snapshot dependency".into(),
                                ));
                            }
                            Some((_, true)) => {} // Force may untag; durable backing remains protected below.
                        }
                    }
                    let parsed: Reference = reference
                        .reference
                        .parse::<Reference>()
                        .map_err(|error| MicrosandboxError::InvalidConfig(error.to_string()))?;
                    let path = cache.image_metadata_path(&parsed);
                    if !admit(&mut cleanup, vec![path.clone()], &mut report)? {
                        if selected.is_some() && !cleanup.more {
                            return Err(MicrosandboxError::ImageInUse(
                                "active storage operation".into(),
                            ));
                        }
                        continue;
                    }
                    if retained {
                        // Snapshot export still reads the cached config by its original
                        // reference. Untagging must preserve that metadata as well as disks.
                        cleanup.files.retain(|candidate| candidate != &path);
                    }
                    image_ref::Entity::delete_by_id(reference.id)
                        .exec(&txn)
                        .await?;
                    report.image_refs_removed += 1;
                }
                // A metadata pathname can have several catalog aliases, including aliases
                // whose older catalog digest differs from the currently published bytes.
                let remaining_paths = image_ref::Entity::find()
                    .all(&txn)
                    .await?
                    .into_iter()
                    .filter_map(|reference| reference.reference.parse::<Reference>().ok())
                    .map(|reference| cache.image_metadata_path(&reference))
                    .collect::<HashSet<_>>();
                let retained_digests = manifest::Entity::find()
                    .all(&txn)
                    .await?
                    .into_iter()
                    .filter(|manifest| {
                        sandbox_refs.contains(&manifest.id)
                            || snapshot_refs.contains(&manifest.digest)
                    })
                    .map(|manifest| manifest.digest)
                    .collect::<HashSet<_>>();
                let mut deletable = Vec::new();
                for path in &cleanup.files {
                    let bytes = match std::fs::read(path) {
                        Ok(bytes) => Some(bytes),
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                        Err(error) => return Err(error.into()),
                    };
                    let retained_generation = bytes
                        .as_deref()
                        .and_then(|bytes| {
                            serde_json::from_slice::<microsandbox_image::CachedImageMetadata>(bytes)
                                .ok()
                        })
                        .is_some_and(|metadata| {
                            retained_digests.contains(&metadata.manifest_digest)
                        });
                    if !remaining_paths.contains(path)
                        && !retained_paths.contains(path)
                        && !retained_generation
                    {
                        deletable.push(path.clone());
                    }
                }
                cleanup.files = deletable;

                for manifest in manifest::Entity::find().all(&txn).await? {
                    if selected.is_some() && !selected_manifests.contains(&manifest.id) {
                        continue;
                    }
                    if sandbox_refs.contains(&manifest.id)
                        || snapshot_refs.contains(&manifest.digest)
                    {
                        continue;
                    }
                    if image_ref::Entity::find()
                        .filter(image_ref::Column::ManifestId.eq(manifest.id))
                        .count(&txn)
                        .await?
                        != 0
                    {
                        continue;
                    }
                    let digest: Digest = manifest.digest.parse()?;
                    if !admit(
                        &mut cleanup,
                        vec![cache.fsmeta_erofs_path(&digest), cache.vmdk_path(&digest)],
                        &mut report,
                    )? {
                        continue;
                    }
                    manifest::Entity::delete_by_id(manifest.id)
                        .exec(&txn)
                        .await?;
                    report.manifests_removed += 1;
                }
                let orphaned = layer::Entity::find()
                    .left_join(manifest_layer::Entity)
                    .filter(manifest_layer::Column::Id.is_null())
                    .all(&txn)
                    .await?;
                for layer in orphaned {
                    if selected.is_some() && !selected_layers.contains(&layer.id) {
                        continue;
                    }
                    if !admit(
                        &mut cleanup,
                        vec![cache.layer_erofs_path(&layer.diff_id.parse()?)],
                        &mut report,
                    )? {
                        continue;
                    }
                    layer::Entity::delete_by_id(layer.id).exec(&txn).await?;
                    report.layers_removed += 1;
                }
                cleanup.journal = Journal::prepare(&local.cache_dir(), &cleanup.files)?;
                Ok::<_, MicrosandboxError>((txn, (report, cleanup)))
            }
        })
        .await?;

    // Removal of catalog ownership precedes unlink. A crash can leave reclaimable bytes,
    // but never a committed catalog row claiming a partially deleted artifact is usable.
    // Cancellation cannot release the leases while a detached filesystem task still unlinks.
    tokio::task::spawn_blocking(
        move || -> MicrosandboxResult<(ImagePruneReport, bool, HashSet<PathBuf>)> {
            let mut cleanup = cleanup;
            let removed = match cleanup.journal.take() {
                Some(journal) => journal.finish()?,
                None => Vec::new(),
            };
            for (path, size) in removed {
                report.bytes_reclaimed =
                    Some(report.bytes_reclaimed.unwrap_or(0).saturating_add(size));
                match path
                    .parent()
                    .and_then(|parent| parent.file_name())
                    .and_then(|name| name.to_str())
                {
                    Some("fsmeta") => report.fsmeta_removed += 1,
                    Some("vmdk") => report.vmdk_removed += 1,
                    _ => {}
                }
            }
            Ok((report, cleanup.more, cleanup.skipped))
        },
    )
    .await
    .map_err(|error| MicrosandboxError::Custom(format!("image cleanup task: {error}")))?
}

/// Nonblocking acquisition is allowed inside the catalog transaction. Readers/publishers
/// acquire shared protection before entering their transaction; deletion never waits on them.
fn admit(
    cleanup: &mut Cleanup,
    mut paths: Vec<PathBuf>,
    report: &mut ImagePruneReport,
) -> MicrosandboxResult<bool> {
    paths.sort();
    paths.dedup();
    if paths.iter().any(|path| cleanup.skipped.contains(path)) {
        return Ok(false);
    }
    let additional = paths
        .iter()
        .filter(|path| !cleanup.leases.contains_key(*path))
        .count();
    // Bound descriptors even when pruning thousands of independent manifests. All selected
    // objects remain exclusively pinned until this batch's catalog and unlink finish.
    if cleanup.leases.len() + additional > 48 {
        cleanup.more = true;
        return Ok(false);
    }
    let mut leases = Vec::new();
    for path in &paths {
        if cleanup.leases.contains_key(path) {
            continue;
        }
        let Some(lease) = StorageLease::try_exclusive(path)? else {
            cleanup.skipped.extend(paths);
            report.skipped_in_use += 1;
            return Ok(false);
        };
        leases.push((path.clone(), lease));
    }
    for path in paths {
        if !cleanup.leases.contains_key(&path) {
            cleanup.files.push(path);
        }
    }
    cleanup.leases.extend(leases);
    Ok(true)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Image;
    use microsandbox_image::{CachedImageMetadata, CachedLayerMetadata, ImageConfig};

    async fn local(home: &std::path::Path) -> LocalBackend {
        crate::test_support::local_backend_builder(home)
            .build()
            .await
            .unwrap()
    }

    fn metadata(id: char, layer: char) -> CachedImageMetadata {
        CachedImageMetadata {
            manifest_digest: format!("sha256:{}", id.to_string().repeat(64)),
            config_digest: format!("sha256:{}", id.to_string().repeat(64)),
            raw_manifest_json: "{}".into(),
            raw_config_json: "{}".into(),
            config: ImageConfig::default(),
            layers: vec![CachedLayerMetadata {
                digest: format!("sha256:{}", layer.to_string().repeat(64)),
                media_type: None,
                size_bytes: Some(7),
                diff_id: format!("sha256:{}", layer.to_string().repeat(64)),
            }],
        }
    }

    async fn install(
        local: &LocalBackend,
        reference: &str,
        metadata: &CachedImageMetadata,
    ) -> GlobalCache {
        let cache = GlobalCache::new(&local.cache_dir()).unwrap();
        for path in cache.metadata_paths(metadata).unwrap() {
            std::fs::write(path, b"payload").unwrap();
        }
        cache
            .write_image_metadata_async(&reference.parse().unwrap(), metadata)
            .await
            .unwrap();
        Image::persist(local, reference, metadata.clone())
            .await
            .unwrap();
        cache
    }

    #[tokio::test]
    async fn aliases_share_one_deletion_lease_and_leave_no_broken_reference() {
        let home = tempfile::tempdir().unwrap();
        let local = local(home.path()).await;
        let data = metadata('a', 'c');
        let cache = install(&local, "audit-tiny:latest", &data).await;
        install(&local, "docker.io/library/audit-tiny:latest", &data).await;
        let report = prune(&local).await.unwrap();
        assert_eq!(report.image_refs_removed, 2);
        assert_eq!(report.skipped_in_use, 0);
        assert_eq!(report.layers_removed, 1);
        assert!(
            !cache
                .image_metadata_path(&"audit-tiny:latest".parse().unwrap())
                .exists()
        );
    }

    #[tokio::test]
    async fn cleanup_spans_bounded_batches() {
        #[cfg(unix)]
        if std::env::var_os("MSB_TEST_BOUNDED_PRUNE").is_none() {
            use std::os::unix::process::CommandExt;
            let mut child = std::process::Command::new(std::env::current_exe().unwrap());
            child
                .args([
                    "--exact",
                    "image::cleanup::tests::cleanup_spans_bounded_batches",
                    "--nocapture",
                ])
                .env("MSB_TEST_BOUNDED_PRUNE", "1");
            // Isolate the process-wide descriptor limit from other parallel tests.
            unsafe {
                child.pre_exec(|| {
                    let limit = libc::rlimit {
                        rlim_cur: 256,
                        rlim_max: 256,
                    };
                    if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            assert!(child.status().unwrap().success());
            return;
        }
        let home = tempfile::tempdir().unwrap();
        let local = local(home.path()).await;
        for index in 0..80 {
            let mut data = metadata('a', 'c');
            data.manifest_digest = format!("sha256:{index:064x}");
            install(&local, &format!("example.com/image-{index}:latest"), &data).await;
        }
        let report = prune(&local).await.unwrap();
        assert_eq!(report.image_refs_removed, 80);
        assert_eq!(report.manifests_removed, 80);
        assert_eq!(report.layers_removed, 1);
        assert_eq!(report.skipped_in_use, 0);
    }

    #[tokio::test]
    async fn interrupted_journal_disposal_without_active_lock_is_recovered() {
        let home = tempfile::tempdir().unwrap();
        let local = local(home.path()).await;
        let journal = local
            .cache_dir()
            .join(".image-deletions/delete-interrupted");
        std::fs::create_dir_all(&journal).unwrap();
        std::fs::write(journal.join("0"), b"retained orphan").unwrap();
        std::fs::write(journal.join("files.json"), b"[]").unwrap();
        cleanup_journal::recover(&local).await.unwrap();
        assert!(!journal.exists());
    }

    #[tokio::test]
    async fn busy_image_does_not_block_unrelated_pruning_or_lose_shared_layer() {
        let home = tempfile::tempdir().unwrap();
        let local = local(home.path()).await;
        let a = "example.com/a:latest";
        let b = "example.com/b:latest";
        let metadata_a = metadata('a', 'c');
        let cache = install(&local, a, &metadata_a).await;
        install(&local, b, &metadata('b', 'c')).await;
        let operation = cache.operation();
        operation
            .lease_paths(vec![cache.image_metadata_path(&a.parse().unwrap())])
            .unwrap();
        let report = prune(&local).await.unwrap();
        assert_eq!(report.image_refs_removed, 1);
        assert_eq!(report.skipped_in_use, 1);
        assert_eq!(report.layers_removed, 0);
        assert!(Image::get_local(&local, a).await.is_ok());
        assert!(Image::get_local(&local, b).await.is_err());
        assert!(
            cache
                .layer_erofs_path(&metadata_a.layers[0].diff_id.parse().unwrap())
                .exists()
        );
        assert!(
            remove(&local, a, true)
                .await
                .unwrap_err()
                .to_string()
                .contains("active storage operation")
        );
        drop(operation);
        let report = prune(&local).await.unwrap();
        assert_eq!(report.layers_removed, 1);
    }

    #[tokio::test]
    async fn shared_layer_publisher_is_protected_before_new_catalog_reference_exists() {
        let home = tempfile::tempdir().unwrap();
        let local = local(home.path()).await;
        let old = metadata('a', 'c');
        let cache = install(&local, "example.com/old:latest", &old).await;
        let operation = cache.operation();
        operation
            .lease_paths(cache.metadata_paths(&old).unwrap())
            .unwrap();
        let report = prune(&local).await.unwrap();
        assert!(report.skipped_in_use > 0);
        let new = metadata('b', 'c');
        Image::persist(&local, "example.com/new:latest", new)
            .await
            .unwrap();
        drop(operation);
        assert!(
            cache
                .layer_erofs_path(&old.layers[0].diff_id.parse().unwrap())
                .exists()
        );
        prune(&local).await.unwrap();
    }

    #[tokio::test]
    async fn pending_snapshot_publication_roots_survive_prune_until_abandoned() {
        use sea_orm::Set;
        let home = tempfile::tempdir().unwrap();
        let local = local(home.path()).await;
        let metadata = metadata('a', 'c');
        let reference = "example.com/a:latest";
        let cache = install(&local, reference, &metadata).await;
        let path = home.path().join("not-published-yet");
        let publisher = microsandbox_image::storage_lease::StorageLease::shared(&path).unwrap();
        let now = chrono::Utc::now().naive_utc();
        // Publication installs this durable root before renaming any snapshot payload.
        snapshot::Entity::insert(snapshot::ActiveModel {
            artifact_path: Set(path.display().to_string()),
            digest: Set("pending-descriptor".into()),
            scope: Set("disk".into()),
            state_kind: Set("file".into()),
            image_ref: Set(reference.into()),
            image_manifest_digest: Set(metadata.manifest_digest.clone()),
            locality: Set("embedded".into()),
            availability: Set("publishing".into()),
            migration_state: Set("current".into()),
            created_at: Set(now),
            indexed_at: Set(now),
            child_count: Set(0),
            ..Default::default()
        })
        .exec(local.db().await.unwrap().write())
        .await
        .unwrap();
        assert_eq!(prune(&local).await.unwrap().image_refs_removed, 0);
        for path in cache.metadata_paths(&metadata).unwrap() {
            assert!(path.exists(), "{}", path.display());
        }
        // A dead publisher with no installed artifact must not leak an image root forever.
        drop(publisher);
        let report = prune(&local).await.unwrap();
        assert_eq!(report.image_refs_removed, 1);
        assert_eq!(report.layers_removed, 1);
        assert!(
            snapshot::Entity::find()
                .all(local.db().await.unwrap().read())
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn force_untags_but_preserves_snapshot_backing_until_last_dependency_is_gone() {
        use sea_orm::Set;
        let home = tempfile::tempdir().unwrap();
        let local = local(home.path()).await;
        let metadata = metadata('a', 'c');
        let reference = "example.com/a:latest";
        let cache = install(&local, reference, &metadata).await;
        let now = chrono::Utc::now().naive_utc();
        snapshot::Entity::insert(snapshot::ActiveModel {
            artifact_path: Set(home.path().join("saved").display().to_string()),
            digest: Set("saved-descriptor".into()),
            scope: Set("disk".into()),
            state_kind: Set("file".into()),
            image_ref: Set(reference.into()),
            image_manifest_digest: Set(metadata.manifest_digest.clone()),
            locality: Set("embedded".into()),
            availability: Set("available".into()),
            migration_state: Set("current".into()),
            created_at: Set(now),
            indexed_at: Set(now),
            child_count: Set(0),
            ..Default::default()
        })
        .exec(local.db().await.unwrap().write())
        .await
        .unwrap();
        assert_eq!(prune(&local).await.unwrap().image_refs_removed, 0);
        assert!(remove(&local, reference, false).await.is_err());
        remove(&local, reference, true).await.unwrap();
        assert_eq!(
            cache
                .read_image_metadata_async(&reference.parse().unwrap())
                .await
                .unwrap()
                .unwrap()
                .manifest_digest,
            metadata.manifest_digest,
        );
        for path in cache.metadata_paths(&metadata).unwrap() {
            assert!(path.exists(), "{}", path.display());
        }
        assert_eq!(prune(&local).await.unwrap().layers_removed, 0);
        snapshot::Entity::delete_many()
            .exec(local.db().await.unwrap().write())
            .await
            .unwrap();
        assert_eq!(prune(&local).await.unwrap().layers_removed, 1);
    }

    #[tokio::test]
    async fn interrupted_cleanup_rechecks_catalog_and_never_unlinks_replacement() {
        let home = tempfile::tempdir().unwrap();
        let local = local(home.path()).await;
        let metadata = metadata('a', 'c');
        let cache = install(&local, "example.com/a:latest", &metadata).await;
        let path = cache.layer_erofs_path(&metadata.layers[0].diff_id.parse().unwrap());
        // A crash before commit: recovery must preserve the still-indexed file.
        let journal = Journal::prepare(&local.cache_dir(), std::slice::from_ref(&path)).unwrap();
        drop(journal);
        cleanup_journal::recover(&local).await.unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"payload");
        // A committed deletion followed by a new publication at the same name. Recovery
        // owns an old hard link, not permission to unlink the new generation.
        let journal = Journal::prepare(&local.cache_dir(), std::slice::from_ref(&path)).unwrap();
        drop(journal);
        image_ref::Entity::delete_many()
            .exec(local.db().await.unwrap().write())
            .await
            .unwrap();
        manifest::Entity::delete_many()
            .exec(local.db().await.unwrap().write())
            .await
            .unwrap();
        layer::Entity::delete_many()
            .exec(local.db().await.unwrap().write())
            .await
            .unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"replacement").unwrap();
        cleanup_journal::recover(&local).await.unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"replacement");
        // With no replacement, the admitted orphan is removed on the next recovery.
        let journal = Journal::prepare(&local.cache_dir(), std::slice::from_ref(&path)).unwrap();
        drop(journal);
        cleanup_journal::recover(&local).await.unwrap();
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn recovery_discards_abandoned_preparation_without_unlinking_sources() {
        let home = tempfile::tempdir().unwrap();
        let local = local(home.path()).await;
        let metadata = metadata('a', 'c');
        let cache = install(&local, "example.com/a:latest", &metadata).await;
        let source = cache.layer_erofs_path(&metadata.layers[0].diff_id.parse().unwrap());
        let stage = local
            .cache_dir()
            .join(".image-deletions/.prepare-interrupted");
        std::fs::create_dir_all(&stage).unwrap();
        let active =
            microsandbox_utils::process_lock::open_lock_file(&stage.join("active.lock")).unwrap();
        microsandbox_utils::process_lock::lock_exclusive(&active).unwrap();
        std::fs::hard_link(&source, stage.join("0")).unwrap();
        cleanup_journal::recover(&local).await.unwrap();
        assert!(stage.exists());
        drop(active);
        cleanup_journal::recover(&local).await.unwrap();
        assert!(!stage.exists());
        assert_eq!(std::fs::read(source).unwrap(), b"payload");
    }

    #[tokio::test]
    async fn concurrent_pruners_preserve_stable_lock_files() {
        let home = tempfile::tempdir().unwrap();
        let local = local(home.path()).await;
        let metadata = metadata('a', 'c');
        let cache = install(&local, "example.com/a:latest", &metadata).await;
        let materializer =
            cache.layer_erofs_lock_path(&metadata.layers[0].diff_id.parse().unwrap());
        let lock = microsandbox_utils::process_lock::open_lock_file(&materializer).unwrap();
        let (first, second) = tokio::join!(prune(&local), prune(&local));
        assert!(first.is_ok(), "{first:?}");
        assert!(second.is_ok(), "{second:?}");
        assert!(materializer.exists());
        assert_eq!(lock.metadata().unwrap().len(), 0);
    }
}
