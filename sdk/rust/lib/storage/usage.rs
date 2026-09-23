use crate::{MicrosandboxError, MicrosandboxResult, Operation};

use super::{Storage, StorageUsage};

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Storage {
    /// Revalidate and prune unused runtime RAM through the selected local backend.
    ///
    /// Durable snapshots, named volumes, sandbox disks, and stable handoff locks are excluded.
    /// Set `dry_run` to inspect the same eligibility rules without removing files.
    #[cfg(feature = "local")]
    pub async fn prune(
        options: &super::MemoryPruneOptions,
    ) -> MicrosandboxResult<super::MemoryCacheReport> {
        let backend = crate::backend::default_backend();
        let local = backend
            .as_local()
            .ok_or_else(|| MicrosandboxError::local_only(Operation::StoragePrune))?;
        Self::prune_local(local, options).await
    }

    /// Revalidate and prune unused runtime RAM in an explicitly selected local backend.
    #[cfg(feature = "local")]
    pub async fn prune_local(
        local: &crate::LocalBackend,
        options: &super::MemoryPruneOptions,
    ) -> MicrosandboxResult<super::MemoryCacheReport> {
        let root = local.cache_dir().join("memory");
        let options = options.clone();
        tokio::task::spawn_blocking(move || {
            microsandbox_runtime::checkpoint::prune_memory_cache(&root, &options)
        })
        .await
        .map_err(|error| MicrosandboxError::Custom(format!("storage pruning: {error}")))?
        .map_err(MicrosandboxError::from)
    }

    /// Observe storage through the selected backend. Remote accounting is explicitly unsupported.
    pub async fn usage() -> MicrosandboxResult<StorageUsage> {
        #[cfg(feature = "local")]
        {
            let backend = crate::backend::default_backend();
            let local = backend
                .as_local()
                .ok_or_else(|| MicrosandboxError::local_only(Operation::StorageUsage))?;
            Self::usage_local(local).await
        }
        #[cfg(not(feature = "local"))]
        Err(MicrosandboxError::local_only(Operation::StorageUsage))
    }

    /// Observe a specific local backend's managed roots and indexed snapshot paths.
    ///
    /// Bind-mounted host trees and unindexed external artifacts are excluded. Directory scans
    /// never follow symlinks. Missing managed roots count as empty; inaccessible roots are unknown.
    #[cfg(feature = "local")]
    pub async fn usage_local(local: &crate::LocalBackend) -> MicrosandboxResult<StorageUsage> {
        local_usage::usage(local).await
    }

    /// Measure one explicitly selected directory, preserving the captured backend at the caller.
    #[cfg(feature = "local")]
    pub(crate) async fn directory_usage(
        name: String,
        path: std::path::PathBuf,
        managed_root: std::path::PathBuf,
        reason: &'static str,
    ) -> MicrosandboxResult<super::StorageItemUsage> {
        tokio::task::spawn_blocking(move || {
            local_usage::item_scoped(name, path, reason, Some(&managed_root))
        })
        .await
        .map_err(|error| MicrosandboxError::Custom(format!("storage inspection: {error}")))
    }
}

#[cfg(feature = "local")]
mod local_usage {
    #[cfg(unix)]
    use std::collections::HashSet;
    use std::io;
    use std::path::{Path, PathBuf};

    #[cfg(unix)]
    use cap_std::fs::MetadataExt;
    use cap_std::fs::{Dir, Metadata};
    use microsandbox_runtime::checkpoint::{
        MemoryCacheEntry, MemoryCacheKind, MemoryCacheState, inspect_memory_cache,
    };
    use sea_orm::EntityTrait;

    use crate::db::entity::{image_ref, sandbox, snapshot, volume};
    use crate::{LocalBackend, MicrosandboxError, MicrosandboxResult};

    use super::super::{StorageCategoryUsage, StorageItemUsage, StorageUsage};

    //--------------------------------------------------------------------------------------------------
    // Types
    //--------------------------------------------------------------------------------------------------

    #[derive(Default)]
    struct Scan {
        logical: u64,
        allocated: u64,
        #[cfg(unix)]
        seen: HashSet<(u64, u64)>,
        skipped: u64,
    }

    //--------------------------------------------------------------------------------------------------
    // Functions
    //--------------------------------------------------------------------------------------------------

    pub(super) async fn usage(local: &LocalBackend) -> MicrosandboxResult<StorageUsage> {
        let db = local.db().await?.read();
        let images = image_ref::Entity::find().all(db).await?;
        let snapshots = snapshot::Entity::find().all(db).await?;
        let sandboxes = sandbox::Entity::find().all(db).await?;
        let volumes = volume::Entity::find().all(db).await?;
        let cache_root = local.cache_dir();
        let snapshot_root = local.snapshots_dir();
        let sandbox_root = local.sandboxes_dir();
        let volume_root = local.volumes_dir();

        tokio::task::spawn_blocking(move || {
            // Image references share materialized layers. Scan each cache component once instead
            // of summing per-reference sizes, which counts shared layers repeatedly.
            let image_roots: Vec<_> = ["layers", "fsmeta", "vmdk", "flat", "manifests", "tmp"]
                .into_iter()
                .map(|component| cache_root.join(component))
                .collect();
            let image_items = image_roots
                .iter()
                .map(|path| item_scoped(
                    path.file_name().unwrap().to_string_lossy().into_owned(),
                    path.clone(),
                    "Shared image-cache component; ownership and reclaimability are not measured.",
                    Some(&cache_root),
                ))
                .collect();
            let mut snapshot_roots = vec![snapshot_root.clone()];
            // The index explicitly identifies external installed artifacts. Include those paths,
            // without discovering arbitrary host directories or following linked payloads.
            snapshot_roots.extend(snapshots.iter().map(|row| PathBuf::from(&row.artifact_path)));
            let snapshot_items = snapshots.iter().map(|row| {
                let mut usage = item_scoped(
                    row.snapshot_id.as_deref().unwrap_or(&row.digest).to_owned(),
                    PathBuf::from(&row.artifact_path),
                    "Durable snapshot; active readers and retention eligibility are unknown.",
                    Some(&snapshot_root),
                );
                if row.child_count > 0 {
                    usage.reasons.push(format!("{} indexed child snapshot(s) retain historical ancestry.", row.child_count));
                }
                usage
            }).collect();
            let sandbox_items = sandboxes.iter().map(|row| item_scoped(
                row.name.clone(), sandbox_root.join(&row.name),
                "Persisted sandbox data is retained, including stopped and crashed sandboxes. Bind-mounted host trees are excluded.",
                Some(&sandbox_root),
            )).collect();
            let volume_items = volumes.iter().map(|row| item_scoped(
                row.name.clone(), volume_root.join(&row.name),
                "Named-volume data is retained. Mount ownership is not measured.",
                Some(&volume_root),
            )).collect();
            let mut usage = StorageUsage {
                images: category(images.len(), image_roots, image_items, Some(&cache_root)),
                snapshots: category(snapshots.len(), snapshot_roots, snapshot_items, Some(&snapshot_root)),
                sandboxes: category(sandboxes.len(), vec![sandbox_root.clone()], sandbox_items, Some(&sandbox_root)),
                volumes: category(volumes.len(), vec![volume_root.clone()], volume_items, Some(&volume_root)),
                notes: vec![
                    "Logical bytes sum regular-file lengths. Allocated bytes are per-file block observations, not unique physical usage or space deletion will free.".into(),
                    "Counts describe indexed objects; managed-directory totals also include unindexed files and metadata. Object sizes overlap shared data and are not additive.".into(),
                    "Bind mounts, logs outside managed object directories, unindexed external artifacts, and anonymous Linux RAM are excluded. Ownership observations can change after inspection.".into(),
                ],
                ..Default::default()
            };
            match inspect_memory_cache(&cache_root.join("memory")) {
                Ok(report) => {
                    usage.branch_memory = memory_category(&report.entries, MemoryCacheKind::BranchMemory);
                    usage.snapshot_memory = memory_category(&report.entries, MemoryCacheKind::SnapshotMemory);
                }
                Err(error) => {
                    let note = format!("Memory-cache inspection unavailable: {error}");
                    usage.branch_memory.notes.push(note.clone());
                    usage.snapshot_memory.notes.push(note);
                }
            }
            // Unusual custom root configurations can overlap categories. Do not offer totals
            // that count one managed tree as two independent categories.
            let roots = [cache_root, snapshot_root, sandbox_root, volume_root];
            for left in 0..roots.len() {
                for right in left + 1..roots.len() {
                    if roots[left].starts_with(&roots[right]) || roots[right].starts_with(&roots[left]) {
                        usage.notes.push(format!("Configured storage roots overlap ({} and {}); category totals are not additive.", roots[left].display(), roots[right].display()));
                    }
                }
            }
            usage
        })
        .await
        .map_err(|error| MicrosandboxError::Custom(format!("storage accounting: {error}")))
    }

    pub(super) fn item_scoped(
        name: String,
        path: PathBuf,
        reason: &str,
        managed_root: Option<&Path>,
    ) -> StorageItemUsage {
        let mut item = StorageItemUsage {
            name,
            path,
            reasons: vec![reason.into()],
            ..Default::default()
        };
        let mut scan = Scan::default();
        match scan_scoped(&item.path, managed_root, &mut scan) {
            Ok(true) => {
                item.logical_bytes = Some(scan.logical);
                item.allocated_bytes = allocated(&scan);
                if scan.skipped > 0 {
                    item.reasons.push(format!(
                        "Skipped {} symlink or special-file entries.",
                        scan.skipped
                    ));
                }
            }
            Ok(false) => item
                .reasons
                .push("Artifact directory is missing; stored bytes are unknown.".into()),
            Err(error) => item
                .reasons
                .push(format!("Storage observation incomplete: {error}")),
        }
        item
    }

    fn category(
        count: usize,
        mut roots: Vec<PathBuf>,
        items: Vec<StorageItemUsage>,
        managed_root: Option<&Path>,
    ) -> StorageCategoryUsage {
        roots.sort();
        let mut selected = Vec::<PathBuf>::new();
        for root in roots {
            if !selected.iter().any(|parent| root.starts_with(parent)) {
                selected.push(root);
            }
        }
        let mut category = StorageCategoryUsage {
            count: Some(count as u64),
            items,
            ..Default::default()
        };
        let mut scan = Scan::default();
        for root in selected {
            // Aggregate components have the same trusted boundary as detail items. Opening
            // only a component's final name would follow a substituted managed-root symlink.
            if let Err(error) = scan_scoped(&root, managed_root, &mut scan) {
                category.notes.push(format!(
                    "Storage observation incomplete at {}: {error}",
                    root.display()
                ));
            }
        }
        if category.notes.is_empty() {
            category.logical_bytes = Some(scan.logical);
            category.allocated_bytes = allocated(&scan);
        }
        if scan.skipped > 0 {
            category.notes.push(format!(
                "Skipped {} symlink or special-file entries; their targets are excluded.",
                scan.skipped
            ));
        }
        category
    }

    fn memory_category(
        entries: &[MemoryCacheEntry],
        kind: MemoryCacheKind,
    ) -> StorageCategoryUsage {
        let items: Vec<_> = entries
            .iter()
            .filter(|entry| entry.kind == kind)
            .map(|entry| {
                let (in_use, reclaimable, reason) = match entry.state {
                    MemoryCacheState::Reclaimable => (
                        Some(false),
                        Some(true),
                        "No owner observed; prune revalidates ownership before removal.",
                    ),
                    MemoryCacheState::InUse => (
                        Some(true),
                        Some(false),
                        "Retained by a runtime mapping, SDK handle, or incremental baseline.",
                    ),
                    MemoryCacheState::PendingHandoff => (
                        Some(true),
                        Some(false),
                        "Retained by a pending branch handoff.",
                    ),
                    MemoryCacheState::TooYoung => {
                        (None, Some(false), "Excluded by the age policy.")
                    }
                    MemoryCacheState::MissingHandoffLock => (
                        None,
                        Some(false),
                        "Stable handoff lock is missing; ownership cannot be established.",
                    ),
                    MemoryCacheState::Changed => {
                        (None, None, "File disappeared or changed during inspection.")
                    }
                    MemoryCacheState::Removed => (None, None, "File was removed."),
                    MemoryCacheState::Error => (None, None, "Ownership observation failed."),
                };
                let mut reasons = vec![reason.into()];
                reasons.extend(entry.error.clone());
                StorageItemUsage {
                    name: entry
                        .path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .into_owned(),
                    path: entry.path.clone(),
                    logical_bytes: entry.logical_bytes,
                    allocated_bytes: entry.allocated_bytes,
                    in_use,
                    reclaimable,
                    reasons,
                }
            })
            .collect();
        StorageCategoryUsage {
            count: Some(items.len() as u64),
            in_use: sum_known(items.iter().map(|item| item.in_use.map(u64::from))),
            logical_bytes: sum_known(items.iter().map(|item| item.logical_bytes)),
            allocated_bytes: if cfg!(unix) {
                sum_known(items.iter().map(|item| item.allocated_bytes))
            } else {
                None
            },
            reclaimable_logical_bytes: sum_known(items.iter().map(|item| match item.reclaimable {
                Some(true) => item.logical_bytes,
                Some(false) => Some(0),
                None => None,
            })),
            items,
            notes: vec![
                "Published .ram files only; stable lock files and staging entries are excluded."
                    .into(),
            ],
        }
    }

    fn allocated(scan: &Scan) -> Option<u64> {
        cfg!(unix).then_some(scan.allocated)
    }

    fn sum_known(mut values: impl Iterator<Item = Option<u64>>) -> Option<u64> {
        values.try_fold(0u64, |total, value| total.checked_add(value?))
    }

    fn scan_scoped(path: &Path, managed_root: Option<&Path>, scan: &mut Scan) -> io::Result<bool> {
        let root = managed_root
            .filter(|root| path.starts_with(root))
            .unwrap_or(path);
        let mut directory = match open_root(root) {
            Ok(directory) => directory,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };
        for component in path
            .strip_prefix(root)
            .expect("selected ancestor root")
            .components()
        {
            let std::path::Component::Normal(name) = component else {
                return Err(io::Error::other(
                    "object path escapes its managed storage root",
                ));
            };
            directory = match cap_primitives::fs::open_dir_nofollow(&directory, Path::new(name)) {
                Ok(directory) => directory,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
                Err(error) => return Err(error),
            };
        }
        walk(Dir::from_std_file(directory), scan, 0)?;
        Ok(true)
    }

    fn open_root(path: &Path) -> io::Result<std::fs::File> {
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(io::Error::other("storage root is not a regular directory"));
        }
        let absolute = std::path::absolute(path)?;
        let parent = absolute
            .parent()
            .ok_or_else(|| io::Error::other("storage root must have a parent"))?;
        let name = absolute
            .file_name()
            .ok_or_else(|| io::Error::other("storage root has no name"))?;
        let parent = Dir::open_ambient_dir(parent, cap_std::ambient_authority())?.into_std_file();
        cap_primitives::fs::open_dir_nofollow(&parent, Path::new(name))
    }

    fn walk(directory: Dir, scan: &mut Scan, depth: usize) -> io::Result<()> {
        if depth > 128 {
            return Err(io::Error::other(
                "storage directory nesting exceeds 128 levels",
            ));
        }
        let entries = directory.entries()?;
        let parent = directory.into_std_file();
        for entry in entries {
            let entry = entry?;
            let metadata = entry.metadata()?;
            if metadata.file_type().is_symlink() {
                scan.skipped += 1;
            } else if metadata.is_dir() {
                // Relative no-follow opens prevent a directory swapped for a symlink between
                // metadata inspection and traversal from leading us into another host tree.
                let child =
                    cap_primitives::fs::open_dir_nofollow(&parent, Path::new(&entry.file_name()))?;
                walk(Dir::from_std_file(child), scan, depth + 1)?;
            } else if metadata.is_file() {
                add_file(scan, &metadata)?;
            } else {
                scan.skipped += 1;
            }
        }
        Ok(())
    }

    fn add_file(scan: &mut Scan, metadata: &Metadata) -> io::Result<()> {
        #[cfg(unix)]
        if !scan.seen.insert((metadata.dev(), metadata.ino())) {
            return Ok(());
        }
        scan.logical = scan
            .logical
            .checked_add(metadata.len())
            .ok_or_else(|| io::Error::other("logical byte count overflow"))?;
        #[cfg(unix)]
        {
            let bytes = metadata
                .blocks()
                .checked_mul(512)
                .ok_or_else(|| io::Error::other("allocated byte count overflow"))?;
            scan.allocated = scan
                .allocated
                .checked_add(bytes)
                .ok_or_else(|| io::Error::other("allocated byte count overflow"))?;
        }
        Ok(())
    }

    //--------------------------------------------------------------------------------------------------
    // Tests
    //--------------------------------------------------------------------------------------------------

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn regular_files_and_overlapping_roots_are_counted_once() {
            let temporary = tempfile::tempdir().unwrap();
            let nested = temporary.path().join("nested");
            std::fs::create_dir(&nested).unwrap();
            std::fs::write(temporary.path().join("first"), [1; 5]).unwrap();
            std::fs::write(nested.join("second"), [2; 7]).unwrap();
            let report = category(
                2,
                vec![nested, temporary.path().to_path_buf()],
                Vec::new(),
                None,
            );
            assert_eq!(report.logical_bytes, Some(12));
            assert_eq!(report.in_use, None);
            assert_eq!(report.reclaimable_logical_bytes, None);
        }

        #[test]
        fn incomplete_memory_ownership_does_not_become_zero_reclaimable_bytes() {
            let entry = MemoryCacheEntry {
                path: "fixture.ram".into(),
                kind: MemoryCacheKind::BranchMemory,
                logical_bytes: Some(17),
                allocated_bytes: Some(4096),
                state: MemoryCacheState::Error,
                error: Some("fixture failure".into()),
            };
            let report = memory_category(&[entry], MemoryCacheKind::BranchMemory);
            assert_eq!(report.logical_bytes, Some(17));
            assert_eq!(report.in_use, None);
            assert_eq!(report.reclaimable_logical_bytes, None);
            assert_eq!(sum_known([Some(u64::MAX), Some(1)].into_iter()), None);
        }

        #[test]
        fn missing_managed_root_is_empty_but_missing_object_is_unknown() {
            let temporary = tempfile::tempdir().unwrap();
            let path = temporary.path().join("missing");
            assert_eq!(
                category(0, vec![path.clone()], Vec::new(), None).logical_bytes,
                Some(0)
            );
            let missing = item_scoped("missing".into(), path.clone(), "fixture", None);
            assert_eq!(missing.logical_bytes, None);
            assert!(
                missing
                    .reasons
                    .iter()
                    .any(|reason| reason.contains("missing"))
            );
            assert!(!path.exists());
        }

        #[cfg(unix)]
        #[test]
        fn symlink_targets_are_never_walked_and_hardlinks_are_deduplicated() {
            let temporary = tempfile::tempdir().unwrap();
            let external = tempfile::tempdir().unwrap();
            std::fs::write(external.path().join("secret"), [9; 100]).unwrap();
            std::fs::write(temporary.path().join("owned"), [1; 7]).unwrap();
            std::fs::hard_link(
                temporary.path().join("owned"),
                temporary.path().join("same"),
            )
            .unwrap();
            std::os::unix::fs::symlink(external.path(), temporary.path().join("escape")).unwrap();
            std::os::unix::fs::symlink(
                external.path().join("secret"),
                temporary.path().join("file"),
            )
            .unwrap();
            let report = category(1, vec![temporary.path().to_path_buf()], Vec::new(), None);
            assert_eq!(report.logical_bytes, Some(7));
            assert!(report.notes.iter().any(|note| note.contains("Skipped 2")));
            let linked = item_scoped(
                "linked".into(),
                temporary.path().join("escape"),
                "fixture",
                None,
            );
            assert_eq!(linked.logical_bytes, None);
        }

        #[cfg(unix)]
        #[test]
        fn indexed_object_cannot_follow_a_substituted_ancestor_or_escape_its_root() {
            let temporary = tempfile::tempdir().unwrap();
            let external = tempfile::tempdir().unwrap();
            std::fs::create_dir(external.path().join("artifact")).unwrap();
            std::fs::write(external.path().join("artifact/secret"), [9; 100]).unwrap();
            std::os::unix::fs::symlink(external.path(), temporary.path().join("group")).unwrap();
            let item = item_scoped(
                "snapshot".into(),
                temporary.path().join("group/artifact"),
                "fixture",
                Some(temporary.path()),
            );
            assert_eq!(item.logical_bytes, None);
            assert!(
                item.reasons
                    .iter()
                    .any(|reason| reason.contains("incomplete"))
            );
            let escaped = item_scoped(
                "snapshot".into(),
                temporary.path().join("../outside"),
                "fixture",
                Some(temporary.path()),
            );
            assert_eq!(escaped.logical_bytes, None);
        }

        #[cfg(unix)]
        #[test]
        fn aggregate_and_detail_reject_a_symlinked_managed_cache_root() {
            let temporary = tempfile::tempdir().unwrap();
            let external = tempfile::tempdir().unwrap();
            std::fs::create_dir(external.path().join("layers")).unwrap();
            std::fs::write(external.path().join("layers/foreign"), [9; 100]).unwrap();
            let cache = temporary.path().join("cache");
            std::os::unix::fs::symlink(external.path(), &cache).unwrap();
            let component = cache.join("layers");
            let detail = item_scoped("layers".into(), component.clone(), "fixture", Some(&cache));
            let aggregate = category(0, vec![component], vec![detail], Some(&cache));
            assert_eq!(aggregate.logical_bytes, None);
            assert_eq!(aggregate.allocated_bytes, None);
            assert_eq!(aggregate.items[0].logical_bytes, None);
            assert!(
                aggregate
                    .notes
                    .iter()
                    .any(|note| note.contains("not a regular directory"))
            );
        }

        #[tokio::test]
        async fn selected_backend_controls_roots_without_creating_missing_storage() {
            let temporary = tempfile::tempdir().unwrap();
            let cache = temporary.path().join("custom-cache");
            let local = LocalBackend::builder()
                .home(temporary.path())
                .config_path(temporary.path().join("config.toml"))
                .cache_dir(&cache)
                .build()
                .await
                .unwrap();
            std::fs::create_dir_all(cache.join("layers")).unwrap();
            std::fs::write(cache.join("layers/fixture"), [1; 17]).unwrap();
            let report = crate::with_backend(local, crate::Storage::usage())
                .await
                .unwrap();
            assert_eq!(report.images.logical_bytes, Some(17));
            assert_eq!(report.images.count, Some(0));
            assert!(!cache.join("memory").exists());
            assert!(!cache.join("manifests").exists());
        }

        #[cfg(feature = "cloud")]
        #[tokio::test]
        async fn remote_storage_operations_fail_without_touching_local_cache() {
            let cloud = crate::CloudBackend::builder()
                .url("https://example.invalid")
                .api_key("storage-test-no-network")
                .build()
                .unwrap();
            crate::with_backend(cloud, async {
                let error = crate::Storage::usage().await.unwrap_err();
                assert!(matches!(
                    error,
                    MicrosandboxError::Unsupported {
                        op: crate::Operation::StorageUsage,
                        ..
                    }
                ));
                let error = crate::Storage::prune(&Default::default())
                    .await
                    .unwrap_err();
                assert!(matches!(
                    error,
                    MicrosandboxError::Unsupported {
                        op: crate::Operation::StoragePrune,
                        ..
                    }
                ));
            })
            .await;
        }
    }
}
