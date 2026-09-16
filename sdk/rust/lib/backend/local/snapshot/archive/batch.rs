//! Local backend: One-pass archive staging and dependency resolution for a local group import.

use super::*;
use microsandbox_image::snapshot::{Manifest, SnapshotId};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct StagedArchive {
    source: PathBuf,
    snapshots: tempfile::TempDir,
    cache: tempfile::TempDir,
    unpacked: UnpackedArchive,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) async fn load(
    local: &LocalBackend,
    archives: &[PathBuf],
    opts: LoadOpts,
) -> MicrosandboxResult<Vec<SnapshotHandle>> {
    if archives.is_empty() {
        return Err(MicrosandboxError::InvalidConfig(
            "snapshot load requires at least one archive".into(),
        ));
    }
    let started = Instant::now();
    let snapshots_dir = opts.dest.clone().unwrap_or_else(|| local.snapshots_dir());
    // Validate the requested namespace before doing expensive I/O. This read does not create a
    // group; a bad or incomplete batch must not publish any of its snapshot members.
    let existing = match opts.group.as_deref() {
        Some(group) => super::super::group::dependency_members(&snapshots_dir, group).await?,
        None => Vec::new(),
    };
    tokio::fs::create_dir_all(&snapshots_dir).await?;
    let cache_dir = local.cache_dir();
    let cache_tmp = cache_dir.join("tmp");
    tokio::fs::create_dir_all(&cache_tmp).await?;

    let mut staged = Vec::with_capacity(archives.len());
    for archive in archives {
        staged.push(unpack(archive, &snapshots_dir, &cache_tmp).await?);
    }
    let unpack_us = started.elapsed().as_micros();
    let has_dependencies = staged.iter().try_fold(false, |found, item| {
        Ok::<_, MicrosandboxError>(
            found
                | match item.unpacked.inventory.as_ref() {
                    Some(inventory) => delta::validate(inventory)?.is_some(),
                    None => false,
                },
        )
    })?;

    let mut sources = delta::Sources::default();
    // Legacy archives have no payload omissions. Translate only owned staging, as in a single
    // import, before offering their canonical layers as potential sources for another archive.
    for item in &staged {
        if item.unpacked.inventory.is_none() {
            super::super::migration::normalize_staged(
                local.db().await?,
                &item.unpacked.manifest_dirs,
            )
            .await?;
            for snapshot in verify_imported_snapshots(local, &item.unpacked.manifest_dirs).await? {
                super::super::metadata::write(snapshot.path(), snapshot.labels()).await?;
                normalize_imported_descriptor(&snapshot).await?;
            }
        }
        if has_dependencies {
            for directory in &item.unpacked.manifest_dirs {
                let manifest = read_manifest(directory).await?;
                let shared = item
                    .unpacked
                    .inventory
                    .as_ref()
                    .map(|_| item.snapshots.path());
                sources.add(&manifest, directory, shared).await?;
            }
        }
    }

    // No ambient/global search: only the explicitly selected group and optional external base
    // augment the supplied batch. Keep an unpacked base alive until all copies are destination-owned.
    let complete = |sources: &delta::Sources| {
        staged.iter().all(|item| {
            item.unpacked
                .inventory
                .as_ref()
                .is_none_or(|inventory| sources.require(inventory).is_ok())
        })
    };
    let external = if has_dependencies && !complete(&sources) {
        for directory in &existing {
            if complete(&sources) {
                break;
            }
            // An unrelated damaged checkpoint must not block a load whose dependencies are
            // available elsewhere. A missing required identity is still reported below, and any
            // chosen payload is verified after copying into this operation's owned staging.
            let inspected = async {
                let manifest = read_manifest(directory).await?;
                sources.add(&manifest, directory, None).await
            }
            .await;
            if let Err(error) = inspected {
                tracing::debug!(path = %directory.display(), %error, "skipping unavailable group dependency source");
            }
        }
        match opts.base.as_deref().filter(|_| !complete(&sources)) {
            Some(base) => {
                let opened = Box::pin(delta::open_base(local, base)).await?;
                sources
                    .add(opened.snapshot.manifest(), opened.snapshot.path(), None)
                    .await?;
                Some(opened)
            }
            None => None,
        }
    } else {
        None
    };
    // Plan every omission before copying any of them. Missing dependencies identify their target
    // archive and payload, rather than guessing ancestry or requiring a particular filename.
    for item in &staged {
        if let Some(inventory) = &item.unpacked.inventory {
            sources
                .require(inventory)
                .map_err(|error| archive_error(&item.source, error))?;
        }
    }

    for item in &staged {
        if let Some(inventory) = &item.unpacked.inventory {
            delta::resolve_sources(
                local,
                inventory,
                item.snapshots.path(),
                item.cache.path(),
                &sources,
            )
            .await
            .map_err(|error| archive_error(&item.source, error))?;
        }
    }
    // Keep all original source paths intact until every borrowing read is done. Materializing
    // file snapshots below consumes their archive-shared layer directories.
    let mut imported = Vec::new();
    let mut candidates = Vec::with_capacity(archives.len());
    let mut aliases = BTreeMap::new();
    let mut identities = BTreeMap::new();
    for item in &staged {
        if let Some(inventory) = &item.unpacked.inventory {
            materialize_inventory_layers(inventory, item.snapshots.path()).await?;
        }
        let snapshots = verify_imported_snapshots(local, &item.unpacked.manifest_dirs).await?;
        if let Some(inventory) = &item.unpacked.inventory {
            validate_inventory_snapshot_bindings(inventory, &snapshots)?;
        }
        let head_index = match item.unpacked.head.as_deref() {
            Some(head) => snapshots
                .iter()
                .position(|snapshot| snapshot.id().as_str() == head)
                .ok_or_else(|| {
                    MicrosandboxError::SnapshotIntegrity(format!(
                        "archive {} head {head} is not an imported member",
                        item.source.display()
                    ))
                })?,
            None => select_head_snapshot(&snapshots)?,
        };
        let head = snapshots[head_index].id().clone();
        if let Some(inventory) = &item.unpacked.inventory {
            merge_aliases(&mut aliases, inventory, &head)?;
        }
        candidates.push(head);
        for snapshot in &snapshots {
            if let Some((digest, labels)) = identities.insert(
                snapshot.id().clone(),
                (snapshot.digest().to_string(), snapshot.labels().clone()),
            ) {
                if digest != snapshot.digest() {
                    return Err(MicrosandboxError::SnapshotIntegrity(format!(
                        "snapshot ID {} has conflicting descriptors in this batch",
                        snapshot.id()
                    )));
                }
                if &labels != snapshot.labels() {
                    return Err(MicrosandboxError::InvalidConfig(format!(
                        "snapshot {} has conflicting labels in this batch",
                        snapshot.id()
                    )));
                }
            }
            super::super::metadata::write(snapshot.path(), snapshot.labels()).await?;
            normalize_imported_descriptor(snapshot).await?;
        }
        imported.push(snapshots);
    }
    drop(external);
    let validate_us = started.elapsed().as_micros() - unpack_us;

    let publication = tempfile::Builder::new()
        .prefix(".msb-snapshot-batch-")
        .tempdir_in(&snapshots_dir)?;
    for ((item, snapshots), candidate) in staged.iter().zip(&imported).zip(&candidates) {
        let head = snapshots
            .iter()
            .find(|snapshot| snapshot.id() == candidate)
            .expect("validated archive head");
        Box::pin(install_staged_cache(
            item.cache.path(),
            &cache_dir,
            head.manifest(),
        ))
        .await?;
    }
    // Resolve all cross-archive reads before moving any source directory. Same-ID/same-descriptor
    // duplicates were independently validated above and are published only once.
    for snapshots in &imported {
        for snapshot in snapshots {
            let target = publication.path().join(snapshot.id().as_str());
            if !target.exists() {
                tokio::fs::rename(snapshot.path(), target).await?;
            }
        }
    }
    let group_dir = super::super::group::ensure(&snapshots_dir, opts.group.as_deref()).await?;
    let update = super::super::group::publish_batch(
        &group_dir,
        publication.path(),
        &aliases,
        &candidates,
        opts.set_head,
    )
    .await?;
    let group = group_dir
        .file_name()
        .and_then(|name| name.to_str())
        .expect("validated group name");
    let mut handles = Vec::with_capacity(candidates.len());
    for id in &candidates {
        let path = group_dir.join(id.as_str());
        let snapshot = store::open_snapshot(local, path.to_string_lossy().as_ref()).await?;
        handles.push(handle(&snapshot, group, update.clone())?);
    }
    let _ = store::reindex_dir(local, &group_dir).await;
    tracing::info!(
        target: "microsandbox_checkpoint_timing",
        operation = "snapshot_load_batch",
        archives = archives.len(),
        total_us = started.elapsed().as_micros(),
        unpack_us,
        validate_us,
        "snapshot batch load timing"
    );
    Ok(handles)
}

async fn unpack(
    archive: &Path,
    root: &Path,
    cache_tmp: &Path,
) -> MicrosandboxResult<StagedArchive> {
    let snapshots = tempfile::Builder::new()
        .prefix(".msb-snapshot-import-")
        .tempdir_in(root)?;
    let cache = tempfile::Builder::new()
        .prefix("snapshot-import-")
        .tempdir_in(cache_tmp)?;
    let file = tokio::fs::File::open(archive).await?;
    let mut reader = BufReader::with_capacity(1024 * 1024, file);
    let compressed = reader
        .fill_buf()
        .await?
        .starts_with(&[0x28, 0xb5, 0x2f, 0xfd]);
    let unpacked = if compressed {
        Box::pin(unpack_archive(
            ZstdDecoder::new(reader),
            snapshots.path(),
            cache.path(),
        ))
        .await?
    } else {
        Box::pin(unpack_archive(reader, snapshots.path(), cache.path())).await?
    };
    Ok(StagedArchive {
        source: archive.to_path_buf(),
        snapshots,
        cache,
        unpacked,
    })
}

async fn read_manifest(directory: &Path) -> MicrosandboxResult<Manifest> {
    let bytes = tokio::fs::read(directory.join(DESCRIPTOR_FILENAME)).await?;
    Manifest::from_bytes(&bytes)
        .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))
}

fn archive_error(archive: &Path, error: MicrosandboxError) -> MicrosandboxError {
    MicrosandboxError::SnapshotIntegrity(format!("archive {}: {error}", archive.display()))
}

fn merge_aliases(
    aliases: &mut BTreeMap<String, String>,
    inventory: &ArchiveInventory,
    head: &SnapshotId,
) -> MicrosandboxResult<()> {
    let mut incoming: BTreeMap<String, String> = inventory
        .extensions
        .get("msb-snapshot-member-names")
        .map(|value| serde_json::from_value(value.clone()))
        .transpose()?
        .unwrap_or_default();
    if let Some(name) = inventory
        .suggested_name
        .as_ref()
        .filter(|name| super::super::group::validate_alias(name).is_ok())
    {
        incoming
            .entry(head.to_string())
            .or_insert_with(|| name.clone());
    }
    for (id, name) in incoming {
        if !inventory
            .members
            .iter()
            .any(|member| member.snapshot_id == id)
        {
            return Err(MicrosandboxError::SnapshotIntegrity(format!(
                "archive member name refers to snapshot {id} outside that archive"
            )));
        }
        if let Some(previous) = aliases.get(&id)
            && previous != &name
        {
            return Err(MicrosandboxError::InvalidConfig(format!(
                "snapshot {id} has conflicting batch member names '{previous}' and '{name}'"
            )));
        }
        aliases.insert(id, name);
    }
    Ok(())
}

fn handle(
    snap: &Snapshot,
    group: &str,
    head_update: Option<super::super::HeadUpdate>,
) -> MicrosandboxResult<SnapshotHandle> {
    let (state_kind, format, fstype, checkpoint_manifest_digest, size_bytes) =
        match &snap.manifest().state {
            SnapshotState::File(state) => (
                "file",
                Some(state.disk_format),
                Some(state.filesystem.clone()),
                None,
                Some(state.virtual_size),
            ),
            SnapshotState::Checkpoint(state) => (
                "checkpoint",
                None,
                None,
                Some(state.checkpoint_root.clone()),
                None,
            ),
        };
    Ok(SnapshotHandle {
        group: Some(group.into()),
        head_update,
        snapshot_id: snap.id().to_string(),
        digest: snap.digest().to_string(),
        name: super::super::group::member_name(snap.path())?,
        parent_digest: snap.manifest().parent.as_ref().map(ToString::to_string),
        scope: snap.manifest().scope,
        image_ref: snap.manifest().image.reference.clone(),
        state_kind: state_kind.into(),
        format,
        fstype,
        checkpoint_manifest_digest,
        size_bytes,
        locality: "embedded".into(),
        availability: "ready".into(),
        migration_state: "canonical".into(),
        migration_error_code: None,
        created_at: chrono::DateTime::parse_from_rfc3339(&snap.manifest().capture.created_at)
            .map(|date| date.naive_utc())
            .unwrap_or_else(|_| chrono::Utc::now().naive_utc()),
        artifact_path: snap.path().to_path_buf(),
    })
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn member_alias_cannot_refer_to_snapshot_outside_its_archive() {
        let existing = SnapshotId::new(format!("snap_{:032x}", 1)).unwrap();
        let incoming = SnapshotId::new(format!("snap_{:032x}", 2)).unwrap();
        let inventory = ArchiveInventory {
            schema: "microsandbox.snapshot-archive/1".into(),
            head: incoming.to_string(),
            suggested_name: None,
            completeness: "boot-complete".into(),
            members: vec![ArchiveSnapshot {
                snapshot_id: incoming.to_string(),
                descriptor_path: format!("snapshots/{incoming}/{DESCRIPTOR_FILENAME}"),
                descriptor_digest: format!("sha256:{}", "0".repeat(64)),
            }],
            entries: Vec::new(),
            limits: ArchiveLimits {
                entry_count: 0,
                encoded_bytes: 0,
                apparent_bytes: 0,
            },
            extensions: BTreeMap::from([(
                "msb-snapshot-member-names".into(),
                serde_json::to_value(BTreeMap::from([(existing.to_string(), "renamed-existing")]))
                    .unwrap(),
            )]),
            requires: Vec::new(),
        };
        // Knowing this ID from the destination or another supplied archive does not authorize
        // this inventory to rename it. Membership is checked before merging local aliases.
        let original = BTreeMap::from([(existing.to_string(), "existing-name".into())]);
        let mut aliases = original.clone();
        let error = merge_aliases(&mut aliases, &inventory, &incoming).unwrap_err();
        assert!(
            error.to_string().contains("outside that archive"),
            "{error}"
        );
        assert_eq!(aliases, original);
    }
}
