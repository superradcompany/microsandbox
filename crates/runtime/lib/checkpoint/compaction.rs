//! Selection and one-pause adoption for independent sandbox-owned disk chains.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Instant;

use microsandbox_types::{
    DiskCompactionDiskResult, DiskCompactionResult, DiskCompactionTarget, OwnedVolumeStorage,
    VolumeMount,
};

#[cfg(feature = "runner")]
use super::disk::RootDiskRolloverError as Failure;
use super::disk::{RetiredRootDisk, RootDiskCompaction, RuntimeOwnedRootDisk};
use super::owned_disk::{OwnedDiskCompaction, OwnedDiskRetired, RuntimeOwnedDisk};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

enum Disk {
    Root(RuntimeOwnedRootDisk),
    Owned(RuntimeOwnedDisk),
    Fresh,
}

enum Plan {
    Root(RootDiskCompaction),
    Owned(OwnedDiskCompaction),
    Fresh(DiskCompactionResult),
}

enum Retired {
    Root(RetiredRootDisk),
    Owned(OwnedDiskRetired),
    None,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Plan {
    fn result(&self) -> &DiskCompactionResult {
        match self {
            Self::Root(p) => &p.result,
            Self::Owned(p) => &p.result,
            Self::Fresh(r) => r,
        }
    }

    fn is_noop(&self) -> bool {
        match self {
            Self::Root(p) => p.is_noop(),
            Self::Owned(p) => p.is_noop(),
            Self::Fresh(_) => true,
        }
    }

    fn validate_stopped(&self, runtime: &tokio::runtime::Handle) -> Result<(), String> {
        match self {
            Self::Root(p) => p.validate_stopped(runtime),
            Self::Owned(p) => p.validate_stopped(runtime),
            Self::Fresh(_) => Ok(()),
        }
    }

    #[cfg(feature = "runner")]
    fn prepare_backend(&self) -> Result<Option<msb_krun::PreparedBlockBackend>, String> {
        match self {
            Self::Root(p) => p.prepare_backend(),
            Self::Owned(p) => p.prepare_backend(),
            Self::Fresh(_) => Ok(None),
        }
    }
}

impl Retired {
    fn cleanup(self) {
        match self {
            Self::Root(r) => r.cleanup(),
            Self::Owned(r) => r.cleanup(),
            Self::None => {}
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Compact selected stopped disks while the caller retains the sandbox lifecycle lease.
/// Validate every selection and replacement before committing any disk's journal.
pub fn compact_stopped_disks(
    runtime_dir: &Path,
    mounts: &[VolumeMount],
    root_eligible: bool,
    target: &DiskCompactionTarget,
    layers: Option<usize>,
    dry_run: bool,
) -> Result<DiskCompactionResult, String> {
    let started = Instant::now();
    validate_limit(layers)?;
    let owned = mounts
        .iter()
        .filter_map(|mount| match mount {
            VolumeMount::Owned {
                guest,
                storage: OwnedVolumeStorage::Disk { capacity_mib },
                ..
            } => Some((
                guest.clone(),
                (
                    microsandbox_types::owned_volume_mount_id(guest),
                    *capacity_mib,
                ),
            )),
            _ => None,
        })
        .collect::<BTreeMap<_, _>>();
    let selected = select(root_eligible, owned.keys(), target)?;
    let mut disks = Vec::with_capacity(selected.len());
    for guest in &selected {
        let disk = if guest == "/" {
            RuntimeOwnedRootDisk::read(runtime_dir)?
                .map(Disk::Root)
                .unwrap_or(Disk::Fresh)
        } else {
            let (id, capacity) = &owned[guest];
            match super::owned_disk::load_runtime_owned_disk_chain(runtime_dir, id)? {
                Some(chain) => {
                    if chain.virtual_size != u64::from(*capacity) * 1024 * 1024 {
                        return Err(format!(
                            "owned disk {guest} differs from configured capacity"
                        ));
                    }
                    Disk::Owned(RuntimeOwnedDisk::read(runtime_dir, id)?)
                }
                None => {
                    let path = runtime_dir
                        .parent()
                        .ok_or("runtime has no sandbox parent")?
                        .join("owned-volumes")
                        .join(id)
                        .join("disk.raw");
                    let metadata = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
                    if !metadata.file_type().is_file()
                        || metadata.len() != u64::from(*capacity) * 1024 * 1024
                    {
                        return Err(format!(
                            "owned disk {guest} is missing or has invalid capacity"
                        ));
                    }
                    // Planning a fresh disk must not initialize a journal or checkpoint it.
                    Disk::Fresh
                }
            }
        };
        disks.push(disk);
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    let mut plans = Vec::with_capacity(disks.len());
    for disk in &disks {
        plans.push(match disk {
            Disk::Root(disk) => Plan::Root(
                disk.prepare_compaction(runtime.handle(), layers, dry_run)
                    .map_err(|e| e.to_string())?,
            ),
            Disk::Owned(disk) => Plan::Owned(
                disk.prepare_compaction(runtime.handle(), layers, dry_run)
                    .map_err(|e| e.to_string())?,
            ),
            Disk::Fresh => Plan::Fresh(DiskCompactionResult {
                dry_run,
                input_layers: 1,
                output_layers: 1,
                ..Default::default()
            }),
        });
    }
    for plan in &plans {
        plan.validate_stopped(runtime.handle())?;
    }
    let mut result = aggregate(
        selected
            .iter()
            .zip(&plans)
            .map(|(guest, plan)| (guest.as_str(), plan.result())),
        dry_run,
    );
    let mut retired = Vec::new();
    let mut committed = Vec::new();
    for ((guest, disk), plan) in selected.iter().zip(&mut disks).zip(plans) {
        let changed = !plan.is_noop();
        let outcome = match (disk, plan) {
            (Disk::Root(d), Plan::Root(p)) => p.commit(d).map(Retired::Root),
            (Disk::Owned(d), Plan::Owned(p)) => p.commit(d).map(Retired::Owned),
            (Disk::Fresh, Plan::Fresh(_)) => Ok(Retired::None),
            _ => unreachable!("plan and disk created together"),
        };
        retired.push(outcome.map_err(|error| format!("compaction of {guest} failed: {error}; committed disks: {committed:?}; restart follows each committed journal"))?);
        if changed {
            committed.push(guest);
        }
    }
    for old in retired {
        old.cleanup();
    }
    result.total_us = started.elapsed().as_micros() as u64;
    Ok(result)
}

/// Materialize every selected prefix before a single final device-quiescence interval.
#[cfg(feature = "runner")]
#[allow(clippy::too_many_arguments)]
pub(super) fn compact_live(
    root: &mut Option<RuntimeOwnedRootDisk>,
    additional: &mut BTreeMap<String, super::additional_disk::RuntimeOwnedAdditionalDisk>,
    owned_mounts: &BTreeMap<String, microsandbox_image::snapshot::OwnedMountSnapshot>,
    vm: &msb_krun::VmControl,
    runtime: &tokio::runtime::Handle,
    target: &DiskCompactionTarget,
    layers: Option<usize>,
    dry_run: bool,
) -> Result<DiskCompactionResult, Failure> {
    let started = Instant::now();
    validate_limit(layers).map_err(Failure::pre_rebind)?;
    let owned = owned_mounts
        .iter()
        .filter_map(|(id, mount)| {
            matches!(mount.storage, OwnedVolumeStorage::Disk { .. })
                .then_some((mount.guest.clone(), id.clone()))
        })
        .collect::<BTreeMap<_, _>>();
    let selected = select(root.is_some(), owned.keys(), target).map_err(Failure::pre_rebind)?;
    // Check all providers before materializing even the first prefix.
    for guest in selected.iter().filter(|guest| guest.as_str() != "/") {
        if additional
            .get_mut(&owned[guest])
            .and_then(|disk| disk.owned_mut())
            .is_none()
        {
            return Err(Failure::pre_rebind(format!(
                "owned disk {guest} has no runtime chain provider"
            )));
        }
    }
    let mut plans = Vec::with_capacity(selected.len());
    for guest in &selected {
        plans.push(if guest == "/" {
            Plan::Root(
                root.as_ref()
                    .expect("selected root exists")
                    .prepare_compaction(runtime, layers, dry_run)?,
            )
        } else {
            Plan::Owned(
                additional
                    .get_mut(&owned[guest])
                    .and_then(|disk| disk.owned_mut())
                    .expect("validated owned provider")
                    .prepare_compaction(runtime, layers, dry_run)?,
            )
        });
    }
    let mut result = aggregate(
        selected
            .iter()
            .zip(&plans)
            .map(|(guest, plan)| (guest.as_str(), plan.result())),
        dry_run,
    );
    if dry_run || plans.iter().all(Plan::is_noop) {
        result.total_us = started.elapsed().as_micros() as u64;
        return Ok(result);
    }
    let paused_at = Instant::now();
    let pause = vm.pause().map_err(Failure::pre_rebind)?;
    // Open all changing heads after the workers flush, before any durable state changes.
    let backends = match plans
        .iter()
        .map(Plan::prepare_backend)
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(backends) => backends,
        Err(error) => {
            vm.resume(pause).map_err(Failure::post_journal)?;
            return Err(Failure::pre_rebind(error));
        }
    };
    let mut retired = Vec::new();
    let mut committed = Vec::new();
    for ((guest, plan), backend) in selected.iter().zip(plans).zip(backends) {
        let changed = !plan.is_noop();
        let (device_id, outcome) = match plan {
            Plan::Root(plan) => {
                let disk = root.as_mut().expect("selected root exists");
                (
                    disk.device_id().to_owned(),
                    plan.commit(disk).map(Retired::Root),
                )
            }
            Plan::Owned(plan) => {
                let disk = additional
                    .get_mut(&owned[guest])
                    .and_then(|disk| disk.owned_mut())
                    .expect("validated owned provider");
                (
                    disk.device_id().to_owned(),
                    plan.commit(disk).map(Retired::Owned),
                )
            }
            Plan::Fresh(_) => unreachable!("live providers always own their journals"),
        };
        retired.push(outcome.map_err(|error| Failure::post_journal(format!(
            "compaction of {guest} failed: {error}; committed disks: {committed:?}; VM kept paused; restart follows per-disk journals"
        )))?);
        if changed {
            committed.push(guest);
        }
        if let Some(backend) = backend {
            vm.replace_block_backend(&device_id, backend).map_err(|error| Failure::post_journal(format!(
                "backend switch for {guest} failed: {error}; committed disks: {committed:?}; VM kept paused; restart follows per-disk journals"
            )))?;
        }
    }
    vm.resume(pause).map_err(Failure::post_journal)?;
    result.pause_us = paused_at.elapsed().as_micros() as u64;
    // No retirement on a failed switch: old and committed closures remain available.
    for old in retired {
        old.cleanup();
    }
    result.total_us = started.elapsed().as_micros() as u64;
    Ok(result)
}

fn validate_limit(layers: Option<usize>) -> Result<(), String> {
    if layers.is_some_and(|count| count < 2) {
        return Err("compaction requires at least two sealed layers".into());
    }
    Ok(())
}

fn select<'a>(
    root: bool,
    owned: impl Iterator<Item = &'a String>,
    target: &DiskCompactionTarget,
) -> Result<Vec<String>, String> {
    let owned = owned.cloned().collect::<Vec<_>>();
    match target {
        DiskCompactionTarget::All => Ok(root
            .then_some("/".into())
            .into_iter()
            .chain(owned)
            .collect()),
        DiskCompactionTarget::Root => {
            if root {
                Ok(vec!["/".into()])
            } else {
                Err("this sandbox has no managed or flat root disk".into())
            }
        }
        DiskCompactionTarget::Disk { guest_path } if guest_path == "/" => {
            select(root, owned.iter(), &DiskCompactionTarget::Root)
        }
        DiskCompactionTarget::Disk { guest_path } if owned.contains(guest_path) => {
            Ok(vec![guest_path.clone()])
        }
        DiskCompactionTarget::Disk { guest_path } => {
            Err(format!("{guest_path} is not a sandbox-owned disk mount"))
        }
    }
}

fn aggregate<'a>(
    results: impl Iterator<Item = (&'a str, &'a DiskCompactionResult)>,
    dry_run: bool,
) -> DiskCompactionResult {
    let mut result = DiskCompactionResult {
        dry_run,
        ..Default::default()
    };
    for (guest, disk) in results {
        result.input_layers += disk.input_layers;
        result.selected_layers += disk.selected_layers;
        result.output_layers += disk.output_layers;
        result.materialized_bytes += disk.materialized_bytes;
        result.disks.push(DiskCompactionDiskResult {
            guest_path: guest.into(),
            input_layers: disk.input_layers,
            selected_layers: disk.selected_layers,
            output_layers: disk.output_layers,
            materialized_bytes: disk.materialized_bytes,
            total_us: disk.total_us,
        });
    }
    result
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::owned_disk::{capture_stopped_owned_disk, load_runtime_owned_disk_chain};
    use super::*;

    fn mount(guest: &str) -> VolumeMount {
        VolumeMount::Owned {
            guest: guest.into(),
            storage: OwnedVolumeStorage::Disk { capacity_mib: 1 },
            options: Default::default(),
            stat_virtualization: microsandbox_types::StatVirtualization::Strict,
            host_permissions: microsandbox_types::HostPermissions::Private,
        }
    }

    fn fixture(
        sandbox: &Path,
        guest: &str,
        captures: usize,
    ) -> (
        VolumeMount,
        Vec<microsandbox_image::checkpoint::DiskGenerationManifest>,
    ) {
        let id = microsandbox_types::owned_volume_mount_id(guest);
        let path = sandbox.join("owned-volumes").join(&id).join("disk.raw");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, vec![23_u8; 1024 * 1024]).unwrap();
        let mut generations = Vec::new();
        for index in 0..captures {
            generations.push(
                capture_stopped_owned_disk(
                    &sandbox.join("runtime"),
                    &id,
                    &path,
                    false,
                    &sandbox.join(format!("capture-{id}-{index}")),
                )
                .unwrap(),
            );
        }
        (mount(guest), generations)
    }

    #[test]
    fn stopped_compaction_clamps_unequal_chains_and_preserves_published_layers() {
        let temp = tempfile::tempdir().unwrap();
        let sandbox = temp.path();
        let (first, generations) = fixture(sandbox, "/data", 4);
        let (second, _) = fixture(sandbox, "/logs", 2);
        let mounts = [first, second];
        let runtime = sandbox.join("runtime");
        let before: Vec<_> = mounts
            .iter()
            .map(|mount| {
                let id = microsandbox_types::owned_volume_mount_id(mount.guest());
                std::fs::read(runtime.join("owned-disks").join(id).join("disk.json")).unwrap()
            })
            .collect();
        let dry = compact_stopped_disks(
            &runtime,
            &mounts,
            false,
            &DiskCompactionTarget::All,
            Some(3),
            true,
        )
        .unwrap();
        assert_eq!(
            (dry.input_layers, dry.selected_layers, dry.output_layers),
            (8, 5, 5)
        );
        for (mount, before) in mounts.iter().zip(before) {
            let id = microsandbox_types::owned_volume_mount_id(mount.guest());
            assert_eq!(
                std::fs::read(runtime.join("owned-disks").join(id).join("disk.json")).unwrap(),
                before
            );
        }
        let result = compact_stopped_disks(
            &runtime,
            &mounts,
            false,
            &DiskCompactionTarget::All,
            Some(3),
            false,
        )
        .unwrap();
        assert_eq!(result.pause_us, 0);
        assert_eq!(
            result
                .disks
                .iter()
                .map(|disk| (
                    disk.guest_path.as_str(),
                    disk.input_layers,
                    disk.selected_layers,
                    disk.output_layers
                ))
                .collect::<Vec<_>>(),
            [("/data", 5, 3, 3), ("/logs", 3, 2, 2)]
        );
        let id = microsandbox_types::owned_volume_mount_id("/data");
        assert_eq!(
            load_runtime_owned_disk_chain(&runtime, &id)
                .unwrap()
                .unwrap()
                .layers
                .len(),
            3
        );
        for (index, generation) in generations.iter().enumerate() {
            for layer in &generation.layers {
                let path = sandbox
                    .join(format!("capture-{id}-{index}"))
                    .join("layers")
                    .join(format!("{}.{}", layer.layer_id, layer.format));
                assert_eq!(
                    microsandbox_image::checkpoint::sparse_file_integrity(&path)
                        .unwrap()
                        .root,
                    *layer.integrity_root.as_ref().expect("owned disk integrity")
                );
            }
        }
    }

    #[test]
    fn fresh_dry_run_and_invalid_selection_do_not_create_runtime_state() {
        let temp = tempfile::tempdir().unwrap();
        let (mount, _) = fixture(temp.path(), "/data", 0);
        let runtime = temp.path().join("runtime");
        let result = compact_stopped_disks(
            &runtime,
            std::slice::from_ref(&mount),
            false,
            &DiskCompactionTarget::All,
            Some(99),
            true,
        )
        .unwrap();
        assert_eq!(
            (
                result.input_layers,
                result.selected_layers,
                result.output_layers
            ),
            (1, 0, 1)
        );
        assert!(!runtime.exists());
        for target in [
            DiskCompactionTarget::Root,
            DiskCompactionTarget::Disk {
                guest_path: "/missing".into(),
            },
        ] {
            assert!(
                compact_stopped_disks(
                    &runtime,
                    std::slice::from_ref(&mount),
                    false,
                    &target,
                    None,
                    false
                )
                .is_err()
            );
            assert!(!runtime.exists());
        }
        assert!(
            compact_stopped_disks(
                &runtime,
                &[mount],
                false,
                &DiskCompactionTarget::All,
                Some(1),
                false
            )
            .is_err()
        );
        assert!(!runtime.exists());
    }

    #[test]
    fn partial_commit_retains_old_paths_and_each_authoritative_chain() {
        let temp = tempfile::tempdir().unwrap();
        let sandbox = temp.path();
        fixture(sandbox, "/data", 2);
        fixture(sandbox, "/logs", 2);
        let directory = sandbox.join("runtime");
        let first_id = microsandbox_types::owned_volume_mount_id("/data");
        let second_id = microsandbox_types::owned_volume_mount_id("/logs");
        let mut first = RuntimeOwnedDisk::read(&directory, &first_id).unwrap();
        let mut second = RuntimeOwnedDisk::read(&directory, &second_id).unwrap();
        let old_first = first.layers();
        let old_second = second.layers();
        let executor = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let first_plan = first
            .prepare_compaction(executor.handle(), None, false)
            .unwrap();
        let second_plan = second
            .prepare_compaction(executor.handle(), None, false)
            .unwrap();
        first_plan.validate_stopped(executor.handle()).unwrap();
        second_plan.validate_stopped(executor.handle()).unwrap();
        let retired = first_plan.commit(&mut first).unwrap();
        // Inject failure in the second journal's destination, after the first has committed.
        let second_journal_dir = directory.join("owned-disks").join(&second_id);
        let saved = directory.join("saved-second-journal");
        std::fs::rename(&second_journal_dir, &saved).unwrap();
        std::fs::write(&second_journal_dir, b"injected destination failure").unwrap();
        assert!(second_plan.commit(&mut second).is_err());
        std::fs::remove_file(&second_journal_dir).unwrap();
        std::fs::rename(&saved, &second_journal_dir).unwrap();
        drop(retired); // No cleanup on partial group failure.
        assert!(
            old_first
                .iter()
                .chain(&old_second)
                .all(|layer| layer.path.is_file())
        );
        assert_eq!(
            load_runtime_owned_disk_chain(&directory, &first_id)
                .unwrap()
                .unwrap()
                .layers
                .len(),
            2
        );
        assert_eq!(
            load_runtime_owned_disk_chain(&directory, &second_id)
                .unwrap()
                .unwrap()
                .layers
                .len(),
            3
        );
    }
}
