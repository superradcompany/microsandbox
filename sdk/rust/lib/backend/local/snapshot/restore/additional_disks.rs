//! Local backend: Child-private materialization of snapshot-owned additional block devices.

use std::collections::BTreeSet;
use std::path::Path;

use microsandbox_image::checkpoint::{DiskGenerationManifest, ResourceDescriptor};
use microsandbox_types::{DiskImageFormat, MountOptions, VolumeMount};

use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) async fn materialize_additional_disks(
    disks: &[DiskGenerationManifest],
    resources: &[ResourceDescriptor],
    source: &Path,
    child: &Path,
    root_device: Option<&str>,
    choices: &crate::sandbox::restore_resources::RestoreResources,
) -> MicrosandboxResult<Vec<VolumeMount>> {
    // Resolve the complete selection before copying even the first additional disk. A
    // typo must not silently create an empty disk or leave a partially useful child.
    let available: BTreeSet<&str> = disks
        .iter()
        .filter(|disk| Some(disk.device_id.as_str()) != root_device)
        .filter_map(|disk| {
            resources
                .iter()
                .find(|resource| resource.binding.get("device_id") == Some(&disk.device_id))
                .and_then(|resource| resource.binding.get("guest_path"))
                .map(String::as_str)
        })
        .collect();
    let unknown: Vec<_> = choices
        .captured
        .iter()
        .filter(|guest| !available.contains(guest.as_str()))
        .collect();
    if !unknown.is_empty() {
        return Err(invalid(&format!(
            "no captured disk at selected guest paths: {unknown:?}"
        )));
    }
    let mut mounts = Vec::new();
    let mut guests = BTreeSet::new();
    for disk in disks
        .iter()
        .filter(|disk| Some(disk.device_id.as_str()) != root_device)
    {
        let binding = resources
            .iter()
            .find(|resource| {
                resource.binding.get("device_id") == Some(&disk.device_id)
                    && resource
                        .binding
                        .get("managed_disk")
                        .is_some_and(|value| value == "true")
            })
            .ok_or_else(|| invalid("additional disk has no managed mount binding"))?;
        let guest = binding
            .binding
            .get("guest_path")
            .ok_or_else(|| invalid("additional disk has no guest mount path"))?;
        if binding
            .binding
            .get("lifecycle_owned")
            .is_some_and(|owned| owned == "true")
        {
            // Required owned inventory is materialized separately and is never selected
            // through the external captured-disk or dangerous-inheritance switches.
            continue;
        }
        if !guest.starts_with('/')
            || guest == "/"
            || !guests.insert(guest.clone())
            || crate::runtime::spawn::guest_mount_tag(guest) != disk.device_id
        {
            return Err(invalid(
                "additional disk has an invalid or duplicate mount identity",
            ));
        }
        let [layer] = disk.layers.as_slice() else {
            return Err(invalid(
                "additional managed disk must be a standalone generation",
            ));
        };
        if layer.predecessor.is_some() {
            return Err(invalid(
                "additional managed disk must not open an external backing path",
            ));
        }
        let format = match layer.format.as_str() {
            "raw" => DiskImageFormat::Raw,
            "qcow2" => DiskImageFormat::Qcow2,
            _ => return Err(invalid("unsupported additional disk format")),
        };
        let flags: microsandbox_protocol::bootstrap::BootstrapMountFlags = serde_json::from_str(
            binding
                .binding
                .get("mount_options")
                .ok_or_else(|| invalid("additional disk has no mount flags"))?,
        )
        .map_err(|error| invalid(&format!("invalid additional disk flags: {error}")))?;
        let options = MountOptions {
            readonly: flags.readonly,
            noexec: flags.noexec,
            nosuid: flags.nosuid,
            nodev: flags.nodev,
            ..Default::default()
        };
        // A missing choice grants no host storage access. Full restore constructs
        // an error-serving device from the captured state, not a dummy disk file.
        if choices.mapped.contains(guest) || (!choices.inherit && !choices.captured.contains(guest))
        {
            continue;
        }
        let directory = child.join("additional-disks");
        let target = directory.join(format!("{}.{}", disk.device_id, layer.format));
        let source = source
            .join("layers")
            .join(format!("{}.{}", layer.layer_id, layer.format));
        // A blocking task can outlive its cancelled async caller. Give it only a unique
        // sibling staging namespace, never the deterministic child/replacement path.
        let staging_parent = child
            .parent()
            .ok_or_else(|| invalid("additional disk child has no storage parent"))?
            .to_path_buf();
        let expected_integrity = layer.integrity_root.clone();
        let expected_size = layer.file_size;
        let qcow2 = layer.format == "qcow2";
        let worker = tokio::task::spawn_blocking(move || {
            stage_additional_disk(
                &source,
                &staging_parent,
                expected_integrity.as_deref(),
                expected_size,
                qcow2,
            )
        });
        publish_staged_additional_disk(worker, &target).await?;
        mounts.push(VolumeMount::DiskImage {
            host: target,
            guest: guest.clone(),
            format,
            fstype: binding.binding.get("fstype").cloned(),
            options,
        });
    }
    Ok(mounts)
}

/// Captured disk bytes take precedence over source named-volume references on the same guest path.
pub(crate) fn apply_additional_disks(config: &mut crate::SandboxConfig, mounts: Vec<VolumeMount>) {
    for mount in mounts {
        let guest = mount.guest().to_string();
        config
            .spec
            .mounts
            .retain(|existing| existing.guest() != guest);
        config.spec.mounts.push(mount);
    }
}

pub(super) fn stage_additional_disk(
    source: &Path,
    staging_parent: &Path,
    expected_integrity: Option<&str>,
    expected_size: u64,
    qcow2: bool,
) -> std::io::Result<tempfile::TempDir> {
    let staging = tempfile::Builder::new()
        .prefix(".additional-disk-restore-")
        .tempdir_in(staging_parent)?;
    let copy_to = staging.path().join("disk");
    // Never hard-link an immutable captured file into a writable child. Reflink where
    // available; the sparse-copy fallback preserves independence on other filesystems.
    microsandbox_utils::copy::fast_copy(source, &copy_to)?;
    // The copied file must still match the captured geometry when hashing is disabled.
    if std::fs::metadata(&copy_to)?.len() != expected_size {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "additional disk length changed during child materialization",
        ));
    }
    if let Some(expected_integrity) = expected_integrity
        && microsandbox_image::checkpoint::sparse_file_integrity(&copy_to)
            .map_err(std::io::Error::other)?
            .root
            != expected_integrity
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "additional disk changed during child materialization",
        ));
    }
    // Additional disks use ordinary attachment, which permits implicit dependencies.
    // The manifest's predecessor=None is not evidence about the actual qcow2 header.
    if qcow2 {
        microsandbox_image::checkpoint::validate_standalone_qcow2(&std::fs::File::open(&copy_to)?)?;
    }
    let mut permissions = std::fs::metadata(&copy_to)?.permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        permissions.set_mode(0o600);
    }
    #[cfg(not(unix))]
    {
        // Unix uses owner-only mode above. On Windows this clears the read-only
        // attribute without granting additional access through the file's ACL.
        #[allow(clippy::permissions_set_readonly_false)]
        permissions.set_readonly(false);
    }
    std::fs::set_permissions(&copy_to, permissions)?;
    std::fs::OpenOptions::new()
        .write(true)
        .open(&copy_to)?
        .sync_all()?;
    Ok(staging)
}

pub(super) async fn publish_staged_additional_disk(
    worker: tokio::task::JoinHandle<std::io::Result<tempfile::TempDir>>,
    target: &Path,
) -> MicrosandboxResult<()> {
    let staging = worker
        .await
        .map_err(|error| invalid(&format!("additional disk copy task: {error}")))??;
    let parent = target
        .parent()
        .ok_or_else(|| invalid("additional disk target has no parent"))?;
    // No await after this point: publication stays in the poll that still owns the child
    // transition/lifecycle guards. Same-filesystem rename needs no second payload copy.
    std::fs::create_dir_all(parent)?;
    std::fs::rename(staging.path().join("disk"), target)?;
    Ok(())
}

fn invalid(message: &str) -> MicrosandboxError {
    MicrosandboxError::SnapshotIntegrity(message.to_string())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use microsandbox_image::checkpoint::{DiskLayerRef, ResourceTreatment};
    use std::collections::BTreeMap;

    #[tokio::test]
    async fn cancelled_disk_worker_cannot_write_a_replacement_child() {
        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("source.raw");
        std::fs::write(&source, vec![7; 8192]).unwrap();
        let integrity = microsandbox_image::checkpoint::sparse_file_integrity(&source)
            .unwrap()
            .root;
        let child = temporary.path().join("child");
        let target = child.join("additional-disks/work.raw");
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        let staging_parent = temporary.path().to_path_buf();
        let (started, started_rx) = tokio::sync::oneshot::channel();
        let (release, release_rx) = std::sync::mpsc::channel();
        let (finished, finished_rx) = tokio::sync::oneshot::channel();
        let worker = tokio::task::spawn_blocking(move || {
            let _ = started.send(());
            // Park before opening any destination. Dropping the test's release sender also
            // unblocks this worker if an assertion fails, so the test cannot strand a thread.
            release_rx.recv().map_err(std::io::Error::other)?;
            let staged =
                stage_additional_disk(&source, &staging_parent, Some(&integrity), 8192, false)?;
            let _ = finished.send(staged.path().to_path_buf());
            Ok(staged)
        });
        let original_target = target.clone();
        let publisher =
            tokio::spawn(
                async move { publish_staged_additional_disk(worker, &original_target).await },
            );
        started_rx.await.unwrap();
        publisher.abort();
        assert!(publisher.await.unwrap_err().is_cancelled());

        // Model ChildStageGuard cleanup followed by another creation of the same name.
        std::fs::remove_dir_all(&child).unwrap();
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::write(&target, b"replacement child data").unwrap();
        release.send(()).unwrap();
        let staged_path = finished_rx.await.unwrap();
        assert!(!staged_path.starts_with(&child));
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            // Tokio drops the detached task's returned TempDir when it finishes. Observe
            // that actual cleanup boundary instead of sleeping for a guessed flush window.
            while staged_path.exists() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"replacement child data");
    }

    #[tokio::test]
    async fn additional_disks_are_private_and_require_exact_guest_identity() {
        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("capture");
        std::fs::create_dir_all(source.join("layers")).unwrap();
        let path = source.join("layers/layer_0123456789abcdef0123456789abcdef.raw");
        std::fs::write(&path, vec![7; 8192]).unwrap();
        let device = crate::runtime::spawn::guest_mount_tag("/data");
        let disk = DiskGenerationManifest {
            schema: "microsandbox.disk-generation/1".into(),
            volume_id: "vol_0123456789abcdef0123456789abcdef".into(),
            device_id: device.clone(),
            generation: 1,
            pause_generation: 1,
            head: "layer_0123456789abcdef0123456789abcdef".into(),
            layers: vec![DiskLayerRef {
                file_size: std::fs::metadata(&path).unwrap().len(),
                layer_id: "layer_0123456789abcdef0123456789abcdef".into(),
                format: "raw".into(),
                virtual_size: 8192,
                predecessor: None,
                integrity_root: Some(
                    microsandbox_image::checkpoint::sparse_file_integrity(&path)
                        .unwrap()
                        .root,
                ),
            }],
        };
        let mut resource = ResourceDescriptor {
            id: device.clone(),
            kind: "block".into(),
            treatment: ResourceTreatment::Serialize,
            binding: BTreeMap::from([
                ("device_id".into(), device),
                ("managed_disk".into(), "true".into()),
                ("guest_path".into(), "/data".into()),
                ("mount_options".into(), "{}".into()),
            ]),
        };
        let child = temporary.path().join("child");
        let choices = crate::sandbox::restore_resources::RestoreResources {
            captured: BTreeSet::from(["/data".into()]),
            ..Default::default()
        };
        // Omission and explicit remapping must not read a source file or create a
        // child-owned copy. The full restore's device constructor handles omission.
        for selection in [
            Default::default(),
            crate::sandbox::restore_resources::RestoreResources {
                mapped: BTreeSet::from(["/data".into()]),
                inherit: true,
                ..Default::default()
            },
        ] {
            let untouched = temporary.path().join("unmapped-child");
            let mounts = materialize_additional_disks(
                std::slice::from_ref(&disk),
                std::slice::from_ref(&resource),
                &temporary.path().join("no-source"),
                &untouched,
                Some("vdb"),
                &selection,
            )
            .await
            .unwrap();
            assert!(mounts.is_empty());
            assert!(!untouched.exists());
        }
        let mounts = materialize_additional_disks(
            std::slice::from_ref(&disk),
            std::slice::from_ref(&resource),
            &source,
            &child,
            Some("vdb"),
            &choices,
        )
        .await
        .unwrap();
        let VolumeMount::DiskImage { host, guest, .. } = &mounts[0] else {
            panic!("private disk");
        };
        assert_eq!(guest, "/data");
        std::fs::write(host, vec![9; 8192]).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), vec![7; 8192]);
        resource
            .binding
            .insert("guest_path".into(), "/elsewhere".into());
        assert!(
            materialize_additional_disks(
                std::slice::from_ref(&disk),
                std::slice::from_ref(&resource),
                &source,
                &temporary.path().join("bad"),
                Some("vdb"),
                &choices,
            )
            .await
            .is_err()
        );

        resource.binding.insert("guest_path".into(), "/data".into());
        for (label, offset, bytes, expected) in [
            (
                "backing-offset",
                8,
                80u64.to_be_bytes().to_vec(),
                "backing file",
            ),
            (
                "backing-length",
                16,
                8u32.to_be_bytes().to_vec(),
                "backing file",
            ),
            (
                "external-data",
                72,
                4u64.to_be_bytes().to_vec(),
                "external data file",
            ),
        ] {
            let mut header = vec![0u8; 8192];
            header[..4].copy_from_slice(b"QFI\xfb");
            header[4..8].copy_from_slice(&3u32.to_be_bytes());
            header[offset..offset + bytes.len()].copy_from_slice(&bytes);
            let path = source.join("layers/layer_0123456789abcdef0123456789abcdef.qcow2");
            std::fs::write(&path, header).unwrap();
            let mut disk = disk.clone();
            disk.layers[0].format = "qcow2".into();
            // These are integrity-valid artifacts: hashing alone must not authorize a host open.
            disk.layers[0].integrity_root = Some(
                microsandbox_image::checkpoint::sparse_file_integrity(&path)
                    .unwrap()
                    .root,
            );
            let error = materialize_additional_disks(
                &[disk],
                std::slice::from_ref(&resource),
                &source,
                &temporary.path().join(label),
                Some("vdb"),
                &choices,
            )
            .await
            .unwrap_err();
            assert!(error.to_string().contains(expected), "{label}: {error}");
        }
    }
}
