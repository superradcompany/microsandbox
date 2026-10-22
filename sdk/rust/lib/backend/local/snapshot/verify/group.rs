//! Whole-group verification with a pinned membership and shared physical payload checks.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use microsandbox_image::checkpoint::{
    CheckpointPayloadCheck, CheckpointPayloadIntegrity, CheckpointVerificationPlan, ObjectId,
    SparseFileIntegrity,
};
use microsandbox_image::snapshot::{
    OwnedVolumeData, SnapshotState, UpperIntegrity, visit_owned_directory_payloads,
};

use crate::backend::LocalBackend;
use crate::snapshot::{
    CheckpointVerification, CheckpointVerifyStatus, SnapshotGroupVerifyReport, SnapshotId,
    SnapshotVerificationFinding, SnapshotVerificationFindingKind as FindingKind,
    SnapshotVerificationState as State, SnapshotVerifyReport, UpperVerifyStatus,
};
use crate::{MicrosandboxError, MicrosandboxResult};

use super::super::{Snapshot, create, group, store, writer::WriterLease};
use super::batch::{PayloadFailureKind, verify_payloads};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct MemberPlan {
    checks: Vec<CheckpointPayloadCheck>,
    head: Option<usize>,
    checkpoint: Option<CheckpointVerifyStatus>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(in super::super) async fn verify_group(
    local: &LocalBackend,
    directory: &Path,
) -> MicrosandboxResult<SnapshotGroupVerifyReport> {
    verify_group_observed(local, directory, || {}).await
}

async fn verify_group_observed(
    local: &LocalBackend,
    directory: &Path,
    pinned: impl FnOnce() + Send + 'static,
) -> MicrosandboxResult<SnapshotGroupVerifyReport> {
    // Keep writer admission and one stable lifetime lease through hashing. Atomic
    // imports link existing payloads into a new generation, changing their ctime
    // even without changing bytes; allowing that during hashing would produce a
    // false mutation report. Neither lease opens every checkpoint descriptor.
    let writer = WriterLease::acquire(directory).await?;
    // Complete any pending recovery before taking the reader lifetime gate;
    // rollback may need the exclusive side of that gate itself.
    let paths = group::verification_paths(directory).await?;
    let history =
        microsandbox_image::storage_lease::StorageLease::shared_async(directory.canonicalize()?)
            .await?;
    let mut members = Vec::with_capacity(paths.len());
    for path in paths {
        let result = match tokio::fs::symlink_metadata(&path).await {
            Ok(metadata) if metadata.file_type().is_dir() => {
                store::open_for_verification(local, &path)
                    .await
                    .and_then(|mut artifact| {
                        if path.file_name().and_then(|name| name.to_str())
                            != Some(artifact.id().as_str())
                        {
                            return Err(MicrosandboxError::SnapshotIntegrity(
                                "group member directory does not match its snapshot identity"
                                    .into(),
                            ));
                        }
                        // Opening still validates the descriptor under its normal
                        // pin. Transfer lifetime protection to the group lease now,
                        // keeping the number of simultaneously open handles bounded.
                        artifact.lease = None;
                        Ok(artifact)
                    })
            }
            Ok(_) => Err(MicrosandboxError::SnapshotIntegrity(
                "group member is not a directory".into(),
            )),
            Err(error) => Err(error.into()),
        };
        members.push((path, result));
    }
    let group = directory
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    let fs_state_limit = local.config().fs_state_limit();
    // The worker owns the leases, so cancelling the async caller cannot release protection while
    // blocking payload hashing is still running.
    tokio::task::spawn_blocking(move || {
        let _writer = writer;
        let _history = history;
        pinned();
        verify_members(group, members, fs_state_limit)
    })
    .await
    .map_err(|error| MicrosandboxError::Custom(format!("group verification task: {error}")))?
}

fn verify_members(
    group: String,
    members: Vec<(PathBuf, MicrosandboxResult<Snapshot>)>,
    fs_state_limit: usize,
) -> MicrosandboxResult<SnapshotGroupVerifyReport> {
    let mut checkpoints = Vec::with_capacity(members.len());
    let mut checks = Vec::new();
    let mut plans = Vec::with_capacity(members.len());
    // Metadata stays in memory; the worker owns the single group lifetime lease.
    for (path, artifact) in &members {
        let mut result = CheckpointVerification {
            id: path
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| SnapshotId::new(name).ok()),
            path: path.clone(),
            state: State::Complete,
            report: None,
            findings: Vec::new(),
        };
        let prepared = match artifact {
            Ok(artifact) => prepare(artifact, fs_state_limit),
            Err(error) => {
                result.findings.push(finding(path, error));
                checkpoints.push(result);
                plans.push(None);
                continue;
            }
        };
        match prepared {
            Ok(plan) => {
                let start = checks.len();
                checks.extend(plan.checks);
                plans.push(Some((
                    start..checks.len(),
                    plan.head.map(|index| start + index),
                    plan.checkpoint,
                )));
            }
            Err(error) => {
                result.findings.push(finding(path, &error));
                plans.push(None);
            }
        }
        checkpoints.push(result);
    }
    let batch = verify_payloads(&checks);
    for (index, plan) in plans.into_iter().enumerate() {
        let result = &mut checkpoints[index];
        if let Some((range, head, checkpoint)) = plan {
            let mut unrecorded = BTreeSet::new();
            for check_index in range {
                let check = &checks[check_index];
                match &batch.outcomes[check_index] {
                    Ok(UpperVerifyStatus::Verified { .. }) => {}
                    Ok(UpperVerifyStatus::NotRecorded) => {
                        unrecorded.insert(check.path.clone());
                        result.findings.push(SnapshotVerificationFinding {
                            path: check.path.clone(),
                            kind: FindingKind::NotRecorded,
                            detail: "payload has no recorded integrity".into(),
                        });
                    }
                    Err(error) => result.findings.push(SnapshotVerificationFinding {
                        path: check.path.clone(),
                        kind: match error.kind {
                            PayloadFailureKind::Missing => FindingKind::Missing,
                            PayloadFailureKind::Invalid => FindingKind::Invalid,
                            PayloadFailureKind::Unavailable => FindingKind::Unavailable,
                            PayloadFailureKind::Changed => FindingKind::Changed,
                        },
                        detail: error.detail.clone(),
                    }),
                }
            }
            if result
                .findings
                .iter()
                .all(|finding| finding.kind == FindingKind::NotRecorded)
            {
                let artifact = members[index]
                    .1
                    .as_ref()
                    .expect("planned member was opened");
                result.report = Some(SnapshotVerifyReport {
                    digest: artifact.digest().into(),
                    path: artifact.path().into(),
                    upper: head
                        .map(|index| {
                            batch.outcomes[index]
                                .as_ref()
                                .expect("all recorded checks passed")
                                .clone()
                        })
                        .unwrap_or(UpperVerifyStatus::NotRecorded),
                    checkpoint,
                    coverage: super::verification_coverage(unrecorded),
                });
            }
        }
        result.state = findings_state(&result.findings);
    }
    let state = if checkpoints.is_empty() {
        State::Empty
    } else if checkpoints
        .iter()
        .any(|member| member.state == State::Invalid)
    {
        State::Invalid
    } else if checkpoints
        .iter()
        .any(|member| member.state == State::Incomplete)
    {
        State::Incomplete
    } else {
        State::Complete
    };
    let failed = checkpoints
        .iter()
        .flat_map(|member| &member.findings)
        .any(|finding| finding.kind != FindingKind::NotRecorded);
    let report = SnapshotGroupVerifyReport {
        group,
        state,
        checkpoints,
        payload_hashes: batch.hashes,
    };
    if failed {
        Err(MicrosandboxError::SnapshotVerification(Box::new(report)))
    } else {
        Ok(report)
    }
}

fn prepare(artifact: &Snapshot, fs_state_limit: usize) -> MicrosandboxResult<MemberPlan> {
    let unsupported = artifact.manifest().unsupported_requires();
    if !unsupported.is_empty() {
        return Err(MicrosandboxError::Unsupported {
            op: crate::Operation::SnapshotOps,
            reason: crate::error::UnsupportedReason::NotAvailable(format!(
                "unknown required extensions: {}",
                unsupported.join(", ")
            )),
        });
    }
    match &artifact.manifest().state {
        SnapshotState::Checkpoint(state) => {
            let expected = ObjectId::new(&state.checkpoint_root)?;
            let plan = CheckpointVerificationPlan::prepare(
                artifact.path().join(create::CHECKPOINT_DIRECTORY),
                &expected,
                fs_state_limit,
            )?;
            create::validate_checkpoint_owned_inventory(artifact.manifest(), plan.checkpoint())?;
            Ok(MemberPlan {
                checks: plan.payloads().to_vec(),
                head: None,
                checkpoint: Some(CheckpointVerifyStatus {
                    root: plan.root_id().to_string(),
                }),
            })
        }
        SnapshotState::File(state) => {
            let mut plan = MemberPlan {
                checks: Vec::new(),
                head: None,
                checkpoint: None,
            };
            for layer in &state.layers {
                if layer.layer_id == state.head {
                    plan.head = Some(plan.checks.len());
                }
                let path = artifact.layer_path(layer);
                plan.checks.push(CheckpointPayloadCheck {
                    length: std::fs::symlink_metadata(&path)?.len(),
                    path,
                    integrity: layer.payload.integrity.clone().map(Into::into),
                    metadata_bytes: None,
                });
            }
            let owned = artifact.manifest().owned_volumes()?;
            visit_owned_directory_payloads(artifact.path(), &owned, |path, expected| {
                plan.checks.push(CheckpointPayloadCheck {
                    path: path.into(),
                    length: expected.bytes,
                    integrity: Some(
                        UpperIntegrity::Sha256 {
                            digest: format!("sha256:{}", expected.digest),
                        }
                        .into(),
                    ),
                    metadata_bytes: None,
                });
                Ok(())
            })?;
            for volume in owned {
                if let OwnedVolumeData::Disk { generation } = volume.data {
                    for layer in generation.layers {
                        plan.checks.push(CheckpointPayloadCheck {
                            path: artifact
                                .path()
                                .join("layers")
                                .join(format!("{}.{}", layer.layer_id, layer.format)),
                            length: layer.file_size,
                            integrity: layer.integrity_root.map(|root| {
                                CheckpointPayloadIntegrity::CheckpointFileV1(SparseFileIntegrity {
                                    root,
                                    logical_size: layer.file_size,
                                })
                            }),
                            metadata_bytes: None,
                        });
                    }
                }
            }
            Ok(plan)
        }
    }
}

fn finding(path: &Path, error: &MicrosandboxError) -> SnapshotVerificationFinding {
    let kind = match error {
        MicrosandboxError::Unsupported { .. } => FindingKind::Unsupported,
        MicrosandboxError::SnapshotNotFound(_) => FindingKind::Missing,
        MicrosandboxError::Io(error)
        | MicrosandboxError::Image(microsandbox_image::ImageError::Io(error)) => {
            if error.kind() == std::io::ErrorKind::NotFound {
                FindingKind::Missing
            } else {
                FindingKind::Unavailable
            }
        }
        _ => FindingKind::Invalid,
    };
    SnapshotVerificationFinding {
        path: path.into(),
        kind,
        detail: error.to_string(),
    }
}

fn findings_state(findings: &[SnapshotVerificationFinding]) -> State {
    if findings.iter().any(|finding| {
        matches!(
            finding.kind,
            FindingKind::Invalid | FindingKind::Changed | FindingKind::Missing
        )
    }) {
        State::Invalid
    } else if !findings.is_empty() {
        State::Incomplete
    } else {
        State::Complete
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use microsandbox_image::snapshot::*;
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::time::Duration;

    fn install(directory: &Path, ordinal: u128) -> PathBuf {
        let id = SnapshotId::new(format!("snap_{ordinal:032x}")).unwrap();
        let layer = DiskLayerId::new(format!("layer_{ordinal:032x}")).unwrap();
        let path = directory.join(id.as_str());
        std::fs::create_dir(&path).unwrap();
        let manifest = Manifest {
            schema: SCHEMA.into(),
            snapshot_id: id,
            scope: SnapshotScope::Disk,
            state: SnapshotState::File(FileSnapshotState {
                disk_format: SnapshotFormat::Raw,
                filesystem: "ext4".into(),
                virtual_size: 5,
                head: layer.clone(),
                layers: vec![DiskLayer {
                    layer_id: layer,
                    format: SnapshotFormat::Raw,
                    virtual_size: 5,
                    backing: None,
                    payload: LayerPayload {
                        file_kind: LayerFileKind::Regular,
                        integrity: Some(UpperIntegrity::Sha256 {
                            digest: ObjectId::from_bytes(b"valid").unwrap().to_string(),
                        }),
                    },
                }],
            }),
            capture: SnapshotCapture {
                created_at: "2026-10-19T00:00:00Z".into(),
                source_lineage: None,
                source_checkpoint: None,
                consistency: SnapshotConsistency::CrashConsistent,
            },
            image: ImageRef {
                reference: "docker.io/library/alpine:3.20".into(),
                manifest_digest: format!("sha256:{}", "a".repeat(64)),
            },
            root_disk: SnapshotRootDisk::Managed,
            parent: None,
            extensions: BTreeMap::new(),
            requires: Vec::new(),
        };
        std::fs::write(
            path.join(DESCRIPTOR_FILENAME),
            manifest.to_canonical_bytes().unwrap(),
        )
        .unwrap();
        std::fs::write(path.join(DEFAULT_UPPER_FILE), b"valid").unwrap();
        path
    }

    #[tokio::test]
    async fn owned_disk_group_verification_matches_single_member_and_reports_missing_integrity() {
        use microsandbox_image::checkpoint::{
            DiskGenerationManifest, DiskLayerRef, sparse_file_integrity,
        };
        use microsandbox_types::{OwnedVolumeStorage, owned_volume_mount_id};
        use std::io::{Seek, SeekFrom, Write};

        for recorded in [false, true] {
            let home = tempfile::tempdir().unwrap();
            let local = crate::test_support::local_backend_builder(home.path())
                .build()
                .await
                .unwrap();
            let directory = group::ensure(&local.snapshots_dir(), Some("owned-checks"))
                .await
                .unwrap();
            let path = install(&directory, 1);
            std::fs::create_dir(path.join("layers")).unwrap();
            let disk = path.join("layers/owned.raw");
            let mut file = std::fs::File::create(&disk).unwrap();
            file.set_len(1024 * 1024).unwrap();
            file.write_all(b"owned bytes").unwrap();
            drop(file);
            let mut manifest =
                Manifest::from_bytes(&std::fs::read(path.join(DESCRIPTOR_FILENAME)).unwrap())
                    .unwrap();
            let mount_id = owned_volume_mount_id("/data");
            manifest
                .set_owned_volumes(vec![OwnedVolumeCapture {
                    mount_id: mount_id.clone(),
                    mount: OwnedMountSnapshot {
                        guest: "/data".into(),
                        storage: OwnedVolumeStorage::Disk { capacity_mib: 1 },
                        options: Default::default(),
                        stat_virtualization: microsandbox_types::StatVirtualization::Strict,
                        host_permissions: microsandbox_types::HostPermissions::Private,
                    },
                    data: OwnedVolumeData::Disk {
                        generation: DiskGenerationManifest {
                            schema: "microsandbox.disk-generation/1".into(),
                            volume_id: "owned-volume".into(),
                            device_id: mount_id,
                            generation: 1,
                            pause_generation: 1,
                            head: "owned".into(),
                            layers: vec![DiskLayerRef {
                                layer_id: "owned".into(),
                                format: "raw".into(),
                                virtual_size: 1024 * 1024,
                                file_size: 1024 * 1024,
                                predecessor: None,
                                integrity_root: recorded
                                    .then(|| sparse_file_integrity(&disk).unwrap().root),
                            }],
                        },
                    },
                }])
                .unwrap();
            std::fs::write(
                path.join(DESCRIPTOR_FILENAME),
                manifest.to_canonical_bytes().unwrap(),
            )
            .unwrap();
            let artifact = store::open_for_verification(&local, &path).await.unwrap();
            super::super::verify_snapshot(&artifact, local.config().fs_state_limit())
                .await
                .unwrap();
            drop(artifact);
            let report = verify_group(&local, &directory).await.unwrap();
            assert_eq!(
                report.state,
                if recorded {
                    State::Complete
                } else {
                    State::Incomplete
                }
            );
            let mut file = std::fs::OpenOptions::new().write(true).open(&disk).unwrap();
            file.seek(SeekFrom::Start(0)).unwrap();
            file.write_all(b"wrong bytes").unwrap();
            drop(file);
            let result = verify_group(&local, &directory).await;
            if recorded {
                let error = result.unwrap_err();
                let MicrosandboxError::SnapshotVerification(report) = error else {
                    panic!("{error}")
                };
                assert_eq!(report.state, State::Invalid);
                assert!(report.checkpoints[0].findings.iter().any(|finding| finding.path == disk && finding.kind == FindingKind::Invalid));
            } else {
                assert_eq!(result.unwrap().state, State::Incomplete);
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn whole_group_verification_bounds_open_descriptors() {
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "backend::local::snapshot::verify::group::tests::low_descriptor_limit_verification_worker",
                "--ignored",
                "--nocapture",
            ])
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    #[ignore = "subprocess-only reduced descriptor limit"]
    async fn low_descriptor_limit_verification_worker() {
        let home = tempfile::tempdir().unwrap();
        let local = crate::test_support::local_backend_builder(home.path())
            .build()
            .await
            .unwrap();
        let directory = group::ensure(&local.snapshots_dir(), Some("long-history"))
            .await
            .unwrap();
        for ordinal in 1..=611 {
            install(&directory, ordinal);
        }
        let mut limit = std::mem::MaybeUninit::<libc::rlimit>::uninit();
        // The limit is process-wide, hence this dedicated subprocess.
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, limit.as_mut_ptr()) },
            0
        );
        let mut limit = unsafe { limit.assume_init() };
        limit.rlim_cur = limit.rlim_cur.min(96);
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
        let report = verify_group(&local, &directory).await.unwrap();
        assert_eq!(report.state, State::Complete);
        assert_eq!(report.checkpoints.len(), 611);
    }

    #[tokio::test]
    async fn selection_stays_pinned_and_cancellation_keeps_worker_admission() {
        for cancel in [false, true] {
            let home = tempfile::tempdir().unwrap();
            let local = Arc::new(
                crate::test_support::local_backend_builder(home.path())
                    .build()
                    .await
                    .unwrap(),
            );
            let directory = group::ensure(&local.snapshots_dir(), Some("verification"))
                .await
                .unwrap();
            let first = install(&directory, 1);
            let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            let verifier = tokio::spawn({
                let local = local.clone();
                let directory = directory.clone();
                async move {
                    verify_group_observed(&local, &directory, move || {
                        entered_tx.send(()).unwrap();
                        release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
                    })
                    .await
                }
            });
            tokio::time::timeout(Duration::from_secs(10), entered_rx)
                .await
                .unwrap()
                .unwrap();
            // Import/capture/head writers must remain excluded for the entire hash
            // worker, but unrelated histories and ordinary readers remain usable.
            assert!(WriterLease::try_acquire(&directory).unwrap().is_none());
            let other = group::ensure(&local.snapshots_dir(), Some("unrelated"))
                .await
                .unwrap();
            assert!(WriterLease::try_acquire(&other).unwrap().is_some());
            drop(store::open_for_verification(&local, &first).await.unwrap());
            assert!(
                super::super::super::lease::deletion(&first)
                    .unwrap()
                    .is_none()
            );
            if cancel {
                verifier.abort();
                assert!(verifier.await.unwrap_err().is_cancelled());
                assert!(WriterLease::try_acquire(&directory).unwrap().is_none());
                assert!(
                    super::super::super::lease::deletion(&first)
                        .unwrap()
                        .is_none()
                );
                release_tx.send(()).unwrap();
            } else {
                release_tx.send(()).unwrap();
                let report = verifier.await.unwrap().unwrap();
                assert_eq!(report.state, State::Complete);
                assert_eq!(report.checkpoints.len(), 1);
                assert_eq!(report.checkpoints[0].path, first);
            }
            // Cancellation only detaches the worker; its completion must release all pins.
            tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    if super::super::super::lease::deletion(&first)
                        .unwrap()
                        .is_some()
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            let admission =
                tokio::time::timeout(Duration::from_secs(10), WriterLease::acquire(&directory))
                    .await
                    .unwrap()
                    .unwrap();
            install(&directory, 2);
            drop(admission);
            assert_eq!(
                verify_group(&local, &directory)
                    .await
                    .unwrap()
                    .checkpoints
                    .len(),
                2
            );
        }
    }

    #[tokio::test]
    async fn verification_delays_atomic_import_until_hash_worker_finishes() {
        use super::super::super::archive;
        use crate::snapshot::{LoadOpts, SaveOpts};

        let home = tempfile::tempdir().unwrap();
        let local = Arc::new(
            crate::test_support::local_backend_builder(home.path())
                .build()
                .await
                .unwrap(),
        );
        let directory = group::ensure(&local.snapshots_dir(), Some("verification"))
            .await
            .unwrap();
        install(&directory, 1);
        let incoming = group::ensure(&local.snapshots_dir(), Some("incoming"))
            .await
            .unwrap();
        let second = install(&incoming, 2);
        let archive = home.path().join("second.msb");
        archive::save_snapshot(
            &local,
            second.to_str().unwrap(),
            &archive,
            SaveOpts::default(),
        )
        .await
        .unwrap();

        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let verifier = tokio::spawn({
            let local = local.clone();
            let directory = directory.clone();
            async move {
                verify_group_observed(&local, &directory, move || {
                    entered_tx.send(()).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
                })
                .await
            }
        });
        tokio::time::timeout(Duration::from_secs(10), entered_rx)
            .await
            .unwrap()
            .unwrap();
        let mut importer = tokio::spawn({
            let local = local.clone();
            async move {
                archive::load_group(
                    &local,
                    &[archive],
                    LoadOpts {
                        group: Some("verification".into()),
                        ..LoadOpts::default()
                    },
                )
                .await
            }
        });
        // This invokes the actual importer, including complete-directory exchange,
        // rather than merely checking that another lock acquisition is refused.
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut importer)
                .await
                .is_err()
        );
        assert!(WriterLease::try_acquire(&directory).unwrap().is_none());
        assert!(!directory.join(second.file_name().unwrap()).exists());
        release_tx.send(()).unwrap();
        let report = verifier.await.unwrap().unwrap();
        assert_eq!(report.state, State::Complete);
        assert_eq!(report.checkpoints.len(), 1);
        tokio::time::timeout(Duration::from_secs(10), importer)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let report = verify_group(&local, &directory).await.unwrap();
        assert_eq!(report.state, State::Complete);
        assert_eq!(report.checkpoints.len(), 2);
    }
}
