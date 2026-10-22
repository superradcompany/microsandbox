//! Local backend: Group publication and selector tests using small, complete file-state artifacts.

use microsandbox_image::snapshot::{
    DiskLayer, DiskLayerId, FileSnapshotState, ImageRef, LayerFileKind, LayerPayload, SCHEMA,
    SnapshotCapture, SnapshotConsistency, SnapshotFormat, SnapshotRootDisk, SnapshotScope,
    SnapshotState,
};

use super::*;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) fn id(value: u128) -> SnapshotId {
    SnapshotId::new(format!("snap_{value:032x}")).unwrap()
}

pub(super) fn descriptor(value: u128, parent: Option<u128>) -> Manifest {
    let layer_id = DiskLayerId::new(format!("layer_{value:032x}")).unwrap();
    Manifest {
        schema: SCHEMA.into(),
        snapshot_id: id(value),
        scope: SnapshotScope::Disk,
        state: SnapshotState::File(FileSnapshotState {
            disk_format: SnapshotFormat::Raw,
            filesystem: "ext4".into(),
            virtual_size: 4,
            head: layer_id.clone(),
            layers: vec![DiskLayer {
                layer_id,
                format: SnapshotFormat::Raw,
                virtual_size: 4,
                backing: None,
                payload: LayerPayload {
                    file_kind: LayerFileKind::Regular,
                    integrity: None,
                },
            }],
        }),
        capture: SnapshotCapture {
            created_at: "2026-09-10T00:00:00Z".into(),
            source_lineage: Some("source".into()),
            source_checkpoint: None,
            consistency: SnapshotConsistency::CrashConsistent,
        },
        image: ImageRef {
            reference: "docker.io/library/alpine:latest".into(),
            manifest_digest: format!("sha256:{}", "a".repeat(64)),
        },
        root_disk: SnapshotRootDisk::Managed,
        parent: parent.map(id),
        requires: Vec::new(),
        extensions: BTreeMap::new(),
    }
}

pub(super) fn stage(root: &Path, manifests: &[Manifest]) -> tempfile::TempDir {
    let staging = tempfile::Builder::new()
        .prefix(".stage-")
        .tempdir_in(root)
        .unwrap();
    for manifest in manifests {
        let directory = staging.path().join(manifest.snapshot_id.as_str());
        fs::create_dir(&directory).unwrap();
        fs::write(
            directory.join(DESCRIPTOR_FILENAME),
            manifest.to_canonical_bytes().unwrap(),
        )
        .unwrap();
        let SnapshotState::File(state) = &manifest.state else {
            unreachable!();
        };
        let layer = directory.join(state.layer_path(&state.layers[0]));
        fs::create_dir_all(layer.parent().unwrap()).unwrap();
        fs::write(layer, [0u8; 4]).unwrap();
    }
    staging
}

pub(super) async fn add(group: &Path, value: u128, parent: Option<u128>) -> HeadUpdate {
    let staging = stage(group.parent().unwrap(), &[descriptor(value, parent)]);
    publish(group, staging.path(), &BTreeMap::new(), &id(value), false)
        .await
        .unwrap()
}

#[test]
fn cancelled_head_selection_retains_writer_until_blocking_mutation_finishes() {
    // A single poll below must reach the blocked worker queue. In the parallel
    // harness another test can fork with setup's writer lock, making that poll
    // wait for admission instead. Isolate the schedule, rather than allowing
    // either head outcome and weakening the cancellation contract.
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "backend::local::snapshot::group::tests::cancelled_head_selection_worker",
            "--ignored",
            "--nocapture",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "subprocess-only deterministic cancellation schedule"]
fn cancelled_head_selection_worker() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap()
        .block_on(async {
            let root = tempfile::tempdir().unwrap();
            let group = ensure(root.path(), Some("history")).await.unwrap();
            add(&group, 1, None).await;
            add(&group, 2, Some(1)).await;
            let (started, ready) = tokio::sync::oneshot::channel();
            let (release, wait) = std::sync::mpsc::channel();
            let blocker = tokio::task::spawn_blocking(move || {
                started.send(()).unwrap();
                wait.recv_timeout(std::time::Duration::from_secs(5))
                    .unwrap();
            });
            ready.await.unwrap();

            let selector = format!("history:{}", id(1));
            let mut selection = Box::pin(select(root.path(), &selector));
            assert!(futures::poll!(selection.as_mut()).is_pending());
            drop(selection);
            // The queued blocking mutation still owns admission after its caller
            // cancels. A directory publisher cannot move its destination away.
            assert!(super::WriterLease::try_acquire(&group).unwrap().is_none());
            release.send(()).unwrap();
            blocker.await.unwrap();
            tokio::task::spawn_blocking(|| {}).await.unwrap();
            assert_eq!(read_group(&group).unwrap().head, Some(id(1).to_string()));
            // Parallel subprocess tests may have forked while this file was
            // open. CLOEXEC releases the child's copy at exec, not at fork;
            // test eventual release with a deadline, not instantaneous OS state.
            let _reacquired = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                super::WriterLease::acquire(&group),
            )
            .await
            .expect("cancelled publisher leaked writer admission")
            .unwrap();
        });
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn indexed_publication_distinguishes_preflight_rejection_from_committed() {
    let root = tempfile::tempdir().unwrap();
    let group = ensure(root.path(), Some("certainty")).await.unwrap();
    add(&group, 1, None).await;
    let old_descriptor = fs::read(group.join(id(1).as_str()).join(DESCRIPTOR_FILENAME)).unwrap();
    let state = Arc::new(AtomicU8::new(SnapshotImportOutcome::NotCommitted as u8));
    let publish = || IndexedPublication {
        operation: "00000000000000000000000000000001".into(),
        outcome: state.clone(),
    };
    let mut conflicting = descriptor(1, None);
    conflicting.capture.created_at = "2026-10-14T00:00:00Z".into();
    let staged = stage(root.path(), &[conflicting, descriptor(2, Some(1))]);
    let error = publish_batch_indexed(
        &group,
        staged.path(),
        &BTreeMap::new(),
        &[id(2)],
        false,
        publish(),
    )
    .await
    .unwrap_err();
    assert!(
        error.to_string().contains("different descriptor"),
        "{error}"
    );
    assert_eq!(
        state.load(Ordering::Acquire),
        SnapshotImportOutcome::NotCommitted as u8
    );
    assert_eq!(
        fs::read(group.join(id(1).as_str()).join(DESCRIPTOR_FILENAME)).unwrap(),
        old_descriptor
    );
    assert!(!group.join(id(2).as_str()).exists());
    assert!(!group.join(".group-transaction").exists());

    let staged = stage(root.path(), &[descriptor(2, Some(1))]);
    publish_batch_indexed(
        &group,
        staged.path(),
        &BTreeMap::new(),
        &[id(2)],
        false,
        publish(),
    )
    .await
    .unwrap();
    assert_eq!(
        state.load(Ordering::Acquire),
        SnapshotImportOutcome::Committed as u8
    );
    // The commit is certain even before the index acknowledgement. Readers can
    // finish indexing the retained journal without replaying publication.
    let pending = pending_index(&group).await.unwrap().unwrap();
    assert_eq!(pending.snapshots.len(), 1);
    assert_eq!(pending.snapshots[0].2.snapshot_id, id(2));
    pending.finish().await.unwrap();
    assert!(!group.join(".group-transaction").exists());
}

#[tokio::test]
async fn batch_head_is_independent_of_archive_and_staging_order() {
    let root = tempfile::tempdir().unwrap();
    for (index, order) in [
        [1, 2, 3],
        [1, 3, 2],
        [2, 1, 3],
        [2, 3, 1],
        [3, 1, 2],
        [3, 2, 1],
    ]
    .into_iter()
    .enumerate()
    {
        let group = ensure(root.path(), Some(&format!("order-{index}")))
            .await
            .unwrap();
        let manifests = order
            .iter()
            .map(|value| descriptor(*value, (*value > 1).then_some(*value - 1)))
            .collect::<Vec<_>>();
        let staged = stage(root.path(), &manifests);
        let candidates = order.into_iter().map(id).collect::<Vec<_>>();
        let update = publish_batch(&group, staged.path(), &BTreeMap::new(), &candidates, false)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(update.head.as_deref(), Some(id(3).as_str()));
        assert_eq!(update.reason, HeadUpdateReason::Initialized);
        assert_eq!(read_members(&group, true).unwrap().len(), 3);
    }
}

#[tokio::test]
async fn batch_uses_known_destination_intermediates_to_prove_one_tip() {
    let root = tempfile::tempdir().unwrap();
    let group = ensure(root.path(), Some("intermediate")).await.unwrap();
    add(&group, 1, None).await;
    add(&group, 2, Some(1)).await;
    let staged = stage(root.path(), &[descriptor(3, Some(2))]);
    let update = publish_batch(
        &group,
        staged.path(),
        &BTreeMap::new(),
        &[id(3), id(1), id(3)],
        false,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(update.reason, HeadUpdateReason::FastForwarded);
    assert_eq!(update.previous.as_deref(), Some(id(2).as_str()));
    assert_eq!(update.head.as_deref(), Some(id(3).as_str()));
}

#[tokio::test]
async fn batch_unique_tip_still_respects_existing_head_ancestry() {
    let root = tempfile::tempdir().unwrap();
    let group = ensure(root.path(), Some("retained-head")).await.unwrap();
    add(&group, 1, None).await;
    for (parent, reason) in [
        (None, HeadUpdateReason::Diverged),
        (Some(9), HeadUpdateReason::UnknownAncestry),
    ] {
        let first = if parent.is_none() { 2 } else { 4 };
        let staged = stage(
            root.path(),
            &[
                descriptor(first, parent),
                descriptor(first + 1, Some(first)),
            ],
        );
        let update = publish_batch(
            &group,
            staged.path(),
            &BTreeMap::new(),
            &[id(first), id(first + 1)],
            false,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(update.reason, reason);
        assert!(!update.changed);
        assert_eq!(update.head.as_deref(), Some(id(1).as_str()));
        assert!(group.join(id(first + 1).as_str()).is_dir());
    }
}

#[tokio::test]
async fn batch_branches_preserve_existing_head_or_leave_new_group_unselected() {
    let root = tempfile::tempdir().unwrap();
    for existing in [false, true] {
        for order in [[2, 3], [3, 2]] {
            let name = format!("branches-{existing}-{}", order[0]);
            let group = ensure(root.path(), Some(&name)).await.unwrap();
            if existing {
                add(&group, 1, None).await;
            }
            let staged = stage(
                root.path(),
                &[
                    descriptor(1, None),
                    descriptor(2, Some(1)),
                    descriptor(3, Some(1)),
                ],
            );
            let candidates = order.map(id);
            let update = publish_batch(&group, staged.path(), &BTreeMap::new(), &candidates, false)
                .await
                .unwrap();
            if existing {
                let update = update.unwrap();
                assert_eq!(update.reason, HeadUpdateReason::AmbiguousCandidates);
                assert!(!update.changed);
                assert_eq!(update.head.as_deref(), Some(id(1).as_str()));
            } else {
                assert_eq!(update, None);
                assert_eq!(read_group(&group).unwrap().head, None);
                let error = resolve(root.path(), &name).await.unwrap_err().to_string();
                assert!(error.contains("no head selected"));
                assert!(error.contains("msb snapshot modify"));
                assert_eq!(
                    resolve(root.path(), &format!("{name}:{}", id(3)))
                        .await
                        .unwrap(),
                    group.join(id(3).as_str())
                );
            }
            assert_eq!(read_members(&group, true).unwrap().len(), 3);
        }
    }
}

#[tokio::test]
async fn batch_unknown_history_does_not_guess_a_candidate_order() {
    let root = tempfile::tempdir().unwrap();
    let group = ensure(root.path(), Some("holes")).await.unwrap();
    add(&group, 1, None).await;
    // Snapshot 3 may descend from 1, but absent snapshot 2 prevents proving the relationship.
    let staged = stage(root.path(), &[descriptor(3, Some(2))]);
    let update = publish_batch(
        &group,
        staged.path(),
        &BTreeMap::new(),
        &[id(3), id(1)],
        false,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(update.reason, HeadUpdateReason::AmbiguousCandidates);
    assert_eq!(update.head.as_deref(), Some(id(1).as_str()));
    let staged = stage(root.path(), &[descriptor(2, Some(1))]);
    // Repeating the same candidates is now conclusive, even though their intermediate is not
    // itself a supplied archive head.
    let update = publish_batch(
        &group,
        staged.path(),
        &BTreeMap::new(),
        &[id(1), id(3)],
        false,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(update.reason, HeadUpdateReason::FastForwarded);
    assert_eq!(update.head.as_deref(), Some(id(3).as_str()));
}

#[tokio::test]
async fn batch_set_head_requires_one_candidate_tip_before_any_publication() {
    let root = tempfile::tempdir().unwrap();
    let group = ensure(root.path(), Some("explicit-batch")).await.unwrap();
    add(&group, 1, None).await;
    let staged = stage(
        root.path(),
        &[descriptor(2, Some(1)), descriptor(3, Some(1))],
    );
    let error = publish_batch(
        &group,
        staged.path(),
        &BTreeMap::new(),
        &[id(2), id(3)],
        true,
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("--set-head cannot choose"));
    assert!(error.to_string().contains("msb snapshot modify"));
    for candidate in [2, 3] {
        assert!(!group.join(id(candidate).as_str()).exists());
        assert!(staged.path().join(id(candidate).as_str()).is_dir());
    }
    assert_eq!(
        read_group(&group).unwrap().head.as_deref(),
        Some(id(1).as_str())
    );
    let staged = stage(root.path(), &[descriptor(4, None), descriptor(5, Some(4))]);
    let update = publish_batch(
        &group,
        staged.path(),
        &BTreeMap::new(),
        &[id(5), id(4)],
        true,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(update.reason, HeadUpdateReason::Selected);
    assert_eq!(update.head.as_deref(), Some(id(5).as_str()));
}

#[tokio::test]
async fn batch_descriptor_and_alias_conflicts_do_not_partly_publish() {
    let root = tempfile::tempdir().unwrap();
    let group = ensure(root.path(), Some("batch-conflicts")).await.unwrap();
    let staged = stage(root.path(), &[descriptor(1, None)]);
    publish(
        &group,
        staged.path(),
        &BTreeMap::from([(id(1).to_string(), "base".into())]),
        &id(1),
        false,
    )
    .await
    .unwrap();
    let mut conflict = descriptor(1, None);
    conflict.capture.source_lineage = Some("different-source".into());
    let staged = stage(root.path(), &[descriptor(2, Some(1)), conflict]);
    assert!(
        publish_batch(
            &group,
            staged.path(),
            &BTreeMap::new(),
            &[id(2), id(1)],
            false
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("different descriptor")
    );
    assert!(!group.join(id(2).as_str()).exists());
    assert!(staged.path().join(id(2).as_str()).is_dir());
    let staged = stage(
        root.path(),
        &[descriptor(2, Some(1)), descriptor(3, Some(2))],
    );
    let aliases = BTreeMap::from([
        (id(2).to_string(), "other".into()),
        (id(3).to_string(), "base".into()),
    ]);
    assert!(
        publish_batch(&group, staged.path(), &aliases, &[id(2), id(3)], false)
            .await
            .unwrap_err()
            .to_string()
            .contains("conflicts")
    );
    for candidate in [2, 3] {
        assert!(!group.join(id(candidate).as_str()).exists());
        assert!(staged.path().join(id(candidate).as_str()).is_dir());
    }
    assert_eq!(
        read_group(&group).unwrap().head.as_deref(),
        Some(id(1).as_str())
    );
}

#[tokio::test]
async fn dependency_lookup_reads_only_existing_installed_group_members() {
    let root = tempfile::tempdir().unwrap();
    let missing_root = root.path().join("missing-root");
    assert!(
        dependency_members(&missing_root, "work")
            .await
            .unwrap()
            .is_empty()
    );
    assert!(!missing_root.exists());
    assert!(
        dependency_members(root.path(), "work")
            .await
            .unwrap()
            .is_empty()
    );
    assert!(!root.path().join("work").exists());
    assert!(!root.path().join(".groups.lock").exists());
    assert!(
        dependency_members(&missing_root, "../escape")
            .await
            .is_err()
    );
    let group = ensure(root.path(), Some("work")).await.unwrap();
    add(&group, 1, None).await;
    let _incomplete = stage(&group, &[descriptor(2, Some(1))]);
    assert_eq!(
        dependency_members(root.path(), "work").await.unwrap(),
        vec![group.join(id(1).as_str())]
    );
    let malformed = root.path().join("malformed");
    fs::create_dir(&malformed).unwrap();
    write_group(&malformed, None).unwrap();
    assert!(dependency_members(root.path(), "malformed").await.is_err());
    assert!(!malformed.join(".group.lock").exists());
}

#[cfg(unix)]
#[tokio::test]
async fn dependency_lookup_rejects_symlinked_roots_and_groups() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let group = ensure(root.path(), Some("work")).await.unwrap();
    symlink(&group, root.path().join("redirect")).unwrap();
    assert!(dependency_members(root.path(), "redirect").await.is_err());
    symlink(root.path(), root.path().join("root-link")).unwrap();
    assert!(
        dependency_members(&root.path().join("root-link"), "work")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn initializes_and_fast_forwards_through_multiple_imported_ancestors() {
    let root = tempfile::tempdir().unwrap();
    let group = ensure(root.path(), Some("work")).await.unwrap();
    let first = add(&group, 10, None).await;
    assert_eq!(first.reason, HeadUpdateReason::Initialized);
    assert_eq!(first.previous, None);

    // Directory order puts the tip first. The designated candidate determines the head.
    let staging = stage(
        root.path(),
        &[descriptor(5, Some(20)), descriptor(20, Some(10))],
    );
    let update = publish(&group, staging.path(), &BTreeMap::new(), &id(5), false)
        .await
        .unwrap();
    assert_eq!(update.reason, HeadUpdateReason::FastForwarded);
    assert_eq!(update.previous.as_deref(), Some(id(10).as_str()));
    assert_eq!(
        resolve(root.path(), "work").await.unwrap(),
        group.join(id(5).as_str())
    );
    assert!(group.join(id(20).as_str()).is_dir());
}

#[tokio::test]
async fn resolved_identity_stays_fixed_after_the_group_head_advances() {
    let root = tempfile::tempdir().unwrap();
    let group = ensure(root.path(), Some("stable")).await.unwrap();
    add(&group, 1, None).await;
    let selected = resolve(root.path(), "stable").await.unwrap();
    add(&group, 2, Some(1)).await;
    assert_eq!(selected, group.join(id(1).as_str()));
    assert_eq!(read_member(&selected, true).unwrap().0, id(1).as_str());
    assert_eq!(
        resolve(root.path(), "stable").await.unwrap(),
        group.join(id(2).as_str())
    );
}

#[tokio::test]
async fn head_and_id_lookup_do_not_scan_unrelated_descriptors() {
    let root = tempfile::tempdir().unwrap();
    let group = ensure(root.path(), Some("lookup")).await.unwrap();
    add(&group, 1, None).await;
    let unrelated = group.join(id(2).as_str());
    fs::create_dir(&unrelated).unwrap();
    fs::write(
        unrelated.join(DESCRIPTOR_FILENAME),
        "broken unrelated descriptor",
    )
    .unwrap();
    assert_eq!(
        resolve(root.path(), "lookup").await.unwrap(),
        group.join(id(1).as_str())
    );
    assert_eq!(
        resolve(root.path(), &format!("lookup:{}", id(1)))
            .await
            .unwrap(),
        group.join(id(1).as_str()),
    );
    assert_eq!(
        select(root.path(), "lookup").await.unwrap().head.as_deref(),
        Some(id(1).as_str())
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_siblings_keep_both_artifacts_and_only_one_advances() {
    let root = tempfile::tempdir().unwrap();
    let group = ensure(root.path(), Some("race")).await.unwrap();
    add(&group, 1, None).await;
    let left = stage(root.path(), &[descriptor(2, Some(1))]);
    let right = stage(root.path(), &[descriptor(3, Some(1))]);
    let aliases = BTreeMap::new();
    let left_id = id(2);
    let right_id = id(3);
    let (left_result, right_result) = tokio::join!(
        publish(&group, left.path(), &aliases, &left_id, false),
        publish(&group, right.path(), &aliases, &right_id, false),
    );
    let left_result = left_result.unwrap();
    let right_result = right_result.unwrap();
    assert_ne!(left_result.changed, right_result.changed);
    let (winner, retained) = if left_result.changed {
        (left_result, right_result)
    } else {
        (right_result, left_result)
    };
    assert_eq!(winner.reason, HeadUpdateReason::FastForwarded);
    assert_eq!(retained.reason, HeadUpdateReason::Diverged);
    assert_eq!(retained.head, winner.head);
    assert_eq!(select(root.path(), "race").await.unwrap().head, winner.head);
    assert!(group.join(id(2).as_str()).is_dir());
    assert!(group.join(id(3).as_str()).is_dir());
}

#[tokio::test]
async fn unknown_history_is_retained_without_retroactively_selecting_a_tip() {
    let root = tempfile::tempdir().unwrap();
    let group = ensure(root.path(), Some("history")).await.unwrap();
    add(&group, 1, None).await;
    let unknown = add(&group, 3, Some(2)).await;
    assert_eq!(unknown.reason, HeadUpdateReason::UnknownAncestry);
    assert_eq!(unknown.head.as_deref(), Some(id(1).as_str()));
    assert!(group.join(id(3).as_str()).is_dir());
    let intermediate = add(&group, 2, Some(1)).await;
    assert_eq!(intermediate.head.as_deref(), Some(id(2).as_str()));
    assert_eq!(
        select(root.path(), "history")
            .await
            .unwrap()
            .head
            .as_deref(),
        Some(id(2).as_str())
    );

    let staging = stage(root.path(), &[]);
    let retried = publish(&group, staging.path(), &BTreeMap::new(), &id(3), false)
        .await
        .unwrap();
    assert_eq!(retried.reason, HeadUpdateReason::FastForwarded);
    assert_eq!(retried.head.as_deref(), Some(id(3).as_str()));
}

#[tokio::test]
async fn identical_ids_reuse_members_and_conflicts_fail_before_publication() {
    let root = tempfile::tempdir().unwrap();
    let group = ensure(root.path(), Some("duplicates")).await.unwrap();
    add(&group, 1, None).await;
    fs::write(group.join(id(1).as_str()).join("keep"), "unchanged").unwrap();
    let duplicate = add(&group, 1, None).await;
    assert!(!duplicate.changed);
    assert_eq!(duplicate.reason, HeadUpdateReason::Unchanged);
    assert_eq!(
        fs::read_to_string(group.join(id(1).as_str()).join("keep")).unwrap(),
        "unchanged"
    );

    let mut conflicting = descriptor(1, None);
    conflicting.capture.source_lineage = Some("another-source".into());
    let staging = stage(root.path(), &[descriptor(2, Some(1)), conflicting]);
    let error = publish(&group, staging.path(), &BTreeMap::new(), &id(2), false)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("different descriptor"));
    assert!(!group.join(id(2).as_str()).exists());
    assert!(staging.path().join(id(2).as_str()).is_dir());
    assert_eq!(
        select(root.path(), "duplicates")
            .await
            .unwrap()
            .head
            .as_deref(),
        Some(id(1).as_str())
    );
}

#[tokio::test]
async fn aliases_are_local_and_all_conflicts_are_checked_before_moving_members() {
    let root = tempfile::tempdir().unwrap();
    let group = ensure(root.path(), Some("aliases")).await.unwrap();
    let staging = stage(root.path(), &[descriptor(1, None)]);
    let aliases = BTreeMap::from([(id(1).to_string(), "clean".into())]);
    publish(&group, staging.path(), &aliases, &id(1), false)
        .await
        .unwrap();
    assert_eq!(
        resolve(root.path(), "aliases:clean").await.unwrap(),
        group.join(id(1).as_str())
    );
    assert_eq!(
        member_name(&group.join(id(1).as_str())).unwrap().as_deref(),
        Some("clean")
    );
    assert_eq!(group_path(&group.join(id(1).as_str())), Some(group.clone()));

    let staging = stage(
        root.path(),
        &[descriptor(2, Some(1)), descriptor(3, Some(1))],
    );
    let aliases = BTreeMap::from([
        (id(2).to_string(), "other".into()),
        (id(3).to_string(), "clean".into()),
    ]);
    let error = publish(&group, staging.path(), &aliases, &id(2), false)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("conflicts"));
    assert!(!group.join(id(2).as_str()).exists());
    assert!(!group.join(id(3).as_str()).exists());
    assert!(staging.path().join(id(2).as_str()).is_dir());
}

#[tokio::test]
async fn generated_names_retry_publication_without_recapturing_the_artifact() {
    let root = tempfile::tempdir().unwrap();
    let group = ensure(root.path(), Some("generated")).await.unwrap();
    let first = stage(root.path(), &[descriptor(1, None)]);
    let aliases = BTreeMap::from([(id(1).to_string(), "msb-00000001".into())]);
    publish(&group, first.path(), &aliases, &id(1), false)
        .await
        .unwrap();

    let captured = stage(root.path(), &[descriptor(2, Some(1))]);
    let staged_member = captured.path().join(id(2).as_str());
    let original_descriptor = fs::read(staged_member.join(DESCRIPTOR_FILENAME)).unwrap();
    fs::write(staged_member.join("capture-marker"), b"same capture").unwrap();
    let mut retries = 0;
    let update = super::super::create::publish_with_name_retry(
        &group,
        captured.path(),
        &id(2),
        "msb-00000001".into(),
        true,
        || {
            retries += 1;
            // The conflict was detected before moving or rewriting any captured state.
            assert_eq!(
                fs::read(staged_member.join(DESCRIPTOR_FILENAME)).unwrap(),
                original_descriptor
            );
            assert_eq!(
                fs::read(staged_member.join("capture-marker")).unwrap(),
                b"same capture"
            );
            "msb-00000002".into()
        },
    )
    .await
    .unwrap();
    assert_eq!(retries, 1);
    assert_eq!(update.reason, HeadUpdateReason::FastForwarded);
    let installed = group.join(id(2).as_str());
    assert_eq!(
        member_name(&installed).unwrap().as_deref(),
        Some("msb-00000002")
    );
    assert_eq!(
        fs::read(installed.join(DESCRIPTOR_FILENAME)).unwrap(),
        original_descriptor
    );
    assert_eq!(
        fs::read(installed.join("capture-marker")).unwrap(),
        b"same capture"
    );
    assert_eq!(
        member_name(&group.join(id(1).as_str())).unwrap().as_deref(),
        Some("msb-00000001")
    );
}

#[tokio::test]
async fn explicit_names_report_collision_without_retry_or_staging_changes() {
    let root = tempfile::tempdir().unwrap();
    let group = ensure(root.path(), Some("explicit")).await.unwrap();
    let first = stage(root.path(), &[descriptor(1, None)]);
    let aliases = BTreeMap::from([(id(1).to_string(), "chosen".into())]);
    publish(&group, first.path(), &aliases, &id(1), false)
        .await
        .unwrap();
    let captured = stage(root.path(), &[descriptor(2, Some(1))]);
    let error = super::super::create::publish_with_name_retry(
        &group,
        captured.path(),
        &id(2),
        "chosen".into(),
        false,
        || panic!("explicit names must not be regenerated"),
    )
    .await
    .unwrap_err();
    assert!(matches!(error, MicrosandboxError::SnapshotAlreadyExists(_)));
    assert!(
        captured
            .path()
            .join(id(2).as_str())
            .join(DESCRIPTOR_FILENAME)
            .is_file()
    );
    assert!(!group.join(id(2).as_str()).exists());
    assert_eq!(
        read_group(&group).unwrap().head.as_deref(),
        Some(id(1).as_str())
    );
}

#[tokio::test]
async fn explicit_selection_can_choose_a_retained_branch_or_an_older_snapshot() {
    let root = tempfile::tempdir().unwrap();
    let group = ensure(root.path(), Some("selection")).await.unwrap();
    add(&group, 1, None).await;
    add(&group, 2, Some(1)).await;
    assert_eq!(
        add(&group, 3, Some(1)).await.reason,
        HeadUpdateReason::Diverged
    );
    let side = select(root.path(), &format!("selection:{}", id(3)))
        .await
        .unwrap();
    assert_eq!(side.reason, HeadUpdateReason::Selected);
    assert_eq!(side.previous.as_deref(), Some(id(2).as_str()));
    assert_eq!(side.head.as_deref(), Some(id(3).as_str()));
    let old = select(root.path(), &format!("selection:{}", id(1)))
        .await
        .unwrap();
    assert_eq!(old.head.as_deref(), Some(id(1).as_str()));
    assert_eq!(
        select(root.path(), "selection").await.unwrap().reason,
        HeadUpdateReason::Unchanged
    );
}

#[test]
fn removing_a_head_selects_its_surviving_parent_then_clears_the_last_member() {
    // This contract expects immediate acquisition after each previous operation returns.
    // Unrelated parallel tests can fork with those operations' descriptor/group leases;
    // CLOEXEC closes the inherited handles only at exec. Create all fixtures in a child
    // running this test alone, preserving the immediate-acquisition assertion.
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "backend::local::snapshot::group::tests::removing_a_head_worker",
            "--ignored",
            "--nocapture",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
#[ignore = "subprocess helper for the immediate head-removal contract"]
async fn removing_a_head_worker() {
    let root = tempfile::tempdir().unwrap();
    let group = ensure(root.path(), Some("removal")).await.unwrap();
    add(&group, 1, None).await;
    add(&group, 2, Some(1)).await;
    let path = group.join(id(2).as_str());
    let lease = super::super::lease::deletion(&path).unwrap().unwrap();
    let removal = remove_member_leased(&path, lease).await.unwrap().unwrap();
    assert_eq!(removal.head_update.reason, HeadUpdateReason::ParentSelected);
    assert_eq!(
        removal.head_update.previous.as_deref(),
        Some(id(2).as_str())
    );
    assert_eq!(removal.head_update.head.as_deref(), Some(id(1).as_str()));
    assert!(removal.head_update.changed);
    assert!(!path.exists());
    assert_eq!(
        read_group(&group).unwrap().head.as_deref(),
        Some(id(1).as_str())
    );
    assert!(remove_member(&group.join(id(1).as_str())).await.unwrap());
    assert_eq!(read_group(&group).unwrap().head, None);
    assert!(
        resolve(root.path(), "removal")
            .await
            .unwrap_err()
            .to_string()
            .contains("has no head")
    );
    assert_eq!(
        add(&group, 3, None).await.reason,
        HeadUpdateReason::Initialized
    );
}

#[tokio::test]
async fn cycles_are_rejected_even_when_a_group_has_no_head() {
    let root = tempfile::tempdir().unwrap();
    let group = ensure(root.path(), Some("cycle")).await.unwrap();
    let staging = stage(
        root.path(),
        &[descriptor(1, Some(2)), descriptor(2, Some(1))],
    );
    let error = publish(&group, staging.path(), &BTreeMap::new(), &id(1), false)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("cycle"));
    assert_eq!(read_group(&group).unwrap().head, None);
    assert!(!group.join(id(1).as_str()).exists());
}

#[tokio::test]
async fn generated_groups_are_fresh_and_flat_directories_are_never_migrated() {
    let root = tempfile::tempdir().unwrap();
    let (first, second) = tokio::join!(ensure(root.path(), None), ensure(root.path(), None));
    let first = first.unwrap();
    let second = second.unwrap();
    assert_ne!(first, second);
    assert!(
        first
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("msb-")
    );
    let flat = root.path().join("flat");
    fs::create_dir(&flat).unwrap();
    fs::write(flat.join("keep"), "untouched").unwrap();
    let error = ensure(root.path(), Some("flat")).await.unwrap_err();
    assert!(error.to_string().contains("explicit path"));
    assert!(!flat.join(GROUP_FILENAME).exists());
    assert_eq!(fs::read_to_string(flat.join("keep")).unwrap(), "untouched");
}

#[tokio::test]
async fn selectors_and_group_names_cannot_escape_the_store() {
    let root = tempfile::tempdir().unwrap();
    for name in [
        "",
        ".",
        "..",
        "../escape",
        "a:b",
        "a\\b",
        "con",
        "trailing.",
    ] {
        assert!(
            ensure(root.path(), Some(name)).await.is_err(),
            "accepted {name}"
        );
    }
    for selector in ["valid:", "valid:../escape", "valid:a:b", "../escape:name"] {
        assert!(
            resolve(root.path(), selector).await.is_err(),
            "accepted {selector}"
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn symlinked_group_and_descriptor_paths_are_rejected() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let group = ensure(root.path(), Some("real")).await.unwrap();
    symlink(&group, root.path().join("redirect")).unwrap();
    assert!(ensure(root.path(), Some("redirect")).await.is_err());
    let staging = stage(root.path(), &[descriptor(1, None)]);
    let path = staging
        .path()
        .join(id(1).as_str())
        .join(DESCRIPTOR_FILENAME);
    let external = root.path().join("external.json");
    fs::rename(&path, &external).unwrap();
    symlink(&external, &path).unwrap();
    assert!(
        publish(&group, staging.path(), &BTreeMap::new(), &id(1), false)
            .await
            .is_err()
    );
    assert!(!group.join(id(1).as_str()).exists());
    assert!(external.is_file());
}
#[tokio::test]
async fn capture_binding_is_atomic_and_cannot_be_reassigned_by_name() {
    use super::super::source::{SOURCE_FILENAME, Source};
    use crate::backend::LocalBackend;

    let home = tempfile::tempdir().unwrap();
    let local = LocalBackend::builder()
        .home(home.path())
        .build()
        .await
        .unwrap();
    let db = local.db().await.unwrap().write();
    let root = local.snapshots_dir();
    let source = Source::capture(db, 1, "app").await.unwrap();
    let group = ensure_capture(&root, "history", source.clone())
        .await
        .unwrap();
    let original = fs::read(group.join(SOURCE_FILENAME)).unwrap();
    ensure_capture(&root, "history", source).await.unwrap();
    let replacement = Source::capture(db, 2, "app").await.unwrap();
    assert!(ensure_capture(&root, "history", replacement).await.is_err());
    assert_eq!(original, fs::read(group.join(SOURCE_FILENAME)).unwrap());
    // The strict legacy group document is unchanged; source information lives beside it.
    let state: serde_json::Value =
        serde_json::from_slice(&fs::read(group.join(GROUP_FILENAME)).unwrap()).unwrap();
    assert_eq!(state.as_object().unwrap().len(), 2);

    let unbound = ensure(&root, Some("imported")).await.unwrap();
    assert!(
        ensure_capture(
            &root,
            "imported",
            Source::capture(db, 1, "app").await.unwrap()
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("unbound")
    );
    assert!(!unbound.join(SOURCE_FILENAME).exists());
}

#[tokio::test]
async fn competing_capture_sources_never_share_a_group() {
    use super::super::source::Source;
    use crate::backend::LocalBackend;

    let home = tempfile::tempdir().unwrap();
    let local = LocalBackend::builder()
        .home(home.path())
        .build()
        .await
        .unwrap();
    let db = local.db().await.unwrap().write();
    let left = Source::capture(db, 1, "left").await.unwrap();
    let right = Source::capture(db, 2, "right").await.unwrap();
    let root = local.snapshots_dir();
    let (left, right) = tokio::join!(
        ensure_capture(&root, "history", left),
        ensure_capture(&root, "history", right)
    );
    assert_ne!(left.is_ok(), right.is_ok());
}

#[tokio::test]
async fn checkpoint_selectors_require_one_matching_live_association() {
    use super::super::source::Source;
    use crate::{backend::LocalBackend, db::entity::sandbox, sandbox::SandboxConfig};
    use sea_orm::{ActiveModelTrait, ActiveValue::Set, EntityTrait};

    let home = tempfile::tempdir().unwrap();
    let local = LocalBackend::builder()
        .home(home.path())
        .build()
        .await
        .unwrap();
    let db = local.db().await.unwrap();
    let model = sandbox::ActiveModel {
        name: Set("app".into()),
        config: Set(serde_json::to_string(&SandboxConfig::default()).unwrap()),
        status: Set(sandbox::SandboxStatus::Stopped),
        ephemeral: Set(false),
        ..Default::default()
    }
    .insert(db.write())
    .await
    .unwrap();
    let source = Source::capture(db.write(), model.id, "app").await.unwrap();
    let root = local.snapshots_dir();
    assert!(capture_source(&local, &root, None, None).await.is_err());
    assert!(
        capture_source(&local, &root, None, Some("app"))
            .await
            .unwrap_err()
            .to_string()
            .contains("no associated")
    );
    ensure_capture(&root, "stable", source.clone())
        .await
        .unwrap();
    for (group, name) in [
        (Some("stable"), None),
        (None, Some("app")),
        (Some("stable"), Some("app")),
    ] {
        assert_eq!(
            capture_source(&local, &root, group, name).await.unwrap(),
            ("stable".into(), "app".into())
        );
    }
    ensure_capture(&root, "experiment", source.clone())
        .await
        .unwrap();
    assert!(
        capture_source(&local, &root, None, Some("app"))
            .await
            .unwrap_err()
            .to_string()
            .contains("multiple associated")
    );
    ensure(&root, Some("imported")).await.unwrap();
    assert!(
        capture_source(&local, &root, Some("imported"), Some("app"))
            .await
            .unwrap_err()
            .to_string()
            .contains("unbound")
    );
    sandbox::Entity::delete_by_id(model.id)
        .exec(db.write())
        .await
        .unwrap();
    sandbox::ActiveModel {
        name: Set("app".into()),
        config: Set(serde_json::to_string(&SandboxConfig::default()).unwrap()),
        status: Set(sandbox::SandboxStatus::Stopped),
        ephemeral: Set(false),
        ..Default::default()
    }
    .insert(db.write())
    .await
    .unwrap();
    assert!(
        capture_source(&local, &root, Some("stable"), None)
            .await
            .unwrap_err()
            .to_string()
            .contains("no longer exists")
    );
    assert!(
        capture_source(&local, &root, Some("stable"), Some("app"))
            .await
            .unwrap_err()
            .to_string()
            .contains("another sandbox instance")
    );
    // A checkpoint must not recreate a group removed between selector resolution and capture.
    fs::remove_dir_all(root.join("stable")).unwrap();
    assert!(ensure_checkpoint(&root, "stable", source).await.is_err());
    assert!(!root.join("stable").exists());
}

#[tokio::test]
async fn public_group_lookup_survives_clear_and_exact_member_lookup_never_moves_head() {
    let home = tempfile::tempdir().unwrap();
    let local = crate::test_support::local_backend_builder(home.path())
        .build()
        .await
        .unwrap();
    let directory = ensure(&local.snapshots_dir(), Some("history"))
        .await
        .unwrap();
    add(&directory, 1, None).await;
    add(&directory, 2, Some(1)).await;
    write_member_name(&directory.join(id(1).as_str()), Some("base")).unwrap();

    crate::with_backend(local, async {
        let group = crate::Snapshot::get("history").await.unwrap();
        assert_eq!(group.head().await.unwrap().unwrap().id(), &id(2));
        let base = group.get_checkpoint("base").await.unwrap();
        assert_eq!(base.id(), &id(1));
        assert_eq!(group.head().await.unwrap().unwrap().id(), &id(2));
        let cleared = group.clear_head().await.unwrap();
        assert_eq!(cleared.previous.as_deref(), Some(id(2).as_str()));
        assert_eq!(cleared.head, None);
        assert_eq!(cleared.reason, HeadUpdateReason::Cleared);
        assert!(cleared.changed);
        assert_eq!(
            serde_json::to_value(&cleared).unwrap()["head"],
            serde_json::Value::Null
        );
        assert!(group.head().await.unwrap().is_none());
        let reopened = crate::Snapshot::get("history").await.unwrap();
        assert_eq!(crate::Snapshot::list().await.unwrap().len(), 1);
        assert_eq!(reopened.checkpoints().await.unwrap().len(), 2);
        let unchanged = reopened.clear_head().await.unwrap();
        assert!(!unchanged.changed);
        assert_eq!(unchanged.reason, HeadUpdateReason::Unchanged);
        let selected = reopened.set_head("base").await.unwrap();
        assert_eq!(selected.head.as_deref(), Some(id(1).as_str()));
        assert!(selected.changed);
        assert!(!reopened.set_head(id(1).as_str()).await.unwrap().changed);
        assert!(reopened.get_checkpoint("../escape").await.is_err());
        assert!(reopened.set_head("missing").await.is_err());
        assert_eq!(reopened.head().await.unwrap().unwrap().id(), &id(1));
        // An imported history is useful for reads; its capture API cannot guess a source.
        assert!(
            reopened
                .checkpoint()
                .await
                .unwrap_err()
                .to_string()
                .contains("unbound")
        );
    })
    .await;
}

#[tokio::test]
async fn receiver_capture_refuses_same_name_replacement_before_group_creation() {
    use crate::{db::entity::sandbox, sandbox::SandboxConfig};
    use sea_orm::{ActiveModelTrait, ActiveValue::Set, EntityTrait};

    let home = tempfile::tempdir().unwrap();
    let local = crate::test_support::local_backend_builder(home.path())
        .build()
        .await
        .unwrap();
    let db = local.db().await.unwrap();
    let insert = || sandbox::ActiveModel {
        name: Set("app".into()),
        config: Set(serde_json::to_string(&SandboxConfig::default()).unwrap()),
        status: Set(sandbox::SandboxStatus::Stopped),
        ephemeral: Set(false),
        ..Default::default()
    };
    let first = insert().insert(db.write()).await.unwrap();
    fs::create_dir_all(local.sandboxes_dir().join("app")).unwrap();
    let root = local.snapshots_dir();
    let local = std::sync::Arc::new(local);
    let db = local.db().await.unwrap();
    let backend: std::sync::Arc<dyn crate::backend::Backend> = local.clone();
    let handle = backend
        .sandboxes()
        .get(backend.clone(), "app")
        .await
        .unwrap();
    sandbox::Entity::delete_by_id(first.id)
        .exec(db.write())
        .await
        .unwrap();
    let replacement = insert().insert(db.write()).await.unwrap();
    assert_ne!(first.id, replacement.id);
    let error = handle.snapshot("history").await.unwrap_err();
    assert!(
        matches!(error, MicrosandboxError::SandboxReplaced { .. }),
        "{error}"
    );
    assert!(!root.join("history").exists());
}

#[tokio::test]
async fn new_group_capture_admission_is_exclusive_even_for_the_same_source() {
    let home = tempfile::tempdir().unwrap();
    let local = crate::test_support::local_backend_builder(home.path())
        .build()
        .await
        .unwrap();
    let source = super::super::source::Source::capture(local.db().await.unwrap().write(), 1, "app")
        .await
        .unwrap();
    let root = local.snapshots_dir();
    let (first, second) = tokio::join!(
        ensure_new_capture(&root, "history", source.clone()),
        ensure_new_capture(&root, "history", source.clone()),
    );
    assert_ne!(first.is_ok(), second.is_ok());
    let winner = match (first, second) {
        (Ok(winner), Err(MicrosandboxError::SnapshotAlreadyExists(_)))
        | (Err(MicrosandboxError::SnapshotAlreadyExists(_)), Ok(winner)) => winner,
        _ => panic!("expected one owner and one name collision"),
    };
    // Creation must not silently become append, even when the requested binding matches.
    assert!(ensure_new_capture(&root, "history", source).await.is_err());
    assert!(!winner.directory().join(GROUP_FILENAME).exists());
    drop(winner);
    assert!(!root.join("history").exists());
}

#[tokio::test]
#[ignore = "live VM qualification: requires MSB_TEST_GROUP_HOME, MSB_TEST_GROUP_ARCHIVE and a configured native runtime"]
async fn live_public_group_capture_head_and_spawn_after_source_deletion() {
    use crate::{Checkpoint, LoadOpts, Sandbox, Snapshot};

    let home = PathBuf::from(std::env::var_os("MSB_TEST_GROUP_HOME").expect("isolated home"));
    let archive =
        PathBuf::from(std::env::var_os("MSB_TEST_GROUP_ARCHIVE").expect("native disk archive"));
    let local = crate::backend::LocalBackend::builder()
        .home(&home)
        .build()
        .await
        .unwrap();
    eprintln!(
        "GROUP_API_RUNTIME {}",
        crate::setup::resolve_runtime(local.config())
            .unwrap()
            .msb_path
            .display()
    );
    crate::with_backend(local, async {
        Checkpoint::load_many(
            &[archive],
            LoadOpts {
                group: Some("imported".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let imported = Snapshot::get("imported").await.unwrap();
        assert!(
            imported
                .checkpoint()
                .await
                .unwrap_err()
                .to_string()
                .contains("unbound")
        );
        let source = imported
            .spawn_sandbox_with(|options| {
                options
                    .name("group-api-source")
                    .cpus(2)
                    .memory(512u32)
                    .max_duration(180)
            })
            .await
            .unwrap();
        let captured: MicrosandboxResult<_> = async {
            let output = source
                .exec(
                    "sh",
                    ["-c", "set -eu; mkdir -p /work/removal-files; echo A > /work/group-api; dd if=/dev/urandom of=/work/removal-payload bs=1M count=16; sha256sum /work/removal-payload > /work/removal.sha256; for i in $(seq 1 500); do printf item-$i > /work/removal-files/$i; done; sync"],
                )
                .await?;
            assert!(output.status().success);
            let created = source
                .snapshot_with("history", |options| {
                    options.initial_checkpoint("base").record_integrity()
                })
                .await?;
            assert_eq!(
                created.head_update.head.as_deref(),
                Some(created.checkpoint.id().as_str())
            );
            assert!(source.snapshot("history").await.is_err());
            let output = source
                .exec("sh", ["-c", "echo B > /work/group-api; sync"])
                .await?;
            assert!(output.status().success);
            let next = created
                .snapshot
                .checkpoint_with(|options| options.name("next").record_integrity())
                .await?;
            assert_ne!(created.checkpoint.id(), next.checkpoint.id());
            assert_eq!(
                created.head_update.head.as_deref(),
                Some(created.checkpoint.id().as_str())
            );
            assert_eq!(
                created.snapshot.head().await?.unwrap().id(),
                next.checkpoint.id()
            );
            assert_eq!(created.snapshot.checkpoints().await?.len(), 2);
            created.snapshot.clear_head().await?;
            assert!(created.snapshot.head().await?.is_none());
            assert!(created.snapshot.spawn_sandbox().await.is_err());
            created.snapshot.set_head("base").await?;
            assert_eq!(
                created.snapshot.head().await?.unwrap().id(),
                created.checkpoint.id()
            );
            Ok((created.snapshot, created.checkpoint, next.checkpoint))
        }
        .await;
        let stopped = source.stop().await;
        stopped.unwrap();
        // A full capture of a stopped VM fails after group reservation. The same
        // name must remain usable for a subsequent valid disk-only capture.
        let failed = source
            .snapshot_with("failed-initial", |options| options.full())
            .await;
        let absent = Snapshot::get("failed-initial").await;
        let retry = source.snapshot("failed-initial").await;
        let removed = Sandbox::remove("group-api-source").await;
        removed.unwrap();
        assert!(
            failed.is_err(),
            "stopped full capture unexpectedly succeeded"
        );
        assert!(
            absent.is_err(),
            "failed initial capture exposed an empty group"
        );
        retry.unwrap();
        let (group, base, next) = captured.unwrap();
        assert!(
            group.checkpoint().await.is_err(),
            "an orphaned group must not capture another source"
        );
        for (checkpoint, marker) in [(base, "A"), (next, "B")] {
            checkpoint.verify().await.unwrap();
            let (_progress, task) = checkpoint
                .spawn_sandbox_with_progress_with(|_| {
                    // Even returning a different builder cannot replace the receiver's
                    // exact source. Omitting the name exercises generated destinations.
                    Sandbox::restore("must-not-resolve-this-source")
                        .cpus(2)
                        .memory(512u32)
                        .max_duration(120)
                })
                .await
                .unwrap();
            let child = task.await.unwrap().unwrap();
            assert!(!child.name().is_empty());
            let checked = child.exec("cat", ["/work/group-api"]).await;
            let stopped = child.stop().await;
            let removed = Sandbox::remove(child.name()).await;
            stopped.unwrap();
            removed.unwrap();
            let output = checked.unwrap();
            assert!(output.status().success);
            assert_eq!(output.stdout().unwrap().trim(), marker);
            eprintln!(
                "GROUP_API_GUEST_VERIFIED id={} marker={marker}",
                checkpoint.id()
            );
        }
        // Keep the extra live phase off the test thread's stack. Large debug-build
        // async restore futures otherwise accumulate in this single scenario's frame.
        Box::pin(async {
            // Removing the newest checkpoint must expose the surviving recorded parent
            // through the ordinary group receiver, with all payloads still bootable.
            group.set_head("next").await.unwrap();
            // The stopped-capture retry is an external child of `next`; its dependency
            // protection must still apply before we exercise successful head deletion.
            let protected = Checkpoint::remove_by_reference("history:next", false).await.unwrap_err();
            assert!(protected.to_string().contains("indexed child"), "{protected}");
            Checkpoint::remove_by_reference("failed-initial", false).await.unwrap();
            Checkpoint::remove_by_reference("history:next", false).await.unwrap();
            let fallback = group.get_checkpoint("base").await.unwrap();
            assert_eq!(group.head().await.unwrap().unwrap().id(), fallback.id());
            assert!(group.get_checkpoint("next").await.is_err());
            let child = group.spawn_sandbox_with(|options| options.cpus(2).memory(512u32).max_duration(120)).await.unwrap();
            let checked = child.exec("sh", ["-c", "set -eu; test $(cat /work/group-api) = A; test $(find /work/removal-files -type f | wc -l) = 500; test $(cat /work/removal-files/500) = item-500; sha256sum -c /work/removal.sha256"]).await;
            let stopped = child.stop().await;
            let removed = Sandbox::remove(child.name()).await;
            stopped.unwrap();
            removed.unwrap();
            let output = checked.unwrap();
            assert!(output.status().success, "{}", output.stderr().unwrap());
            Checkpoint::remove_by_reference("history:base", false).await.unwrap();
            assert!(group.head().await.unwrap().is_none());
            assert!(group.checkpoints().await.unwrap().is_empty());
            assert!(group.spawn_sandbox().await.is_err());
        }).await;
        eprintln!("GROUP_API_LIVE_OK source_deleted=true exact_members=2 head_clear_and_replace=true removal_parent_boot=true payload_bytes=16777216 files=500 final_head=none");
    })
    .await;
}

#[cfg(unix)]
#[tokio::test]
#[ignore = "requires MSB_TEST_GROWTH_POLICY_ARCHIVE and matching native runtime; fixture contains /root/checksum and 500 files"]
async fn live_snapshot_root_growth_preserves_managed_policy_and_running_destination() {
    let archive = std::path::PathBuf::from(
        std::env::var_os("MSB_TEST_GROWTH_POLICY_ARCHIVE").expect("archive fixture"),
    );
    let layout =
        std::env::var("MSB_TEST_GROWTH_POLICY_LAYOUT").unwrap_or_else(|_| "managed".into());
    assert!(matches!(layout.as_str(), "managed" | "flat"));
    let home = tempfile::Builder::new()
        .prefix("msb-growth-policy-")
        .tempdir_in("/tmp")
        .unwrap();
    let policy = serde_json::json!({"overrides": {"sandbox_defaults": {"oci": {"root_disk": {
        "kind": layout, "size_mib": 512,
    }}}}});
    fs::write(
        home.path().join("managed.json"),
        serde_json::to_vec(&policy).unwrap(),
    )
    .unwrap();
    // Match production's managed-policy permissions regardless of the test host umask.
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(
        home.path().join("managed.json"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let backend = Arc::new(
        crate::test_support::local_backend_builder(home.path())
            .build()
            .await
            .unwrap(),
    );
    assert_eq!(
        serde_json::to_value(&backend.config().sandbox_defaults.oci.root_disk).unwrap()["size_mib"],
        512
    );
    let digest = microsandbox_image::checkpoint::sparse_file_integrity(&archive)
        .unwrap()
        .root;
    // Full checkpoint fixtures need explicit cold boot; disk archives already cold boot.
    let disk_only =
        std::env::var("MSB_TEST_GROWTH_POLICY_DISK_ONLY").is_ok_and(|value| value == "1");
    let request = |size| {
        crate::sandbox::SandboxBuilder::new("growth-child")
            .override_snapshot(archive.to_string_lossy())
            .snapshot_launch_options(disk_only, false)
            .root_disk(size)
            .memory(256_u32)
            .cpus(1)
            .replace()
    };
    let sandbox = backend
        .create_sandbox(
            backend.clone(),
            request(512_u32),
            crate::runtime::SpawnMode::Attached,
            None,
        )
        .await
        .unwrap();
    // Keep every fallible assertion inside a result, then stop/remove the owned
    // sandbox before reporting failure. The original source archive stays read-only.
    let outcome: crate::MicrosandboxResult<()> = async {
        let seeded = sandbox.exec("sh", ["-ec", "sha256sum -c /root/checksum; test $(find /root/many -type f | wc -l) = 500; test $(df -k /root | tail -1 | awk '{print $2}') -gt 400000; printf retained > /root/policy-marker; dd if=/dev/zero of=/root/policy-growth bs=1M count=300 2>/dev/null; sync"]).await?;
        if !seeded.status().success {
            return Err(crate::MicrosandboxError::Custom("grown guest contents/capacity failed validation".into()));
        }
        match backend.create_sandbox(backend.clone(), request(1024_u32), crate::runtime::SpawnMode::Attached, None).await {
            Err(error) if error.to_string().contains("1024 MiB conflicts with managed root capacity 512 MiB") => {},
            Err(error) => return Err(error),
            Ok(unexpected) => {
                // A regressed implementation may have started a replacement. Reap
                // that handle too, instead of deleting its home beneath a live VM.
                let stop = unexpected.kill().await;
                let remove = unexpected.remove_persisted().await;
                stop?;
                remove?;
                return Err(crate::MicrosandboxError::Custom("conflicting growth replaced the live destination".into()));
            },
        }
        let retained = sandbox.exec("sh", ["-ec", "test $(cat /root/policy-marker) = retained; test $(stat -c %s /root/policy-growth) = 314572800; sha256sum -c /root/checksum"]).await?;
        if !retained.status().success {
            return Err(crate::MicrosandboxError::Custom("policy refusal changed the running destination".into()));
        }
        Ok(())
    }.await;
    let stop = sandbox.kill().await;
    let remove = sandbox.remove_persisted().await;
    stop.unwrap();
    remove.unwrap();
    outcome.unwrap();
    assert_eq!(
        microsandbox_image::checkpoint::sparse_file_integrity(&archive)
            .unwrap()
            .root,
        digest
    );
    assert!(
        !fs::read_dir(backend.sandboxes_dir())
            .unwrap()
            .any(|entry| entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".snapshot-grow-"))
    );
}
