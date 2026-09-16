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

fn id(value: u128) -> SnapshotId {
    SnapshotId::new(format!("snap_{value:032x}")).unwrap()
}

fn descriptor(value: u128, parent: Option<u128>) -> Manifest {
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

fn stage(root: &Path, manifests: &[Manifest]) -> tempfile::TempDir {
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

async fn add(group: &Path, value: u128, parent: Option<u128>) -> HeadUpdate {
    let staging = stage(group.parent().unwrap(), &[descriptor(value, parent)]);
    publish(group, staging.path(), &BTreeMap::new(), &id(value), false)
        .await
        .unwrap()
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

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
        assert_eq!(update.head, id(3).as_str());
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
    assert_eq!(update.head, id(3).as_str());
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
        assert_eq!(update.head, id(1).as_str());
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
                assert_eq!(update.head, id(1).as_str());
            } else {
                assert_eq!(update, None);
                assert_eq!(read_group(&group).unwrap().head, None);
                let error = resolve(root.path(), &name).await.unwrap_err().to_string();
                assert!(error.contains("no head selected"));
                assert!(error.contains("msb snapshot head"));
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
    assert_eq!(update.head, id(1).as_str());
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
    assert_eq!(update.head, id(3).as_str());
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
    assert!(error.to_string().contains("msb snapshot head"));
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
    assert_eq!(update.head, id(5).as_str());
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
        select(root.path(), "lookup").await.unwrap().head,
        id(1).as_str()
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
    assert_eq!(unknown.head, id(1).as_str());
    assert!(group.join(id(3).as_str()).is_dir());
    let intermediate = add(&group, 2, Some(1)).await;
    assert_eq!(intermediate.head, id(2).as_str());
    assert_eq!(
        select(root.path(), "history").await.unwrap().head,
        id(2).as_str()
    );

    let staging = stage(root.path(), &[]);
    let retried = publish(&group, staging.path(), &BTreeMap::new(), &id(3), false)
        .await
        .unwrap();
    assert_eq!(retried.reason, HeadUpdateReason::FastForwarded);
    assert_eq!(retried.head, id(3).as_str());
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
        select(root.path(), "duplicates").await.unwrap().head,
        id(1).as_str()
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
    assert_eq!(side.head, id(3).as_str());
    let old = select(root.path(), &format!("selection:{}", id(1)))
        .await
        .unwrap();
    assert_eq!(old.head, id(1).as_str());
    assert_eq!(
        select(root.path(), "selection").await.unwrap().reason,
        HeadUpdateReason::Unchanged
    );
}

#[tokio::test]
async fn removing_a_head_requires_selection_unless_it_is_the_final_member() {
    let root = tempfile::tempdir().unwrap();
    let group = ensure(root.path(), Some("removal")).await.unwrap();
    add(&group, 1, None).await;
    add(&group, 2, Some(1)).await;
    let error = remove_member(&group.join(id(2).as_str()))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("first select another"));
    assert!(group.join(id(2).as_str()).is_dir());
    assert!(remove_member(&group.join(id(1).as_str())).await.unwrap());
    assert!(remove_member(&group.join(id(2).as_str())).await.unwrap());
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
