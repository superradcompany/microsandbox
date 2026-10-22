//! Whole-history retirement, with preflight dependency checks and recoverable catalog cleanup.

use std::fs::File;
use std::path::Path;

use microsandbox_image::storage_lease::StorageLease;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

use super::super::{deletion, lease, publication, store, writer::WriterLease};
use super::retirement::Retirement;
use crate::backend::LocalBackend;
use crate::db::entity::snapshot;
use crate::snapshot::{HeadUpdate, HeadUpdateReason, SnapshotRemoveResult};
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Move every guard into the blocking publisher so cancellation cannot release ownership early.
struct Prepared {
    retirement: Retirement,
    report: SnapshotRemoveResult,
    _writer: WriterLease,
    _group: lease::GroupDeletionLease,
    members: Vec<lease::DeletionLease>,
    lock: Option<File>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(in crate::backend::local::snapshot) async fn remove(
    local: &LocalBackend,
    directory: &Path,
) -> MicrosandboxResult<SnapshotRemoveResult> {
    remove_observed(local, directory, || Ok(())).await
}

async fn remove_observed(
    local: &LocalBackend,
    directory: &Path,
    before_admission: impl FnOnce() -> MicrosandboxResult<()> + Send,
) -> MicrosandboxResult<SnapshotRemoveResult> {
    let directory = directory.canonicalize()?;
    let parent = directory
        .parent()
        .ok_or_else(|| super::integrity("group has no parent".into()))?;
    let pools = local.db().await?;
    recover(local, parent).await?;
    publication::complete_batch(pools.write(), &directory).await?;
    deletion::recover_parent(local, &directory).await?;
    // The parent pointer outlives the last member row and also covers external stores.
    deletion::register_parent(local, parent)?;
    before_admission()?;
    let writer = WriterLease::try_acquire(&directory)?.ok_or_else(|| {
        super::integrity("snapshot group has an active writer; retry removal".into())
    })?;
    // Another member removal may have committed between the first recovery pass
    // and admission. Reconcile its receipt now, before retiring the containing group.
    publication::complete_batch(pools.write(), &directory).await?;
    deletion::recover_parent_admitted(local, &directory, writer.clone()).await?;
    let prepared = super::blocking({
        let directory = directory.clone();
        move || prepare(&directory, writer)
    })
    .await?;
    // All source members are pinned before checking edges. A new dependent cannot finish
    // source admission during this interval; internal ancestry disappears with this group.
    let rows = snapshot::Entity::find().all(pools.read()).await?;
    for row in rows {
        if row
            .parent_digest
            .as_ref()
            .is_some_and(|id| prepared.retirement.members().contains_key(id))
            && Path::new(&row.artifact_path).parent() != Some(directory.as_path())
        {
            return Err(super::integrity(format!(
                "cannot remove snapshot group: surviving checkpoint {} depends on its history",
                row.artifact_path
            )));
        }
    }
    let prepared = super::blocking(move || {
        #[cfg(windows)]
        let mut prepared = prepared;
        #[cfg(not(windows))]
        let prepared = prepared;
        #[cfg(windows)]
        {
            // Windows directory rename itself refuses open descendant handles. Release our
            // own interior handles, retaining stable external writer/group ownership. A new
            // exact reader in this interval makes retirement fail, never partial-delete it.
            prepared.members.clear();
            prepared.lock.take();
        }
        prepared.retirement.publish()?;
        Ok(prepared)
    })
    .await?;
    let report = prepared.report.clone();
    if let Err(source) = reconcile(local, &prepared.retirement).await {
        return Err(MicrosandboxError::SnapshotGroupRemovalRecovery {
            result: Box::new(report),
            source: Box::new(source),
        });
    }
    super::blocking(move || {
        let Prepared {
            retirement,
            mut report,
            _writer,
            _group,
            members,
            lock,
        } = prepared;
        if let Err(error) = retirement.finish() {
            report.warnings.push(format!(
                "group removal committed; cleanup needs recovery: {error}"
            ));
        }
        drop((members, lock, _writer, _group));
        Ok(report)
    })
    .await
}

/// Acquire all publication ownership inside the blocking worker, including during cancellation.
fn prepare(directory: &Path, writer: WriterLease) -> MicrosandboxResult<Prepared> {
    let group = lease::group_deletion(directory)?
        .ok_or_else(|| super::integrity("snapshot group is in use by verification".into()))?;
    let lock = super::lock_group(directory)?;
    deletion::require_no_pending(directory)?;
    let state = super::read_group(directory)?;
    let selected = super::read_members(directory, true)?;
    super::validate_head(&state, &selected)?;
    let mut members = Vec::with_capacity(selected.len());
    for member in selected.values() {
        members.push(
            lease::deletion_under_group_lock(&member.path, &group)
                .map_err(|error| member_lock_error(error, selected.len()))?
                .ok_or_else(|| {
                    super::integrity(format!(
                        "checkpoint is in use by an active reader: {}",
                        member.path.display()
                    ))
                })?,
        );
    }
    let name = directory
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let report = SnapshotRemoveResult {
        group: name.clone(),
        removed: selected
            .keys()
            .map(|id| {
                super::SnapshotId::new(id).map_err(|error| super::integrity(error.to_string()))
            })
            .collect::<Result<_, _>>()?,
        head_update: HeadUpdate {
            group: name,
            changed: state.head.is_some(),
            previous: state.head.clone(),
            head: None,
            reason: if state.head.is_some() {
                HeadUpdateReason::Cleared
            } else {
                HeadUpdateReason::Unchanged
            },
        },
        warnings: Vec::new(),
    };
    let retirement = Retirement::prepare(directory)?;
    Ok(Prepared {
        retirement,
        report,
        _writer: writer,
        _group: group,
        members,
        lock: Some(lock),
    })
}

/// Older readers hold member descriptor locks, not the newer group lease. Keep every
/// member pin until publication; releasing pins in batches would permit unsafe deletion.
fn member_lock_error(error: std::io::Error, members: usize) -> std::io::Error {
    #[cfg(unix)]
    if matches!(error.raw_os_error(), Some(libc::EMFILE | libc::ENFILE)) {
        return std::io::Error::new(
            error.kind(),
            format!(
                "cannot acquire reader-protection locks for all {members} checkpoints: open-file limit reached before group removal; no checkpoints were removed; increase the process/system open-file limit or close other open files and retry (Unix removal retains two file descriptors per checkpoint plus catalog and operation overhead): {error}"
            ),
        );
    }
    #[cfg(not(unix))]
    let _ = members;
    error
}

/// The journal is outside the removed directory, so listing can recover even an empty group.
pub(in crate::backend::local::snapshot) async fn recover(
    local: &LocalBackend,
    parent: &Path,
) -> MicrosandboxResult<()> {
    let parent = parent.to_path_buf();
    let records = super::blocking(move || super::retirement::pending(&parent)).await?;
    for retirement in records {
        let source = retirement.source();
        let Some(writer) = WriterLease::try_reserve(&source)? else {
            continue;
        };
        let Some(group) = StorageLease::try_exclusive(&source)? else {
            continue;
        };
        retirement.validate_payload()?;
        retirement.confirm()?;
        reconcile(local, &retirement).await?;
        super::blocking(move || {
            let _guards = (writer, group);
            retirement.finish()
        })
        .await?;
    }
    Ok(())
}

async fn reconcile(local: &LocalBackend, retirement: &Retirement) -> MicrosandboxResult<()> {
    retirement.validate_payload()?;
    retirement.confirm()?;
    let source = retirement.source();
    let mut missing = Vec::new();
    for (id, digest) in retirement.members() {
        let path = source.join(id);
        match std::fs::symlink_metadata(&path) {
            // A newly created group/member owns its row, even if it reused an old identity.
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing.push((path, digest.clone()))
            }
            Err(error) => return Err(error.into()),
        }
    }
    local
        .db()
        .await?
        .write()
        .transaction(|transaction| {
            let missing = missing.clone();
            async move {
                for (path, digest) in missing {
                    snapshot::Entity::delete_many()
                        .filter(snapshot::Column::ArtifactPath.eq(path.to_string_lossy().as_ref()))
                        .filter(snapshot::Column::Digest.eq(digest))
                        .exec(&transaction)
                        .await?;
                }
                store::recompute_children(&transaction).await?;
                Ok((transaction, ()))
            }
        })
        .await
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;

    #[test]
    fn whole_group_removal_recovers_member_retired_before_admission() {
        // The assertion models the old process's descriptors being fully gone.
        // Isolate it from unrelated fork/exec tests inheriting those descriptors.
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "backend::local::snapshot::group::remove_history::tests::member_recovery_worker",
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
    #[ignore = "subprocess-only recovery interleaving"]
    async fn member_recovery_worker() {
        let home = tempfile::tempdir().unwrap();
        let local = crate::test_support::local_backend_builder(home.path())
            .build()
            .await
            .unwrap();
        let directory = super::super::ensure(&local.snapshots_dir(), Some("history"))
            .await
            .unwrap();
        super::super::tests::add(&directory, 1, None).await;
        super::super::tests::add(&directory, 2, None).await;
        store::reindex_dir(&local, &local.snapshots_dir())
            .await
            .unwrap();
        let pools = local.db().await.unwrap();
        assert_eq!(
            snapshot::Entity::find()
                .all(pools.read())
                .await
                .unwrap()
                .len(),
            2
        );
        let head = super::super::read_group(&directory).unwrap().head.unwrap();
        let retired = if head == super::super::tests::id(1).as_str() {
            2
        } else {
            1
        };
        let path = directory.join(super::super::tests::id(retired).as_str());
        let report = remove_observed(&local, &directory, || {
            // Leave exactly the receipt/payload state from a remover that exits
            // after retirement and before its catalog reconciliation.
            deletion::quarantine(&path)
        })
        .await
        .unwrap();
        assert_eq!(report.removed.len(), 1);
        assert!(!directory.exists());
        // Query the catalog directly: a listing must not repair the state under test.
        assert!(
            snapshot::Entity::find()
                .all(pools.read())
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            super::super::retirement::pending(&local.snapshots_dir())
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn whole_group_removal_preserves_busy_member_receipt() {
        let home = tempfile::tempdir().unwrap();
        let local = crate::test_support::local_backend_builder(home.path())
            .build()
            .await
            .unwrap();
        let directory = super::super::ensure(&local.snapshots_dir(), Some("history"))
            .await
            .unwrap();
        let (receipt, active) =
            deletion::prepare_retirement(&directory, std::ffi::OsStr::new("retired")).unwrap();
        let error = remove(&local, &directory).await.unwrap_err();
        assert!(
            error.to_string().contains("pending member cleanup"),
            "{error}"
        );
        assert!(receipt.join("source.json").is_file());
        assert!(directory.exists());
        drop(active);
    }

    #[tokio::test]
    async fn cancelled_whole_group_preflight_retains_worker_ownership() {
        const CHILD: &str = "MSB_GROUP_PREFLIGHT_CANCELLATION_CHILD";
        if std::env::var_os(CHILD).is_none() {
            // Other parallel tests fork while this test briefly probes admission.
            // CLOEXEC closes inherited descriptors at exec, not at fork, so a
            // successful probe does not guarantee the next nonblocking removal
            // can acquire its lock. Keep this cancellation test's exact ownership
            // assertions in a process with no unrelated fork producers.
            let output = tokio::task::spawn_blocking(|| {
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "backend::local::snapshot::group::remove_history::tests::cancelled_whole_group_preflight_retains_worker_ownership",
                        "--nocapture",
                    ])
                    .env(CHILD, "1")
                    .output()
                    .unwrap()
            })
            .await
            .unwrap();
            assert!(
                output.status.success(),
                "isolated preflight cancellation test failed:\n{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let home = tempfile::tempdir().unwrap();
        let local = crate::test_support::local_backend_builder(home.path())
            .build()
            .await
            .unwrap();
        let directory = super::super::ensure(&local.snapshots_dir(), Some("history"))
            .await
            .unwrap();
        let writer = WriterLease::try_acquire(&directory).unwrap().unwrap();
        let lock = super::super::lock_group(&directory).unwrap();
        let worker_directory = directory.clone();
        let (started, ready) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let mut work = Box::pin(super::super::blocking(move || {
                prepare(&worker_directory, writer)
            }));
            // Dispatch the exact preflight worker used by remove(). Earlier catalog recovery
            // also uses group.lock, so pausing the public call there would test the wrong phase.
            std::future::poll_fn(|cx| {
                assert!(std::future::Future::poll(work.as_mut(), cx).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
            started.send(()).unwrap();
            let _ = work.await;
        });
        ready.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(WriterLease::try_acquire(&directory).unwrap().is_none());
        drop(lock);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if WriterLease::try_acquire(&directory).unwrap().is_some() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "cancelled preflight did not release ownership"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(directory.join(super::super::GROUP_FILENAME).exists());
        // An abandoned preparation never publishes, and normal recovery permits a later removal.
        assert!(remove(&local, &directory).await.unwrap().removed.is_empty());
        assert!(!directory.exists());
    }
}
