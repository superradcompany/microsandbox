//! Local backend: Capture ancestry independent of group names, dirty tracking, and export dependencies.

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde::{Deserialize, Serialize};

use crate::backend::LocalBackend;
use crate::db::entity::sandbox;
use crate::sandbox::SandboxConfig;
use crate::{MicrosandboxError, MicrosandboxResult};

use super::SnapshotId;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    sandbox_id: i32,
    snapshot_id: String,
}

/// Holds the per-source capture sequencer without holding a VM pause or database transaction.
pub(crate) struct CaptureLineage {
    _lock: Arc<File>,
    path: PathBuf,
    sandbox_id: i32,
    pub(crate) parent: Option<SnapshotId>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl CaptureLineage {
    /// Source incarnation whose ancestry is protected by this sequencer.
    pub(crate) fn sandbox_id(&self) -> i32 {
        self.sandbox_id
    }

    /// Refuse a completed capture if its named source was removed or replaced meanwhile.
    pub(crate) async fn validate_source(
        &self,
        local: &LocalBackend,
        name: &str,
    ) -> MicrosandboxResult<()> {
        let current = sandbox::Entity::find()
            .filter(sandbox::Column::Name.eq(name))
            .one(local.db().await?.read())
            .await?;
        if current
            .as_ref()
            .is_none_or(|model| model.id != self.sandbox_id)
        {
            return Err(MicrosandboxError::InvalidConfig(
                "source sandbox changed during snapshot capture".into(),
            ));
        }
        Ok(())
    }

    /// Advance only after the artifact/archive has been successfully published.
    pub(crate) async fn commit(&self, snapshot_id: &SnapshotId) -> MicrosandboxResult<()> {
        let path = self.path.clone();
        // A cancelled awaiting task must not release the source sequencer while its blocking
        // publication still runs, otherwise an older cursor could replace a newer capture.
        let lock = Arc::clone(&self._lock);
        let cursor = Cursor {
            sandbox_id: self.sandbox_id,
            snapshot_id: snapshot_id.to_string(),
        };
        tokio::task::spawn_blocking(move || -> MicrosandboxResult<()> {
            let _lock = lock;
            let parent = path.parent().expect("cursor has a sandbox directory");
            let mut staged = tempfile::NamedTempFile::new_in(parent)?;
            staged.write_all(&serde_json::to_vec(&cursor)?)?;
            staged.as_file().sync_all()?;
            staged
                .persist(&path)
                .map_err(|error| MicrosandboxError::Io(error.error))?;
            #[cfg(unix)]
            File::open(parent)?.sync_all()?;
            Ok(())
        })
        .await
        .map_err(|error| {
            MicrosandboxError::Runtime(format!("snapshot ancestry publication: {error}"))
        })?
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Serialize capture publication with removal/replacement of the same named source. The lock
/// lives outside its removable directory and must never be unlinked. Callers that also own a
/// transition or lifecycle guard acquire transition, then lineage, then lifecycle ownership.
pub(crate) async fn lock_source(run_dir: &Path, name: &str) -> MicrosandboxResult<File> {
    let path = microsandbox_runtime::ipc::snapshot_lineage_lock_path(run_dir, name);
    tokio::fs::create_dir_all(path.parent().expect("lineage lock has a parent")).await?;
    let lock = microsandbox_utils::process_lock::open_lock_file(&path)?;
    // Waiting asynchronously keeps cancellation bounded and avoids occupying a blocking-pool
    // thread for each capture queued behind a large archive publication.
    loop {
        if microsandbox_utils::process_lock::try_lock_exclusive(&lock)? {
            return Ok(lock);
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

pub(crate) async fn begin(local: &LocalBackend, name: &str) -> MicrosandboxResult<CaptureLineage> {
    let model = sandbox::Entity::find()
        .filter(sandbox::Column::Name.eq(name))
        .one(local.db().await?.read())
        .await?
        .ok_or_else(|| MicrosandboxError::SandboxNotFound(name.into()))?;
    let expected_id = model.id;
    let lock = lock_source(&local.config().run_dir(), name).await?;
    let directory = local.sandboxes_dir().join(name);
    let (lock, cursor) = tokio::task::spawn_blocking(move || -> MicrosandboxResult<_> {
        // Removal/replacement owns the same stable lock, so this path remains bound to the
        // checked source until publication commits. Never recreate a missing source directory.
        if !std::fs::symlink_metadata(&directory)?.is_dir() {
            return Err(MicrosandboxError::SnapshotIntegrity(
                "snapshot source directory is not a directory".into(),
            ));
        }
        let path = directory.join("snapshot-lineage.json");
        let cursor = match std::fs::symlink_metadata(&path) {
            Ok(meta) if meta.is_file() && meta.len() <= 4096 => {
                Some(serde_json::from_slice::<Cursor>(&std::fs::read(&path)?)?)
            }
            Ok(_) => {
                return Err(MicrosandboxError::SnapshotIntegrity(
                    "invalid snapshot ancestry cursor".into(),
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        Ok((lock, (path, cursor)))
    })
    .await
    .map_err(|error| MicrosandboxError::Runtime(format!("snapshot ancestry lock: {error}")))??;
    let current = sandbox::Entity::find()
        .filter(sandbox::Column::Name.eq(name))
        .one(local.db().await?.read())
        .await?
        .ok_or_else(|| MicrosandboxError::SandboxNotFound(name.into()))?;
    if current.id != expected_id {
        return Err(MicrosandboxError::InvalidConfig(
            "source sandbox changed while waiting for capture".into(),
        ));
    }
    let config: SandboxConfig =
        serde_json::from_str(current.active_config.as_deref().unwrap_or(&current.config))?;
    let parent = match cursor.1 {
        Some(cursor) if cursor.sandbox_id == current.id => Some(cursor.snapshot_id),
        Some(_) => {
            return Err(MicrosandboxError::SnapshotIntegrity(
                "snapshot ancestry belongs to another sandbox instance".into(),
            ));
        }
        None => config.snapshot_parent,
    }
    .map(SnapshotId::new)
    .transpose()
    .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
    Ok(CaptureLineage {
        _lock: Arc::new(lock),
        path: cursor.0,
        sandbox_id: current.id,
        parent,
    })
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use sea_orm::{ActiveModelTrait, ActiveValue::Set};

    use super::*;

    async fn source(local: &LocalBackend, name: &str, origin: Option<&SnapshotId>) -> i32 {
        let mut config = SandboxConfig::default();
        config.spec.name = name.into();
        config.snapshot_parent = origin.map(ToString::to_string);
        std::fs::create_dir_all(local.sandboxes_dir().join(name)).unwrap();
        sandbox::ActiveModel {
            name: Set(name.into()),
            config: Set(serde_json::to_string(&config).unwrap()),
            status: Set(sandbox::SandboxStatus::Stopped),
            ephemeral: Set(false),
            ..Default::default()
        }
        .insert(local.db().await.unwrap().write())
        .await
        .unwrap()
        .id
    }

    fn id(value: u128) -> SnapshotId {
        SnapshotId::new(format!("snap_{value:032x}")).unwrap()
    }

    #[test]
    fn cancelled_cursor_wait_retains_lock_until_blocking_publication_finishes() {
        // Hold the sole blocking worker so cancellation deterministically lands after commit
        // queues publication but before that publication can touch the cursor.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .max_blocking_threads(1)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let directory = tempfile::tempdir().unwrap();
            let lock_path = directory.path().join(".snapshot-lineage.lock");
            let lock = microsandbox_utils::process_lock::open_lock_file(&lock_path).unwrap();
            microsandbox_utils::process_lock::lock_exclusive(&lock).unwrap();
            let lineage = CaptureLineage {
                _lock: Arc::new(lock),
                path: directory.path().join("snapshot-lineage.json"),
                sandbox_id: 1,
                parent: None,
            };
            let (release, wait_release) = std::sync::mpsc::channel();
            let (started, wait_started) = tokio::sync::oneshot::channel();
            let blocker = tokio::task::spawn_blocking(move || {
                started.send(()).unwrap();
                wait_release.recv().unwrap();
            });
            wait_started.await.unwrap();
            let snapshot = id(4);
            let mut publication = Box::pin(lineage.commit(&snapshot));
            assert!(futures::poll!(&mut publication).is_pending());
            drop(publication);
            drop(lineage);
            let observer =
                microsandbox_utils::process_lock::open_existing_lock_file(&lock_path).unwrap();
            let retained =
                !microsandbox_utils::process_lock::try_lock_exclusive(&observer).unwrap();
            // Release before asserting so a failed test cannot strand its runtime worker.
            release.send(()).unwrap();
            blocker.await.unwrap();
            assert!(
                retained,
                "cancelled await released an in-flight cursor publication lock"
            );
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                while !microsandbox_utils::process_lock::try_lock_exclusive(&observer).unwrap() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            let cursor: Cursor = serde_json::from_slice(
                &std::fs::read(directory.path().join("snapshot-lineage.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(cursor.snapshot_id, snapshot.as_str());
        });
    }

    #[tokio::test]
    async fn restored_origin_advances_only_after_successful_publication() {
        let home = tempfile::tempdir().unwrap();
        let local = crate::test_support::local_backend_builder(home.path())
            .build()
            .await
            .unwrap();
        let origin = id(1);
        let captured = id(2);
        let source_id = source(&local, "worker", Some(&origin)).await;
        let failed = begin(&local, "worker").await.unwrap();
        assert_eq!(failed.sandbox_id(), source_id);
        assert_eq!(failed.parent.as_ref(), Some(&origin));
        drop(failed);
        let successful = begin(&local, "worker").await.unwrap();
        assert_eq!(successful.parent.as_ref(), Some(&origin));
        successful.commit(&captured).await.unwrap();
        drop(successful);
        assert_eq!(
            begin(&local, "worker").await.unwrap().parent,
            Some(captured)
        );
    }

    #[tokio::test]
    async fn replacement_waits_for_cursor_publication_and_gets_independent_ancestry() {
        let home = tempfile::tempdir().unwrap();
        let local = crate::test_support::local_backend_builder(home.path())
            .build()
            .await
            .unwrap();
        let original = source(&local, "worker", Some(&id(1))).await;
        let capture = begin(&local, "worker").await.unwrap();
        let run_dir = local.config().run_dir();
        let mut replacement = Box::pin(lock_source(&run_dir, "worker"));
        assert!(futures::poll!(&mut replacement).is_pending());

        // Publication may be delayed arbitrarily after the source check; removal still cannot
        // change the directory receiving this cursor while the capture owns its lineage pin.
        capture.commit(&id(2)).await.unwrap();
        assert!(futures::poll!(&mut replacement).is_pending());
        drop(capture);
        let replacement = replacement.await.unwrap();
        std::fs::remove_dir_all(local.sandboxes_dir().join("worker")).unwrap();
        sandbox::Entity::delete_by_id(original)
            .exec(local.db().await.unwrap().write())
            .await
            .unwrap();
        source(&local, "worker", Some(&id(3))).await;
        drop(replacement);

        let next = begin(&local, "worker").await.unwrap();
        assert_eq!(next.parent, Some(id(3)));
        assert!(
            !local
                .sandboxes_dir()
                .join("worker/snapshot-lineage.json")
                .exists()
        );
    }

    #[tokio::test]
    async fn same_named_sources_in_different_backends_keep_separate_ancestry() {
        let first_home = tempfile::tempdir().unwrap();
        let second_home = tempfile::tempdir().unwrap();
        let first = crate::test_support::local_backend_builder(first_home.path())
            .build()
            .await
            .unwrap();
        let second = crate::test_support::local_backend_builder(second_home.path())
            .build()
            .await
            .unwrap();
        source(&first, "worker", Some(&id(1))).await;
        source(&second, "worker", Some(&id(2))).await;
        let capture = begin(&first, "worker").await.unwrap();
        capture.commit(&id(3)).await.unwrap();
        drop(capture);
        assert_eq!(begin(&first, "worker").await.unwrap().parent, Some(id(3)));
        assert_eq!(begin(&second, "worker").await.unwrap().parent, Some(id(2)));
    }

    #[tokio::test]
    async fn cursor_from_a_different_source_incarnation_is_rejected() {
        let home = tempfile::tempdir().unwrap();
        let local = crate::test_support::local_backend_builder(home.path())
            .build()
            .await
            .unwrap();
        let source_id = source(&local, "worker", None).await;
        std::fs::write(
            local.sandboxes_dir().join("worker/snapshot-lineage.json"),
            serde_json::to_vec(&Cursor {
                sandbox_id: source_id + 1,
                snapshot_id: id(1).to_string(),
            })
            .unwrap(),
        )
        .unwrap();
        let error = begin(&local, "worker")
            .await
            .err()
            .expect("wrong incarnation must fail");
        assert!(error.to_string().contains("another sandbox instance"));
    }

    #[tokio::test]
    async fn completed_capture_accepts_status_changes_but_rejects_replacement() {
        let home = tempfile::tempdir().unwrap();
        let local = crate::test_support::local_backend_builder(home.path())
            .build()
            .await
            .unwrap();
        let original = source(&local, "worker", None).await;
        let lineage = begin(&local, "worker").await.unwrap();
        sandbox::Entity::update_many()
            .col_expr(
                sandbox::Column::Status,
                sea_orm::sea_query::Expr::value("Crashed"),
            )
            .filter(sandbox::Column::Id.eq(original))
            .exec(local.db().await.unwrap().write())
            .await
            .unwrap();
        lineage.validate_source(&local, "worker").await.unwrap();
        sandbox::Entity::delete_by_id(original)
            .exec(local.db().await.unwrap().write())
            .await
            .unwrap();
        assert!(lineage.validate_source(&local, "worker").await.is_err());
        let replacement = source(&local, "worker", None).await;
        assert_ne!(original, replacement);
        assert!(lineage.validate_source(&local, "worker").await.is_err());
    }
}
