//! Coherent group metadata selection, followed by observation of its saved source identity.

use std::path::Path;

use crate::MicrosandboxResult;
use crate::backend::LocalBackend;
use crate::snapshot::{SnapshotGroupInfo, SnapshotId};

use super::super::writer::WriterLease;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(in crate::backend::local::snapshot) async fn inspect(
    local: &LocalBackend,
    directory: &Path,
) -> MicrosandboxResult<SnapshotGroupInfo> {
    super::require_directory(directory)?;
    let directory = directory.canonicalize()?;
    let writer = WriterLease::acquire(&directory).await?;
    let (mut info, source) = super::blocking(move || {
        // Stable admission protects the directory across exchange/removal. Move ownership
        // into the worker so cancellation cannot expose a mixed head/membership read.
        let _writer = writer;
        let _lock = super::lock_group(&directory)?;
        let state = super::read_group(&directory)?;
        let members = super::read_members(&directory, true)?;
        super::validate_head(&state, &members)?;
        let source = super::read_source(&directory)?;
        let head = state
            .head
            .map(SnapshotId::new)
            .transpose()
            .map_err(|error| super::integrity(error.to_string()))?;
        let name = directory
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        Ok((
            SnapshotGroupInfo {
                name,
                path: directory,
                head,
                checkpoint_count: members.len() as u64,
                source: None,
            },
            source,
        ))
    })
    .await?;
    // The row may later stop, disappear or be renamed. This reports observed association
    // availability, not a promise that a future checkpoint operation will succeed.
    if let Some(source) = source {
        info.source = Some(source.inspect(local).await?);
    }
    Ok(info)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::tests::{add, id};
    use super::*;

    #[tokio::test]
    async fn inspection_reports_headless_and_populated_histories_without_mutation() {
        let home = tempfile::tempdir().unwrap();
        let local = crate::test_support::local_backend_builder(home.path())
            .build()
            .await
            .unwrap();
        let directory = super::super::ensure(&local.snapshots_dir(), Some("history"))
            .await
            .unwrap();
        let empty = inspect(&local, &directory).await.unwrap();
        assert_eq!(empty.name, "history");
        assert!(empty.head.is_none());
        assert!(empty.source.is_none());
        assert_eq!(empty.checkpoint_count, 0);
        add(&directory, 1, None).await;
        add(&directory, 2, Some(1)).await;
        let before = std::fs::read(directory.join(super::super::GROUP_FILENAME)).unwrap();
        let info = inspect(&local, &directory).await.unwrap();
        assert_eq!(info.head, Some(id(2)));
        assert_eq!(info.checkpoint_count, 2);
        assert_eq!(
            before,
            std::fs::read(directory.join(super::super::GROUP_FILENAME)).unwrap()
        );
        super::super::write_group(&directory, None).unwrap();
        let info = inspect(&local, &directory).await.unwrap();
        assert_eq!(info.checkpoint_count, 2);
        assert!(info.head.is_none());
        super::super::write_group(&directory, Some(id(999).to_string())).unwrap();
        assert!(inspect(&local, &directory).await.is_err());
    }

    #[tokio::test]
    async fn inspection_waits_for_publication_before_observing_head_and_members() {
        use super::super::tests::{descriptor, stage};
        use std::time::Duration;

        let home = tempfile::tempdir().unwrap();
        let local = crate::test_support::local_backend_builder(home.path())
            .build()
            .await
            .unwrap();
        let directory = super::super::ensure(&local.snapshots_dir(), Some("history"))
            .await
            .unwrap();
        add(&directory, 1, None).await;
        let staged = stage(directory.parent().unwrap(), &[descriptor(2, Some(1))]);
        let admission = WriterLease::acquire(&directory).await.unwrap();
        // Model an in-flight writer's temporary metadata inconsistency. Inspection must
        // neither report that transient error nor combine the new head with the old count.
        super::super::write_group(&directory, Some(id(2).to_string())).unwrap();
        let mut pending = Box::pin(inspect(&local, &directory));
        assert!(
            tokio::time::timeout(Duration::from_millis(30), pending.as_mut())
                .await
                .is_err()
        );
        std::fs::rename(
            staged.path().join(id(2).as_str()),
            directory.join(id(2).as_str()),
        )
        .unwrap();
        drop(admission);
        let info = tokio::time::timeout(Duration::from_secs(2), pending)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(info.head, Some(id(2)));
        assert_eq!(info.checkpoint_count, 2);
    }
}
