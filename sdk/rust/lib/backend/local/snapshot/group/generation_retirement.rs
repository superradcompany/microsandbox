//! Durable reclamation of unpublished and retired complete-group generations.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::super::{
    MAX_METADATA_BYTES, integrity, read_regular, require_directory, sync_directory, write_json,
};
use crate::MicrosandboxResult;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

pub(super) const DIRECTORY: &str = ".group-retirements";
const SCHEMA: &str = "microsandbox.group-retirement/1";
const PREPARATIONS_DIRECTORY: &str = ".group-preparations";
const PREPARATION_SCHEMA: &str = "microsandbox.group-preparation/1";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct Retirement {
    schema: String,
    name: PathBuf,
    device: u64,
    inode: u64,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Record the old directory's identity in the new view before either name changes.
/// The separate journal is intentional: old readers may recover/delete an old-format
/// `.snapshot-deletions` receipt, but must not erase this reclamation intent with it.
pub(super) fn stage(group: &Path, prepared: &Path) -> MicrosandboxResult<()> {
    stage_record(prepared, group, prepared, DIRECTORY, SCHEMA)
}

/// Keep preparation intent in the still-published group, before linking any payload.
/// This record is deliberately not copied into the prepared view: after exchange
/// the retirement record owns cleanup of the old view, including this intent.
pub(super) fn stage_preparation(group: &Path, prepared: &Path) -> MicrosandboxResult<()> {
    stage_record(
        group,
        prepared,
        prepared,
        PREPARATIONS_DIRECTORY,
        PREPARATION_SCHEMA,
    )
}

fn stage_record(
    owner: &Path,
    target: &Path,
    prepared: &Path,
    directory: &str,
    schema: &str,
) -> MicrosandboxResult<()> {
    let metadata = fs::symlink_metadata(target)?;
    require_directory(target)?;
    let name = prepared
        .file_name()
        .ok_or_else(|| integrity("generation has no name".into()))?;
    let root = owner.join(directory);
    fs::create_dir_all(&root)?;
    require_directory(&root)?;
    write_json(
        &root,
        &format!("{}.json", name.to_string_lossy()),
        &Retirement {
            schema: schema.into(),
            name: name.into(),
            device: metadata.dev(),
            inode: metadata.ino(),
        },
    )?;
    sync_directory(owner)?;
    Ok(())
}

/// The caller holds writer admission throughout this operation, including on cancellation.
pub(super) fn recover(group: &Path) -> MicrosandboxResult<()> {
    recover_records(group, PREPARATIONS_DIRECTORY, PREPARATION_SCHEMA)?;
    recover_records(group, DIRECTORY, SCHEMA)
}

fn recover_records(group: &Path, directory: &str, schema: &str) -> MicrosandboxResult<()> {
    let root = group.join(directory);
    match fs::symlink_metadata(&root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
        Ok(_) => require_directory(&root)?,
    }
    for entry in fs::read_dir(&root)? {
        let entry = entry?;
        if entry.path().extension().and_then(|value| value.to_str()) == Some("json") {
            finish_record(group, &entry.path(), schema)?;
        }
    }
    Ok(())
}

pub(super) fn finish(group: &Path, retired: &Path) -> MicrosandboxResult<()> {
    let name = retired
        .file_name()
        .ok_or_else(|| integrity("generation has no name".into()))?;
    finish_record(
        group,
        &group
            .join(DIRECTORY)
            .join(format!("{}.json", name.to_string_lossy())),
        SCHEMA,
    )
}

fn finish_record(group: &Path, record: &Path, schema: &str) -> MicrosandboxResult<()> {
    let kind = if schema == PREPARATION_SCHEMA {
        "unpublished"
    } else {
        "retired"
    };
    let retirement: Retirement =
        serde_json::from_slice(&read_regular(record, MAX_METADATA_BYTES)?)?;
    if retirement.schema != schema
        || retirement.name.components().count() != 1
        || !matches!(
            retirement.name.components().next(),
            Some(Component::Normal(_))
        )
        || !retirement
            .name
            .to_string_lossy()
            .starts_with(".group-generation-")
    {
        return Err(integrity(format!("invalid {kind} group generation record")));
    }
    let parent = group
        .parent()
        .ok_or_else(|| integrity("group has no parent".into()))?;
    let retired = parent.join(&retirement.name);
    // A crash can occur immediately after exchange, before either directory entry
    // is durable. Flush the published view for both kinds of cleanup so we cannot
    // reclaim a generation that the filesystem could still publish after reboot.
    sync_directory(group)?;
    sync_directory(parent)?;
    let published = fs::metadata(group)?;
    match fs::symlink_metadata(&retired) {
        Ok(metadata) => {
            // Even a well-shaped record must never authorize deleting the live
            // group itself, including through an aliased parent path.
            if !metadata.file_type().is_dir()
                || (metadata.dev(), metadata.ino()) != (retirement.device, retirement.inode)
                || (metadata.dev(), metadata.ino()) == (published.dev(), published.ino())
            {
                return Err(integrity(format!(
                    "{kind} group generation identity changed at {}; cleanup record retained",
                    retired.display()
                )));
            }
            fs::remove_dir_all(&retired)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    // Payload removal is durable before the intent disappears. A missing retired
    // directory on retry means cleanup reached this boundary, not a failed import.
    sync_directory(parent)?;
    fs::remove_file(record)?;
    sync_directory(record.parent().unwrap())?;
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::local::snapshot::writer::WriterLease;

    fn exchanged() -> (tempfile::TempDir, PathBuf, PathBuf, WriterLease) {
        let root = tempfile::tempdir().unwrap();
        let group = root.path().join("history");
        fs::create_dir(&group).unwrap();
        fs::write(group.join("payload"), b"retired bytes").unwrap();
        let retired = tempfile::Builder::new()
            .prefix(".group-generation-")
            .tempdir_in(root.path())
            .unwrap()
            .keep();
        let admission = WriterLease::try_acquire(&group).unwrap().unwrap();
        stage(&group, &retired).unwrap();
        super::super::exchange_names(&group, &retired).unwrap();
        (root, group, retired, admission)
    }

    fn preparing() -> (tempfile::TempDir, PathBuf, PathBuf, WriterLease) {
        let root = tempfile::tempdir().unwrap();
        let group = root.path().join("history");
        fs::create_dir(&group).unwrap();
        fs::write(group.join("payload"), b"published bytes").unwrap();
        let prepared = tempfile::Builder::new()
            .prefix(".group-generation-")
            .tempdir_in(root.path())
            .unwrap()
            .keep();
        let admission = WriterLease::try_acquire(&group).unwrap().unwrap();
        stage_preparation(&group, &prepared).unwrap();
        fs::hard_link(group.join("payload"), prepared.join("payload")).unwrap();
        (root, group, prepared, admission)
    }

    #[test]
    fn unpublished_links_are_reclaimed_without_touching_published_payloads() {
        let (_root, group, prepared, _admission) = preparing();
        assert_eq!(fs::metadata(group.join("payload")).unwrap().nlink(), 2);
        recover(&group).unwrap();
        recover(&group).unwrap();
        assert!(!prepared.exists());
        assert_eq!(fs::read(group.join("payload")).unwrap(), b"published bytes");
        assert_eq!(fs::metadata(group.join("payload")).unwrap().nlink(), 1);
        assert_eq!(
            fs::read_dir(group.join(PREPARATIONS_DIRECTORY))
                .unwrap()
                .count(),
            0
        );
    }

    #[test]
    fn preparation_receipt_survives_interruption_after_removing_private_links() {
        let (_root, group, prepared, _admission) = preparing();
        fs::remove_dir_all(prepared).unwrap();
        recover(&group).unwrap();
        recover(&group).unwrap();
        assert_eq!(fs::read(group.join("payload")).unwrap(), b"published bytes");
        assert_eq!(
            fs::read_dir(group.join(PREPARATIONS_DIRECTORY))
                .unwrap()
                .count(),
            0
        );
    }

    #[test]
    fn cleanup_record_cannot_select_the_published_group_itself() {
        let root = tempfile::tempdir().unwrap();
        let group = root.path().join(".group-generation-published");
        fs::create_dir(&group).unwrap();
        fs::write(group.join("payload"), b"keep").unwrap();
        let _admission = WriterLease::try_acquire(&group).unwrap().unwrap();
        stage_preparation(&group, &group).unwrap();
        assert!(
            recover(&group)
                .unwrap_err()
                .to_string()
                .contains("identity changed")
        );
        assert_eq!(fs::read(group.join("payload")).unwrap(), b"keep");
    }

    #[test]
    fn substituted_preparation_path_preserves_both_generations_and_receipt() {
        for symlink in [false, true] {
            let (root, group, prepared, _admission) = preparing();
            let original = root.path().join("original");
            fs::rename(&prepared, &original).unwrap();
            if symlink {
                std::os::unix::fs::symlink(&original, &prepared).unwrap();
            } else {
                fs::create_dir(&prepared).unwrap();
                fs::write(prepared.join("unrelated"), b"keep").unwrap();
            }
            assert!(
                recover(&group)
                    .unwrap_err()
                    .to_string()
                    .contains("identity changed")
            );
            assert_eq!(
                fs::read(original.join("payload")).unwrap(),
                b"published bytes"
            );
            assert_eq!(fs::read(group.join("payload")).unwrap(), b"published bytes");
            assert_eq!(
                fs::read_dir(group.join(PREPARATIONS_DIRECTORY))
                    .unwrap()
                    .count(),
                1
            );
            if !symlink {
                assert_eq!(fs::read(prepared.join("unrelated")).unwrap(), b"keep");
            }
        }
    }

    #[test]
    fn cleanup_is_recoverable_after_payload_removal_before_receipt_removal() {
        let (_root, group, retired, _admission) = exchanged();
        fs::remove_dir_all(&retired).unwrap();
        recover(&group).unwrap();
        recover(&group).unwrap();
        assert_eq!(fs::read_dir(group.join(DIRECTORY)).unwrap().count(), 0);
    }

    #[test]
    fn replacement_at_retired_name_is_never_deleted() {
        let (root, group, retired, _admission) = exchanged();
        let original = root.path().join("original");
        fs::rename(&retired, &original).unwrap();
        fs::create_dir(&retired).unwrap();
        fs::write(retired.join("unrelated"), b"keep").unwrap();
        let error = recover(&group).unwrap_err();
        assert!(error.to_string().contains("identity changed"));
        assert_eq!(fs::read(retired.join("unrelated")).unwrap(), b"keep");
        assert!(original.join("payload").exists());
        assert_eq!(fs::read_dir(group.join(DIRECTORY)).unwrap().count(), 1);
        fs::remove_dir_all(&retired).unwrap();
        fs::rename(&original, &retired).unwrap();
        recover(&group).unwrap();
        assert!(!retired.exists());
    }

    #[test]
    fn traversal_and_symlink_records_cannot_select_external_payload() {
        let (root, group, retired, _admission) = exchanged();
        let record = fs::read_dir(group.join(DIRECTORY))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let bytes = fs::read(&record).unwrap();
        let mut invalid: Retirement = serde_json::from_slice(&bytes).unwrap();
        invalid.name = PathBuf::from("../outside");
        fs::write(&record, serde_json::to_vec(&invalid).unwrap()).unwrap();
        assert!(
            recover(&group)
                .unwrap_err()
                .to_string()
                .contains("invalid retired")
        );
        assert!(retired.join("payload").exists());
        fs::write(&record, bytes).unwrap();
        let original = root.path().join("original");
        fs::rename(&retired, &original).unwrap();
        std::os::unix::fs::symlink(&original, &retired).unwrap();
        assert!(
            recover(&group)
                .unwrap_err()
                .to_string()
                .contains("identity changed")
        );
        assert_eq!(
            fs::read(original.join("payload")).unwrap(),
            b"retired bytes"
        );
    }
}
