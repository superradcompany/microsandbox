//! Recovery intent outside a group that is atomically removed from its live name.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::path::{Path, PathBuf};

use microsandbox_utils::process_lock;
use serde::{Deserialize, Serialize};

use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const ROOT: &str = ".snapshot-group-deletions";
const SCHEMA: &str = "microsandbox.group-deletion/1";
// Records contain metadata only. Bound hostile/corrupt input without limiting payload sizes.
const MAX_RECORD_BYTES: usize = 64 * 1024 * 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectoryIdentity {
    volume: u64,
    file: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: String,
    group: String,
    identity: DirectoryIdentity,
    // Exact path-relative IDs and descriptor digests, never arbitrary deletion paths.
    members: BTreeMap<String, String>,
}

/// The active lock spans publication, catalog completion and cleanup. Dropping it retains
/// the intent for recovery; it must never implicitly erase evidence after a partial failure.
pub(super) struct Retirement {
    directory: PathBuf,
    parent: PathBuf,
    record: Record,
    _active: File,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Retirement {
    /// Caller owns group writer admission and every selected member's deletion lease.
    pub(super) fn prepare(group: &Path) -> MicrosandboxResult<Self> {
        super::require_directory(group)?;
        let group = group.canonicalize()?;
        let parent = group
            .parent()
            .ok_or_else(|| super::integrity("group has no parent".into()))?
            .to_path_buf();
        let name = group
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| super::integrity("group name is not UTF-8".into()))?;
        super::validate_group_name(name)?;
        let members = super::read_members(&group, true)?
            .into_iter()
            .map(|(id, member)| (id, member.digest))
            .collect();
        let record = Record {
            schema: SCHEMA.into(),
            group: name.into(),
            identity: identity(&group)?,
            members,
        };
        if serde_json::to_vec(&record)?.len() > MAX_RECORD_BYTES {
            return Err(super::integrity(
                "group deletion metadata exceeds the recoverable record bound".into(),
            ));
        }
        let root = parent.join(ROOT);
        fs::create_dir_all(&root)?;
        super::require_directory(&root)?;
        let coordination = process_lock::open_lock_file(&root.join(".lock"))?;
        process_lock::lock_exclusive(&coordination)?;
        let directory = root.join(format!("delete-{:032x}", rand::random::<u128>()));
        fs::create_dir(&directory)?;
        let active = process_lock::open_lock_file(&directory.join("active.lock"))?;
        process_lock::lock_exclusive(&active)?;
        super::write_json(&directory, "source.json", &record)?;
        super::sync_directory(&directory)?;
        super::sync_directory(&root)?;
        // The journal's parent entry must be durable before the source moves into it.
        super::sync_directory(&parent)?;
        drop(coordination);
        Ok(Self {
            directory,
            parent,
            record,
            _active: active,
        })
    }

    pub(super) fn source(&self) -> PathBuf {
        self.parent.join(&self.record.group)
    }

    pub(super) fn members(&self) -> &BTreeMap<String, String> {
        &self.record.members
    }

    /// Rename the whole directory, so readers see its old complete name or absence.
    /// A failed durability barrier is explicitly uncertain and leaves the intent intact.
    pub(super) fn publish(&self) -> MicrosandboxResult<()> {
        let source = self.source();
        if identity(&source)? != self.record.identity {
            return Err(super::integrity(
                "group identity changed before retirement".into(),
            ));
        }
        #[cfg(test)]
        super::removal::publication_boundary(&source, "group-prepared");
        #[cfg(windows)]
        {
            super::txf::check(&source)?;
            let mut transaction = super::txf::Transaction::new()?;
            transaction.rename(&source, &self.directory.join("payload"), false)?;
            transaction.commit().map_err(|error| super::integrity(format!(
                "whole-group removal commit is unconfirmed: {error}; recovery record retained at {}", self.directory.display()
            )))?;
        }
        #[cfg(not(windows))]
        fs::rename(&source, self.directory.join("payload"))?;
        #[cfg(test)]
        super::removal::publication_boundary(&source, "group-renamed");
        if let Err(error) = self.confirm() {
            return Err(super::integrity(format!(
                "whole-group removal durability is unconfirmed: {error}; recovery record retained at {}; recover before retrying",
                self.directory.display()
            )));
        }
        #[cfg(test)]
        super::removal::publication_boundary(&source, "group-committed");
        Ok(())
    }

    /// Also called before recovery releases catalog/image roots for a missing live group.
    pub(super) fn confirm(&self) -> MicrosandboxResult<()> {
        super::sync_directory(&self.parent)?;
        super::sync_directory(&self.directory)?;
        Ok(())
    }

    pub(super) fn validate_payload(&self) -> MicrosandboxResult<()> {
        let payload = self.directory.join("payload");
        match fs::symlink_metadata(&payload) {
            Ok(_) if identity(&payload)? != self.record.identity => Err(super::integrity(
                "retired group directory was replaced; recovery retained".into(),
            )),
            Ok(_) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    /// Run only after catalog reconciliation. Never touch the possibly recreated live name.
    pub(super) fn finish(self) -> MicrosandboxResult<()> {
        self.confirm()?;
        let payload = self.directory.join("payload");
        match fs::symlink_metadata(&payload) {
            Ok(_) => {
                if identity(&payload)? != self.record.identity {
                    return Err(super::integrity(format!(
                        "retired group identity changed at {}; recovery record retained",
                        payload.display()
                    )));
                }
                fs::remove_dir_all(&payload)?;
                super::sync_directory(&self.directory)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        // Namespace coordination prevents another recovery opening a replacement lock
        // between closing this Windows handle and removing the completed journal.
        let root = self.directory.parent().unwrap();
        let coordination = process_lock::open_lock_file(&root.join(".lock"))?;
        process_lock::lock_exclusive(&coordination)?;
        drop(self._active);
        fs::remove_dir_all(&self.directory)?;
        super::sync_directory(root)?;
        drop(coordination);
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Discover complete records with nonblocking ownership. A live publisher is never recovered.
pub(super) fn pending(parent: &Path) -> MicrosandboxResult<Vec<Retirement>> {
    let root = parent.join(ROOT);
    match fs::symlink_metadata(&root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
        Ok(_) => super::require_directory(&root)?,
    }
    let coordination = process_lock::open_lock_file(&root.join(".lock"))?;
    process_lock::lock_exclusive(&coordination)?;
    let mut records = Vec::new();
    for entry in fs::read_dir(&root)? {
        let entry = entry?;
        if !entry.file_name().to_string_lossy().starts_with("delete-") {
            continue;
        }
        let directory = entry.path();
        super::require_directory(&directory)?;
        let active = process_lock::open_lock_file(&directory.join("active.lock"))?;
        if !process_lock::try_lock_exclusive(&active)? {
            continue;
        }
        let bytes = match super::read_regular(&directory.join("source.json"), MAX_RECORD_BYTES) {
            Ok(bytes) => bytes,
            Err(MicrosandboxError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                match directory.join("payload").symlink_metadata() {
                    Ok(_) => {
                        return Err(super::integrity(
                            "retired group has no recovery identity; payload retained".into(),
                        ));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
                drop(active);
                fs::remove_dir_all(&directory)?;
                super::sync_directory(&root)?;
                continue;
            }
            Err(error) => return Err(error),
        };
        let record: Record = serde_json::from_slice(&bytes)?;
        if record.schema != SCHEMA {
            return Err(super::integrity("unsupported group deletion record".into()));
        }
        super::validate_group_name(&record.group)?;
        for (id, digest) in &record.members {
            super::SnapshotId::new(id).map_err(|error| super::integrity(error.to_string()))?;
            if digest.is_empty() {
                return Err(super::integrity("empty retired checkpoint digest".into()));
            }
        }
        records.push(Retirement {
            directory,
            parent: parent.canonicalize()?,
            record,
            _active: active,
        });
    }
    Ok(records)
}

fn identity(path: &Path) -> MicrosandboxResult<DirectoryIdentity> {
    super::require_directory(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::symlink_metadata(path)?;
        Ok(DirectoryIdentity {
            volume: metadata.dev(),
            file: metadata.ino(),
        })
    }
    #[cfg(windows)]
    {
        use std::os::windows::{fs::OpenOptionsExt, io::AsRawHandle};
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, FILE_FLAG_BACKUP_SEMANTICS, GetFileInformationByHandle,
        };
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)?;
        let mut info = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), info.as_mut_ptr()) } == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let info = unsafe { info.assume_init() };
        Ok(DirectoryIdentity {
            volume: info.dwVolumeSerialNumber as u64,
            file: ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64,
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // These tests model owners that have exited and closed every descriptor.
    // Sibling fork/exec tests must not extend the active.lock lifetime beyond drop.
    fn isolated(test: &str) -> bool {
        const CHILD: &str = "MSB_TEST_RETIREMENT_CHILD";
        if std::env::var(CHILD).as_deref() == Ok(test) {
            return false;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(format!(
                "backend::local::snapshot::group::retirement::tests::{test}"
            ))
            .arg("--nocapture")
            .env(CHILD, test)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
        true
    }

    fn group(root: &Path) -> PathBuf {
        let group = root.join("history");
        fs::create_dir(&group).unwrap();
        super::super::write_group(&group, None).unwrap();
        group
    }

    #[test]
    fn active_retirement_is_not_recovered_and_recreated_group_is_untouched() {
        if isolated("active_retirement_is_not_recovered_and_recreated_group_is_untouched") {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let source = group(root.path());
        let retirement = Retirement::prepare(&source).unwrap();
        assert!(pending(root.path()).unwrap().is_empty());
        retirement.publish().unwrap();
        group(root.path());
        fs::write(source.join("new-content"), b"keep").unwrap();
        drop(retirement);
        let recovered = pending(root.path()).unwrap();
        assert_eq!(recovered.len(), 1);
        for record in recovered {
            record.finish().unwrap();
        }
        assert_eq!(fs::read(source.join("new-content")).unwrap(), b"keep");
        assert!(pending(root.path()).unwrap().is_empty());
    }

    #[test]
    fn interrupted_preparation_preserves_the_live_group() {
        if isolated("interrupted_preparation_preserves_the_live_group") {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let source = group(root.path());
        drop(Retirement::prepare(&source).unwrap());
        let records = pending(root.path()).unwrap();
        assert_eq!(records.len(), 1, "released preparation must be recoverable");
        for record in records {
            record.finish().unwrap();
        }
        assert!(source.join(super::super::GROUP_FILENAME).exists());
        assert!(pending(root.path()).unwrap().is_empty());
    }

    #[test]
    fn replaced_quarantine_directory_is_never_removed() {
        if isolated("replaced_quarantine_directory_is_never_removed") {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let source = group(root.path());
        let retirement = Retirement::prepare(&source).unwrap();
        retirement.publish().unwrap();
        let payload = retirement.directory.join("payload");
        fs::rename(&payload, retirement.directory.join("original")).unwrap();
        fs::create_dir(&payload).unwrap();
        fs::write(payload.join("unrelated"), b"keep").unwrap();
        assert!(retirement.finish().is_err());
        assert_eq!(fs::read(payload.join("unrelated")).unwrap(), b"keep");
        assert_eq!(pending(root.path()).unwrap().len(), 1);
    }
}
