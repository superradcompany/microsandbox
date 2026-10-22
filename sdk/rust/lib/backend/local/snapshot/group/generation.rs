//! Complete-directory publication for atomic group changes on macOS and Linux.
//!
//! Immutable files and reader locks keep their inode identity. Only a complete private
//! generation becomes visible; the catalog journal travels with that generation.

#[path = "generation_retirement.rs"]
mod retirement;

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io;
use std::path::Path;
use std::sync::atomic::Ordering;

use microsandbox_image::storage_lease;

use crate::{MicrosandboxError, SnapshotImportOutcome};

use super::super::metadata::METADATA_FILENAME;
use super::{
    MEMBER_FILENAME, MicrosandboxResult, integrity, read_members, require_directory,
    sync_directory, write_group, write_member_name,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A private complete view. Dropping it removes links, never the source payloads.
struct Generation {
    directory: tempfile::TempDir,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Generation {
    /// The caller must retain group ownership and source reader pins while staging.
    fn prepare(
        group: &Path,
        incoming: &Path,
        aliases: &BTreeMap<String, String>,
        head: Option<String>,
    ) -> MicrosandboxResult<Self> {
        require_directory(group)?;
        require_directory(incoming)?;
        let mut members = read_members(group, true)?;
        for (id, member) in read_members(incoming, false)? {
            if let Some(existing) = members.get(&id) {
                if existing.digest != member.digest {
                    return Err(integrity(format!("conflicting descriptor for {id}")));
                }
            } else {
                members.insert(id, member);
            }
        }
        super::apply_aliases(&mut members, aliases)?;
        Self::prepare_members(group, members, head)
    }

    /// Build one complete view from the chosen membership, preserving immutable payload
    /// and lease identity for surviving readers. The caller owns group writer admission.
    fn prepare_members(
        group: &Path,
        members: BTreeMap<String, super::Member>,
        head: Option<String>,
    ) -> MicrosandboxResult<Self> {
        let root = group
            .parent()
            .ok_or_else(|| integrity("group has no parent".into()))?;
        super::validate_ancestry(&members)?;
        if let Some(head) = &head
            && !members.contains_key(head)
        {
            return Err(integrity("staged head is not a member".into()));
        }
        // Retry cleanup before another exchange can retire its published records.
        // Writer admission excludes a live preparation for this group.
        retirement::recover(group)?;
        let directory = tempfile::Builder::new()
            .prefix(".group-generation-")
            .tempdir_in(root)?;
        retirement::stage_preparation(group, directory.path())?;
        // Seed every published member's namespace before copying the lock directory.
        // An older reader may first acquire its namespace lease after preparation;
        // that lease must refer to the same file in both directory generations.
        for id in members.keys() {
            // Writer admission protects membership during staging. These leases
            // only seed stable lock files; retaining every descriptor would make
            // removing one checkpoint require an fd for the entire history.
            drop(storage_lease::StorageLease::shared(&group.join(id))?);
        }
        for (id, member) in members {
            let destination = directory.path().join(id);
            link_tree(&member.path, &destination)?;
            write_member_name(&destination, member.name.as_deref())?;
            sync_directory(&destination)?;
            #[cfg(test)]
            {
                publication_boundary(group, "linking");
                super::removal::publication_boundary(group, "linking");
            }
        }
        // Mutable metadata has a distinct inode; truncating the staged copy must never
        // change the published generation. The group lock instead MUST keep its identity.
        write_group(directory.path(), head)?;
        let source = group.join(super::super::source::SOURCE_FILENAME);
        if source.try_exists()? {
            // Binding is immutable local metadata, not an archive dependency. Preserve
            // it across publication without ever importing another host's association.
            if !fs::symlink_metadata(&source)?.is_file() {
                return Err(integrity(
                    "group source metadata is not a regular file".into(),
                ));
            }
            fs::hard_link(
                source,
                directory.path().join(super::super::source::SOURCE_FILENAME),
            )?;
        }
        fs::hard_link(
            group.join(".group.lock"),
            directory.path().join(".group.lock"),
        )?;
        if group.join(".msb-leases").exists() {
            link_tree(
                &group.join(".msb-leases"),
                &directory.path().join(".msb-leases"),
            )?;
        }
        // An interrupted deletion may still own a catalog row. Its journal is
        // part of the recoverable group state, even though it is not a member.
        // Writer admission excludes cleanup while these paths are copied, and
        // hard-linking its locks preserves ownership across the exchange.
        if group.join(".snapshot-deletions").exists() {
            link_tree(
                &group.join(".snapshot-deletions"),
                &directory.path().join(".snapshot-deletions"),
            )?;
        }
        if group.join(retirement::DIRECTORY).exists() {
            link_tree(
                &group.join(retirement::DIRECTORY),
                &directory.path().join(retirement::DIRECTORY),
            )?;
        }
        retirement::stage(group, directory.path())?;
        sync_directory(directory.path())?;
        Ok(Self { directory })
    }

    fn path(&self) -> &Path {
        self.directory.path()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Recover only generations named by published, identity-checked cleanup journals.
/// Caller retains group writer admission through this blocking operation.
pub(super) fn recover_retired(group: &Path) -> MicrosandboxResult<()> {
    retirement::recover(group)
}

/// Probe the destination filesystem with disposable files before archive unpacking. A
/// missing destination uses its nearest existing parent; publication rechecks its parent.
pub(super) fn check(root: &Path) -> MicrosandboxResult<()> {
    check_with(root, |from, to| fs::hard_link(from, to), exchange)
}

fn check_with(
    root: &Path,
    link: impl FnOnce(&Path, &Path) -> io::Result<()>,
    swap: impl FnOnce(&Path, &Path) -> io::Result<()>,
) -> MicrosandboxResult<()> {
    let probe = || -> io::Result<()> {
        let absolute = std::path::absolute(root)?;
        let mut existing = absolute.as_path();
        while !existing.try_exists()? {
            existing = existing.parent().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "destination has no existing parent",
                )
            })?;
        }
        let directory = tempfile::Builder::new()
            .prefix(".msb-import-probe-")
            .tempdir_in(existing)?;
        let left = directory.path().join("left");
        let right = directory.path().join("right");
        fs::create_dir(&left)?;
        fs::create_dir(&right)?;
        fs::write(left.join("payload"), b"probe")?;
        link(&left.join("payload"), &right.join("linked"))?;
        swap(&left, &right)?;
        if !storage_lease::same_file(&left.join("linked"), &right.join("payload"))? {
            return Err(io::Error::other(
                "filesystem did not preserve the linked file across directory exchange",
            ));
        }
        Ok(())
    };
    probe().map_err(|error| MicrosandboxError::InvalidConfig(format!(
        "atomic snapshot import is unavailable at {}: hard links, atomic directory exchange, and directory durability are required ({error}); choose a filesystem supporting these operations; no group members or head were changed",
        root.display()
    )))
}

pub(super) fn publish(
    group: &Path,
    input: &Path,
    incoming: &BTreeMap<String, super::Member>,
    aliases: &BTreeMap<String, String>,
    head: Option<String>,
    operation: &super::IndexedPublication,
) -> MicrosandboxResult<Vec<String>> {
    publish_with_flush(
        group,
        input,
        incoming,
        aliases,
        head,
        operation,
        sync_directory,
    )
}

fn publish_with_flush(
    group: &Path,
    input: &Path,
    incoming: &BTreeMap<String, super::Member>,
    aliases: &BTreeMap<String, String>,
    head: Option<String>,
    operation: &super::IndexedPublication,
    flush: impl FnOnce(&Path) -> io::Result<()>,
) -> MicrosandboxResult<Vec<String>> {
    let parent = group
        .parent()
        .ok_or_else(|| integrity("group has no parent".into()))?;
    check(parent)?;
    let prepared = Generation::prepare(group, input, aliases, head)?;
    super::transaction::stage_generation_index(prepared.path(), incoming, operation)?;
    // Persist both names before the atomic swap. On interruption, either complete
    // generation is recoverable; no old reader needs to understand our journal.
    sync_directory(parent)?;
    #[cfg(test)]
    publication_boundary(group, "prepared");
    exchange_names(group, prepared.path())?;
    operation
        .outcome
        .store(SnapshotImportOutcome::Unknown as u8, Ordering::Release);
    // After the syscall this path owns the OLD generation. Do not let TempDir erase
    // it if the durability flush fails: the outcome is uncertain across a host crash.
    let retired = prepared.directory.keep();
    #[cfg(test)]
    publication_boundary(group, "exchanged");
    flush(parent).map_err(|error| integrity(format!(
        "snapshot batch {} was exchanged but durability is unconfirmed: {error}; previous generation retained at {}; recover through the same group before retrying",
        operation.operation, retired.display()
    )))?;
    operation
        .outcome
        .store(SnapshotImportOutcome::Committed as u8, Ordering::Release);
    #[cfg(test)]
    publication_boundary(group, "committed");
    // Cleanup failure cannot undo a published batch. The old generation contains
    // only extra links; removing them cannot invalidate live reader descriptors.
    if let Err(error) = retirement::finish(group, &retired) {
        let warning = format!(
            "snapshot batch committed; retired generation cleanup remains at {}: {error}",
            retired.display()
        );
        tracing::warn!(%warning);
        return Ok(vec![warning]);
    }
    Ok(Vec::new())
}

/// No payload-copy fallback: a hard-link error leaves the published generation intact.
/// Remove one member and select its replacement head as one complete publication.
/// The deletion receipt is part of the new view, so catalog recovery cannot mistake a
/// prepared-but-unpublished removal for a committed one.
pub(super) fn remove(
    group: &Path,
    id: &str,
    head: Option<String>,
) -> MicrosandboxResult<Vec<String>> {
    remove_with_flush(group, id, head, sync_directory)
}

fn remove_with_flush(
    group: &Path,
    id: &str,
    head: Option<String>,
    flush: impl FnOnce(&Path) -> io::Result<()>,
) -> MicrosandboxResult<Vec<String>> {
    let parent = group
        .parent()
        .ok_or_else(|| integrity("group has no parent".into()))?;
    check(parent).map_err(|error| {
        MicrosandboxError::InvalidConfig(
            error
                .to_string()
                .replace("atomic snapshot import", "atomic checkpoint removal"),
        )
    })?;
    let mut members = read_members(group, true)?;
    if members.remove(id).is_none() {
        return Err(MicrosandboxError::SnapshotNotFound(id.into()));
    }
    let prepared = Generation::prepare_members(group, members, head)?;
    let (_receipt, _receipt_lock) =
        super::super::deletion::prepare_retirement(prepared.path(), std::ffi::OsStr::new(id))?;
    sync_directory(prepared.path())?;
    sync_directory(parent)?;
    #[cfg(test)]
    super::removal::publication_boundary(group, "prepared");
    exchange_names(group, prepared.path())?;
    // The old generation is recovery evidence until the containing name is durable.
    // Never let TempDir silently erase it after an uncertain post-exchange failure.
    let retired = prepared.directory.keep();
    #[cfg(test)]
    super::removal::publication_boundary(group, "exchanged");
    flush(parent).map_err(|error| integrity(format!(
        "checkpoint removal was exchanged but durability is unconfirmed: {error}; previous generation retained at {}; recover the group before retrying",
        retired.display()
    )))?;
    #[cfg(test)]
    super::removal::publication_boundary(group, "committed");
    if let Err(error) = retirement::finish(group, &retired) {
        return Ok(vec![format!(
            "checkpoint removal committed; retired generation cleanup remains at {}: {error}",
            retired.display()
        )]);
    }
    Ok(Vec::new())
}

fn link_tree(source: &Path, destination: &Path) -> MicrosandboxResult<()> {
    require_directory(source)?;
    fs::create_dir(destination)?;
    let source_root = source.to_path_buf();
    let mut pending = vec![(source.to_path_buf(), destination.to_path_buf())];
    let mut directories = Vec::new();
    while let Some((source, destination)) = pending.pop() {
        directories.push(destination.clone());
        for entry in fs::read_dir(&source)? {
            let entry = entry?;
            let target = destination.join(entry.file_name());
            let kind = entry.file_type()?;
            if kind.is_dir() {
                fs::create_dir(&target)?;
                pending.push((entry.path(), target));
            } else if kind.is_file() {
                // Only artifact-root sidecars are mutable. Payloads with these names in
                // nested directories must retain their original identity as well.
                if source == source_root
                    && matches!(
                        entry.file_name().to_str(),
                        Some(MEMBER_FILENAME | METADATA_FILENAME)
                    )
                {
                    // Bound metadata copies to the established largest sidecar limit.
                    if entry.metadata()?.len() > 1024 * 1024 {
                        return Err(integrity("staged metadata exceeds its size limit".into()));
                    }
                    fs::copy(entry.path(), &target)?;
                    OpenOptions::new().write(true).open(&target)?.sync_all()?;
                } else {
                    fs::hard_link(entry.path(), target)?;
                }
            } else {
                return Err(integrity(format!(
                    "staging requires regular files and directories: {}",
                    entry.path().display()
                )));
            }
        }
    }
    // Persist children before their containing directories. Shared payload bytes were
    // already made durable by capture/import; no payload read or rewrite is needed here.
    for directory in directories.iter().rev() {
        sync_directory(directory)?;
    }
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn exchange(left: &Path, right: &Path) -> std::io::Result<()> {
    exchange_names(left, right)?;
    sync_directory(left.parent().expect("qualified group parent"))
}

fn exchange_names(left: &Path, right: &Path) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let left_name = CString::new(left.as_os_str().as_bytes())?;
    let right_name = CString::new(right.as_os_str().as_bytes())?;
    // SAFETY: both C strings remain valid for the duration of the synchronous syscall.
    #[cfg(target_os = "macos")]
    let result =
        unsafe { libc::renamex_np(left_name.as_ptr(), right_name.as_ptr(), libc::RENAME_SWAP) };
    #[cfg(target_os = "linux")]
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            left_name.as_ptr(),
            libc::AT_FDCWD,
            right_name.as_ptr(),
            libc::RENAME_EXCHANGE,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
fn publish_new(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let source_name = CString::new(source.as_os_str().as_bytes())?;
    let destination_name = CString::new(destination.as_os_str().as_bytes())?;
    // Refuse collisions in the syscall itself. An existence check followed by ordinary
    // rename could replace a concurrently created empty directory on Unix.
    #[cfg(target_os = "macos")]
    let result = unsafe {
        libc::renamex_np(
            source_name.as_ptr(),
            destination_name.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    #[cfg(target_os = "linux")]
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            source_name.as_ptr(),
            libc::AT_FDCWD,
            destination_name.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }
    sync_directory(destination.parent().expect("qualified group parent"))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
fn publication_boundary(group: &Path, boundary: &str) {
    use std::io::Write;
    if std::env::var_os("MSB_TEST_ATOMIC_GROUP").as_deref() == Some(group.as_os_str())
        && std::env::var("MSB_TEST_ATOMIC_BOUNDARY").as_deref() == Ok(boundary)
    {
        println!("ATOMIC_IMPORT_BOUNDARY_READY");
        std::io::stdout().flush().unwrap();
        loop {
            std::thread::park();
        }
    }
}

#[cfg(test)]
#[path = "generation_tests.rs"]
mod tests;
