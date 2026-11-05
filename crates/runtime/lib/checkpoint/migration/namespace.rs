//! Non-mutating authority checks for migration destinations and their existing namespace.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::path::{Component, Path, PathBuf};

use super::super::layout;
use super::io;
use super::types::MigrationBindings;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Execution retains Windows deny-delete handles across asynchronous catalog admission and
/// synchronous publication. Inspection uses share-all handles and retains none of them.
pub(super) struct Guard {
    _pins: Vec<File>,
    #[cfg(unix)]
    private_boundaries: Vec<PathBuf>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) fn acquire(
    runtime: &Path,
    bindings: &MigrationBindings,
    execution: bool,
) -> Result<Guard, String> {
    let sandbox = layout::host_root(runtime)?;
    if bindings.owned_disks.len() > 64 {
        return Err("host migration bindings exceed their bounds".into());
    }
    let mut parents = vec![sandbox.to_path_buf(), runtime.to_path_buf()];
    for name in [".storage-migration", "owned-disks"] {
        optional_parent(&sandbox.join(name), &mut parents)?;
    }
    if !bindings.owned_disks.is_empty() {
        parents.push(sandbox.join("owned-volumes"));
    }
    for disk in &bindings.owned_disks {
        let mut components = Path::new(&disk.id).components();
        if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
            return Err("owned disk has an invalid namespace identity".into());
        }
        parents.push(sandbox.join("owned-volumes").join(&disk.id));
        optional_parent(&sandbox.join("owned-disks").join(&disk.id), &mut parents)?;
    }

    acquire_parents(parents, execution, true)
}

pub(super) fn private_parent(path: &Path) -> Result<Guard, String> {
    let guard = acquire_parents(vec![path.to_owned()], true, true)?;
    io::verify_private_directory(path)?;
    Ok(guard)
}

/// Unix sticky system temp directories safely admit exclusive creation of a new owner-only
/// entry. Windows temp roots must also prevent deletion/replacement of existing children.
pub(super) fn temporary_parent(path: &Path) -> Result<Guard, String> {
    acquire_parents(vec![path.to_owned()], true, cfg!(windows))
}

/// Pin a regular image-cache object for the private recovery reader. This is a read-only
/// lookup in a host-selected cache; no filename obtained from a guest is opened by this API.
pub fn open_preview_cache_file(cache: &Path, relative: &Path) -> Result<File, String> {
    let mut parts = relative.components();
    let (Some(Component::Normal(role)), Some(Component::Normal(name)), None) =
        (parts.next(), parts.next(), parts.next())
    else {
        return Err("invalid recovery cache role".into());
    };
    let suffix = match role.to_str() {
        Some("fsmeta" | "layers") => ".erofs",
        Some("vmdk") => ".vmdk",
        _ => return Err("unknown recovery cache role".into()),
    };
    let valid = name
        .to_str()
        .and_then(|n| n.strip_prefix("sha256_"))
        .and_then(|n| n.strip_suffix(suffix))
        .is_some_and(|hash| {
            hash.len() == 64
                && hash
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        });
    if !valid {
        return Err("invalid digest-keyed recovery cache filename".into());
    }
    let parent = cache.join(role);
    let guard = acquire_parents(vec![cache.to_owned(), parent.clone()], true, true)?;
    let source = io::open(&io::directory(cache)?, relative)?;
    if io::identity(&source)?.links != 1 {
        return Err("recovery cache object has hardlink aliases".into());
    }
    #[cfg(unix)]
    let private = {
        let actual = fs::canonicalize(&parent).map_err(|error| failure(&parent, &error))?;
        guard
            .private_boundaries
            .iter()
            .any(|boundary| actual.starts_with(boundary))
    };
    #[cfg(not(unix))]
    let private = false;
    microsandbox_db::private_storage::verify_read_source_authority(&source, private)
        .map_err(|error| format!("cached recovery disk is not host controlled: {error}"))?;
    drop(guard);
    Ok(source)
}

fn acquire_parents(
    parents: Vec<PathBuf>,
    execution: bool,
    publication: bool,
) -> Result<Guard, String> {
    let mut paths = BTreeMap::<PathBuf, bool>::new();
    for parent in parents {
        let absolute = std::path::absolute(&parent).map_err(|error| failure(&parent, &error))?;
        add_ancestors(&mut paths, &absolute, publication)?;
    }
    // Preserve legacy spellings and normal system aliases (/tmp and /var on Mac). Check
    // actual target chains AND lexical alias owners/parents; canonicalizing only the final
    // destination would miss replacement of an alias later used by path-based I/O.
    let mut expanded = BTreeSet::new();
    loop {
        let pending = paths
            .iter()
            .filter(|(path, _)| !expanded.contains(*path))
            .map(|(path, publication)| (path.clone(), *publication))
            .collect::<Vec<_>>();
        if pending.is_empty() {
            break;
        }
        for (path, publication) in pending {
            let canonical = fs::canonicalize(&path).map_err(|error| failure(&path, &error))?;
            add_ancestors(&mut paths, &canonical, publication)?;
            expanded.insert(path);
        }
    }

    let mut pins = Vec::new();
    #[cfg(unix)]
    let mut private_boundaries = Vec::<PathBuf>::new();
    for (path, publication_parent) in paths {
        let metadata = fs::symlink_metadata(&path).map_err(|error| failure(&path, &error))?;
        #[cfg(unix)]
        if metadata.file_type().is_symlink() {
            // Parent authority is checked in this same inventory. On Mac a symlink's
            // own ACL can independently grant deletion or security changes, so ownership
            // and the containing directory's permissions alone are insufficient.
            if publication_parent {
                return Err(format!(
                    "migration destination namespace {} has an untrusted alias",
                    path.display()
                ));
            }
            microsandbox_db::private_storage::verify_symbolic_link_authority(&path)
                .map_err(|error| failure(&path, &error))?;
            continue;
        }
        io::reject_link(&metadata)?;
        let file = open_directory(&path, execution && publication_parent)?;
        #[cfg(unix)]
        let closed = private_boundaries
            .iter()
            .any(|boundary| path.starts_with(boundary));
        #[cfg(not(unix))]
        let closed = false;
        if closed {
            // Unix traversal through an owner-private ancestor excludes other accounts,
            // including when a safe descendant inherited umask 0002. This exemption must
            // never apply on Windows, whose usual tokens bypass ancestor traversal checks.
            verify_owner(&file).map_err(|error| failure(&path, &error))?;
        } else {
            microsandbox_db::private_storage::verify_directory_authority(&file, publication_parent)
                .map_err(|error| failure(&path, &error))?;
        }
        #[cfg(unix)]
        if microsandbox_db::private_storage::is_private_directory_boundary(&file)
            .map_err(|error| failure(&path, &error))?
        {
            // The helper checks the actual FD. On Mac, harmless deny/owner-only ACLs
            // remain private, but untrusted ACL grants prevent a mode0700 exemption.
            private_boundaries.push(path.clone());
        }
        #[cfg(windows)]
        if execution && publication_parent {
            pins.push(file);
        }
        #[cfg(not(windows))]
        let _ = (file, &mut pins);
    }
    Ok(Guard {
        _pins: pins,
        #[cfg(unix)]
        private_boundaries,
    })
}

fn optional_parent(path: &Path, parents: &mut Vec<PathBuf>) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(_) => parents.push(path.to_path_buf()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(failure(path, &error)),
    }
    Ok(())
}

fn add_ancestors(
    paths: &mut BTreeMap<PathBuf, bool>,
    path: &Path,
    publication_parent: bool,
) -> Result<(), String> {
    for ancestor in path.ancestors() {
        paths
            .entry(ancestor.to_path_buf())
            .and_modify(|publication| *publication |= publication_parent && ancestor == path)
            .or_insert(publication_parent && ancestor == path);
        if paths.len() > io::MAX_ENTRIES {
            return Err("migration destination namespace exceeds its metadata bound".into());
        }
    }
    Ok(())
}

#[cfg(unix)]
fn verify_owner(file: &File) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata()?;
    if metadata.is_dir() && [unsafe { libc::geteuid() }, 0].contains(&metadata.uid()) {
        Ok(())
    } else {
        Err(std::io::Error::other(
            "directory has an untrusted owner or file type",
        ))
    }
}

#[cfg(not(unix))]
fn verify_owner(_file: &File) -> std::io::Result<()> {
    unreachable!("private ancestor traversal exemption is Unix-only")
}

fn open_directory(path: &Path, deny_delete: bool) -> Result<File, String> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
            FILE_SHARE_READ, FILE_SHARE_WRITE,
        };
        let file = fs::OpenOptions::new()
            // Metadata-only handles do not enforce Windows share-delete exclusion.
            // Execution also requests FILE_LIST_DIRECTORY to activate that exclusion;
            // inspection remains metadata-only and fully shared, without listing anything.
            .access_mode(0x0002_0080 | u32::from(deny_delete))
            .share_mode(
                FILE_SHARE_READ
                    | FILE_SHARE_WRITE
                    | if deny_delete { 0 } else { FILE_SHARE_DELETE },
            )
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|error| failure(path, &error))?;
        io::reject_link(&file.metadata().map_err(|error| failure(path, &error))?)?;
        Ok(file)
    }
    #[cfg(not(windows))]
    {
        let _ = deny_delete;
        // Keep cap-primitives' metadata-only handle (O_PATH on Linux). No chmod/fsync is
        // needed, and searchable ancestors need not permit reading their directory entries.
        let file = if let (Some(parent), Some(name)) = (path.parent(), path.file_name()) {
            let parent =
                cap_primitives::fs::open_ambient_dir(parent, cap_primitives::ambient_authority())
                    .map_err(|error| failure(path, &error))?;
            cap_primitives::fs::open_dir_nofollow(&parent, Path::new(name))
        } else {
            cap_primitives::fs::open_ambient_dir(path, cap_primitives::ambient_authority())
        }
        .map_err(|error| failure(path, &error))?;
        io::reject_link(&file.metadata().map_err(|error| failure(path, &error))?)?;
        Ok(file)
    }
}

fn failure(path: &Path, error: &std::io::Error) -> String {
    format!(
        "migration destination namespace {} is not protected from other accounts: {error}; preserve the storage and secure its permissions before retrying",
        path.display()
    )
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (tempfile::TempDir, PathBuf, MigrationBindings) {
        // /tmp has no private user-profile ancestor on Unix. Refusal tests must exercise
        // an actually reachable publication parent rather than a safe private subtree.
        #[cfg(unix)]
        let temporary = tempfile::tempdir_in("/tmp").unwrap();
        #[cfg(not(unix))]
        let temporary = tempfile::tempdir().unwrap();
        let sandbox = temporary.path().canonicalize().unwrap();
        let runtime = sandbox.join("runtime");
        fs::create_dir(&runtime).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for path in [&sandbox, &runtime] {
                fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
            }
        }
        #[cfg(windows)]
        {
            super::super::io::harden_created(&sandbox, true).unwrap();
            super::super::io::harden_created(&runtime, true).unwrap();
        }
        let bindings = MigrationBindings {
            identity: "namespace-fixture".into(),
            config_revision: "config".into(),
            root: None,
            owned_disks: Vec::new(),
            aliases: Vec::new(),
        };
        (temporary, runtime, bindings)
    }

    #[cfg(unix)]
    #[test]
    fn ordinary_searchable_directories_and_private_umask_descendants_are_accepted() {
        use std::os::unix::fs::PermissionsExt;
        let (_temporary, runtime, bindings) = fixture();
        acquire(&runtime, &bindings, false).unwrap();
        acquire(&runtime, &bindings, true).unwrap();
        let sandbox = runtime.parent().unwrap();
        fs::set_permissions(sandbox, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o775)).unwrap();
        acquire(&runtime, &bindings, false).unwrap();
        acquire(&runtime, &bindings, true).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn reachable_writable_parent_is_refused_without_permission_repair() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let (_temporary, runtime, bindings) = fixture();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o777)).unwrap();
        let before = fs::metadata(&runtime).unwrap();
        for execution in [false, true] {
            let error = acquire(&runtime, &bindings, execution).err().unwrap();
            assert!(error.contains("destination namespace"), "{error}");
        }
        let after = fs::metadata(&runtime).unwrap();
        assert_eq!(before.mode(), after.mode());
        assert_eq!(
            (before.ctime(), before.ctime_nsec()),
            (after.ctime(), after.ctime_nsec())
        );
        assert_eq!(fs::read_dir(&runtime).unwrap().count(), 0);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn trusted_tmp_alias_does_not_rewrite_runtime_bindings() {
        let (temporary, runtime, bindings) = fixture();
        let lexical = Path::new("/tmp")
            .join(temporary.path().file_name().unwrap())
            .join("runtime");
        assert_eq!(lexical.canonicalize().unwrap(), runtime);
        acquire(&lexical, &bindings, false).unwrap();
        acquire(&lexical, &bindings, true).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn lexical_alias_mutation_acl_is_rejected_while_read_acl_remains_eligible() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        use std::process::Command;
        let (_temporary, runtime, bindings) = fixture();
        let root = runtime.parent().unwrap();
        let storage = root.join("storage");
        let real_runtime = storage.join("sbx/runtime");
        fs::create_dir_all(&real_runtime).unwrap();
        for path in [&storage, &storage.join("sbx"), &real_runtime] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let alias = root.join("alias");
        symlink(&storage, &alias).unwrap();
        let lexical_runtime = alias.join("sbx/runtime");
        assert!(
            Command::new("chmod")
                .args(["-h", "+a", "everyone allow read"])
                .arg(&alias)
                .output()
                .unwrap()
                .status
                .success()
        );
        acquire(&lexical_runtime, &bindings, false).unwrap();
        assert!(
            Command::new("chmod")
                .args(["-h", "+a", "everyone allow delete"])
                .arg(&alias)
                .output()
                .unwrap()
                .status
                .success()
        );
        let error = acquire(&lexical_runtime, &bindings, false).err().unwrap();
        assert!(error.contains("destination namespace"), "{error}");
        assert_eq!(fs::read_link(&alias).unwrap(), storage);
        assert_eq!(fs::read_dir(real_runtime).unwrap().count(), 0);
    }

    #[cfg(windows)]
    #[test]
    fn inspection_shares_deletion_but_execution_retains_namespace_guards() {
        let (_temporary, runtime, bindings) = fixture();
        let renamed = runtime.with_file_name("runtime-renamed");
        let inspected = acquire(&runtime, &bindings, false).unwrap();
        fs::rename(&runtime, &renamed).unwrap();
        fs::rename(&renamed, &runtime).unwrap();
        drop(inspected);
        let protected = acquire(&runtime, &bindings, true).unwrap();
        assert!(fs::rename(&runtime, &renamed).is_err());
        drop(protected);
        fs::rename(&runtime, &renamed).unwrap();
        fs::rename(&renamed, &runtime).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn private_ancestor_does_not_hide_writable_windows_publication_parent() {
        use std::process::Command;
        let (_temporary, runtime, bindings) = fixture();
        assert!(
            Command::new("icacls.exe")
                .arg(&runtime)
                .arg("/grant:r")
                .arg("*S-1-5-11:(DC,WD,AD)")
                .output()
                .unwrap()
                .status
                .success()
        );
        for execution in [false, true] {
            let error = acquire(&runtime, &bindings, execution).err().unwrap();
            assert!(error.contains("destination namespace"), "{error}");
        }
    }
}
