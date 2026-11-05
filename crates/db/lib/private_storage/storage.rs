#[cfg(unix)]
use std::ffi::CString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::fs::OpenOptions;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Permissions for the catalog's private directory.
#[cfg(unix)]
pub const PRIVATE_DATABASE_DIRECTORY_MODE: u32 = 0o700;
/// Permissions for new catalogs and copies containing catalog data.
#[cfg(unix)]
pub const PRIVATE_DATABASE_FILE_MODE: u32 = 0o600;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Protect only this owned directory and known legacy catalog files, never shared ancestors.
/// Configured parent aliases (including macOS `/tmp`) are resolved before retaining the path.
pub fn ensure_private_database_directory(path: &Path) -> io::Result<()> {
    let directory = private_directory(path, true)?;
    repair_legacy_files(&directory)
}

/// Prepare storage before SQLite sees it. New files are exclusive and private while still empty.
/// Readers do not create a missing catalog; secure read-only files are inspected without chmod.
pub fn prepare_database_file(path: &Path, create: bool) -> io::Result<PathBuf> {
    let directory = private_directory(parent(path), create)?;
    repair_legacy_files(&directory)?;
    let name = path
        .file_name()
        .ok_or_else(|| invalid("catalog has no filename"))?;
    let path = directory.join(name);
    if create && !path.try_exists()? {
        // Close the empty inode before publishing its catalog name. A simultaneous
        // opener must never acquire SQLite locks before we close this descriptor.
        let file = tempfile::Builder::new()
            .prefix(".msb-db-new-")
            .tempfile_in(&directory)?;
        harden_file(file.path())?;
        match file.into_temp_path().persist_noclobber(&path) {
            Ok(_) => {}
            Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.error),
        }
    }
    harden_file(&path)?;
    harden_sidecars(&path)?;
    Ok(path)
}

/// Validate and, when necessary, repair an existing catalog and its journals.
pub fn harden_database_files(path: &Path) -> io::Result<()> {
    let directory = private_directory(parent(path), false)?;
    let name = path
        .file_name()
        .ok_or_else(|| invalid("catalog has no filename"))?;
    let path = directory.join(name);
    harden_file(&path)?;
    harden_sidecars(&path)
}

fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

fn private_directory(path: &Path, create: bool) -> io::Result<PathBuf> {
    if create {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        builder.mode(PRIVATE_DATABASE_DIRECTORY_MODE);
        builder.create(path)?;
    }
    // Resolve configured ancestors, but reject a symlink in the owned directory entry itself.
    // Creating empty directories above is harmless; no secret or permission mutation occurs
    // until ownership and ancestor substitution checks have succeeded.
    let absolute = std::path::absolute(path)?;
    let resolved_parent = fs::canonicalize(parent(&absolute))?;
    let name = absolute
        .file_name()
        .ok_or_else(|| invalid("catalog directory must not be a filesystem root"))?;
    let resolved = resolved_parent.join(name);
    #[cfg(unix)]
    {
        verify_ancestors(&resolved_parent)?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&resolved)?;
        let metadata = directory.metadata()?;
        require_owner(&metadata, &resolved)?;
        #[cfg(target_os = "macos")]
        super::macos_acl::clear_directory(&directory).map_err(|e| repair_error(&resolved, e))?;
        // Do not require mutation on secure read-only storage. 0500 is also private.
        if metadata.mode() & 0o077 != 0 {
            directory
                .set_permissions(fs::Permissions::from_mode(PRIVATE_DATABASE_DIRECTORY_MODE))
                .map_err(|e| repair_error(&resolved, e))?;
        }
        let after = fs::symlink_metadata(&resolved)?;
        if after.dev() != metadata.dev()
            || after.ino() != metadata.ino()
            || after.mode() & 0o077 != 0
            || !after.is_dir()
        {
            return Err(invalid("catalog directory changed or is not private"));
        }
    }
    Ok(resolved)
}

#[cfg(unix)]
fn verify_ancestors(path: &Path) -> io::Result<()> {
    let uid = unsafe { libc::geteuid() };
    let ancestors: Vec<_> = path.ancestors().collect();
    let mut private_boundary = false;
    for ancestor in ancestors.into_iter().rev() {
        let metadata = fs::symlink_metadata(ancestor)?;
        let trusted_owner = metadata.uid() == uid || metadata.uid() == 0;
        // A sticky directory such as /tmp cannot have our owned child replaced by another
        // account. Shared writable non-sticky ancestors cannot provide that guarantee.
        if !metadata.is_dir()
            || !trusted_owner
            || (!private_boundary && metadata.mode() & 0o022 != 0 && metadata.mode() & 0o1000 == 0)
        {
            return Err(invalid(&format!(
                "catalog ancestor {} permits path substitution; use a storage root protected from other accounts",
                ancestor.display()
            )));
        }
        if !private_boundary {
            #[cfg(target_os = "macos")]
            let no_acl_grants = super::macos_acl::verify_ancestor(ancestor)?;
            #[cfg(not(target_os = "macos"))]
            let no_acl_grants = true;
            // A private owned ancestor already prevents other accounts from reaching
            // descendants, even when their inherited group bits are permissive.
            private_boundary =
                metadata.uid() == uid && metadata.mode() & 0o077 == 0 && no_acl_grants;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn require_owner(metadata: &fs::Metadata, path: &Path) -> io::Result<()> {
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err(invalid(&format!(
            "catalog storage {} is not owned by this account; run as its owner or use a separate storage root",
            path.display()
        )));
    }
    Ok(())
}

fn harden_file(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_file() || metadata.nlink() != 1 {
            return Err(invalid(&format!(
                "catalog artifact {} must be a regular file with one link",
                path.display()
            )));
        }
        require_owner(&metadata, path)?;
        // The containing directory and its ancestors have already been secured against
        // other accounts. Use no-follow metadata/ACL operations, never open the live DB.
        #[cfg(target_os = "macos")]
        super::macos_acl::clear_file(path).map_err(|e| repair_error(path, e))?;
        if metadata.mode() & 0o077 != 0 {
            let name = CString::new(path.as_os_str().as_bytes())
                .map_err(|_| invalid("catalog path contains NUL"))?;
            let result = unsafe {
                libc::fchmodat(
                    libc::AT_FDCWD,
                    name.as_ptr(),
                    PRIVATE_DATABASE_FILE_MODE as libc::mode_t,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if result != 0 {
                return Err(repair_error(path, io::Error::last_os_error()));
            }
        }
        let after = fs::symlink_metadata(path)?;
        if after.dev() != metadata.dev()
            || after.ino() != metadata.ino()
            || after.mode() & 0o077 != 0
        {
            return Err(invalid("catalog artifact changed or is not private"));
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn harden_sidecars(path: &Path) -> io::Result<()> {
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut name = path.as_os_str().to_os_string();
        name.push(suffix);
        harden_if_present(Path::new(&name))?;
    }
    Ok(())
}

fn harden_if_present(path: &Path) -> io::Result<()> {
    match harden_file(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}

fn repair_legacy_files(directory: &Path) -> io::Result<()> {
    // Restrict repair to the catalog's documented namespace. Other files and directories
    // are not chmod'd; legacy preflight copies remain behind the private db boundary and
    // are checked individually when resumed. Do not descend into staged runtime bundles.
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if matches!(
            name,
            "msb.db" | "msb.db-wal" | "msb.db-shm" | "msb.db-journal" | "msb.db.bak"
        ) || name.starts_with("msb.db.bak-")
        {
            harden_if_present(&entry.path())?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn repair_error(path: &Path, error: io::Error) -> io::Error {
    io::Error::new(
        error.kind(),
        format!(
            "cannot make catalog storage {} private: {error}; repair its ownership/permissions as the owner or use a separate private storage root",
            path.display()
        ),
    )
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}
