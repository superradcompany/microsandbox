//! The recovery VM's trusted reader. Only data devices are mounted; candidate programs are never invoked.

use std::ffi::{CString, OsStr};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};

use microsandbox_protocol::storage_preview::{
    ABSENT, DATA, LOWER, MAX_ENTRIES, MAX_FILE, MERGED, StoragePreviewEntry,
};
use nix::mount::{self, MsFlags};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Combine the captured overlay upper and exact OCI lower as read-only layers. Kernel
/// overlayfs interprets whiteouts and opaque directories; walking the upper alone cannot.
pub fn mount_merged() -> io::Result<()> {
    mounted_view(DATA, 0xef53)?;
    mounted_view(LOWER, 0xe0f5_e1e2)?;
    let upper = Path::new(DATA).join("upper");
    if !fs::symlink_metadata(&upper).is_ok_and(|metadata| metadata.is_dir()) {
        return Err(io::Error::other(
            "captured OCI upper directory is unavailable",
        ));
    }
    fs::create_dir(MERGED)?;
    let options = format!("lowerdir={DATA}/upper:{LOWER}");
    mount::mount(
        Some("overlay"),
        MERGED,
        Some("overlay"),
        MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        Some(options.as_str()),
    )
    .map_err(io::Error::from)
}

/// Serve a single bounded query on stdout, with a separate exit code for a missing guest path.
pub fn query(mut args: impl Iterator<Item = String>) -> i32 {
    let first = args.next();
    if first.as_deref() == Some("handshake") && args.next().is_none() {
        print!("{}", microsandbox_protocol::storage_preview::HANDSHAKE);
        return 0;
    }
    let (Some(layout), Some(operation), Some(path), None) =
        (first, args.next(), args.next(), args.next())
    else {
        eprintln!("invalid recovery reader arguments");
        return 2;
    };
    let (root, expected_magic) = match layout.as_str() {
        "merged" => (MERGED, 0x794c_7630),
        "disk" => (DATA, 0xef53),
        _ => {
            eprintln!("unsupported recovery view");
            return 2;
        }
    };
    let root = match mounted_view(root, expected_magic) {
        Ok(root) => root,
        Err(_) => {
            eprintln!("recovery view was not mounted");
            return 2;
        }
    };
    let object = match open_guest_path(&root, &path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return ABSENT,
        Err(error) => {
            eprintln!("guest path cannot be inspected: {error}");
            return 2;
        }
    };
    if let Err(error) = write_reply(&object, &operation, io::stdout().lock()) {
        eprintln!("guest view cannot be read: {error}");
        return 2;
    }
    0
}

/// A missing or failed mount must never look like an empty guest directory. Check the
/// filesystem and read-only flags on the pinned root before accepting a lookup's ENOENT.
fn mounted_view(path: &str, expected_magic: u64) -> io::Result<File> {
    let root = File::open(path)?;
    let mut fs = std::mem::MaybeUninit::<libc::statfs>::uninit();
    let mut flags = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    if unsafe { libc::fstatfs(root.as_raw_fd(), fs.as_mut_ptr()) } != 0
        || unsafe { libc::fstatvfs(root.as_raw_fd(), flags.as_mut_ptr()) } != 0
    {
        return Err(io::Error::last_os_error());
    }
    // libc uses an unsigned filesystem word on musl and a signed word on glibc.
    // A shared, lossless type keeps the magic comparison identical on both targets.
    if i128::from(unsafe { fs.assume_init() }.f_type) != i128::from(expected_magic)
        || unsafe { flags.assume_init() }.f_flag & libc::ST_RDONLY == 0
    {
        return Err(io::Error::other(
            "expected read-only recovery filesystem is unavailable",
        ));
    }
    Ok(root)
}

fn open_guest_path(root: &File, path: &str) -> io::Result<File> {
    let path = Path::new(path);
    if !path.is_absolute() || path.as_os_str().len() > 4096 {
        return Err(io::Error::other(
            "expected an absolute guest path of at most 4096 bytes",
        ));
    }
    let mut object = root.try_clone()?;
    for component in path.components() {
        let name = match component {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(name) => name,
            _ => {
                return Err(io::Error::other(
                    "parent traversal is unavailable in recovery views",
                ));
            }
        };
        if !object.metadata()?.is_dir() {
            return Err(io::Error::other("guest path component is not a directory"));
        }
        let name = CString::new(OsStr::as_bytes(name))?;
        // O_PATH never opens a special device or blocks on a FIFO. Hold each resolved child
        // directly so guest symlinks cannot escape into the reader's own root, proc or sysfs.
        let fd = unsafe {
            libc::openat(
                object.as_raw_fd(),
                name.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        object = unsafe { File::from_raw_fd(fd) };
        if object.metadata()?.is_symlink() {
            return Err(io::Error::other(
                "symbolic links cannot be followed in recovery views",
            ));
        }
    }
    Ok(object)
}

fn write_reply(file: &File, operation: &str, mut output: impl Write) -> io::Result<()> {
    let metadata = file.metadata()?;
    let pinned = format!("/proc/self/fd/{}", file.as_raw_fd());
    match operation {
        "list" if metadata.is_dir() => {
            let mut entries = Vec::new();
            for entry in fs::read_dir(&pinned)? {
                if entries.len() == MAX_ENTRIES {
                    return Err(io::Error::other(
                        "directory exceeds the 512-entry preview limit",
                    ));
                }
                let entry = entry?;
                let name = entry
                    .file_name()
                    .into_string()
                    .map_err(|_| io::Error::other("directory contains a non-UTF-8 filename"))?;
                let meta = fs::symlink_metadata(entry.path())?;
                let kind = if meta.is_dir() {
                    "directory"
                } else if meta.is_file() {
                    "file"
                } else if meta.is_symlink() {
                    "symlink"
                } else {
                    "other"
                };
                entries.push(StoragePreviewEntry {
                    name,
                    kind: kind.into(),
                    size: meta.len(),
                });
            }
            entries.sort_by(|a, b| a.name.cmp(&b.name));
            serde_json::to_writer(output, &entries).map_err(io::Error::other)
        }
        "read" if metadata.is_file() => {
            if metadata.len() > MAX_FILE as u64 {
                return Err(io::Error::other("file exceeds the 64 KiB preview limit"));
            }
            let mut contents = Vec::new();
            File::open(pinned)?
                .take(MAX_FILE as u64 + 1)
                .read_to_end(&mut contents)?;
            if contents.len() > MAX_FILE {
                return Err(io::Error::other("file exceeds the 64 KiB preview limit"));
            }
            output.write_all(&contents)
        }
        _ => Err(io::Error::other(
            "list requires a directory and read requires a regular file",
        )),
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests;
