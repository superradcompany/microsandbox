//! Offline editor booted against an unpublished snapshot child. No guest program is run.

use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions, Permissions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};
use std::path::{Component, Path};

use microsandbox_protocol::snapshot_patch::{Action, Edit, RECEIPT};
use nix::mount::{MsFlags, mount, umount};
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{ForkResult, chroot, fork};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute the private boot protocol and then power off. A panic or premature
/// shutdown cannot manufacture a success receipt in the fresh scratch directory.
pub fn boot() -> ! {
    let result = edit_disk();
    let report = result
        .map(|()| RECEIPT.to_owned())
        .unwrap_or_else(|e| e.to_string());
    if let Ok(mut file) = File::create_new("/result") {
        let _ = file
            .write_all(report.as_bytes())
            .and_then(|()| file.sync_all());
    }
    unsafe { libc::reboot(libc::RB_POWER_OFF) };
    std::process::exit(1)
}

fn edit_disk() -> io::Result<()> {
    let mut payload = File::open("/payload")?;
    let manifest = File::open("/edits")?;
    let failure = File::create_new("/failure")?;
    let layered = Path::new("/layered").try_exists()?;
    crate::init::prepare_bootstrap_console().map_err(io::Error::other)?;
    let flags = MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC;
    fs::create_dir("/view")?;
    if layered {
        fs::create_dir("/lower")?;
        fs::create_dir("/upperfs")?;
        mount(
            Some("/dev/vda"),
            "/lower",
            Some("erofs"),
            flags | MsFlags::MS_RDONLY,
            None::<&str>,
        )?;
        mount(
            Some("/dev/vdb"),
            "/upperfs",
            Some("ext4"),
            flags,
            None::<&str>,
        )?;
        for dir in ["/upperfs/upper", "/upperfs/work"] {
            match fs::symlink_metadata(dir) {
                Ok(meta) if meta.is_dir() => {}
                Ok(_) => return Err(io::Error::other(format!("invalid overlay directory {dir}"))),
                Err(e) if e.kind() == io::ErrorKind::NotFound => fs::create_dir(dir)?,
                Err(e) => return Err(e),
            }
        }
        mount(
            Some("overlay"),
            "/view",
            Some("overlay"),
            flags,
            Some("lowerdir=/lower,upperdir=/upperfs/upper,workdir=/upperfs/work"),
        )?;
    } else {
        mount(Some("/dev/vda"), "/view", Some("ext4"), flags, None::<&str>)?;
    }
    // Fork before starting any threads. Only the parent can reach the bootstrap
    // mount and publish a receipt. The child inherits three regular input/error
    // files and resolves even absolute guest symlinks inside its chroot.
    match unsafe { fork()? } {
        ForkResult::Parent { child } => {
            if !matches!(waitpid(child, None)?, WaitStatus::Exited(_, 0)) {
                return Err(io::Error::other(fs::read_to_string("/failure")?));
            }
        }
        ForkResult::Child => {
            let result = (|| {
                chroot("/view")?;
                std::env::set_current_dir("/")?;
                let stream = serde_json::Deserializer::from_reader(io::BufReader::new(manifest))
                    .into_iter::<Edit>();
                for (i, record) in stream.enumerate() {
                    let edit = record?;
                    let path = Path::new(OsStr::from_bytes(&edit.path));
                    apply(path, edit.action, &mut payload).map_err(|e| {
                        io::Error::other(format!("edit {} at {path:?}: {e}", i + 1))
                    })?;
                }
                if payload.read(&mut [0])? != 0 {
                    return Err(io::Error::other("unexpected trailing edit data"));
                }
                Ok(())
            })();
            let status = if let Err(e) = result {
                let _ = writeln!(&failure, "{e}");
                1
            } else {
                0
            };
            unsafe { libc::_exit(status) }
        }
    }
    let writable = if layered { "/upperfs" } else { "/view" };
    let disk = File::open(writable)?;
    if unsafe { libc::syncfs(disk.as_raw_fd()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    drop(disk);
    umount("/view")?;
    if layered {
        umount("/upperfs")?;
        umount("/lower")?;
    }
    Ok(())
}

fn apply(path: &Path, action: Action, data: &mut File) -> io::Result<()> {
    if !path.is_absolute()
        || path.file_name().is_none()
        || path.components().any(|c| c == Component::ParentDir)
    {
        return Err(io::Error::other("expected an absolute non-root guest path"));
    }
    let entry = match fs::symlink_metadata(path) {
        Ok(meta) => Some(meta),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => return Err(e),
    };
    let remove = || -> io::Result<()> {
        match &entry {
            Some(meta) if meta.is_dir() => fs::remove_dir_all(path),
            Some(_) => fs::remove_file(path),
            None => Ok(()),
        }
    };
    let create = |replace: bool| -> io::Result<()> {
        if entry.is_some() && !replace {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "path exists (set replace to allow)",
            ));
        }
        remove()?;
        fs::create_dir_all(path.parent().expect("validated non-root path"))
    };
    match action {
        Action::Write { mode, replace, len } => {
            create(replace)?;
            let mut file = File::create_new(path)?;
            copy_exact(data, &mut file, len)?;
            file.set_permissions(Permissions::from_mode(mode & 0o7777))
        }
        Action::Append { len } => {
            if !entry.as_ref().is_some_and(|meta| meta.is_file()) {
                return Err(io::Error::other("append requires an existing regular file"));
            }
            let mut file = OpenOptions::new()
                .append(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(path)?;
            copy_exact(data, &mut file, len)
        }
        Action::Symlink { target, replace } => {
            create(replace)?;
            symlink(OsStr::from_bytes(&target), path)
        }
        Action::Directory { mode } => {
            if entry.as_ref().is_some_and(|meta| meta.is_dir()) {
                return Ok(());
            }
            create(false)?;
            fs::create_dir(path)?;
            fs::set_permissions(path, Permissions::from_mode(mode & 0o7777))
        }
        Action::CopyDirectory { mode, replace } => {
            if !(replace && entry.as_ref().is_some_and(|meta| meta.is_dir())) {
                create(replace)?;
                fs::create_dir(path)?;
            }
            fs::set_permissions(path, Permissions::from_mode(mode & 0o7777))
        }
        Action::Remove => remove(),
    }
}

fn copy_exact(data: &mut File, out: &mut File, len: u64) -> io::Result<()> {
    if io::copy(&mut data.take(len), out)? != len {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "incomplete edit payload",
        ));
    }
    Ok(())
}
