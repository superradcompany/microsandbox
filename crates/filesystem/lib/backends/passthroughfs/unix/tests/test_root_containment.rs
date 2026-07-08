use std::{ffi::CString, os::fd::AsRawFd, os::unix::fs::symlink};

use super::*;
use crate::{Context, DynFileSystem, FsOptions};

/// Root-user context for driving FUSE ops in these tests.
fn ctx() -> Context {
    Context {
        uid: 0,
        gid: 0,
        pid: 1,
    }
}

//--------------------------------------------------------------------------------------------------
// Helpers
//--------------------------------------------------------------------------------------------------

/// A two-tenant `/vol` layout on the host:
///
/// ```text
/// <base>/vol/tenant-a/          <- this tenant's assigned dir
/// <base>/vol/tenant-a/evil ---> <base>/vol/tenant-b   (tenant-created symlink)
/// <base>/vol/tenant-b/secret.txt   "tenant-b private data"
/// ```
///
/// `base` is the *canonicalized* temp dir, standing in for a control plane that
/// hands this backend a fully resolved, symlink-free path.
struct VolLayout {
    _tmp: tempfile::TempDir,
    base: std::path::PathBuf,
    tenant_a: std::path::PathBuf,
    tenant_b: std::path::PathBuf,
    evil_link: std::path::PathBuf,
}

impl VolLayout {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        // Canonicalize so no symlinked system prefix (macOS /var -> /private/var)
        // trips the no-symlink resolver; the control plane owns this step.
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        let tenant_a = base.join("vol").join("tenant-a");
        let tenant_b = base.join("vol").join("tenant-b");
        std::fs::create_dir_all(&tenant_a).unwrap();
        std::fs::create_dir_all(&tenant_b).unwrap();
        std::fs::write(tenant_b.join("secret.txt"), b"tenant-b private data").unwrap();

        let evil_link = tenant_a.join("evil");
        symlink(&tenant_b, &evil_link).unwrap();

        Self {
            _tmp: tmp,
            base,
            tenant_a,
            tenant_b,
            evil_link,
        }
    }
}

/// `st_ino`/`st_dev` identity of a host path (follows symlinks — the real target).
fn host_identity(path: &std::path::Path) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    let md = std::fs::metadata(path).unwrap();
    (md.ino(), md.dev())
}

/// `st_ino`/`st_dev` that an open fd actually points at.
fn fd_identity(fd: i32) -> (u64, u64) {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstat(fd, &mut st) };
    assert_eq!(rc, 0, "fstat failed: {}", io::Error::last_os_error());
    (st.st_ino as u64, st.st_dev as u64)
}

fn build_fs(cfg: PassthroughConfig) -> io::Result<PassthroughFs> {
    let fs = PassthroughFs::new(cfg)?;
    fs.init(FsOptions::empty())?;
    Ok(fs)
}

/// Build with the no-trusted-prefix resolver enabled.
fn build_no_symlink(root_dir: std::path::PathBuf) -> io::Result<PassthroughFs> {
    build_fs(PassthroughConfig {
        root_dir,
        no_symlink_root: true,
        stat_virtualization: StatVirtualization::Off,
        inject_init: false,
        ..Default::default()
    })
}

//--------------------------------------------------------------------------------------------------
// Tests: pre-fix escape demonstration (legacy follow)
//--------------------------------------------------------------------------------------------------

/// Legacy behavior: a tenant-created symlink at the root is followed, landing
/// `root_fd` on the sibling tenant's directory and exposing its files.
#[test]
fn escape_symlink_root_is_followed() {
    let vol = VolLayout::new();

    let fs = build_fs(PassthroughConfig {
        root_dir: vol.evil_link.clone(),
        no_symlink_root: false,
        stat_virtualization: StatVirtualization::Off,
        inject_init: false,
        ..Default::default()
    })
    .expect("legacy path follows the symlink silently");

    let root_id = fd_identity(fs.root_fd.as_raw_fd());
    eprintln!(
        "[legacy] tenant-a       = {:?}",
        host_identity(&vol.tenant_a)
    );
    eprintln!(
        "[legacy] tenant-b       = {:?}",
        host_identity(&vol.tenant_b)
    );
    eprintln!("[legacy] root_fd points = {root_id:?}");

    assert_eq!(
        root_id,
        host_identity(&vol.tenant_b),
        "escape: root_fd is tenant-b"
    );
    assert!(
        fs.lookup(ctx(), 1, &CString::new("secret.txt").unwrap())
            .is_ok(),
        "guest reached tenant-b's secret.txt (escape confirmed)"
    );
    eprintln!("[legacy] lookup tenant-b/secret.txt => Ok (ESCAPED)");
}

//--------------------------------------------------------------------------------------------------
// Tests: no-trusted-prefix resolution
//--------------------------------------------------------------------------------------------------

/// A tenant-created symlink as the mount root is refused — never followed.
#[test]
fn no_symlink_root_rejects_symlink_root() {
    let vol = VolLayout::new();
    let result = build_no_symlink(vol.evil_link.clone());

    assert!(result.is_err(), "symlink root must be refused");
    let errno = result.err().and_then(|e| e.raw_os_error());
    assert!(
        errno == Some(LINUX_ELOOP) || errno == Some(LINUX_ENOTDIR),
        "expected ELOOP or ENOTDIR, got {errno:?}"
    );
    eprintln!("[fixed] symlink root => Err(errno {errno:?}) (REFUSED)");
}

/// The exact `.../evil/evil/evil` shape: a repeated symlink component is refused
/// at the first symlink no matter how deep it repeats.
#[test]
fn no_symlink_root_rejects_repeated_symlink_component() {
    let vol = VolLayout::new();
    // tenant-b also links `evil` back to itself, so the chain would keep
    // resolving under the legacy follow path.
    symlink(&vol.tenant_b, vol.tenant_b.join("evil")).unwrap();

    let deep = vol.tenant_a.join("evil").join("evil").join("evil");
    let result = build_no_symlink(deep);

    assert!(
        result.is_err(),
        "repeated symlink must be refused at the first link"
    );
    eprintln!("[fixed] tenant-a/evil/evil/evil => Err (rejected at first symlink)");
}

/// A symlink in a NON-tenant prefix is refused too — nothing in the path is
/// trusted, not even a directory above the tenant's own subtree.
#[test]
fn no_symlink_root_rejects_symlinked_prefix() {
    let vol = VolLayout::new();
    // A real target dir, and a symlink standing in for one prefix component.
    let real = vol.base.join("real-mnt");
    std::fs::create_dir_all(real.join("work")).unwrap();
    let linked_prefix = vol.base.join("linked-mnt");
    symlink(&real, &linked_prefix).unwrap();

    // Path goes THROUGH the symlinked prefix component `linked-mnt`.
    let via_prefix = linked_prefix.join("work");
    let result = build_no_symlink(via_prefix);

    assert!(
        result.is_err(),
        "a symlinked prefix component must be refused — no trusted prefix"
    );
    eprintln!("[fixed] .../linked-mnt/work (symlinked prefix) => Err (REFUSED)");

    // Sanity: the same real path with no symlink component mounts fine.
    let fs = build_no_symlink(real.join("work")).expect("real path should mount");
    assert_eq!(
        fd_identity(fs.root_fd.as_raw_fd()),
        host_identity(&real.join("work"))
    );
}

/// A `..` segment is refused even though it crosses no symlink — it would move
/// the target laterally out of the intended subtree.
#[test]
fn no_symlink_root_rejects_dotdot() {
    let vol = VolLayout::new();
    // .../tenant-a/../tenant-b resolves to tenant-b with zero symlinks.
    let escaping = vol.tenant_a.join("..").join("tenant-b");
    let result = build_no_symlink(escaping);

    assert!(result.is_err(), "a `..` segment must be refused");
    assert_eq!(
        result.err().and_then(|e| e.raw_os_error()),
        Some(LINUX_EINVAL)
    );
    eprintln!("[fixed] tenant-a/../tenant-b => Err(EINVAL) (dotdot refused)");
}

/// A legitimate real subdirectory mounts and stays anchored on the real dir.
#[test]
fn no_symlink_root_allows_real_subdir() {
    let vol = VolLayout::new();
    let work = vol.tenant_a.join("work");
    std::fs::create_dir_all(&work).unwrap();
    std::fs::write(work.join("hello.txt"), b"tenant-a data").unwrap();

    let fs = build_no_symlink(work.clone()).expect("real subdir should mount");
    assert_eq!(fd_identity(fs.root_fd.as_raw_fd()), host_identity(&work));
    assert_ne!(
        fd_identity(fs.root_fd.as_raw_fd()),
        host_identity(&vol.tenant_b)
    );
    fs.lookup(ctx(), 1, &CString::new("hello.txt").unwrap())
        .expect("guest should see its own file");
    eprintln!("[fixed] real subdir => Ok, contained on tenant-a/work");
}

/// A deep chain of real directories is allowed — the resolver rejects symlinks,
/// not depth.
#[test]
fn no_symlink_root_allows_deep_real_path() {
    let vol = VolLayout::new();
    let deep = vol.tenant_a.join("a").join("b").join("c");
    std::fs::create_dir_all(&deep).unwrap();

    let fs = build_no_symlink(deep.clone()).expect("deep real path should mount");
    assert_eq!(fd_identity(fs.root_fd.as_raw_fd()), host_identity(&deep));
    eprintln!("[fixed] tenant-a/a/b/c (all real) => Ok, contained");
}

// Relative paths resolve from the process working directory (still no-follow),
// so relative bind mounts keep working under the protective default. This is
// covered end-to-end at the app level rather than here, because a unit test
// would have to mutate the shared process CWD and race other parallel tests.
