//! Best-effort filesystem teardown before guest poweroff.
//!
//! agentd is effectively init: nothing else unmounts filesystems before the kernel powers off, so without this pass every graceful stop leaves block-backed
//! filesystems (notably the OCI overlay upper) with a dirty jbd2 journal (`EXT4_FEATURE_INCOMPAT_RECOVER` set) that the next mount or offline tool must replay.
//! Teardown is strictly best-effort: a sandbox must always power off, so every step logs and continues on failure, and the whole pass is bounded by a deadline.

use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use nix::mount::{self, MntFlags, MsFlags};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Budget for the whole teardown pass.
///
/// Must stay comfortably inside `microsandbox_protocol::NORMAL_SHUTDOWN_FLUSH_TIMEOUT` (2s): the host hard-kills the VMM when that window expires, so a
/// slow teardown would turn a graceful stop into the very unclean shutdown it is trying to prevent.
const TEARDOWN_DEADLINE: Duration = Duration::from_millis(1000);

/// Sub-budget for waiting on killed processes to exit and release their open files.
const PROCESS_REAP_BUDGET: Duration = Duration::from_millis(300);

/// Poll interval while reaping killed processes.
const PROCESS_REAP_POLL: Duration = Duration::from_millis(5);

/// Filesystem types with no backing store worth flushing or detaching at poweroff.
const PSEUDO_FSTYPES: &[&str] = &[
    "autofs",
    "binfmt_misc",
    "bpf",
    "cgroup",
    "cgroup2",
    "configfs",
    "debugfs",
    "devpts",
    "devtmpfs",
    "efivarfs",
    "fusectl",
    "hugetlbfs",
    "mqueue",
    "nsfs",
    "proc",
    "pstore",
    "ramfs",
    "rootfs",
    "securityfs",
    "selinuxfs",
    "sysfs",
    "tmpfs",
    "tracefs",
];

/// Directory fd pinned to the root of the OCI overlay upper filesystem.
///
/// After the root pivot (`MS_MOVE` + chroot) the upper ext4 mount lives under the old, shadowed root: it has no reachable path and does not appear in
/// `/proc/self/mounts`, so the only way to address it at shutdown is through a fd captured at mount time, resolved via `/proc/self/fd/N`.
static UPPER_FS_DIR: OnceLock<File> = OnceLock::new();

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// One real (non-pseudo) mount from `/proc/self/mounts`.
#[derive(Debug, PartialEq, Eq)]
struct MountPoint {
    path: PathBuf,
    fstype: String,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Captures a fd to the OCI overlay upper filesystem root so teardown can still reach it after the root pivot hides its path.
///
/// Best effort: on failure the upper simply keeps today's behavior (dirty journal at stop, replayed on next use).
pub fn register_upper_fs(path: &str) {
    match File::open(path) {
        Ok(file) => {
            let _ = UPPER_FS_DIR.set(file);
        }
        Err(err) => eprintln!("agentd: teardown: failed to pin upper fs dir {path}: {err}"),
    }
}

/// Flushes and tears down filesystems ahead of guest poweroff so block-backed mounts reach a clean terminal state (unmounted or read-only with the
/// journal checkpointed).
///
/// `kill_remaining_processes` should be true only when agentd is PID 1 and about to power the kernel off: lingering processes with write-open files
/// would otherwise make every read-only remount fail with `EBUSY`. Never fails — the caller must proceed to poweroff regardless.
pub fn teardown_filesystems(kill_remaining_processes: bool) {
    let deadline = Instant::now() + TEARDOWN_DEADLINE;

    // SAFETY: sync(2) has no failure modes and takes no arguments.
    unsafe { libc::sync() };

    if kill_remaining_processes {
        quiesce_processes(deadline);
    }

    match std::fs::read_to_string("/proc/self/mounts") {
        Ok(table) => {
            for mount_point in teardown_plan(&table) {
                if Instant::now() >= deadline {
                    eprintln!("agentd: teardown: deadline reached, skipping remaining mounts");
                    break;
                }
                detach_or_remount_readonly(&mount_point.path);
            }
        }
        Err(err) => eprintln!("agentd: teardown: failed to read /proc/self/mounts: {err}"),
    }

    remount_upper_readonly(deadline);

    // SAFETY: sync(2) has no failure modes and takes no arguments.
    unsafe { libc::sync() };
}

/// Parses `/proc/self/mounts` into the teardown order: real filesystems only, reversed so children are handled before their parents and the root
/// mount comes last.
fn teardown_plan(proc_mounts: &str) -> Vec<MountPoint> {
    let mut plan: Vec<MountPoint> = proc_mounts
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let _device = fields.next()?;
            let path = fields.next()?;
            let fstype = fields.next()?;
            if PSEUDO_FSTYPES.contains(&fstype) {
                return None;
            }
            Some(MountPoint {
                path: unescape_mount_path(path),
                fstype: fstype.to_string(),
            })
        })
        .collect();
    plan.reverse();
    plan
}

/// Decodes the octal escapes (`\040` for space, etc.) the kernel uses for special characters in `/proc/mounts` paths.
fn unescape_mount_path(escaped: &str) -> PathBuf {
    let bytes = escaped.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() {
            let octal = &bytes[i + 1..i + 4];
            if octal.iter().all(|b| (b'0'..=b'7').contains(b)) {
                let value = octal
                    .iter()
                    .fold(0u32, |acc, b| acc * 8 + u32::from(b - b'0'));
                if let Ok(byte) = u8::try_from(value) {
                    out.push(byte);
                    i += 4;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    PathBuf::from(std::ffi::OsString::from_vec(out))
}

/// Unmounts a filesystem, falling back to a read-only remount when it is busy.
///
/// The busy case is expected for the overlay root (it hosts the running agentd) — remounting its superblock read-only is the correct terminal state,
/// and it also stops new writes from reaching the upper filesystem underneath.
fn detach_or_remount_readonly(path: &Path) {
    if mount::umount2(path, MntFlags::empty()).is_ok() {
        return;
    }
    if let Err(err) = mount::mount(
        None::<&str>,
        path,
        None::<&str>,
        MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
        None::<&str>,
    ) {
        eprintln!(
            "agentd: teardown: {} left mounted read-write: {err}",
            path.display()
        );
    }
}

/// Remounts the pinned upper filesystem read-only via `/proc/self/fd`.
///
/// Remount — not unmount — is deliberate: overlayfs holds a private clone of the upper mount, so detaching our mount would not release the superblock
/// or flush anything. `MS_REMOUNT | MS_RDONLY` acts on the superblock itself, which makes ext4 checkpoint the jbd2 journal and clear
/// `EXT4_FEATURE_INCOMPAT_RECOVER`. Must run after the overlay root has gone read-only so no writers remain on the upper.
fn remount_upper_readonly(deadline: Instant) {
    let Some(file) = UPPER_FS_DIR.get() else {
        return;
    };
    if Instant::now() >= deadline {
        eprintln!("agentd: teardown: deadline reached, upper fs left mounted read-write");
        return;
    }
    let target = format!("/proc/self/fd/{}", file.as_raw_fd());
    if let Err(err) = mount::mount(
        None::<&str>,
        target.as_str(),
        None::<&str>,
        MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
        None::<&str>,
    ) {
        eprintln!("agentd: teardown: upper fs left mounted read-write: {err}");
    }
}

/// Kills every remaining process and briefly waits for them to exit.
///
/// A read-only remount fails with `EBUSY` while any process holds a file open for write, so the mount walk is only reliable once userland is gone.
/// The graceful SIGTERM already went out in the shutdown handler, and the kernel poweroff that follows would kill everything anyway — this just makes
/// that death happen before the remounts instead of after. `kill(-1)` never signals the calling process or PID 1, so agentd survives.
fn quiesce_processes(deadline: Instant) {
    // SAFETY: kill(2) with pid -1 is well-defined; failure (e.g. no processes left) is benign.
    unsafe { libc::kill(-1, libc::SIGKILL) };

    let reap_deadline = deadline.min(Instant::now() + PROCESS_REAP_BUDGET);
    loop {
        // SAFETY: waitpid(2) with WNOHANG and a null status pointer is well-defined.
        let ret = unsafe { libc::waitpid(-1, ptr::null_mut(), libc::WNOHANG) };
        if ret > 0 {
            continue;
        }
        if ret == 0 {
            // Children remain but none exited yet; give SIGKILL a moment to land.
            if Instant::now() >= reap_deadline {
                break;
            }
            std::thread::sleep(PROCESS_REAP_POLL);
            continue;
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        // ECHILD: everything is reaped (or another reaper got there first).
        break;
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A realistic post-pivot guest mount table: overlay root, pseudo filesystems, the /.msb virtiofs runtime share, a virtiofs dir volume, an ext4
    /// disk volume, and tmpfs mounts.
    const GUEST_MOUNTS: &str = "\
overlay / overlay rw,relatime,lowerdir=/.msb/rootfs/lower,upperdir=/.msb/rootfs/upperfs/upper,workdir=/.msb/rootfs/upperfs/work 0 0
devtmpfs /dev devtmpfs rw,relatime,size=100k 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
cgroup2 /sys/fs/cgroup cgroup2 rw,nosuid,nodev,noexec,relatime 0 0
devpts /dev/pts devpts rw,nosuid,noexec,relatime 0 0
tmpfs /dev/shm tmpfs rw,nosuid,noexec,relatime 0 0
msb_runtime /.msb virtiofs rw,relatime 0 0
vol0 /data virtiofs rw,relatime 0 0
/dev/vdc /mnt/disk ext4 rw,relatime 0 0
tmpfs /tmp tmpfs rw,nosuid,nodev,relatime,mode=1777 0 0
";

    #[test]
    fn plan_filters_pseudo_filesystems_and_reverses_mount_order() {
        let plan = teardown_plan(GUEST_MOUNTS);
        let paths: Vec<&Path> = plan.iter().map(|m| m.path.as_path()).collect();
        assert_eq!(
            paths,
            vec![
                Path::new("/mnt/disk"),
                Path::new("/data"),
                Path::new("/.msb"),
                Path::new("/"),
            ]
        );
    }

    #[test]
    fn plan_orders_root_last_so_upper_remount_follows_overlay() {
        // The upper ext4 remount only succeeds once the overlay root is read-only, so the root mount must be the final entry of the walk.
        let plan = teardown_plan(GUEST_MOUNTS);
        let last = plan.last().expect("plan must not be empty");
        assert_eq!(last.path, Path::new("/"));
        assert_eq!(last.fstype, "overlay");
    }

    #[test]
    fn plan_unescapes_octal_mount_paths() {
        let plan = teardown_plan("/dev/vdc /mnt/my\\040disk ext4 rw,relatime 0 0\n");
        assert_eq!(plan[0].path, Path::new("/mnt/my disk"));
    }

    #[test]
    fn plan_keeps_literal_backslashes_that_are_not_octal_escapes() {
        let plan = teardown_plan(
            "/dev/vdc /mnt/we\\134ird ext4 rw 0 0\n/dev/vdd /mnt/tail\\04 ext4 rw 0 0\n",
        );
        assert_eq!(plan[1].path, Path::new("/mnt/we\\ird"));
        assert_eq!(plan[0].path, Path::new("/mnt/tail\\04"));
    }

    #[test]
    fn plan_skips_malformed_lines() {
        let plan = teardown_plan("garbage\n\n/dev/vda\n/dev/vdb /ok ext4 rw 0 0\n");
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].path, Path::new("/ok"));
    }
}
