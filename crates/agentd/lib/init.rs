//! PID 1 init: mount filesystems, apply tmpfs mounts, prepare runtime directories.
//!
//! This module only performs real work on Linux. On other platforms, `init()` is a no-op
//! to allow the crate to compile for development purposes.

use crate::error::{AgentdError, AgentdResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Parsed tmpfs mount specification.
#[derive(Debug)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct TmpfsSpec<'a> {
    path: &'a str,
    size_mib: Option<u32>,
    mode: Option<u32>,
    noexec: bool,
}

/// Parsed block-device root specification.
#[derive(Debug)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct BlockRootSpec<'a> {
    device: &'a str,
    fstype: Option<&'a str>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Performs synchronous PID 1 initialization.
///
/// Mounts essential filesystems, applies tmpfs mounts from `MSB_TMPFS` env var,
/// configures networking from `MSB_NET*` env vars, and prepares runtime directories.
#[cfg(target_os = "linux")]
pub fn init() -> AgentdResult<()> {
    linux::mount_filesystems()?;
    linux::mount_runtime()?;
    linux::mount_block_root()?;
    linux::apply_tmpfs_mounts()?;
    crate::network::apply_network_config()?;
    linux::create_run_dir()?;
    Ok(())
}

/// No-op on non-Linux platforms.
#[cfg(not(target_os = "linux"))]
pub fn init() -> AgentdResult<()> {
    Ok(())
}

/// Parses a single tmpfs entry: `path[,size=N][,mode=N][,noexec]`
///
/// Mode is parsed as octal (e.g. `mode=1777`).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_tmpfs_entry(entry: &str) -> AgentdResult<TmpfsSpec<'_>> {
    let mut parts = entry.split(',');
    let path = parts.next().unwrap(); // always at least one element
    if path.is_empty() {
        return Err(AgentdError::Init("tmpfs entry has empty path".into()));
    }

    let mut size_mib = None;
    let mut mode = None;
    let mut noexec = false;

    for opt in parts {
        if opt == "noexec" {
            noexec = true;
        } else if let Some(val) = opt.strip_prefix("size=") {
            size_mib = Some(val.parse::<u32>().map_err(|_| {
                AgentdError::Init(format!("invalid tmpfs size: {val}"))
            })?);
        } else if let Some(val) = opt.strip_prefix("mode=") {
            mode = Some(u32::from_str_radix(val, 8).map_err(|_| {
                AgentdError::Init(format!("invalid octal tmpfs mode: {val}"))
            })?);
        } else {
            return Err(AgentdError::Init(format!(
                "unknown tmpfs option: {opt}"
            )));
        }
    }

    Ok(TmpfsSpec {
        path,
        size_mib,
        mode,
        noexec,
    })
}

/// Parses a block-device root specification: `device[,fstype=TYPE]`
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_block_root(val: &str) -> AgentdResult<BlockRootSpec<'_>> {
    let mut parts = val.split(',');
    let device = parts.next().unwrap();
    if device.is_empty() {
        return Err(AgentdError::Init("MSB_BLOCK_ROOT has empty device path".into()));
    }

    let mut fstype = None;
    for opt in parts {
        if let Some(val) = opt.strip_prefix("fstype=") {
            if val.is_empty() {
                return Err(AgentdError::Init("MSB_BLOCK_ROOT has empty fstype value".into()));
            }
            fstype = Some(val);
        } else {
            return Err(AgentdError::Init(format!(
                "unknown MSB_BLOCK_ROOT option: {opt}"
            )));
        }
    }

    Ok(BlockRootSpec { device, fstype })
}

//--------------------------------------------------------------------------------------------------
// Modules
//--------------------------------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod linux {
    use std::os::unix::fs::symlink;
    use std::path::Path;

    use nix::mount::{MsFlags, mount};
    use nix::sys::stat::Mode;
    use nix::unistd::{chdir, chroot, mkdir};

    use crate::error::{AgentdError, AgentdResult};

    use super::TmpfsSpec;

    /// Mounts essential Linux filesystems.
    pub fn mount_filesystems() -> AgentdResult<()> {
        // /dev — devtmpfs
        mkdir_ignore_exists("/dev")?;
        mount_ignore_busy(
            Some("devtmpfs"),
            "/dev",
            Some("devtmpfs"),
            MsFlags::MS_RELATIME,
            None::<&str>,
        )?;

        // /proc — proc
        let nodev_noexec_nosuid =
            MsFlags::MS_NODEV | MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID | MsFlags::MS_RELATIME;

        mkdir_ignore_exists("/proc")?;
        mount_ignore_busy(
            Some("proc"),
            "/proc",
            Some("proc"),
            nodev_noexec_nosuid,
            None::<&str>,
        )?;

        // /sys — sysfs
        mkdir_ignore_exists("/sys")?;
        mount_ignore_busy(
            Some("sysfs"),
            "/sys",
            Some("sysfs"),
            nodev_noexec_nosuid,
            None::<&str>,
        )?;

        // /sys/fs/cgroup — cgroup2
        mkdir_ignore_exists("/sys/fs/cgroup")?;
        mount_ignore_busy(
            Some("cgroup2"),
            "/sys/fs/cgroup",
            Some("cgroup2"),
            nodev_noexec_nosuid,
            None::<&str>,
        )?;

        // /dev/pts — devpts
        let noexec_nosuid = MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID | MsFlags::MS_RELATIME;

        mkdir_ignore_exists("/dev/pts")?;
        mount_ignore_busy(
            Some("devpts"),
            "/dev/pts",
            Some("devpts"),
            noexec_nosuid,
            None::<&str>,
        )?;

        // /dev/shm — tmpfs
        mkdir_ignore_exists("/dev/shm")?;
        mount_ignore_busy(
            Some("tmpfs"),
            "/dev/shm",
            Some("tmpfs"),
            noexec_nosuid,
            None::<&str>,
        )?;

        // /dev/fd → /proc/self/fd
        if !Path::new("/dev/fd").exists() {
            symlink("/proc/self/fd", "/dev/fd").map_err(|e| {
                AgentdError::Init(format!("failed to symlink /dev/fd: {e}"))
            })?;
        }

        Ok(())
    }

    /// Mounts the virtiofs runtime filesystem at the canonical mount point.
    pub fn mount_runtime() -> AgentdResult<()> {
        mkdir_ignore_exists(microsandbox_protocol::RUNTIME_MOUNT_POINT)?;
        mount_ignore_busy(
            Some(microsandbox_protocol::RUNTIME_FS_TAG),
            microsandbox_protocol::RUNTIME_MOUNT_POINT,
            Some("virtiofs"),
            MsFlags::empty(),
            None::<&str>,
        )?;
        Ok(())
    }

    /// Mounts a block device as the new root filesystem, if `MSB_BLOCK_ROOT` is set.
    ///
    /// Steps: mount block device at `/newroot`, bind-mount `/.msb` into it,
    /// pivot via `MS_MOVE` + `chroot`, then re-mount essential filesystems.
    pub fn mount_block_root() -> AgentdResult<()> {
        let val = match std::env::var(microsandbox_protocol::ENV_BLOCK_ROOT) {
            Ok(v) if !v.is_empty() => v,
            _ => return Ok(()),
        };

        let spec = super::parse_block_root(&val)?;

        // Create the temporary mount point.
        mkdir_ignore_exists("/newroot")?;

        // Mount the block device.
        if let Some(fstype) = spec.fstype {
            mount(
                Some(spec.device),
                "/newroot",
                Some(fstype),
                MsFlags::empty(),
                None::<&str>,
            )
            .map_err(|e| {
                AgentdError::Init(format!(
                    "failed to mount {} at /newroot as {fstype}: {e}",
                    spec.device
                ))
            })?;
        } else {
            try_mount(spec.device, "/newroot")?;
        }

        // Bind-mount the runtime filesystem into the new root.
        let msb_target = "/newroot/.msb";
        mkdir_ignore_exists(msb_target)?;
        mount(
            Some(microsandbox_protocol::RUNTIME_MOUNT_POINT),
            msb_target,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .map_err(|e| AgentdError::Init(format!("failed to bind-mount /.msb into /newroot: {e}")))?;

        // Pivot: move the new root on top of /.
        chdir("/newroot")
            .map_err(|e| AgentdError::Init(format!("failed to chdir /newroot: {e}")))?;

        mount(
            Some("."),
            "/",
            None::<&str>,
            MsFlags::MS_MOVE,
            None::<&str>,
        )
        .map_err(|e| AgentdError::Init(format!("failed to MS_MOVE /newroot to /: {e}")))?;

        chroot(".")
            .map_err(|e| AgentdError::Init(format!("failed to chroot: {e}")))?;

        chdir("/")
            .map_err(|e| AgentdError::Init(format!("failed to chdir / after chroot: {e}")))?;

        // Re-mount essential filesystems in the new root.
        mount_filesystems()?;

        Ok(())
    }

    /// Tries every filesystem type listed in `/proc/filesystems` until one succeeds.
    fn try_mount(device: &str, target: &str) -> AgentdResult<()> {
        let content = std::fs::read_to_string("/proc/filesystems").map_err(|e| {
            AgentdError::Init(format!("failed to read /proc/filesystems: {e}"))
        })?;

        for line in content.lines() {
            // Skip virtual filesystems marked with "nodev".
            if line.starts_with("nodev") {
                continue;
            }

            let fstype = line.trim();
            if fstype.is_empty() {
                continue;
            }

            if mount(
                Some(device),
                target,
                Some(fstype),
                MsFlags::empty(),
                None::<&str>,
            )
            .is_ok()
            {
                return Ok(());
            }
        }

        Err(AgentdError::Init(format!(
            "failed to mount {device} at {target}: no supported filesystem found"
        )))
    }

    /// Reads `MSB_TMPFS` env var and mounts each tmpfs entry.
    ///
    /// Missing env var is not an error (no tmpfs mounts requested).
    /// Parse failures and mount failures are hard errors.
    pub fn apply_tmpfs_mounts() -> AgentdResult<()> {
        let val = match std::env::var(microsandbox_protocol::ENV_TMPFS) {
            Ok(v) if !v.is_empty() => v,
            _ => return Ok(()),
        };

        for entry in val.split(';') {
            if entry.is_empty() {
                continue;
            }

            let spec = super::parse_tmpfs_entry(entry)?;
            mount_tmpfs(&spec)?;
        }

        Ok(())
    }

    /// Mounts a single tmpfs from a parsed spec.
    fn mount_tmpfs(spec: &TmpfsSpec<'_>) -> AgentdResult<()> {
        let path = spec.path;

        // Determine the permission mode.
        let mode = spec.mode.unwrap_or(if path == "/tmp" || path == "/var/tmp" {
            0o1777
        } else {
            0o755
        });

        // Create the target directory.
        std::fs::create_dir_all(path).map_err(|e| {
            AgentdError::Init(format!("failed to create directory {path}: {e}"))
        })?;

        // Flags: nosuid + nodev (sensible safety defaults).
        let mut flags =
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_RELATIME;
        if spec.noexec {
            flags |= MsFlags::MS_NOEXEC;
        }

        // Mount data: size and mode options.
        let mut data = String::new();
        if let Some(mib) = spec.size_mib {
            data.push_str(&format!("size={}", u64::from(mib) * 1024 * 1024));
        }
        if !data.is_empty() {
            data.push(',');
        }
        data.push_str(&format!("mode={mode:o}"));

        mount(
            Some("tmpfs"),
            path,
            Some("tmpfs"),
            flags,
            Some(data.as_str()),
        )
        .map_err(|e| AgentdError::Init(format!("failed to mount tmpfs at {path}: {e}")))?;

        Ok(())
    }

    /// Creates the `/run` directory.
    pub fn create_run_dir() -> AgentdResult<()> {
        mkdir_ignore_exists("/run")?;
        Ok(())
    }

    /// Creates a directory, ignoring EEXIST errors.
    fn mkdir_ignore_exists(path: &str) -> AgentdResult<()> {
        match mkdir(path, Mode::from_bits_truncate(0o755)) {
            Ok(()) => Ok(()),
            Err(nix::Error::EEXIST) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Mounts a filesystem, ignoring EBUSY errors (already mounted).
    fn mount_ignore_busy(
        source: Option<&str>,
        target: &str,
        fstype: Option<&str>,
        flags: MsFlags,
        data: Option<&str>,
    ) -> AgentdResult<()> {
        match mount(source, target, fstype, flags, data) {
            Ok(()) => Ok(()),
            Err(nix::Error::EBUSY) => Ok(()),
            Err(e) => Err(AgentdError::Init(format!("failed to mount {target}: {e}"))),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_path_only() {
        let spec = parse_tmpfs_entry("/tmp").unwrap();
        assert_eq!(spec.path, "/tmp");
        assert_eq!(spec.size_mib, None);
        assert_eq!(spec.mode, None);
        assert!(!spec.noexec);
    }

    #[test]
    fn test_parse_with_size() {
        let spec = parse_tmpfs_entry("/tmp,size=256").unwrap();
        assert_eq!(spec.path, "/tmp");
        assert_eq!(spec.size_mib, Some(256));
    }

    #[test]
    fn test_parse_with_noexec() {
        let spec = parse_tmpfs_entry("/tmp,noexec").unwrap();
        assert_eq!(spec.path, "/tmp");
        assert!(spec.noexec);
    }

    #[test]
    fn test_parse_with_octal_mode() {
        let spec = parse_tmpfs_entry("/tmp,mode=1777").unwrap();
        assert_eq!(spec.mode, Some(0o1777));

        let spec = parse_tmpfs_entry("/data,mode=755").unwrap();
        assert_eq!(spec.mode, Some(0o755));
    }

    #[test]
    fn test_parse_multi_options() {
        let spec = parse_tmpfs_entry("/tmp,size=256,mode=1777,noexec").unwrap();
        assert_eq!(spec.path, "/tmp");
        assert_eq!(spec.size_mib, Some(256));
        assert_eq!(spec.mode, Some(0o1777));
        assert!(spec.noexec);
    }

    #[test]
    fn test_parse_unknown_option_errors() {
        let err = parse_tmpfs_entry("/tmp,bogus=42").unwrap_err();
        assert!(err.to_string().contains("unknown tmpfs option"));
    }

    #[test]
    fn test_parse_invalid_size_errors() {
        let err = parse_tmpfs_entry("/tmp,size=abc").unwrap_err();
        assert!(err.to_string().contains("invalid tmpfs size"));
    }

    #[test]
    fn test_parse_invalid_mode_errors() {
        let err = parse_tmpfs_entry("/tmp,mode=zzz").unwrap_err();
        assert!(err.to_string().contains("invalid octal tmpfs mode"));
    }

    #[test]
    fn test_parse_empty_path_errors() {
        let err = parse_tmpfs_entry(",size=256").unwrap_err();
        assert!(err.to_string().contains("empty path"));
    }

    #[test]
    fn test_parse_block_root_device_only() {
        let spec = parse_block_root("/dev/vda").unwrap();
        assert_eq!(spec.device, "/dev/vda");
        assert_eq!(spec.fstype, None);
    }

    #[test]
    fn test_parse_block_root_with_fstype() {
        let spec = parse_block_root("/dev/vda,fstype=ext4").unwrap();
        assert_eq!(spec.device, "/dev/vda");
        assert_eq!(spec.fstype, Some("ext4"));
    }

    #[test]
    fn test_parse_block_root_empty_device_errors() {
        let err = parse_block_root(",fstype=ext4").unwrap_err();
        assert!(err.to_string().contains("empty device path"));
    }

    #[test]
    fn test_parse_block_root_unknown_option_errors() {
        let err = parse_block_root("/dev/vda,bogus=42").unwrap_err();
        assert!(err.to_string().contains("unknown MSB_BLOCK_ROOT option"));
    }

    #[test]
    fn test_parse_block_root_empty_fstype_errors() {
        let err = parse_block_root("/dev/vda,fstype=").unwrap_err();
        assert!(err.to_string().contains("empty fstype"));
    }
}
