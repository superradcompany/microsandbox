//! PID 1 init: mount filesystems, apply tmpfs mounts, prepare runtime directories.

use crate::error::{AgentdError, AgentdResult};
use microsandbox_protocol::ENV_RLIMITS;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Parsed tmpfs mount specification.
#[derive(Debug)]
struct TmpfsSpec<'a> {
    path: &'a str,
    size_mib: Option<u32>,
    mode: Option<u32>,
    noexec: bool,
}

/// Parsed block-device root specification.
#[derive(Debug)]
struct BlockRootSpec<'a> {
    device: &'a str,
    fstype: Option<&'a str>,
}

/// Parsed virtiofs directory volume mount specification.
#[derive(Debug)]
struct DirMountSpec<'a> {
    tag: &'a str,
    guest_path: &'a str,
    readonly: bool,
}

/// Parsed virtiofs file volume mount specification.
#[derive(Debug)]
struct FileMountSpec<'a> {
    tag: &'a str,
    filename: &'a str,
    guest_path: &'a str,
    readonly: bool,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Performs synchronous PID 1 initialization.
///
/// Mounts essential filesystems, applies directory mounts from
/// `MSB_DIR_MOUNTS`, file mounts from `MSB_FILE_MOUNTS`, and tmpfs mounts
/// from `MSB_TMPFS`. Configures networking from `MSB_NET*` env vars and
/// prepares runtime directories.
pub fn init() -> AgentdResult<()> {
    linux::mount_filesystems()?;
    linux::mount_runtime()?;
    linux::mount_block_root()?;
    linux::apply_dir_mounts()?;
    linux::apply_file_mounts()?;
    crate::network::apply_hostname()?;
    linux::apply_tmpfs_mounts()?;
    linux::ensure_standard_tmp_permissions()?;
    crate::network::apply_network_config()?;
    crate::tls::install_ca_cert()?;
    linux::ensure_scripts_path_in_profile()?;
    linux::create_run_dir()?;
    Ok(())
}

/// Applies sandbox-wide resource limits for PID 1.
///
/// This runs before the rest of init so every later guest process inherits
/// the raised baseline automatically, including bootstrap daemons that are
/// not started through the per-exec API.
pub fn apply_rlimits() -> AgentdResult<()> {
    let Some(spec) = std::env::var_os(ENV_RLIMITS) else {
        return Ok(());
    };

    for entry in spec.to_string_lossy().split(';').filter(|entry| !entry.is_empty()) {
        let (resource_name, limit_spec) = entry.split_once('=').ok_or_else(|| {
            AgentdError::Init(format!(
                "{ENV_RLIMITS} entry must be resource=soft[:hard], got: {entry}"
            ))
        })?;

        let resource = parse_rlimit_resource(resource_name).ok_or_else(|| {
            AgentdError::Init(format!(
                "{ENV_RLIMITS} has unknown resource: {resource_name}"
            ))
        })?;

        let (soft, hard) = parse_rlimit_pair(limit_spec).map_err(|err| {
            AgentdError::Init(format!(
                "{ENV_RLIMITS} has invalid limit for {resource_name}: {err}"
            ))
        })?;

        let limit = libc::rlimit {
            rlim_cur: soft as libc::rlim_t,
            rlim_max: hard as libc::rlim_t,
        };

        // Edge case: we intentionally apply guest-wide defaults in PID 1
        // rather than at per-exec call sites so bootstrap daemons inherit the
        // raised soft limit before they open large descriptor sets.
        if unsafe { libc::setrlimit(resource as _, &limit) } != 0 {
            return Err(AgentdError::Init(format!(
                "failed to apply {ENV_RLIMITS} entry {entry}: {}",
                std::io::Error::last_os_error()
            )));
        }
    }

    Ok(())
}

/// Parses a single tmpfs entry: `path[,size=N][,mode=N][,noexec]`
///
/// Mode is parsed as octal (e.g. `mode=1777`).
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
            size_mib = Some(
                val.parse::<u32>()
                    .map_err(|_| AgentdError::Init(format!("invalid tmpfs size: {val}")))?,
            );
        } else if let Some(val) = opt.strip_prefix("mode=") {
            mode = Some(
                u32::from_str_radix(val, 8)
                    .map_err(|_| AgentdError::Init(format!("invalid octal tmpfs mode: {val}")))?,
            );
        } else {
            return Err(AgentdError::Init(format!("unknown tmpfs option: {opt}")));
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
fn parse_block_root(val: &str) -> AgentdResult<BlockRootSpec<'_>> {
    let mut parts = val.split(',');
    let device = parts.next().unwrap();
    if device.is_empty() {
        return Err(AgentdError::Init(
            "MSB_BLOCK_ROOT has empty device path".into(),
        ));
    }

    let mut fstype = None;
    for opt in parts {
        if let Some(val) = opt.strip_prefix("fstype=") {
            if val.is_empty() {
                return Err(AgentdError::Init(
                    "MSB_BLOCK_ROOT has empty fstype value".into(),
                ));
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

/// Parses a single virtiofs directory volume mount entry: `tag:guest_path[:ro]`
fn parse_dir_mount_entry(entry: &str) -> AgentdResult<DirMountSpec<'_>> {
    let parts: Vec<&str> = entry.split(':').collect();
    if parts.len() < 2 {
        return Err(AgentdError::Init(format!(
            "MSB_DIR_MOUNTS entry must be tag:path[:ro], got: {entry}"
        )));
    }

    let tag = parts[0];
    let guest_path = parts[1];
    let readonly = match parts.get(2) {
        Some(&"ro") => true,
        None => false,
        Some(flag) => {
            return Err(AgentdError::Init(format!(
                "MSB_DIR_MOUNTS unknown flag '{flag}' (expected 'ro')"
            )));
        }
    };

    if parts.len() > 3 {
        return Err(AgentdError::Init(format!(
            "MSB_DIR_MOUNTS entry has too many parts: {entry}"
        )));
    }

    if tag.is_empty() {
        return Err(AgentdError::Init(
            "MSB_DIR_MOUNTS entry has empty tag".into(),
        ));
    }
    if guest_path.is_empty() || !guest_path.starts_with('/') {
        return Err(AgentdError::Init(format!(
            "MSB_DIR_MOUNTS guest path must be absolute: {guest_path}"
        )));
    }

    Ok(DirMountSpec {
        tag,
        guest_path,
        readonly,
    })
}

/// Parses a single virtiofs file volume mount entry: `tag:filename:guest_path[:ro]`
fn parse_file_mount_entry(entry: &str) -> AgentdResult<FileMountSpec<'_>> {
    let parts: Vec<&str> = entry.split(':').collect();
    if parts.len() < 3 {
        return Err(AgentdError::Init(format!(
            "MSB_FILE_MOUNTS entry must be tag:filename:path[:ro], got: {entry}"
        )));
    }

    let tag = parts[0];
    let filename = parts[1];
    let guest_path = parts[2];
    let readonly = match parts.get(3) {
        Some(&"ro") => true,
        None => false,
        Some(flag) => {
            return Err(AgentdError::Init(format!(
                "MSB_FILE_MOUNTS unknown flag '{flag}' (expected 'ro')"
            )));
        }
    };

    if parts.len() > 4 {
        return Err(AgentdError::Init(format!(
            "MSB_FILE_MOUNTS entry has too many parts: {entry}"
        )));
    }

    if tag.is_empty() {
        return Err(AgentdError::Init(
            "MSB_FILE_MOUNTS entry has empty tag".into(),
        ));
    }
    if filename.is_empty() {
        return Err(AgentdError::Init(
            "MSB_FILE_MOUNTS entry has empty filename".into(),
        ));
    }
    if guest_path.is_empty() || !guest_path.starts_with('/') {
        return Err(AgentdError::Init(format!(
            "MSB_FILE_MOUNTS guest path must be absolute: {guest_path}"
        )));
    }

    Ok(FileMountSpec {
        tag,
        filename,
        guest_path,
        readonly,
    })
}

fn ensure_scripts_profile_block(profile: &str) -> String {
    const START_MARKER: &str = "# >>> microsandbox scripts path >>>";
    const END_MARKER: &str = "# <<< microsandbox scripts path <<<";
    const BLOCK: &str = "# >>> microsandbox scripts path >>>\ncase \":$PATH:\" in\n  *:/.msb/scripts:*) ;;\n  *) export PATH=\"/.msb/scripts:$PATH\" ;;\nesac\n# <<< microsandbox scripts path <<<\n";

    if profile.contains(START_MARKER) && profile.contains(END_MARKER) {
        return profile.to_string();
    }

    let mut updated = profile.to_string();
    if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push_str(BLOCK);
    updated
}

fn parse_rlimit_pair(value: &str) -> Result<(u64, u64), String> {
    let mut parts = value.split(':');
    let soft = parts
        .next()
        .ok_or_else(|| "missing soft limit".to_string())?
        .parse::<u64>()
        .map_err(|err| format!("invalid soft limit: {err}"))?;
    let hard = match parts.next() {
        Some(value) => value
            .parse::<u64>()
            .map_err(|err| format!("invalid hard limit: {err}"))?,
        None => soft,
    };

    if parts.next().is_some() {
        return Err("too many ':' separators".into());
    }

    if soft > hard {
        return Err("soft limit cannot exceed hard limit".into());
    }

    Ok((soft, hard))
}

fn parse_rlimit_resource(name: &str) -> Option<libc::c_int> {
    // Linux x86_64 RLIMIT_* values for resources not exposed by libc on all platforms.
    const RLIMIT_LOCKS: libc::c_int = 10;
    const RLIMIT_SIGPENDING: libc::c_int = 11;
    const RLIMIT_MSGQUEUE: libc::c_int = 12;
    const RLIMIT_NICE: libc::c_int = 13;
    const RLIMIT_RTPRIO: libc::c_int = 14;
    const RLIMIT_RTTIME: libc::c_int = 15;

    match name.to_ascii_lowercase().as_str() {
        "cpu" => Some(libc::RLIMIT_CPU as _),
        "fsize" => Some(libc::RLIMIT_FSIZE as _),
        "data" => Some(libc::RLIMIT_DATA as _),
        "stack" => Some(libc::RLIMIT_STACK as _),
        "core" => Some(libc::RLIMIT_CORE as _),
        "rss" => Some(libc::RLIMIT_RSS as _),
        "nproc" => Some(libc::RLIMIT_NPROC as _),
        "nofile" => Some(libc::RLIMIT_NOFILE as _),
        "memlock" => Some(libc::RLIMIT_MEMLOCK as _),
        "as" => Some(libc::RLIMIT_AS as _),
        "locks" => Some(RLIMIT_LOCKS),
        "sigpending" => Some(RLIMIT_SIGPENDING),
        "msgqueue" => Some(RLIMIT_MSGQUEUE),
        "nice" => Some(RLIMIT_NICE),
        "rtprio" => Some(RLIMIT_RTPRIO),
        "rttime" => Some(RLIMIT_RTTIME),
        _ => None,
    }
}

//--------------------------------------------------------------------------------------------------
// Modules
//--------------------------------------------------------------------------------------------------

mod linux {
    use std::{
        os::unix::fs::{PermissionsExt, symlink},
        path::Path,
    };

    use nix::{
        mount::{MntFlags, MsFlags, mount, umount2},
        sys::stat::Mode,
        unistd::{chdir, chroot, mkdir},
    };

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
            symlink("/proc/self/fd", "/dev/fd")
                .map_err(|e| AgentdError::Init(format!("failed to symlink /dev/fd: {e}")))?;
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

        mount(Some("."), "/", None::<&str>, MsFlags::MS_MOVE, None::<&str>)
            .map_err(|e| AgentdError::Init(format!("failed to MS_MOVE /newroot to /: {e}")))?;

        chroot(".").map_err(|e| AgentdError::Init(format!("failed to chroot: {e}")))?;

        chdir("/")
            .map_err(|e| AgentdError::Init(format!("failed to chdir / after chroot: {e}")))?;

        // Re-mount essential filesystems in the new root.
        mount_filesystems()?;

        Ok(())
    }

    /// Tries every filesystem type listed in `/proc/filesystems` until one succeeds.
    fn try_mount(device: &str, target: &str) -> AgentdResult<()> {
        let content = std::fs::read_to_string("/proc/filesystems")
            .map_err(|e| AgentdError::Init(format!("failed to read /proc/filesystems: {e}")))?;

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

    /// Reads `MSB_DIR_MOUNTS` env var and mounts each virtiofs directory volume.
    ///
    /// For each entry, creates the guest mount point directory and mounts the
    /// virtiofs share using the tag provided by the host. If the entry
    /// specifies `:ro`, the mount is made read-only via `MS_RDONLY`.
    ///
    /// Missing env var is not an error (no directory volume mounts requested).
    /// Parse failures and mount failures are hard errors.
    pub fn apply_dir_mounts() -> AgentdResult<()> {
        let val = match std::env::var(microsandbox_protocol::ENV_DIR_MOUNTS) {
            Ok(v) if !v.is_empty() => v,
            _ => return Ok(()),
        };

        for entry in val.split(';') {
            if entry.is_empty() {
                continue;
            }

            let spec = super::parse_dir_mount_entry(entry)?;
            mount_dir(&spec)?;
        }

        Ok(())
    }

    /// Mounts a single virtiofs directory share from a parsed spec.
    fn mount_dir(spec: &super::DirMountSpec<'_>) -> AgentdResult<()> {
        let path = spec.guest_path;

        // Create the mount point directory.
        std::fs::create_dir_all(path)
            .map_err(|e| AgentdError::Init(format!("failed to create directory {path}: {e}")))?;

        let mut flags = MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_RELATIME;
        if spec.readonly {
            flags |= MsFlags::MS_RDONLY;
        }

        mount(Some(spec.tag), path, Some("virtiofs"), flags, None::<&str>).map_err(|e| {
            AgentdError::Init(format!(
                "failed to mount virtiofs tag '{}' at {path}: {e}",
                spec.tag
            ))
        })?;

        Ok(())
    }

    /// Reads `MSB_FILE_MOUNTS` env var and bind-mounts each file.
    ///
    /// Missing env var is not an error (no file mounts requested).
    /// Parse failures and mount failures are hard errors.
    pub fn apply_file_mounts() -> AgentdResult<()> {
        let val = match std::env::var(microsandbox_protocol::ENV_FILE_MOUNTS) {
            Ok(v) if !v.is_empty() => v,
            _ => return Ok(()),
        };

        // Create the staging root directory.
        std::fs::create_dir_all(microsandbox_protocol::FILE_MOUNTS_DIR).map_err(|e| {
            AgentdError::Init(format!(
                "failed to create file mounts dir {}: {e}",
                microsandbox_protocol::FILE_MOUNTS_DIR
            ))
        })?;

        for entry in val.split(';') {
            if entry.is_empty() {
                continue;
            }

            let spec = super::parse_file_mount_entry(entry)?;
            mount_file(&spec)?;
        }

        // Best-effort cleanup of the staging root (succeeds only if all
        // per-tag subdirs were already removed inside mount_file).
        let _ = std::fs::remove_dir(microsandbox_protocol::FILE_MOUNTS_DIR);

        Ok(())
    }

    /// Mounts a single file from a virtiofs share via bind mount.
    fn mount_file(spec: &super::FileMountSpec<'_>) -> AgentdResult<()> {
        let staging_path = format!("{}/{}", microsandbox_protocol::FILE_MOUNTS_DIR, spec.tag);

        // 1. Create the staging mount point directory.
        std::fs::create_dir_all(&staging_path).map_err(|e| {
            AgentdError::Init(format!("failed to create staging dir {staging_path}: {e}"))
        })?;

        // 2. Mount the virtiofs share at the staging directory.
        let mut flags = MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_RELATIME;
        if spec.readonly {
            flags |= MsFlags::MS_RDONLY;
        }

        mount(
            Some(spec.tag),
            staging_path.as_str(),
            Some("virtiofs"),
            flags,
            None::<&str>,
        )
        .map_err(|e| {
            AgentdError::Init(format!(
                "failed to mount virtiofs tag '{}' at {staging_path}: {e}",
                spec.tag
            ))
        })?;

        // 3. Create parent directories for the guest path.
        let guest = Path::new(spec.guest_path);
        if let Some(parent) = guest.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                AgentdError::Init(format!(
                    "failed to create parent dirs for {}: {e}",
                    spec.guest_path
                ))
            })?;
        }

        // 4. Create the target file (touch) as a bind mount target.
        std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(spec.guest_path)
            .map_err(|e| {
                AgentdError::Init(format!(
                    "failed to create bind target {}: {e}",
                    spec.guest_path
                ))
            })?;

        // 5. Bind mount the file from staging to the guest path.
        let source_path = format!("{staging_path}/{}", spec.filename);
        mount(
            Some(source_path.as_str()),
            spec.guest_path,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .map_err(|e| {
            AgentdError::Init(format!(
                "failed to bind mount {source_path} to {}: {e}",
                spec.guest_path
            ))
        })?;

        // 6. If read-only, remount the bind mount as read-only.
        if spec.readonly {
            mount(
                None::<&str>,
                spec.guest_path,
                None::<&str>,
                MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
                None::<&str>,
            )
            .map_err(|e| {
                AgentdError::Init(format!(
                    "failed to remount {} as read-only: {e}",
                    spec.guest_path
                ))
            })?;
        }

        // 7. Unmount the staging virtiofs share and remove the directory.
        //    The bind mount keeps the file accessible at the guest path;
        //    removing the share prevents alternate-path access.
        let _ = umount2(staging_path.as_str(), MntFlags::MNT_DETACH);
        let _ = std::fs::remove_dir(&staging_path);

        Ok(())
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

    /// Ensure standard temporary directories are writable and sticky.
    pub fn ensure_standard_tmp_permissions() -> AgentdResult<()> {
        ensure_directory_mode("/tmp", 0o1777)?;
        ensure_directory_mode("/var/tmp", 0o1777)?;
        Ok(())
    }

    /// Mounts a single tmpfs from a parsed spec.
    fn mount_tmpfs(spec: &TmpfsSpec<'_>) -> AgentdResult<()> {
        let path = spec.path;

        // Determine the permission mode.
        let mode = spec
            .mode
            .unwrap_or(if path == "/tmp" || path == "/var/tmp" {
                0o1777
            } else {
                0o755
            });

        // Create the target directory.
        std::fs::create_dir_all(path)
            .map_err(|e| AgentdError::Init(format!("failed to create directory {path}: {e}")))?;

        // Flags: nosuid + nodev (sensible safety defaults).
        let mut flags = MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_RELATIME;
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

    /// Ensure login shells preserve `/.msb/scripts` on PATH.
    pub fn ensure_scripts_path_in_profile() -> AgentdResult<()> {
        let profile_path = Path::new("/etc/profile");
        let existing = match std::fs::read_to_string(profile_path) {
            Ok(contents) => contents,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(err) => {
                return Err(AgentdError::Init(format!(
                    "failed to read {}: {err}",
                    profile_path.display()
                )));
            }
        };

        let updated = super::ensure_scripts_profile_block(&existing);
        if updated != existing {
            if let Some(parent) = profile_path.parent() {
                std::fs::create_dir_all(parent).map_err(|err| {
                    AgentdError::Init(format!("failed to create {}: {err}", parent.display()))
                })?;
            }
            std::fs::write(profile_path, updated).map_err(|err| {
                AgentdError::Init(format!("failed to write {}: {err}", profile_path.display()))
            })?;
        }

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

    fn ensure_directory_mode(path: &str, mode: u32) -> AgentdResult<()> {
        std::fs::create_dir_all(path)
            .map_err(|e| AgentdError::Init(format!("failed to create directory {path}: {e}")))?;

        let metadata = std::fs::metadata(path)
            .map_err(|e| AgentdError::Init(format!("failed to stat {path}: {e}")))?;
        if !metadata.is_dir() {
            return Err(AgentdError::Init(format!(
                "expected directory at {path}, found non-directory"
            )));
        }

        let current_mode = metadata.permissions().mode() & 0o7777;
        if current_mode != mode {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(|e| {
                AgentdError::Init(format!("failed to chmod {path} to {mode:o}: {e}"))
            })?;
        }

        Ok(())
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

    #[test]
    fn test_parse_file_mount_entry_basic() {
        let spec = parse_file_mount_entry("fm_config:app.conf:/etc/app.conf").unwrap();
        assert_eq!(spec.tag, "fm_config");
        assert_eq!(spec.filename, "app.conf");
        assert_eq!(spec.guest_path, "/etc/app.conf");
        assert!(!spec.readonly);
    }

    #[test]
    fn test_parse_file_mount_entry_readonly() {
        let spec = parse_file_mount_entry("fm_config:app.conf:/etc/app.conf:ro").unwrap();
        assert!(spec.readonly);
    }

    #[test]
    fn test_parse_file_mount_entry_too_few_parts() {
        assert!(parse_file_mount_entry("fm_config:/etc/app.conf").is_err());
    }

    #[test]
    fn test_parse_file_mount_entry_empty_filename() {
        assert!(parse_file_mount_entry("fm_config::/etc/app.conf").is_err());
    }

    #[test]
    fn test_parse_file_mount_entry_relative_path() {
        assert!(parse_file_mount_entry("fm_config:app.conf:relative/path").is_err());
    }

    #[test]
    fn test_parse_file_mount_entry_too_many_parts() {
        assert!(parse_file_mount_entry("fm_config:app.conf:/etc/app.conf:ro:extra").is_err());
    }

    #[test]
    fn test_parse_file_mount_entry_unknown_flag() {
        assert!(parse_file_mount_entry("fm_config:app.conf:/etc/app.conf:rw").is_err());
    }

    #[test]
    fn test_parse_file_mount_entry_empty_tag() {
        assert!(parse_file_mount_entry(":app.conf:/etc/app.conf").is_err());
    }

    #[test]
    fn test_ensure_scripts_profile_block_appends_block() {
        let updated = ensure_scripts_profile_block("export PATH=/usr/bin:/bin\n");
        assert!(updated.contains("# >>> microsandbox scripts path >>>"));
        assert!(updated.contains("export PATH=\"/.msb/scripts:$PATH\""));
    }

    #[test]
    fn test_ensure_scripts_profile_block_adds_newline_when_missing() {
        let updated = ensure_scripts_profile_block("export PATH=/usr/bin:/bin");
        assert!(updated.contains("/usr/bin:/bin\n# >>> microsandbox scripts path >>>"));
    }

    #[test]
    fn test_ensure_scripts_profile_block_is_idempotent() {
        let profile = ensure_scripts_profile_block("");
        let updated = ensure_scripts_profile_block(&profile);
        assert_eq!(profile, updated);
    }

    #[test]
    fn test_parse_rlimit_pair_uses_soft_for_hard_when_omitted() {
        assert_eq!(parse_rlimit_pair("65535").unwrap(), (65_535, 65_535));
    }

    #[test]
    fn test_parse_rlimit_pair_parses_soft_and_hard() {
        assert_eq!(parse_rlimit_pair("4096:65535").unwrap(), (4_096, 65_535));
    }

    #[test]
    fn test_parse_rlimit_pair_rejects_soft_above_hard() {
        let err = parse_rlimit_pair("65535:4096").unwrap_err();
        assert!(err.contains("soft limit cannot exceed hard limit"));
    }

    #[test]
    fn test_parse_rlimit_resource_supports_nofile() {
        assert_eq!(parse_rlimit_resource("nofile"), Some(libc::RLIMIT_NOFILE as _));
        assert_eq!(parse_rlimit_resource("NOFILE"), Some(libc::RLIMIT_NOFILE as _));
    }
}
