//! PID 1 init: mount filesystems, apply tmpfs mounts, prepare runtime directories.

use crate::config::AgentdConfig;
use crate::error::AgentdResult;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Performs synchronous PID 1 initialization.
///
/// Mounts essential filesystems, applies directory mounts, file mounts, and
/// tmpfs mounts from the parsed config. Configures networking and prepares
/// runtime directories.
pub fn init(config: &AgentdConfig) -> AgentdResult<()> {
    linux::mount_filesystems()?;
    linux::mount_runtime()?;
    if let Some(spec) = &config.block_root {
        linux::mount_block_root(spec)?;
    }
    linux::apply_dir_mounts(&config.dir_mounts)?;
    linux::apply_file_mounts(&config.file_mounts)?;
    crate::network::apply_hostname(config.hostname.as_deref())?;
    linux::apply_tmpfs_mounts(&config.tmpfs)?;
    linux::ensure_standard_tmp_permissions()?;
    crate::network::apply_network_config(config.network())?;
    crate::tls::install_ca_cert()?;
    linux::ensure_scripts_path_in_profile()?;
    linux::create_run_dir()?;
    Ok(())
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

    use crate::config::{BlockRootSpec, DirMountSpec, FileMountSpec, TmpfsSpec};
    use crate::error::{AgentdError, AgentdResult};

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

    /// Assembles the root filesystem from the parsed block-root spec.
    ///
    /// Dispatches on the spec variant, then pivots `/newroot` into `/`.
    pub fn mount_block_root(spec: &BlockRootSpec) -> AgentdResult<()> {
        mkdir_ignore_exists("/newroot")?;

        match spec {
            BlockRootSpec::DiskImage { device, fstype } => {
                mount_disk_image(device, fstype.as_deref())?;
            }
            BlockRootSpec::OciErofs {
                lower,
                upper,
                upper_fstype,
            } => {
                mount_oci_erofs(lower, upper, upper_fstype)?;
            }
        }

        pivot_to_newroot()?;

        Ok(())
    }

    /// Mount a single disk image at /newroot.
    fn mount_disk_image(device: &str, fstype: Option<&str>) -> AgentdResult<()> {
        if let Some(fstype) = fstype {
            mount(
                Some(device),
                "/newroot",
                Some(fstype),
                MsFlags::empty(),
                None::<&str>,
            )
            .map_err(|e| {
                AgentdError::Init(format!(
                    "failed to mount {device} at /newroot as {fstype}: {e}"
                ))
            })?;
        } else {
            try_mount(device, "/newroot")?;
        }
        Ok(())
    }

    /// Mount merged EROFS lower + writable upper + overlayfs at /newroot.
    fn mount_oci_erofs(
        lower_device: &str,
        upper_device: &str,
        upper_fstype: &str,
    ) -> AgentdResult<()> {
        // Mount the EROFS lower device read-only.
        let lower_dir = "/.msb/rootfs/lower";
        mkdir_ignore_exists("/.msb/rootfs")?;
        mkdir_ignore_exists("/.msb/rootfs/lower")?;
        mount(
            Some(lower_device),
            lower_dir,
            Some("erofs"),
            MsFlags::MS_RDONLY,
            None::<&str>,
        )
        .map_err(|e| AgentdError::Init(format!("mount {lower_device} at {lower_dir}: {e}")))?;

        // Mount the writable upper device.
        let upperfs_dir = "/.msb/rootfs/upperfs";
        mkdir_ignore_exists("/.msb/rootfs/upperfs")?;
        mount(
            Some(upper_device),
            upperfs_dir,
            Some(upper_fstype),
            MsFlags::empty(),
            None::<&str>,
        )
        .map_err(|e| AgentdError::Init(format!("mount {upper_device} at {upperfs_dir}: {e}")))?;

        // Create upper and work subdirs on the writable device.
        let upper_dir = format!("{upperfs_dir}/upper");
        let work_dir = format!("{upperfs_dir}/work");
        std::fs::create_dir_all(&upper_dir)
            .map_err(|e| AgentdError::Init(format!("mkdir {upper_dir}: {e}")))?;
        std::fs::create_dir_all(&work_dir)
            .map_err(|e| AgentdError::Init(format!("mkdir {work_dir}: {e}")))?;

        // Assemble overlayfs mount.
        let mount_data = format!("lowerdir={lower_dir},upperdir={upper_dir},workdir={work_dir}");

        mount(
            Some("overlay"),
            "/newroot",
            Some("overlay"),
            MsFlags::empty(),
            Some(mount_data.as_str()),
        )
        .map_err(|e| AgentdError::Init(format!("mount overlay at /newroot: {e}")))?;

        Ok(())
    }

    /// Bind-mount /.msb into /newroot, then MS_MOVE + chroot + re-mount essentials.
    fn pivot_to_newroot() -> AgentdResult<()> {
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

        chdir("/newroot")
            .map_err(|e| AgentdError::Init(format!("failed to chdir /newroot: {e}")))?;

        mount(Some("."), "/", None::<&str>, MsFlags::MS_MOVE, None::<&str>)
            .map_err(|e| AgentdError::Init(format!("failed to MS_MOVE /newroot to /: {e}")))?;

        chroot(".").map_err(|e| AgentdError::Init(format!("failed to chroot: {e}")))?;

        chdir("/")
            .map_err(|e| AgentdError::Init(format!("failed to chdir / after chroot: {e}")))?;

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

    /// Mounts each virtiofs directory volume from the parsed specs.
    pub fn apply_dir_mounts(specs: &[DirMountSpec]) -> AgentdResult<()> {
        for spec in specs {
            mount_dir(spec)?;
        }
        Ok(())
    }

    /// Mounts a single virtiofs directory share from a parsed spec.
    fn mount_dir(spec: &DirMountSpec) -> AgentdResult<()> {
        let path = spec.guest_path.as_str();

        // Create the mount point directory.
        std::fs::create_dir_all(path)
            .map_err(|e| AgentdError::Init(format!("failed to create directory {path}: {e}")))?;

        let mut flags = MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_RELATIME;
        if spec.readonly {
            flags |= MsFlags::MS_RDONLY;
        }

        mount(
            Some(spec.tag.as_str()),
            path,
            Some("virtiofs"),
            flags,
            None::<&str>,
        )
        .map_err(|e| {
            AgentdError::Init(format!(
                "failed to mount virtiofs tag '{}' at {path}: {e}",
                spec.tag
            ))
        })?;

        Ok(())
    }

    /// Bind-mounts each file from virtiofs shares.
    pub fn apply_file_mounts(specs: &[FileMountSpec]) -> AgentdResult<()> {
        if specs.is_empty() {
            return Ok(());
        }

        // Create the staging root directory.
        std::fs::create_dir_all(microsandbox_protocol::FILE_MOUNTS_DIR).map_err(|e| {
            AgentdError::Init(format!(
                "failed to create file mounts dir {}: {e}",
                microsandbox_protocol::FILE_MOUNTS_DIR
            ))
        })?;

        for spec in specs {
            mount_file(spec)?;
        }

        // Best-effort cleanup of the staging root (succeeds only if all
        // per-tag subdirs were already removed inside mount_file).
        let _ = std::fs::remove_dir(microsandbox_protocol::FILE_MOUNTS_DIR);

        Ok(())
    }

    /// Mounts a single file from a virtiofs share via bind mount.
    fn mount_file(spec: &FileMountSpec) -> AgentdResult<()> {
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
            Some(spec.tag.as_str()),
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
        let guest = Path::new(&spec.guest_path);
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
            .open(&spec.guest_path)
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
            spec.guest_path.as_str(),
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
                spec.guest_path.as_str(),
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

    /// Mounts each tmpfs from the parsed specs.
    pub fn apply_tmpfs_mounts(specs: &[TmpfsSpec]) -> AgentdResult<()> {
        for spec in specs {
            mount_tmpfs(spec)?;
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
    fn mount_tmpfs(spec: &TmpfsSpec) -> AgentdResult<()> {
        let path = spec.path.as_str();

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
}
