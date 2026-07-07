//! PID 1 init: mount filesystems, apply tmpfs mounts, prepare runtime directories.

use crate::config::{BootParams, SecurityProfile};
use crate::error::AgentdResult;
use crate::{network, rlimit, tls};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Performs synchronous PID 1 initialization.
///
/// Applies sandbox-wide resource limits first so every later guest process
/// inherits the raised baseline, then mounts filesystems, applies directory
/// mounts, file mounts, and tmpfs mounts from the parsed params. Configures
/// networking and prepares runtime directories.
///
/// Consumes the [`BootParams`] by value — the data is one-shot and not
/// needed after init returns.
pub fn init(
    mut params: BootParams,
    before_user_mounts: impl FnOnce() -> AgentdResult<()>,
) -> AgentdResult<()> {
    rlimit::apply_baseline(&params.rlimits)?;
    linux::mount_filesystems()?;
    linux::mount_runtime()?;
    if let Some(spec) = &params.block_root {
        linux::mount_block_root(spec)?;
    }
    before_user_mounts()?;
    if params.security_profile == SecurityProfile::Restricted {
        force_restricted_mount_flags(&mut params);
    }
    linux::apply_dir_mounts(&params.dir_mounts)?;
    linux::apply_file_mounts(&params.file_mounts)?;
    linux::apply_disk_mounts(&params.disk_mounts)?;
    network::apply_hostname(
        params.hostname.as_deref(),
        params.host_alias.as_deref(),
        params.net_ipv4.as_ref().map(|v4| v4.gateway),
        params.net_ipv6.as_ref().map(|v6| v6.gateway),
    )?;
    linux::apply_tmpfs_mounts(&params.tmpfs)?;
    linux::ensure_standard_tmp_permissions()?;
    network::apply_network_config(params.network())?;
    tls::install_ca_cert()?;
    tls::install_host_cas()?;
    linux::ensure_scripts_path_in_profile()?;
    linux::create_run_dir()?;
    Ok(())
}

fn force_restricted_mount_flags(params: &mut BootParams) {
    for spec in &mut params.dir_mounts {
        spec.nosuid = true;
        spec.nodev = true;
    }
    for spec in &mut params.file_mounts {
        spec.nosuid = true;
        spec.nodev = true;
    }
    for spec in &mut params.disk_mounts {
        spec.nosuid = true;
        spec.nodev = true;
    }
    for spec in &mut params.tmpfs {
        spec.nosuid = true;
        spec.nodev = true;
    }
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
    use std::os::unix::fs::{self as unix_fs, PermissionsExt};
    use std::path::Path;
    use std::{fs, thread, time::Duration};

    use nix::mount::{self, MntFlags, MsFlags};
    use nix::sys::stat::Mode;
    use nix::unistd;

    use crate::config::{BlockRootSpec, DirMountSpec, DiskMountSpec, FileMountSpec, TmpfsSpec};
    use crate::error::{AgentdError, AgentdResult};

    const UPPER_METRICS_PATH: &str = "/sys/kernel/msb_metrics/upper_path";
    const UPPER_METRICS_REGISTER_ATTEMPTS: usize = 100;
    const UPPER_METRICS_REGISTER_RETRY: Duration = Duration::from_millis(10);

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
            unix_fs::symlink("/proc/self/fd", "/dev/fd")
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
            mount::mount(
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
            let fstypes = read_proc_filesystems()?;
            try_mount_any(device, "/newroot", MsFlags::empty(), &fstypes)?;
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
        mount::mount(
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
        mount::mount(
            Some(upper_device),
            upperfs_dir,
            Some(upper_fstype),
            MsFlags::empty(),
            None::<&str>,
        )
        .map_err(|e| AgentdError::Init(format!("mount {upper_device} at {upperfs_dir}: {e}")))?;
        register_upper_metrics(upperfs_dir);
        // The pivot below makes this mount unreachable by path; pin a fd now so poweroff teardown can still remount it read-only.
        crate::teardown::register_upper_fs(upperfs_dir);

        // Create upper and work subdirs on the writable device.
        let upper_dir = format!("{upperfs_dir}/upper");
        let work_dir = format!("{upperfs_dir}/work");
        fs::create_dir_all(&upper_dir)
            .map_err(|e| AgentdError::Init(format!("mkdir {upper_dir}: {e}")))?;
        fs::create_dir_all(&work_dir)
            .map_err(|e| AgentdError::Init(format!("mkdir {work_dir}: {e}")))?;

        // Assemble overlayfs mount.
        let mount_data = format!("lowerdir={lower_dir},upperdir={upper_dir},workdir={work_dir}");

        mount::mount(
            Some("overlay"),
            "/newroot",
            Some("overlay"),
            MsFlags::empty(),
            Some(mount_data.as_str()),
        )
        .map_err(|e| AgentdError::Init(format!("mount overlay at /newroot: {e}")))?;

        Ok(())
    }

    fn register_upper_metrics(upperfs_dir: &str) {
        for attempt in 0..UPPER_METRICS_REGISTER_ATTEMPTS {
            match fs::write(UPPER_METRICS_PATH, upperfs_dir) {
                Ok(()) => return,
                Err(err)
                    if err.kind() == std::io::ErrorKind::NotFound
                        && attempt + 1 < UPPER_METRICS_REGISTER_ATTEMPTS =>
                {
                    thread::sleep(UPPER_METRICS_REGISTER_RETRY);
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => return,
                Err(err) => {
                    eprintln!("agentd: upper metrics registration failed: {err}");
                    return;
                }
            }
        }
    }

    /// Bind-mount /.msb into /newroot, then MS_MOVE + chroot + re-mount essentials.
    fn pivot_to_newroot() -> AgentdResult<()> {
        let msb_target = "/newroot/.msb";
        mkdir_ignore_exists(msb_target)?;
        mount::mount(
            Some(microsandbox_protocol::RUNTIME_MOUNT_POINT),
            msb_target,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .map_err(|e| AgentdError::Init(format!("failed to bind-mount /.msb into /newroot: {e}")))?;

        unistd::chdir("/newroot")
            .map_err(|e| AgentdError::Init(format!("failed to chdir /newroot: {e}")))?;

        mount::mount(Some("."), "/", None::<&str>, MsFlags::MS_MOVE, None::<&str>)
            .map_err(|e| AgentdError::Init(format!("failed to MS_MOVE /newroot to /: {e}")))?;

        unistd::chroot(".").map_err(|e| AgentdError::Init(format!("failed to chroot: {e}")))?;

        unistd::chdir("/")
            .map_err(|e| AgentdError::Init(format!("failed to chdir / after chroot: {e}")))?;

        mount_filesystems()?;

        Ok(())
    }

    /// Read native filesystem types from `/proc/filesystems`, skipping
    /// `nodev` entries (virtual filesystems that can't back a real device).
    fn read_proc_filesystems() -> AgentdResult<Vec<String>> {
        let content = fs::read_to_string("/proc/filesystems")
            .map_err(|e| AgentdError::Init(format!("failed to read /proc/filesystems: {e}")))?;
        Ok(content
            .lines()
            .filter_map(|line| {
                if line.starts_with("nodev") {
                    return None;
                }
                let fstype = line.trim();
                if fstype.is_empty() {
                    None
                } else {
                    Some(fstype.to_string())
                }
            })
            .collect())
    }

    /// Try mounting `device` at `target` with `flags`, walking the supplied
    /// candidate filesystem list until one succeeds. Use
    /// `read_proc_filesystems` to build the candidate list (typically once
    /// per init phase) and reuse it across multiple mount attempts.
    fn try_mount_any(
        device: &str,
        target: &str,
        flags: MsFlags,
        fstypes: &[String],
    ) -> AgentdResult<()> {
        for fstype in fstypes {
            if mount::mount(
                Some(device),
                target,
                Some(fstype.as_str()),
                flags,
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

    /// Filesystem-specific mount data for disk-image volume mounts.
    fn disk_mount_data(fstype: &str, readonly: bool) -> Option<&'static str> {
        if readonly && fstype == "ext4" {
            // A read-only block device cannot replay an ext4 journal. `noload`
            // lets seeded or intentionally read-only ext4 images mount without
            // attempting journal recovery.
            Some("noload")
        } else {
            None
        }
    }

    /// Try mounting a disk-image volume, adding filesystem-specific options
    /// where read-only block devices need them.
    fn try_mount_disk_any(
        device: &str,
        target: &str,
        flags: MsFlags,
        readonly: bool,
        fstypes: &[String],
    ) -> AgentdResult<()> {
        for fstype in fstypes {
            let data = disk_mount_data(fstype, readonly);
            if mount::mount(Some(device), target, Some(fstype.as_str()), flags, data).is_ok() {
                return Ok(());
            }
        }
        Err(AgentdError::Init(format!(
            "disk mount: failed to mount {device} at {target}: no supported filesystem found"
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
        fs::create_dir_all(path)
            .map_err(|e| AgentdError::Init(format!("failed to create directory {path}: {e}")))?;

        let mut flags = MsFlags::MS_RELATIME;
        if spec.nosuid {
            flags |= MsFlags::MS_NOSUID;
        }
        if spec.nodev {
            flags |= MsFlags::MS_NODEV;
        }
        if spec.noexec {
            flags |= MsFlags::MS_NOEXEC;
        }
        if spec.readonly {
            flags |= MsFlags::MS_RDONLY;
        }

        mount::mount(
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
        fs::create_dir_all(microsandbox_protocol::FILE_MOUNTS_DIR).map_err(|e| {
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
        let _ = fs::remove_dir(microsandbox_protocol::FILE_MOUNTS_DIR);

        Ok(())
    }

    /// Mounts a single file from a virtiofs share via bind mount.
    fn mount_file(spec: &FileMountSpec) -> AgentdResult<()> {
        let staging_path = format!("{}/{}", microsandbox_protocol::FILE_MOUNTS_DIR, spec.tag);

        // 1. Create the staging mount point directory.
        fs::create_dir_all(&staging_path).map_err(|e| {
            AgentdError::Init(format!("failed to create staging dir {staging_path}: {e}"))
        })?;

        // 2. Mount the virtiofs share at the staging directory.
        let mut flags = MsFlags::MS_RELATIME;
        if spec.nosuid {
            flags |= MsFlags::MS_NOSUID;
        }
        if spec.nodev {
            flags |= MsFlags::MS_NODEV;
        }
        if spec.noexec {
            flags |= MsFlags::MS_NOEXEC;
        }
        if spec.readonly {
            flags |= MsFlags::MS_RDONLY;
        }

        mount::mount(
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

        let bind_result = (|| {
            // 3. Create parent directories for the guest path.
            let guest = Path::new(&spec.guest_path);
            if let Some(parent) = guest.parent() {
                fs::create_dir_all(parent).map_err(|e| {
                    AgentdError::Init(format!(
                        "failed to create parent dirs for {}: {e}",
                        spec.guest_path
                    ))
                })?;
            }

            // 4. Create the target file (touch) as a bind mount target.
            fs::OpenOptions::new()
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
            mount::mount(
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

            // 6. Remount the file bind with the guest-facing VFS flags.
            let mut remount_flags = MsFlags::MS_BIND | MsFlags::MS_REMOUNT;
            if spec.nosuid {
                remount_flags |= MsFlags::MS_NOSUID;
            }
            if spec.nodev {
                remount_flags |= MsFlags::MS_NODEV;
            }
            if spec.noexec {
                remount_flags |= MsFlags::MS_NOEXEC;
            }
            if spec.readonly {
                remount_flags |= MsFlags::MS_RDONLY;
            }
            mount::mount(
                None::<&str>,
                spec.guest_path.as_str(),
                None::<&str>,
                remount_flags,
                None::<&str>,
            )
            .map_err(|e| {
                AgentdError::Init(format!(
                    "failed to remount {} with volume flags: {e}",
                    spec.guest_path
                ))
            })?;

            Ok(())
        })();

        let cleanup_result = cleanup_file_mount_staging(&staging_path);
        match (bind_result, cleanup_result) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(err), Ok(())) => Err(err),
            (Ok(()), Err(err)) => Err(err),
            (Err(err), Err(cleanup_err)) => Err(AgentdError::Init(format!(
                "{err}; additionally failed to cleanup file mount staging {staging_path}: {cleanup_err}"
            ))),
        }
    }

    fn cleanup_file_mount_staging(staging_path: &str) -> AgentdResult<()> {
        // The bind mount keeps the file accessible at the guest path; removing
        // the share prevents alternate-path access through the staging tree.
        mount::umount2(staging_path, MntFlags::MNT_DETACH).map_err(|e| {
            AgentdError::Init(format!(
                "failed to unmount file mount staging {staging_path}: {e}"
            ))
        })?;
        fs::remove_dir(staging_path).map_err(|e| {
            AgentdError::Init(format!(
                "failed to remove file mount staging {staging_path}: {e}"
            ))
        })?;
        Ok(())
    }

    /// Mounts each disk-image volume at its guest path.
    pub fn apply_disk_mounts(specs: &[DiskMountSpec]) -> AgentdResult<()> {
        if specs.is_empty() {
            return Ok(());
        }
        // Read /proc/filesystems only when at least one mount needs
        // autodetection, then reuse the candidate list across the batch.
        let fstypes = if specs.iter().any(|spec| spec.fstype.is_none()) {
            Some(read_proc_filesystems()?)
        } else {
            None
        };
        for spec in specs {
            mount_disk(spec, fstypes.as_deref())?;
        }
        Ok(())
    }

    /// Resolve the block device for a disk-image mount id.
    ///
    /// Primary path: `/dev/disk/by-id/virtio-<id>`, which udev/kernel
    /// create when the VMM sets `virtio_blk_config.serial`.
    /// Fallback: scan `/sys/block/*/serial` for a match, which works
    /// even when udev is unavailable or has not yet populated the
    /// symlink.
    fn resolve_disk_device(id: &str) -> AgentdResult<String> {
        use std::{thread::sleep, time::Duration};
        const RETRIES: u32 = 20;
        const INTERVAL: Duration = Duration::from_millis(10);

        let by_id = format!("/dev/disk/by-id/virtio-{id}");
        for attempt in 0..RETRIES {
            if Path::new(&by_id).exists() {
                return Ok(by_id);
            }
            if let Some(dev) = scan_block_serial(id) {
                return Ok(dev);
            }
            // Skip the sleep after the last check so the failure path
            // doesn't pay 10ms it can't use.
            if attempt + 1 < RETRIES {
                sleep(INTERVAL);
            }
        }
        Err(AgentdError::Init(format!(
            "disk mount: no block device found for id '{id}' \
             (checked /dev/disk/by-id/virtio-{id} and /sys/block/*/serial)"
        )))
    }

    /// Walk `/sys/block/*` for an entry whose `serial` file matches `id`.
    fn scan_block_serial(id: &str) -> Option<String> {
        let entries = fs::read_dir("/sys/block").ok()?;
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name_str) = name.to_str() else {
                continue;
            };
            if !name_str.starts_with("vd") {
                continue;
            }
            let serial_path = entry.path().join("serial");
            let Ok(serial) = fs::read_to_string(&serial_path) else {
                continue;
            };
            if serial.trim() == id {
                return Some(format!("/dev/{name_str}"));
            }
        }
        None
    }

    fn mount_disk(spec: &DiskMountSpec, fstypes: Option<&[String]>) -> AgentdResult<()> {
        let path = spec.guest_path.as_str();
        fs::create_dir_all(path)
            .map_err(|e| AgentdError::Init(format!("disk mount: create dir {path}: {e}")))?;

        let device = resolve_disk_device(&spec.id)?;

        let mut flags = MsFlags::MS_RELATIME;
        if spec.nosuid {
            flags |= MsFlags::MS_NOSUID;
        }
        if spec.nodev {
            flags |= MsFlags::MS_NODEV;
        }
        if spec.noexec {
            flags |= MsFlags::MS_NOEXEC;
        }
        if spec.readonly {
            flags |= MsFlags::MS_RDONLY;
        }

        if let Some(fstype) = spec.fstype.as_deref() {
            let data = disk_mount_data(fstype, spec.readonly);
            mount::mount(Some(device.as_str()), path, Some(fstype), flags, data).map_err(|e| {
                AgentdError::Init(format!(
                    "disk mount: failed to mount {device} at {path} as {fstype}: {e}"
                ))
            })?;
        } else {
            let fstypes = fstypes.ok_or_else(|| {
                AgentdError::Init("disk mount: missing filesystem autodetect list".into())
            })?;
            try_mount_disk_any(&device, path, flags, spec.readonly, fstypes)?;
        }

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
        fs::create_dir_all(path)
            .map_err(|e| AgentdError::Init(format!("failed to create directory {path}: {e}")))?;

        let mut flags = MsFlags::MS_RELATIME;
        if spec.nosuid {
            flags |= MsFlags::MS_NOSUID;
        }
        if spec.nodev {
            flags |= MsFlags::MS_NODEV;
        }
        if spec.noexec {
            flags |= MsFlags::MS_NOEXEC;
        }
        if spec.readonly {
            flags |= MsFlags::MS_RDONLY;
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

        mount::mount(
            Some("tmpfs"),
            path,
            Some("tmpfs"),
            flags,
            Some(data.as_str()),
        )
        .map_err(|e| AgentdError::Init(format!("failed to mount tmpfs at {path}: {e}")))?;

        Ok(())
    }

    /// Creates `/run` and `/run/microsandbox` directories.
    ///
    /// `/run/microsandbox` is the canonical directory for agentd-owned
    /// runtime files (e.g. the post-handoff stderr log). Creating it
    /// here keeps the ownership in `init::init` regardless of whether
    /// handoff is configured.
    pub fn create_run_dir() -> AgentdResult<()> {
        mkdir_ignore_exists("/run")?;
        mkdir_ignore_exists("/run/microsandbox")?;
        Ok(())
    }

    /// Ensure login shells preserve `/.msb/scripts` on PATH.
    pub fn ensure_scripts_path_in_profile() -> AgentdResult<()> {
        let profile_path = Path::new("/etc/profile");
        let existing = match fs::read_to_string(profile_path) {
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
                fs::create_dir_all(parent).map_err(|err| {
                    AgentdError::Init(format!("failed to create {}: {err}", parent.display()))
                })?;
            }
            fs::write(profile_path, updated).map_err(|err| {
                AgentdError::Init(format!("failed to write {}: {err}", profile_path.display()))
            })?;
        }

        Ok(())
    }

    /// Creates a directory, ignoring EEXIST errors.
    fn mkdir_ignore_exists(path: &str) -> AgentdResult<()> {
        match unistd::mkdir(path, Mode::from_bits_truncate(0o755)) {
            Ok(()) => Ok(()),
            Err(nix::Error::EEXIST) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    fn ensure_directory_mode(path: &str, mode: u32) -> AgentdResult<()> {
        fs::create_dir_all(path)
            .map_err(|e| AgentdError::Init(format!("failed to create directory {path}: {e}")))?;

        let metadata = fs::metadata(path)
            .map_err(|e| AgentdError::Init(format!("failed to stat {path}: {e}")))?;
        if !metadata.is_dir() {
            return Err(AgentdError::Init(format!(
                "expected directory at {path}, found non-directory"
            )));
        }

        let current_mode = metadata.permissions().mode() & 0o7777;
        if current_mode != mode {
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|e| {
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
        match mount::mount(source, target, fstype, flags, data) {
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
