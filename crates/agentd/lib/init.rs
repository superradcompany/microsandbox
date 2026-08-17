//! PID 1 init: mount filesystems, apply tmpfs mounts, prepare runtime directories.

use crate::config::{BootParams, SecurityProfile};
use crate::error::AgentdResult;
use crate::{network, rlimit, tls};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Mount only the filesystems needed to discover and open the agent console.
///
/// The console descriptor remains valid when a block-backed root later pivots
/// and remounts the essential filesystems inside the final guest root.
pub fn prepare_bootstrap_console() -> AgentdResult<()> {
    linux::mount_bootstrap_filesystems()
}

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
    linux::apply_user_mounts(
        &params.dir_mounts,
        &params.file_mounts,
        &params.disk_mounts,
        &params.tmpfs,
    )?;
    network::apply_hostname(
        params.hostname.as_deref(),
        params.host_alias.as_deref(),
        params.net_ipv4.as_ref().map(|v4| v4.gateway),
        params.net_ipv6.as_ref().map(|v6| v6.gateway),
    )?;
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
    use typed_path::{Utf8Component, Utf8UnixComponent, Utf8UnixPath};

    use crate::config::{
        BlockRootSpec, BlockRootUpper, DirMountSpec, DiskMountSpec, FileMountSpec, TmpfsSpec,
    };
    use crate::error::{AgentdError, AgentdResult};

    const UPPER_METRICS_PATH: &str = "/sys/kernel/msb_metrics/upper_path";
    const UPPER_METRICS_REGISTER_ATTEMPTS: usize = 100;
    const UPPER_METRICS_REGISTER_RETRY: Duration = Duration::from_millis(10);

    //--------------------------------------------------------------------------------------------------
    // Types
    //--------------------------------------------------------------------------------------------------

    /// A mount from any user-facing volume transport.
    ///
    /// Keeping the variants together is essential: mounting by transport
    /// group can let a later parent hide a child from an earlier group.
    enum UserMount<'a> {
        Dir(&'a DirMountSpec),
        File(&'a FileMountSpec),
        Disk(&'a DiskMountSpec),
        Tmpfs(&'a TmpfsSpec),
    }

    struct PlannedUserMount<'a> {
        depth: usize,
        canonical_path: String,
        mount: UserMount<'a>,
    }

    //--------------------------------------------------------------------------------------------------
    // Methods
    //--------------------------------------------------------------------------------------------------

    impl UserMount<'_> {
        fn guest_path(&self) -> &str {
            match self {
                Self::Dir(spec) => &spec.guest_path,
                Self::File(spec) => &spec.guest_path,
                Self::Disk(spec) => &spec.guest_path,
                Self::Tmpfs(spec) => &spec.path,
            }
        }

        fn is_file(&self) -> bool {
            matches!(self, Self::File(_))
        }
    }

    /// Mount the minimum filesystems needed for virtio-console discovery.
    pub fn mount_bootstrap_filesystems() -> AgentdResult<()> {
        mount_dev()?;
        mount_sys()?;
        Ok(())
    }

    /// Mounts essential Linux filesystems.
    pub fn mount_filesystems() -> AgentdResult<()> {
        mount_dev()?;

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

        mount_sys()?;

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

    fn mount_dev() -> AgentdResult<()> {
        mkdir_ignore_exists("/dev")?;
        mount_ignore_busy(
            Some("devtmpfs"),
            "/dev",
            Some("devtmpfs"),
            MsFlags::MS_RELATIME,
            None::<&str>,
        )
    }

    fn mount_sys() -> AgentdResult<()> {
        let flags =
            MsFlags::MS_NODEV | MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID | MsFlags::MS_RELATIME;
        mkdir_ignore_exists("/sys")?;
        mount_ignore_busy(Some("sysfs"), "/sys", Some("sysfs"), flags, None::<&str>)
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
            BlockRootSpec::OciErofs { lower, upper } => {
                mount_oci_erofs(lower, upper)?;
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
    fn mount_oci_erofs(lower_device: &str, upper: &BlockRootUpper) -> AgentdResult<()> {
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

        // Mount the writable upper: a block-device filesystem (managed ext4
        // or user disk image), or a RAM-backed tmpfs for tmpfs root disks.
        let upperfs_dir = "/.msb/rootfs/upperfs";
        mkdir_ignore_exists("/.msb/rootfs/upperfs")?;
        match upper {
            BlockRootUpper::Device { device, fstype } => {
                mount::mount(
                    Some(device.as_str()),
                    upperfs_dir,
                    Some(fstype.as_str()),
                    MsFlags::empty(),
                    None::<&str>,
                )
                .map_err(|e| AgentdError::Init(format!("mount {device} at {upperfs_dir}: {e}")))?;
            }
            BlockRootUpper::Tmpfs { size_mib } => {
                let data = size_mib
                    .map(|mib| format!("size={},mode=755", u64::from(mib) * 1024 * 1024))
                    .unwrap_or_else(|| "mode=755".to_owned());
                mount::mount(
                    Some("tmpfs"),
                    upperfs_dir,
                    Some("tmpfs"),
                    MsFlags::MS_RELATIME,
                    Some(data.as_str()),
                )
                .map_err(|e| {
                    AgentdError::Init(format!("mount tmpfs upper at {upperfs_dir}: {e}"))
                })?;
            }
        }
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

    /// Applies every user mount in one parent-before-child plan.
    pub fn apply_user_mounts(
        dir_specs: &[DirMountSpec],
        file_specs: &[FileMountSpec],
        disk_specs: &[DiskMountSpec],
        tmpfs_specs: &[TmpfsSpec],
    ) -> AgentdResult<()> {
        let plan = plan_user_mounts(dir_specs, file_specs, disk_specs, tmpfs_specs)?;

        // Read the autodetection candidates once even when disk mounts are
        // interleaved with other kinds in the final plan.
        let fstypes = if disk_specs.iter().any(|spec| spec.fstype.is_none()) {
            Some(read_proc_filesystems()?)
        } else {
            None
        };

        if !file_specs.is_empty() {
            fs::create_dir_all(microsandbox_protocol::FILE_MOUNTS_DIR).map_err(|e| {
                AgentdError::Init(format!(
                    "failed to create file mounts dir {}: {e}",
                    microsandbox_protocol::FILE_MOUNTS_DIR
                ))
            })?;
        }

        let result = (|| {
            for planned in plan {
                match planned.mount {
                    UserMount::Dir(spec) => mount_dir(spec)?,
                    UserMount::File(spec) => mount_file(spec)?,
                    UserMount::Disk(spec) => mount_disk(spec, fstypes.as_deref())?,
                    UserMount::Tmpfs(spec) => mount_tmpfs(spec)?,
                }
            }
            Ok(())
        })();

        // Each file share is detached by mount_file; remove the common
        // staging root after the complete cross-kind plan finishes.
        if !file_specs.is_empty() {
            let _ = fs::remove_dir(microsandbox_protocol::FILE_MOUNTS_DIR);
        }

        result
    }

    fn plan_user_mounts<'a>(
        dir_specs: &'a [DirMountSpec],
        file_specs: &'a [FileMountSpec],
        disk_specs: &'a [DiskMountSpec],
        tmpfs_specs: &'a [TmpfsSpec],
    ) -> AgentdResult<Vec<PlannedUserMount<'a>>> {
        let mounts = dir_specs
            .iter()
            .map(UserMount::Dir)
            .chain(file_specs.iter().map(UserMount::File))
            .chain(disk_specs.iter().map(UserMount::Disk))
            .chain(tmpfs_specs.iter().map(UserMount::Tmpfs));
        let mut plan = Vec::with_capacity(
            dir_specs.len() + file_specs.len() + disk_specs.len() + tmpfs_specs.len(),
        );

        for mount in mounts {
            let (depth, canonical_path) = mount_order_key(mount.guest_path())?;
            plan.push(PlannedUserMount {
                depth,
                canonical_path,
                mount,
            });
        }

        plan.sort_by(|left, right| {
            (left.depth, left.canonical_path.as_str())
                .cmp(&(right.depth, right.canonical_path.as_str()))
        });

        for pair in plan.windows(2) {
            if pair[0].canonical_path == pair[1].canonical_path {
                return Err(AgentdError::Init(format!(
                    "multiple volumes cannot mount the same guest path: {}",
                    pair[0].canonical_path
                )));
            }
        }

        // A file can be a mount leaf, but it cannot contain another mount.
        // Reject the complete plan before executing its first mount so this
        // configuration cannot fail later with ENOTDIR after partial setup.
        for file in plan.iter().filter(|planned| planned.mount.is_file()) {
            let file_path = Utf8UnixPath::new(&file.canonical_path);
            if let Some(descendant) = plan.iter().find(|candidate| {
                candidate.depth > file.depth
                    && Utf8UnixPath::new(&candidate.canonical_path).starts_with(file_path)
            }) {
                return Err(AgentdError::Init(format!(
                    "file mount cannot contain another mount: {} is an ancestor of {}",
                    file.canonical_path, descendant.canonical_path
                )));
            }
        }

        Ok(plan)
    }

    fn mount_order_key(guest: &str) -> AgentdResult<(usize, String)> {
        let path = Utf8UnixPath::new(guest);
        if !path.is_valid() || !path.is_absolute() {
            return Err(AgentdError::Init(format!(
                "invalid guest mount path: {guest}"
            )));
        }
        if path
            .components()
            .any(|component| matches!(component, Utf8UnixComponent::ParentDir))
        {
            return Err(AgentdError::Init(format!(
                "guest mount path must not contain '..': {guest}"
            )));
        }

        let canonical = path.normalize();
        if canonical.as_str() == "/" {
            return Err(AgentdError::Init(
                "cannot mount a volume at guest root /".into(),
            ));
        }
        let depth = canonical
            .components()
            .filter(Utf8Component::is_normal)
            .count();
        Ok((depth, canonical.to_string()))
    }

    #[cfg(test)]
    pub(super) fn planned_user_mounts_for_test<'a>(
        dir_specs: &'a [DirMountSpec],
        file_specs: &'a [FileMountSpec],
        disk_specs: &'a [DiskMountSpec],
        tmpfs_specs: &'a [TmpfsSpec],
    ) -> AgentdResult<Vec<(&'static str, String)>> {
        plan_user_mounts(dir_specs, file_specs, disk_specs, tmpfs_specs).map(|plan| {
            plan.into_iter()
                .map(|planned| {
                    let kind = match planned.mount {
                        UserMount::Dir(_) => "dir",
                        UserMount::File(_) => "file",
                        UserMount::Disk(_) => "disk",
                        UserMount::Tmpfs(_) => "tmpfs",
                    };
                    (kind, planned.canonical_path)
                })
                .collect()
        })
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
    use crate::config::{DirMountSpec, DiskMountSpec, FileMountSpec, TmpfsSpec};

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
    fn test_user_mount_plan_orders_mixed_kinds_parent_first() {
        let dirs = vec![DirMountSpec {
            tag: "workspace".into(),
            guest_path: "/workspace".into(),
            readonly: false,
            noexec: false,
            nosuid: false,
            nodev: false,
        }];
        let files = vec![FileMountSpec {
            tag: "config".into(),
            filename: "app.toml".into(),
            guest_path: "/workspace/persist/app.toml".into(),
            readonly: true,
            noexec: false,
            nosuid: false,
            nodev: false,
        }];
        let disks = vec![DiskMountSpec {
            id: "durable".into(),
            guest_path: "/workspace/persist".into(),
            fstype: Some("ext4".into()),
            readonly: false,
            noexec: false,
            nosuid: false,
            nodev: false,
        }];
        let tmpfs = vec![TmpfsSpec {
            path: "/workspace/persist/cache".into(),
            size_mib: None,
            mode: None,
            noexec: false,
            nosuid: false,
            nodev: false,
            readonly: false,
        }];

        let plan = linux::planned_user_mounts_for_test(&dirs, &files, &disks, &tmpfs).unwrap();

        assert_eq!(
            plan,
            vec![
                ("dir", "/workspace".into()),
                ("disk", "/workspace/persist".into()),
                ("file", "/workspace/persist/app.toml".into()),
                ("tmpfs", "/workspace/persist/cache".into()),
            ]
        );
    }

    #[test]
    fn test_user_mount_plan_rejects_file_mount_as_parent() {
        let dirs = vec![DirMountSpec {
            tag: "persist".into(),
            guest_path: "/workspace/persist".into(),
            readonly: false,
            noexec: false,
            nosuid: false,
            nodev: false,
        }];
        let files = vec![FileMountSpec {
            tag: "workspace".into(),
            filename: "workspace".into(),
            guest_path: "/workspace".into(),
            readonly: true,
            noexec: false,
            nosuid: false,
            nodev: false,
        }];

        let error = linux::planned_user_mounts_for_test(&dirs, &files, &[], &[]).unwrap_err();

        assert!(error.to_string().contains("file mount cannot contain"));
    }
}
