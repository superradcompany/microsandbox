//! Host VMM resource placement, separate from guest workload cgroups.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::fd::{AsFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use microsandbox_protocol::isolation::WorkloadResources;
use serde::{Deserialize, Serialize};
use zbus::zvariant::{Fd, OwnedObjectPath, Value};

use crate::{RuntimeError, RuntimeResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const CGROUP_RECORD: &str = "host-cgroup.json";
// Provisional management budgets, not a guarantee of sufficient overhead for every workload.
const HOST_RESERVE_MIB: u64 = 128;
/// Guest kernel and agent reserve, separate from the workload memory limit.
pub const GUEST_RESERVE_MIB: u32 = 128;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct HostLimits {
    memory: Option<u64>,
    swap: Option<u64>,
    cpu_quota: Option<u64>,
    cpu_period: u64,
    cpu_weight: Option<u64>,
}

/// Host resource placement performed by the VMM before allocating guest memory.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostCgroupConfig {
    /// Cgroup-v2 path relative to its hierarchy, or systemd slice:prefix:name.
    pub path: String,
    /// Absolute host OCI state directory for ownership and cleanup records.
    pub state_dir: PathBuf,
    /// Workload limits before adding management overhead.
    pub resources: WorkloadResources,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Place the VMM into its host cgroup before any guest memory is allocated.
pub async fn place(config: &HostCgroupConfig, pid: i32) -> RuntimeResult<()> {
    place_inner(config, pid)
        .await
        .map_err(|error| RuntimeError::Custom(format!("host cgroup placement: {error:#}")))
}

async fn place_inner(config: &HostCgroupConfig, pid: i32) -> Result<()> {
    if pid <= 0 {
        bail!("invalid VMM PID for cgroup placement");
    }
    if !config.state_dir.is_absolute() {
        bail!("OCI state directory must be absolute");
    }
    let state_dir = &config.state_dir;
    if !Path::new(CGROUP_ROOT).join("cgroup.controllers").is_file() {
        bail!("runmsb resource isolation requires host cgroup v2");
    }
    let limits = host_limits(&config.resources)?;
    let requested = &config.path;
    if requested.contains(':') {
        let (slice, unit) = systemd_names(requested)?;
        tokio::time::timeout(
            Duration::from_secs(10),
            place_systemd(&slice, &unit, pid as u32, &limits),
        )
        .await
        .context("timed out creating VMM systemd scope")??;
    } else {
        let path = cgroup_path(requested)?;
        let parent = path.parent().context("cgroup path has no parent")?;
        fs::create_dir_all(parent).context("create VMM cgroup parent")?;
        enable_controllers(parent, &limits)?;
        fs::create_dir(&path).context("create exclusive VMM cgroup")?;
        let metadata = fs::metadata(&path)?;
        let record = serde_json::json!({"path": path, "inode": metadata.ino()});
        let saved = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(state_dir.join(CGROUP_RECORD))
            .and_then(|mut file| file.write_all(record.to_string().as_bytes()));
        if let Err(error) = saved {
            let _ = fs::remove_dir(&path);
            return Err(error).context("record owned VMM cgroup");
        }
        if let Some(memory) = limits.memory {
            write(&path, "memory.max", memory)?;
        }
        if let Some(swap) = limits.swap {
            write(&path, "memory.swap.max", swap)?;
        }
        if let Some(quota) = limits.cpu_quota {
            write(&path, "cpu.max", format!("{quota} {}", limits.cpu_period))?;
        }
        if let Some(weight) = limits.cpu_weight {
            write(&path, "cpu.weight", weight)?;
        }
        write(&path, "cgroup.procs", pid)?;
    }
    Ok(())
}

/// Remove an owned, empty cgroup after the VMM has stopped.
pub fn cleanup(state_dir: &Path) -> RuntimeResult<()> {
    cleanup_inner(state_dir)
        .map_err(|error| RuntimeError::Custom(format!("host cgroup cleanup: {error:#}")))
}

fn cleanup_inner(state_dir: &Path) -> Result<()> {
    let record_path = state_dir.join(CGROUP_RECORD);
    let contents = match fs::read(&record_path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let record: serde_json::Value = serde_json::from_slice(&contents)?;
    let path = Path::new(
        record["path"]
            .as_str()
            .context("invalid host cgroup record")?,
    );
    if !path.starts_with(CGROUP_ROOT) || path == Path::new(CGROUP_ROOT) {
        bail!("unsafe host cgroup record");
    }
    if path
        .components()
        .any(|part| matches!(part, Component::ParentDir))
    {
        bail!("unsafe host cgroup path");
    }
    match fs::metadata(path) {
        Ok(metadata) => {
            if Some(metadata.ino()) != record["inode"].as_u64() {
                bail!("VMM cgroup ownership changed; refusing deletion");
            }
            // A populated cgroup cannot be removed. Never kill arbitrary occupants here.
            fs::remove_dir(path).context("remove stopped VMM cgroup")?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    fs::remove_file(record_path)?;
    Ok(())
}

fn host_limits(resources: &WorkloadResources) -> Result<HostLimits> {
    let memory = guest_memory_mib(resources)?
        .map(|guest| (u64::from(guest) + HOST_RESERVE_MIB) * 1024 * 1024);
    let period = resources.cpu_period.unwrap_or(100_000);
    if !(1_000..=1_000_000).contains(&period)
        || resources.cpu_quota.is_some_and(|quota| quota < 1_000)
    {
        bail!("invalid host CPU quota or period");
    }
    if resources
        .cpu_weight
        .is_some_and(|weight| !(1..=10_000).contains(&weight))
    {
        bail!("invalid host CPU weight");
    }
    let cpu_quota = resources
        .cpu_quota
        .map(|quota| {
            quota
                .checked_add(period.div_ceil(10))
                .context("host CPU budget overflow")
        })
        .transpose()?;
    Ok(HostLimits {
        memory,
        swap: resources.swap_max,
        cpu_quota,
        cpu_period: period,
        cpu_weight: resources.cpu_weight,
    })
}

/// Convert the workload memory ceiling into guest RAM with an agent/kernel reserve.
pub fn guest_memory_mib(resources: &WorkloadResources) -> RuntimeResult<Option<u32>> {
    resources
        .memory_max
        .map(|bytes| {
            if bytes == 0 {
                return Err(RuntimeError::Custom(
                    "workload memory limit must be positive".into(),
                ));
            }
            let mib = u32::try_from(bytes.div_ceil(1024 * 1024))
                .map_err(|_| RuntimeError::Custom("guest memory budget overflow".into()))?;
            mib.checked_add(GUEST_RESERVE_MIB)
                .ok_or_else(|| RuntimeError::Custom("guest memory budget overflow".into()))
        })
        .transpose()
}

fn cgroup_path(requested: &str) -> Result<PathBuf> {
    let relative = requested.trim_start_matches('/');
    if relative.is_empty()
        || Path::new(relative)
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        bail!("cgroup path must name a non-root group without parent components");
    }
    Ok(Path::new(CGROUP_ROOT).join(relative))
}

fn systemd_names(requested: &str) -> Result<(String, String)> {
    let parts = requested.split(':').collect::<Vec<_>>();
    if parts.len() != 3 {
        bail!("systemd cgroup path must be slice:prefix:name");
    }
    for part in &parts {
        if part.is_empty()
            || part
                .bytes()
                .any(|byte| !byte.is_ascii_alphanumeric() && !b"_.-".contains(&byte))
        {
            bail!("invalid systemd cgroup component");
        }
    }
    if !parts[0].ends_with(".slice") {
        bail!("systemd cgroup parent must be a slice");
    }
    Ok((parts[0].into(), format!("{}-{}.scope", parts[1], parts[2])))
}

async fn place_systemd(slice: &str, unit: &str, pid: u32, limits: &HostLimits) -> Result<()> {
    let pidfd = open_pidfd(pid)?;
    let connection = zbus::Connection::system()
        .await
        .context("connect to systemd for VMM resource placement")?;
    place_systemd_on(&connection, slice, unit, pid, &pidfd, limits).await
}

async fn place_systemd_on(
    connection: &zbus::Connection,
    slice: &str,
    unit: &str,
    pid: u32,
    pidfd: &OwnedFd,
    limits: &HostLimits,
) -> Result<()> {
    let manager = zbus::Proxy::new(
        connection,
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
    )
    .await?;
    let mut properties: Vec<(&str, Value<'_>)> = vec![
        ("Description", "Microsandbox OCI VMM".into()),
        ("Slice", slice.into()),
        // Carry process identity across D-Bus, not a PID that could be reused.
        ("PIDFDs", vec![Fd::from(pidfd.as_fd())].into()),
        ("Delegate", true.into()),
        ("CPUAccounting", true.into()),
        ("MemoryAccounting", true.into()),
        // Guest task limits do not describe VMM threads.
        ("TasksMax", u64::MAX.into()),
    ];
    if let Some(memory) = limits.memory {
        properties.push(("MemoryMax", memory.into()));
    }
    if let Some(swap) = limits.swap {
        properties.push(("MemorySwapMax", swap.into()));
    }
    if let Some(weight) = limits.cpu_weight {
        properties.push(("CPUWeight", weight.into()));
    }
    if let Some(quota) = limits.cpu_quota {
        let per_second =
            u64::try_from((u128::from(quota) * 1_000_000).div_ceil(u128::from(limits.cpu_period)))?;
        properties.push(("CPUQuotaPerSecUSec", per_second.into()));
        properties.push(("CPUQuotaPeriodUSec", limits.cpu_period.into()));
    }
    let auxiliary: Vec<(&str, Vec<(&str, Value<'_>)>)> = Vec::new();
    let _: OwnedObjectPath = manager
        .call("StartTransientUnit", &(unit, "fail", properties, auxiliary))
        .await
        .context("create VMM systemd scope (systemd must support PIDFDs)")?;
    let path: OwnedObjectPath = manager.call("GetUnit", &(unit,)).await?;
    let scope = zbus::Proxy::new(
        connection,
        "org.freedesktop.systemd1",
        path,
        "org.freedesktop.systemd1.Scope",
    )
    .await?;
    for _ in 0..100 {
        let group: String = scope.get_property("ControlGroup").await?;
        let actual = fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
        if !group.is_empty()
            && actual
                .lines()
                .any(|line| line.strip_prefix("0::") == Some(group.as_str()))
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    bail!("systemd did not place the VMM in its requested cgroup")
}

fn open_pidfd(pid: u32) -> Result<OwnedFd> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
    if fd < 0 {
        bail!(
            "open VMM process handle: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn enable_controllers(parent: &Path, limits: &HostLimits) -> Result<()> {
    if let Some(ancestor) = parent.parent().filter(|path| path.starts_with(CGROUP_ROOT)) {
        enable_controllers(ancestor, limits)?;
    }
    let mut controls = Vec::new();
    if limits.memory.is_some() || limits.swap.is_some() {
        controls.push("+memory");
    }
    if limits.cpu_quota.is_some() || limits.cpu_weight.is_some() {
        controls.push("+cpu");
    }
    if !controls.is_empty() {
        let enabled = fs::read_to_string(parent.join("cgroup.subtree_control"))?;
        controls.retain(|control| !enabled.split_whitespace().any(|item| item == &control[1..]));
        if !controls.is_empty() {
            write(parent, "cgroup.subtree_control", controls.join(" "))?;
        }
    }
    Ok(())
}

fn write(path: &Path, name: &str, value: impl ToString) -> Result<()> {
    OpenOptions::new()
        .write(true)
        .open(path.join(name))?
        .write_all(value.to_string().as_bytes())
        .with_context(|| format!("set host cgroup {name}"))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires a private systemd user scope with Delegate=yes and MSB_TEST_DELEGATED_CGROUP=1"]
    async fn live_cgroupfs_placement_and_cleanup() {
        assert_eq!(
            std::env::var("MSB_TEST_DELEGATED_CGROUP").as_deref(),
            Ok("1")
        );
        let memberships = fs::read_to_string("/proc/self/cgroup").unwrap();
        let relative = memberships
            .lines()
            .find_map(|line| line.strip_prefix("0::"))
            .unwrap();
        assert!(relative.ends_with(".scope"));
        let parent = Path::new(CGROUP_ROOT).join(relative.trim_start_matches('/'));
        assert_eq!(
            fs::read_to_string(parent.join("cgroup.procs"))
                .unwrap()
                .trim(),
            std::process::id().to_string()
        );
        fs::create_dir(parent.join("manager")).unwrap();
        write(&parent.join("manager"), "cgroup.procs", 0).unwrap();
        let requested = format!("{relative}/vmm");
        let state = tempfile::tempdir().unwrap();
        let config = HostCgroupConfig {
            path: requested,
            state_dir: state.path().into(),
            resources: WorkloadResources {
                memory_max: Some(67108864),
                cpu_quota: Some(20000),
                ..Default::default()
            },
        };
        let mut child = tokio::process::Command::new("/bin/sleep")
            .arg("30")
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let result = place(&config, child.id().unwrap() as i32).await;
        if let Err(error) = result {
            let _ = child.kill().await;
            let _ = child.wait().await;
            panic!("cgroupfs placement: {error:#}");
        }
        let path = parent.join("vmm");
        assert_eq!(
            fs::read_to_string(path.join("memory.max")).unwrap().trim(),
            "335544320"
        );
        assert_eq!(
            fs::read_to_string(path.join("cpu.max")).unwrap().trim(),
            "30000 100000"
        );
        assert!(
            cleanup(state.path()).is_err(),
            "must not delete a live cgroup"
        );
        child.kill().await.unwrap();
        child.wait().await.unwrap();
        cleanup(state.path()).unwrap();
        assert!(!path.exists());
        assert!(!state.path().join(CGROUP_RECORD).exists());
    }

    #[tokio::test]
    #[ignore = "requires an accessible systemd user manager with cgroup-v2 delegation"]
    async fn live_systemd_scope_limits() {
        let connection = zbus::Connection::session().await.unwrap();
        let mut child = tokio::process::Command::new("/bin/sleep")
            .arg("30")
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let pid = child.id().unwrap();
        let pidfd = open_pidfd(pid).unwrap();
        let unit = format!("runmsb-cgroup-test-{pid}.scope");
        let limits = host_limits(&WorkloadResources {
            memory_max: Some(64 * 1024 * 1024),
            swap_max: Some(0),
            cpu_quota: Some(20_000),
            ..Default::default()
        })
        .unwrap();
        let placed = tokio::time::timeout(
            Duration::from_secs(10),
            place_systemd_on(&connection, "app.slice", &unit, pid, &pidfd, &limits),
        )
        .await;
        if !matches!(&placed, Ok(Ok(()))) {
            let _ = child.kill().await;
            let _ = child.wait().await;
            panic!("scope placement failed: {placed:?}");
        }
        let membership = fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap();
        let relative = membership
            .lines()
            .find_map(|line| line.strip_prefix("0::"))
            .unwrap();
        let path = Path::new(CGROUP_ROOT).join(relative.trim_start_matches('/'));
        assert_eq!(
            fs::read_to_string(path.join("memory.max")).unwrap().trim(),
            limits.memory.unwrap().to_string()
        );
        assert_eq!(
            fs::read_to_string(path.join("memory.swap.max"))
                .unwrap()
                .trim(),
            "0"
        );
        assert_eq!(
            fs::read_to_string(path.join("cpu.max")).unwrap().trim(),
            "30000 100000"
        );
        child.kill().await.unwrap();
        child.wait().await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while path.exists() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("systemd should release the finished scope");
    }

    #[test]
    fn separates_host_overhead_from_guest_limits() {
        let limits = host_limits(&WorkloadResources {
            memory_max: Some(512 * 1024 * 1024),
            cpu_quota: Some(100_000),
            pids_max: Some(8),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(limits.memory, Some(768 * 1024 * 1024));
        assert_eq!(limits.cpu_quota, Some(110_000));
    }

    #[test]
    fn rejects_invalid_launch_limits_before_touching_cgroups() {
        for resources in [
            WorkloadResources {
                cpu_period: Some(0),
                cpu_quota: Some(1000),
                ..Default::default()
            },
            WorkloadResources {
                cpu_quota: Some(1),
                ..Default::default()
            },
            WorkloadResources {
                cpu_weight: Some(10001),
                ..Default::default()
            },
            WorkloadResources {
                memory_max: Some(0),
                ..Default::default()
            },
            WorkloadResources {
                memory_max: Some(u64::MAX),
                ..Default::default()
            },
        ] {
            assert!(host_limits(&resources).is_err());
        }
    }

    #[test]
    fn validates_cgroup_paths() {
        assert_eq!(
            cgroup_path("/docker/test").unwrap(),
            Path::new(CGROUP_ROOT).join("docker/test")
        );
        for path in ["", "/", "../other", "docker/../../other"] {
            assert!(cgroup_path(path).is_err());
        }
        assert_eq!(
            systemd_names("system.slice:docker:abc").unwrap(),
            ("system.slice".into(), "docker-abc.scope".into())
        );
        for path in [
            "system.slice:docker:../abc",
            "system.slice:abc",
            "system:docker:abc",
        ] {
            assert!(systemd_names(path).is_err());
        }
    }
}
