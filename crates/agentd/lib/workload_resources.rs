//! Cgroup-v2 limits for guest workloads, excluding the managing agent.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

use microsandbox_protocol::isolation::WorkloadResources;
use nix::mount::{MsFlags, mount};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn enable_namespace_delegation() -> io::Result<()> {
    // A privileged workload can remount its own view writable. nsdelegate still
    // prevents it from changing the limits at its cgroup namespace root.
    mount(
        Some("cgroup2"),
        "/sys/fs/cgroup",
        Some("cgroup2"),
        MsFlags::MS_REMOUNT
            | MsFlags::MS_NOSUID
            | MsFlags::MS_NODEV
            | MsFlags::MS_NOEXEC
            | MsFlags::MS_RELATIME,
        Some("nsdelegate"),
    )
    .map_err(io::Error::from)
}

pub(crate) fn configure(root: &Path, resources: &WorkloadResources) -> io::Result<()> {
    let controls = controls(resources)?;
    if !fs::read_to_string(root.join("cgroup.procs"))?
        .trim()
        .is_empty()
    {
        return Err(io::Error::other(
            "cannot configure isolation after workload execution",
        ));
    }
    let parent = root
        .parent()
        .ok_or_else(|| io::Error::other("missing cgroup parent"))?;
    let available = fs::read_to_string(parent.join("cgroup.controllers"))?;
    let mut controllers = Vec::new();
    for (name, _) in &controls {
        let controller = name.split_once('.').unwrap().0;
        if !available.split_whitespace().any(|item| item == controller) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("guest cgroup controller {controller} is unavailable"),
            ));
        }
        if !controllers.contains(&controller) {
            controllers.push(controller);
        }
    }
    if !controllers.is_empty() {
        let enable = controllers
            .iter()
            .map(|name| format!("+{name}"))
            .collect::<Vec<_>>()
            .join(" ");
        write_control(parent, "cgroup.subtree_control", &enable)?;
    }
    for (name, value) in controls {
        write_control(root, name, &value)?;
    }
    Ok(())
}

fn write_control(root: &Path, name: &str, value: &str) -> io::Result<()> {
    // Never create an ordinary file when a kernel controller is missing.
    let result = OpenOptions::new()
        .write(true)
        .open(root.join(name))
        .and_then(|mut file| file.write_all(value.as_bytes()));
    if name == "memory.swap.max"
        && result
            .as_ref()
            .is_err_and(|error| error.kind() == io::ErrorKind::NotFound)
        && kernel_swap_disabled(Path::new("/proc"))?
    {
        // CONFIG_SWAP=n provides no swap controller or swap activation syscall.
        // Every requested swap ceiling is satisfied by that permanent zero capacity.
        return Ok(());
    }
    result.map_err(|error| io::Error::new(error.kind(), format!("set guest {name}: {error}")))
}

fn kernel_swap_disabled(proc_root: &Path) -> io::Result<bool> {
    match fs::metadata(proc_root.join("swaps")) {
        Ok(_) => return Ok(false),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let meminfo = fs::read_to_string(proc_root.join("meminfo"))?;
    Ok(meminfo.lines().any(|line| {
        let mut fields = line.split_whitespace();
        fields.next() == Some("SwapTotal:") && fields.next() == Some("0")
    }))
}

fn controls(resources: &WorkloadResources) -> io::Result<Vec<(&'static str, String)>> {
    let mut result = Vec::new();
    let invalid = |message| io::Error::new(io::ErrorKind::InvalidInput, message);
    if resources.cpu_quota.is_some() || resources.cpu_period.is_some() {
        let period = resources.cpu_period.unwrap_or(100_000);
        if !(1_000..=1_000_000).contains(&period)
            || resources.cpu_quota.is_some_and(|value| value < 1_000)
        {
            return Err(invalid("invalid guest CPU quota or period"));
        }
        let quota = resources
            .cpu_quota
            .map_or_else(|| "max".into(), |value| value.to_string());
        result.push(("cpu.max", format!("{quota} {period}")));
    }
    if let Some(weight) = resources.cpu_weight {
        if !(1..=10_000).contains(&weight) {
            return Err(invalid("guest CPU weight must be between 1 and 10000"));
        }
        result.push(("cpu.weight", weight.to_string()));
    }
    if let Some(memory) = resources.memory_max {
        if memory == 0 {
            return Err(invalid("guest memory limit must be positive"));
        }
        result.push(("memory.max", memory.to_string()));
        result.push(("memory.oom.group", "1".into()));
    }
    if let Some(swap) = resources.swap_max {
        result.push(("memory.swap.max", swap.to_string()));
    }
    if let Some(pids) = resources.pids_max {
        if pids == 0 {
            return Err(invalid("guest task limit must be positive"));
        }
        result.push(("pids.max", pids.to_string()));
    }
    Ok(result)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::process::Command;
    use std::time::{Duration, Instant};

    #[test]
    fn preserves_full_workload_allowance() {
        let values = controls(&WorkloadResources {
            cpu_quota: Some(200_000),
            cpu_period: Some(100_000),
            memory_max: Some(512 * 1024 * 1024),
            swap_max: Some(0),
            pids_max: Some(32),
            ..Default::default()
        })
        .unwrap();
        assert!(values.contains(&("cpu.max", "200000 100000".into())));
        assert!(values.contains(&("memory.max", "536870912".into())));
        assert!(values.contains(&("memory.swap.max", "0".into())));
        assert!(values.contains(&("pids.max", "32".into())));
    }

    #[test]
    fn validates_before_writing_any_controls() {
        for resources in [
            WorkloadResources {
                cpu_period: Some(0),
                ..Default::default()
            },
            WorkloadResources {
                cpu_quota: Some(0),
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
                pids_max: Some(0),
                ..Default::default()
            },
        ] {
            assert!(controls(&resources).is_err());
        }
        assert!(controls(&WorkloadResources::default()).unwrap().is_empty());
    }

    #[test]
    fn missing_controller_file_is_never_created() {
        let directory =
            std::env::temp_dir().join(format!("msb-controller-test-{}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        let result = write_control(&directory, "memory.max", "1024");
        let exists = directory.join("memory.max").exists();
        fs::remove_dir(&directory).unwrap();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::NotFound);
        assert!(!exists);
    }

    #[test]
    fn no_swap_requires_kernel_evidence_not_just_a_missing_controller() {
        let directory =
            std::env::temp_dir().join(format!("msb-no-swap-test-{}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        assert!(kernel_swap_disabled(&directory).is_err());
        fs::write(directory.join("meminfo"), "SwapTotal: 0 kB\n").unwrap();
        assert!(kernel_swap_disabled(&directory).unwrap());
        fs::write(
            directory.join("swaps"),
            "Filename Type Size Used Priority\n",
        )
        .unwrap();
        assert!(
            !kernel_swap_disabled(&directory).unwrap(),
            "an enabled but unused swap subsystem still needs a limit"
        );
        fs::remove_file(directory.join("swaps")).unwrap();
        fs::write(directory.join("meminfo"), "SwapTotal: 1024 kB\n").unwrap();
        assert!(!kernel_swap_disabled(&directory).unwrap());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    #[ignore = "requires a private systemd user scope with Delegate=yes and MSB_TEST_DELEGATED_CGROUP=1"]
    fn live_resource_limits() {
        const TEST: &str = "workload_resources::tests::live_resource_limits";
        if let Ok(probe) = std::env::var("MSB_RESOURCE_PROBE") {
            match probe.as_str() {
                "memory" => {
                    let mut bytes = vec![0u8; 128 * 1024 * 1024];
                    for index in (0..bytes.len()).step_by(4096) {
                        unsafe {
                            std::ptr::write_volatile(bytes.as_mut_ptr().add(index), 1);
                        }
                    }
                    panic!("memory limit did not terminate probe");
                }
                "cpu" => {
                    let deadline = Instant::now() + Duration::from_secs(2);
                    while Instant::now() < deadline {
                        std::hint::spin_loop();
                    }
                }
                "pids" => {
                    let mut children = Vec::new();
                    let mut limited = false;
                    for _ in 0..32 {
                        match Command::new("/bin/sleep").arg("30").spawn() {
                            Ok(child) => children.push(child),
                            Err(error) => {
                                limited = error.raw_os_error() == Some(libc::EAGAIN);
                                break;
                            }
                        }
                    }
                    for mut child in children {
                        let _ = child.kill();
                        let _ = child.wait();
                    }
                    assert!(limited, "pids.max did not reject excess tasks");
                }
                _ => panic!("unknown probe"),
            }
            return;
        }
        assert_eq!(
            std::env::var("MSB_TEST_DELEGATED_CGROUP").as_deref(),
            Ok("1")
        );
        let memberships = fs::read_to_string("/proc/self/cgroup").unwrap();
        let relative = memberships
            .lines()
            .find_map(|line| line.strip_prefix("0::"))
            .unwrap();
        assert!(
            relative.ends_with(".scope"),
            "test must own a transient scope"
        );
        let parent = Path::new("/sys/fs/cgroup").join(relative.trim_start_matches('/'));
        let processes = fs::read_to_string(parent.join("cgroup.procs")).unwrap();
        assert_eq!(
            processes.trim(),
            std::process::id().to_string(),
            "scope contains other processes"
        );
        let manager = parent.join("manager");
        let workload = parent.join("workload");
        fs::create_dir(&manager).unwrap();
        fs::write(manager.join("cgroup.procs"), "0").unwrap();
        fs::create_dir(&workload).unwrap();
        configure(
            &workload,
            &WorkloadResources {
                memory_max: Some(32 * 1024 * 1024),
                swap_max: Some(0),
                cpu_quota: Some(20_000),
                cpu_period: Some(100_000),
                pids_max: Some(8),
                ..Default::default()
            },
        )
        .unwrap();
        for probe in ["cpu", "pids", "memory"] {
            let fd = OpenOptions::new()
                .write(true)
                .open(workload.join("cgroup.procs"))
                .unwrap();
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args(["--exact", TEST, "--ignored", "--nocapture"])
                .env("MSB_RESOURCE_PROBE", probe);
            unsafe {
                command.pre_exec(move || {
                    if libc::write(fd.as_raw_fd(), b"0".as_ptr().cast(), 1) == 1 {
                        Ok(())
                    } else {
                        Err(io::Error::last_os_error())
                    }
                });
            }
            let status = command.status().unwrap();
            if probe == "memory" {
                assert_eq!(status.signal(), Some(libc::SIGKILL));
                let events = fs::read_to_string(workload.join("memory.events")).unwrap();
                let kills: u64 = events
                    .lines()
                    .find_map(|line| line.strip_prefix("oom_kill "))
                    .unwrap()
                    .parse()
                    .unwrap();
                assert!(kills > 0);
            } else {
                assert!(status.success(), "{probe} probe failed: {status}");
            }
            if probe == "cpu" {
                let stats = fs::read_to_string(workload.join("cpu.stat")).unwrap();
                let usage: u64 = stats
                    .lines()
                    .find_map(|line| line.strip_prefix("usage_usec "))
                    .unwrap()
                    .parse()
                    .unwrap();
                assert!(
                    usage < 1_000_000,
                    "20% quota exceeded one CPU-second during a two-second probe: {usage}"
                );
                assert!(stats.lines().any(|line| {
                    line.strip_prefix("nr_throttled ")
                        .is_some_and(|value| value.parse::<u64>().unwrap() > 0)
                }));
            }
        }
        fs::remove_dir(workload).unwrap();
    }
}
