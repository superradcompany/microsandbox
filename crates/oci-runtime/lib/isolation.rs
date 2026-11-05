//! OCI namespace and resource requests mapped into one guest workload domain.

use anyhow::{Result, bail};
use microsandbox_protocol::isolation::{
    WorkloadIdMapping, WorkloadIsolation, WorkloadResources, WorkloadTimeNamespace,
    WorkloadTimeOffset, WorkloadUserNamespace,
};
use microsandbox_runtime::oci::OciBundle;
use oci_spec::runtime::{LinuxNamespaceType, LinuxResources};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

pub(crate) const ISOLATION_LABEL: &str = "oci.microsandbox.isolation";

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn policy(bundle: &OciBundle) -> Result<WorkloadIsolation> {
    let mut policy = WorkloadIsolation::default();
    if let Some(linux) = bundle.spec.linux() {
        for namespace in linux.namespaces().as_deref().unwrap_or_default() {
            let kind = namespace.typ();
            if kind == LinuxNamespaceType::Network {
                continue;
            }
            if namespace.path().is_some() {
                bail!("cannot join a host {kind} namespace from the guest kernel");
            }
            match kind {
                LinuxNamespaceType::Mount => policy.mount = true,
                LinuxNamespaceType::Pid => policy.pid = true,
                LinuxNamespaceType::Ipc => policy.ipc = true,
                LinuxNamespaceType::Uts => policy.uts = true,
                LinuxNamespaceType::Cgroup => policy.cgroup = true,
                LinuxNamespaceType::Time => policy.time = Some(WorkloadTimeNamespace::default()),
                LinuxNamespaceType::User => {
                    policy.user = Some(WorkloadUserNamespace::default());
                }
                LinuxNamespaceType::Network => unreachable!(),
            }
        }
        if let Some(offsets) = linux.time_offsets() {
            for (clock, offset) in offsets {
                let time = policy.time.as_mut().ok_or_else(|| {
                    anyhow::anyhow!("clock offsets require a guest time namespace")
                })?;
                let target = match clock.as_str() {
                    "monotonic" => &mut time.monotonic,
                    "boottime" => &mut time.boottime,
                    _ => bail!("unsupported time namespace clock `{clock}`"),
                };
                let nanoseconds = offset.nanosecs().unwrap_or(0);
                if nanoseconds >= 1_000_000_000 {
                    bail!("invalid time namespace nanoseconds");
                }
                *target = Some(WorkloadTimeOffset {
                    seconds: offset.secs().unwrap_or(0),
                    nanoseconds,
                });
            }
        }
        if let Some(user) = policy.user.as_mut() {
            for mapping in linux.uid_mappings().as_deref().unwrap_or_default() {
                user.uid_mappings.push(WorkloadIdMapping {
                    container_id: mapping.container_id(),
                    guest_id: mapping.host_id(),
                    size: mapping.size(),
                });
            }
            for mapping in linux.gid_mappings().as_deref().unwrap_or_default() {
                user.gid_mappings.push(WorkloadIdMapping {
                    container_id: mapping.container_id(),
                    guest_id: mapping.host_id(),
                    size: mapping.size(),
                });
            }
            user.validate().map_err(anyhow::Error::msg)?;
        } else if linux
            .uid_mappings()
            .as_ref()
            .is_some_and(|mappings| !mappings.is_empty())
            || linux
                .gid_mappings()
                .as_ref()
                .is_some_and(|mappings| !mappings.is_empty())
        {
            bail!("UID/GID mappings require a guest user namespace");
        }
        if let Some(resources) = linux.resources() {
            policy.resources = resource_policy(resources)?;
        }
    }
    if (policy.pid || policy.cgroup || policy.ipc) && !policy.mount {
        bail!("guest PID, IPC and cgroup namespaces require a private mount namespace");
    }
    if policy.user.is_some() && (!policy.pid || !policy.mount) {
        bail!("guest user namespaces require private PID and mount namespaces");
    }
    if let Some(hostname) = bundle
        .spec
        .hostname()
        .as_ref()
        .filter(|name| !name.is_empty())
    {
        if !policy.uts {
            bail!("setting a workload hostname requires a guest UTS namespace");
        }
        if hostname.len() > 63 || hostname.as_bytes().contains(&0) {
            bail!("invalid workload hostname");
        }
        policy.hostname = Some(hostname.clone());
    }
    Ok(policy)
}

pub(crate) fn guest_memory_mib(resources: &WorkloadResources) -> Result<Option<u32>> {
    Ok(microsandbox_runtime::oci::cgroup::guest_memory_mib(
        resources,
    )?)
}

pub(crate) fn guest_cpus(resources: &WorkloadResources) -> Result<Option<u8>> {
    resources
        .cpu_quota
        .map(|quota| {
            let period = resources.cpu_period.unwrap_or(100_000);
            if !(1_000..=1_000_000).contains(&period) || quota < 1_000 {
                bail!("invalid CPU quota or period");
            }
            // The guest agent and kernel must not consume the workload's virtual CPU capacity.
            let count = quota
                .div_ceil(period)
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("guest CPU budget overflow"))?;
            Ok(u8::try_from(count)?)
        })
        .transpose()
}

fn resource_policy(resources: &LinuxResources) -> Result<WorkloadResources> {
    if let Some(block_io) = resources.block_io() {
        // Docker emits blockIO even without limits; older versions also emit weight: 0.
        if block_io.weight().is_some_and(|weight| weight != 0)
            || block_io.leaf_weight().is_some_and(|weight| weight != 0)
            || block_io
                .weight_device()
                .as_ref()
                .is_some_and(|devices| !devices.is_empty())
            || block_io
                .throttle_read_bps_device()
                .as_ref()
                .is_some_and(|devices| !devices.is_empty())
            || block_io
                .throttle_write_bps_device()
                .as_ref()
                .is_some_and(|devices| !devices.is_empty())
            || block_io
                .throttle_read_iops_device()
                .as_ref()
                .is_some_and(|devices| !devices.is_empty())
            || block_io
                .throttle_write_iops_device()
                .as_ref()
                .is_some_and(|devices| !devices.is_empty())
        {
            bail!("guest block I/O resource controls are not implemented");
        }
    }
    if resources
        .hugepage_limits()
        .as_ref()
        .is_some_and(|limits| !limits.is_empty())
        || resources.network().is_some()
        || resources
            .rdma()
            .as_ref()
            .is_some_and(|value| !value.is_empty())
        || resources
            .unified()
            .as_ref()
            .is_some_and(|value| !value.is_empty())
    {
        bail!(
            "guest hugepage, network, RDMA and arbitrary unified cgroup controls are not implemented"
        );
    }
    let mut result = WorkloadResources::default();
    if let Some(cpu) = resources.cpu() {
        if cpu.cpus().as_ref().is_some_and(|cpus| !cpus.is_empty())
            || cpu.mems().as_ref().is_some_and(|mems| !mems.is_empty())
            || cpu.realtime_runtime().is_some()
            || cpu.realtime_period().is_some()
            || cpu.burst().is_some()
            || cpu.idle().is_some()
        {
            bail!("guest cpuset, realtime, burst and idle CPU controls are not implemented");
        }
        result.cpu_quota = positive_limit(cpu.quota(), "CPU quota")?;
        result.cpu_period = cpu.period().filter(|value| *value != 0);
        if let Some(period) = result.cpu_period
            && !(1_000..=1_000_000).contains(&period)
        {
            bail!("invalid CPU period");
        }
        if let Some(quota) = result.cpu_quota
            && quota < 1_000
        {
            bail!("CPU quota must be at least 1000 microseconds");
        }
        if let Some(shares) = cpu.shares().filter(|value| *value != 0) {
            if !(2..=262_144).contains(&shares) {
                bail!("CPU shares must be between 2 and 262144");
            }
            result.cpu_weight = Some(1 + (shares - 2) * 9_999 / 262_142);
        }
    }
    if let Some(memory) = resources.memory() {
        #[allow(deprecated)]
        let kernel_limit = memory.kernel();
        if memory.reservation().is_some_and(|value| value != 0)
            || kernel_limit.is_some_and(|value| value != 0)
            || memory.kernel_tcp().is_some_and(|value| value != 0)
            || memory.swappiness().is_some()
            || memory.use_hierarchy() == Some(false)
            || memory.check_before_update().unwrap_or(false)
            || memory.disable_oom_killer().unwrap_or(false)
        {
            bail!(
                "guest memory reservation, separate kernel limits, swappiness, nonhierarchical accounting, update checks and OOM-disable controls are not implemented"
            );
        }
        result.memory_max = positive_limit(memory.limit(), "memory limit")?;
        if let Some(total) = positive_limit(memory.swap(), "memory plus swap limit")? {
            let memory = result
                .memory_max
                .ok_or_else(|| anyhow::anyhow!("swap limit requires a memory limit"))?;
            result.swap_max =
                Some(total.checked_sub(memory).ok_or_else(|| {
                    anyhow::anyhow!("memory plus swap limit is below memory limit")
                })?);
        }
    }
    if let Some(pids) = resources.pids() {
        result.pids_max = positive_limit(Some(pids.limit()), "task limit")?;
    }
    Ok(result)
}

fn positive_limit(value: Option<i64>, name: &str) -> Result<Option<u64>> {
    match value {
        None | Some(-1 | 0) => Ok(None),
        Some(value) if value > 0 => Ok(Some(value as u64)),
        _ => bail!("invalid {name}"),
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_application_user_namespace_and_rejects_incomplete_requests() {
        let request = serde_json::json!({
            "namespaces": [{"type":"user"}, {"type":"pid"}, {"type":"mount"}],
            "uidMappings": [{"containerID":0, "hostID":100000, "size":65536}],
            "gidMappings": [{"containerID":0, "hostID":200000, "size":65536}]
        });
        let bundle = |linux| OciBundle {
            path: "/bundle".into(),
            spec: serde_json::from_value(serde_json::json!({"ociVersion":"1.2.0", "linux":linux}))
                .unwrap(),
        };
        let user = policy(&bundle(request.clone())).unwrap().user.unwrap();
        assert_eq!(user.uid_mappings[0].guest_id, 100000);
        assert_eq!(user.gid_mappings[0].guest_id, 200000);

        for key in ["uidMappings", "gidMappings", "namespaces"] {
            let mut invalid = request.clone();
            invalid.as_object_mut().unwrap().remove(key);
            assert!(policy(&bundle(invalid)).is_err(), "missing {key}");
        }
        let mut invalid = request;
        invalid["namespaces"][0]["path"] = "/proc/1/ns/user".into();
        assert!(
            policy(&bundle(invalid))
                .unwrap_err()
                .to_string()
                .contains("cannot join a host")
        );
    }

    #[test]
    fn maps_one_guest_namespace_set_and_rejects_host_paths() {
        let bundle = |namespaces: serde_json::Value, hostname: &str| OciBundle {
            path: "/bundle".into(),
            spec: serde_json::from_value(serde_json::json!({
                "ociVersion": "1.2.0", "hostname": hostname,
                "linux": {"namespaces": namespaces}
            }))
            .unwrap(),
        };
        let requested = bundle(
            serde_json::json!([
                {"type": "pid"}, {"type": "mount"}, {"type": "ipc"},
                {"type": "uts"}, {"type": "cgroup"}, {"type": "time"},
                {"type": "network", "path": "/run/netns/container"}
            ]),
            "workload",
        );
        let mapped = policy(&requested).unwrap();
        assert!(mapped.pid && mapped.mount && mapped.ipc && mapped.uts && mapped.cgroup);
        assert!(mapped.time.is_some());
        assert_eq!(mapped.hostname.as_deref(), Some("workload"));
        for namespaces in [
            serde_json::json!([{"type": "mount", "path": "/proc/1/ns/mnt"}]),
            serde_json::json!([{"type": "pid"}]),
            serde_json::json!([{"type": "user"}]),
            serde_json::json!([{"type": "time", "path": "/proc/1/ns/time"}]),
        ] {
            assert!(policy(&bundle(namespaces, "")).is_err());
        }
        assert!(policy(&bundle(serde_json::json!([]), "workload")).is_err());
    }

    #[test]
    fn maps_time_offsets_and_rejects_invalid_requests() {
        let bundle = |linux| OciBundle {
            path: "/bundle".into(),
            spec: serde_json::from_value(serde_json::json!({
                "ociVersion": "1.2.0", "linux": linux
            }))
            .unwrap(),
        };
        let request = serde_json::json!({
            "namespaces": [{"type": "time"}],
            "timeOffsets": {
                "monotonic": {"secs": -2, "nanosecs": 123},
                "boottime": {"secs": 34}
            }
        });
        let time = policy(&bundle(request)).unwrap().time.unwrap();
        assert_eq!(
            time.monotonic.unwrap(),
            WorkloadTimeOffset {
                seconds: -2,
                nanoseconds: 123
            }
        );
        assert_eq!(
            time.boottime.unwrap(),
            WorkloadTimeOffset {
                seconds: 34,
                nanoseconds: 0
            }
        );

        for invalid in [
            serde_json::json!({"timeOffsets": {"monotonic": {"secs": 1}}}),
            serde_json::json!({"namespaces": [{"type": "time"}], "timeOffsets": {"realtime": {"secs": 1}}}),
            serde_json::json!({"namespaces": [{"type": "time"}], "timeOffsets": {"monotonic": {"nanosecs": 1000000000}}}),
        ] {
            assert!(policy(&bundle(invalid)).is_err());
        }
    }

    #[test]
    fn maps_limits_without_subtracting_management_overhead() {
        let resources = serde_json::from_value(serde_json::json!({
            "cpu": {"quota": 150000, "period": 100000, "shares": 1024},
            "memory": {"limit": 536870912, "swap": 536870912}, "pids": {"limit": 32}
        }))
        .unwrap();
        let mapped = resource_policy(&resources).unwrap();
        assert_eq!(mapped.cpu_quota, Some(150000));
        assert_eq!(mapped.memory_max, Some(536870912));
        assert_eq!(mapped.swap_max, Some(0));
        assert_eq!(mapped.pids_max, Some(32));
        assert_eq!(guest_memory_mib(&mapped).unwrap(), Some(640));
        assert_eq!(guest_cpus(&mapped).unwrap(), Some(3));
    }

    #[test]
    fn accepts_docker_empty_block_io_without_losing_supported_limits() {
        for block_io in [
            serde_json::Value::Null,
            serde_json::json!({}),
            serde_json::json!({"weight": 0}),
            serde_json::json!({
                "weight": 0, "leafWeight": 0, "weightDevice": [],
                "throttleReadBpsDevice": [], "throttleWriteBpsDevice": [],
                "throttleReadIOPSDevice": [], "throttleWriteIOPSDevice": []
            }),
        ] {
            let resources = serde_json::from_value(serde_json::json!({
                "blockIO": block_io,
                "cpu": {"quota": 50000, "period": 100000},
                "memory": {"limit": 67108864, "swap": 67108864},
                "pids": {"limit": 8}
            }))
            .unwrap();

            let mapped = resource_policy(&resources).unwrap();
            assert_eq!(mapped.cpu_quota, Some(50000));
            assert_eq!(mapped.cpu_period, Some(100000));
            assert_eq!(mapped.memory_max, Some(67108864));
            assert_eq!(mapped.swap_max, Some(0));
            assert_eq!(mapped.pids_max, Some(8));
        }
    }

    #[test]
    fn rejects_every_requested_block_io_control() {
        for block_io in [
            serde_json::json!({"weight": 500}),
            serde_json::json!({"leafWeight": 500}),
            serde_json::json!({"weightDevice": [{"major": 8, "minor": 0, "weight": 500}]}),
            serde_json::json!({"throttleReadBpsDevice": [{"major": 8, "minor": 0, "rate": 1024}]}),
            serde_json::json!({"throttleWriteBpsDevice": [{"major": 8, "minor": 0, "rate": 1024}]}),
            serde_json::json!({"throttleReadIOPSDevice": [{"major": 8, "minor": 0, "rate": 10}]}),
            serde_json::json!({"throttleWriteIOPSDevice": [{"major": 8, "minor": 0, "rate": 10}]}),
        ] {
            let resources =
                serde_json::from_value(serde_json::json!({"blockIO": block_io})).unwrap();

            let error = resource_policy(&resources).unwrap_err();
            assert!(error.to_string().contains("block I/O"), "{error}");
        }
    }

    #[test]
    fn rejects_untranslated_controls_and_invalid_limits() {
        for value in [
            serde_json::json!({"cpu": {"cpus": "2-3"}}),
            serde_json::json!({"cpu": {"quota": 1}}),
            serde_json::json!({"memory": {"limit": 1024, "swap": 512}}),
            serde_json::json!({"pids": {"limit": -2}}),
            serde_json::json!({"unified": {"memory.max": "100"}}),
        ] {
            assert!(resource_policy(&serde_json::from_value(value).unwrap()).is_err());
        }
    }
}
