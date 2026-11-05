//! Explicit guest workload isolation requested by the OCI runtime.

use serde::{Deserialize, Serialize};

use crate::exec::ExecRequest;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// One namespace and resource domain for the init command and subsequent execs.
///
/// This is a create-once policy, not a per-exec request to create nested containers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WorkloadIsolation {
    /// Create a workload PID namespace with the first command as PID 1.
    pub pid: bool,
    /// Clone the prepared mount tree once for this workload.
    pub mount: bool,
    /// Isolate System V IPC and POSIX message queues.
    pub ipc: bool,
    /// Isolate the workload hostname.
    pub uts: bool,
    /// Hide ancestor cgroups from the workload.
    pub cgroup: bool,
    /// Isolate monotonic and boot-time clocks; absent for existing workloads.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<WorkloadTimeNamespace>,
    /// Application IDs mapped into the guest's IDs, not the host kernel's IDs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<WorkloadUserNamespace>,
    /// Hostname applied only in the workload UTS namespace.
    pub hostname: Option<String>,
    /// Resource ceilings for the workload, excluding agentd.
    pub resources: WorkloadResources,
}

/// Clock offsets applied before the first process enters the time namespace.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WorkloadTimeNamespace {
    /// Offset from the guest kernel's monotonic clock.
    pub monotonic: Option<WorkloadTimeOffset>,
    /// Offset from the guest kernel's boot-time clock.
    pub boottime: Option<WorkloadTimeOffset>,
}

/// Signed seconds plus nonnegative nanoseconds for a namespaced clock.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WorkloadTimeOffset {
    /// Signed whole seconds.
    pub seconds: i64,
    /// Fractional nanoseconds, strictly below one billion.
    pub nanoseconds: u32,
}

/// UID/GID maps for one user namespace shared by init and subsequent execs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadUserNamespace {
    /// User ID mappings into agentd's guest user namespace.
    pub uid_mappings: Vec<WorkloadIdMapping>,
    /// Group ID mappings into agentd's guest user namespace.
    pub gid_mappings: Vec<WorkloadIdMapping>,
}

/// One contiguous, non-overlapping range of application and guest IDs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadIdMapping {
    /// First ID visible to the application.
    pub container_id: u32,
    /// First corresponding ID outside the namespace, inside the guest.
    pub guest_id: u32,
    /// Number of IDs in this range.
    pub size: u32,
}

/// Supported cgroup-v2 workload controls, in kernel units.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WorkloadResources {
    /// Aggregate CPU quota in microseconds; absence means unlimited.
    pub cpu_quota: Option<u64>,
    /// CPU period in microseconds.
    pub cpu_period: Option<u64>,
    /// Cgroup-v2 CPU weight, between 1 and 10000.
    pub cpu_weight: Option<u64>,
    /// Workload memory ceiling in bytes.
    pub memory_max: Option<u64>,
    /// Additional swap ceiling in bytes, not memory plus swap.
    pub swap_max: Option<u64>,
    /// Aggregate task ceiling; Linux counts threads as well as processes.
    pub pids_max: Option<u64>,
}

/// Start the first command in a new, explicitly isolated workload domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolatedExecRequest {
    /// Ordinary process settings.
    pub process: ExecRequest,
    /// Create-once namespace and cgroup configuration.
    pub isolation: WorkloadIsolation,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl WorkloadUserNamespace {
    /// Validate both maps before any namespace or process is created.
    pub fn validate(&self) -> Result<(), &'static str> {
        validate_id_mappings(&self.uid_mappings)?;
        validate_id_mappings(&self.gid_mappings)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn validate_id_mappings(mappings: &[WorkloadIdMapping]) -> Result<(), &'static str> {
    if mappings.is_empty() || mappings.len() > 340 {
        return Err("user namespaces require between 1 and 340 UID and GID mappings");
    }
    if !mappings.iter().any(|mapping| mapping.container_id == 0) {
        return Err("user namespace mappings must include application ID 0");
    }
    for (index, mapping) in mappings.iter().enumerate() {
        // Linux reserves (uid_t)-1 and (gid_t)-1; neither may be mapped.
        if mapping.size == 0
            || mapping.container_id.checked_add(mapping.size).is_none()
            || mapping.guest_id.checked_add(mapping.size).is_none()
        {
            return Err("invalid or overflowing user namespace ID mapping");
        }
        for previous in &mappings[..index] {
            let overlaps = |left: u32, left_size: u32, right: u32, right_size: u32| {
                u64::from(left) < u64::from(right) + u64::from(right_size)
                    && u64::from(right) < u64::from(left) + u64::from(left_size)
            };
            if overlaps(
                mapping.container_id,
                mapping.size,
                previous.container_id,
                previous.size,
            ) || overlaps(
                mapping.guest_id,
                mapping.size,
                previous.guest_id,
                previous.size,
            ) {
                return Err("overlapping user namespace ID mappings");
            }
        }
    }
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_user_namespace_mappings() {
        let mapping = WorkloadIdMapping {
            container_id: 0,
            guest_id: 100000,
            size: 65536,
        };
        let valid = WorkloadUserNamespace {
            uid_mappings: vec![mapping.clone()],
            gid_mappings: vec![mapping.clone()],
        };
        assert!(valid.validate().is_ok());
        for invalid in [
            Vec::new(),
            vec![WorkloadIdMapping {
                size: 0,
                ..mapping.clone()
            }],
            vec![WorkloadIdMapping {
                guest_id: u32::MAX,
                ..mapping.clone()
            }],
            vec![WorkloadIdMapping {
                container_id: 1,
                ..mapping.clone()
            }],
            vec![
                mapping.clone(),
                WorkloadIdMapping {
                    container_id: 1,
                    guest_id: 200000,
                    size: 1,
                },
            ],
            vec![
                mapping.clone(),
                WorkloadIdMapping {
                    container_id: 65536,
                    guest_id: 100001,
                    size: 1,
                },
            ],
        ] {
            let mut policy = valid.clone();
            policy.uid_mappings = invalid.clone();
            assert!(policy.validate().is_err());
            policy = valid.clone();
            policy.gid_mappings = invalid;
            assert!(policy.validate().is_err());
        }
    }

    #[test]
    fn old_isolation_omits_user_and_new_policy_round_trips() {
        let old = serde_json::json!({"pid": true, "mount": true});
        let mut policy: WorkloadIsolation = serde_json::from_value(old).unwrap();
        assert!(policy.user.is_none());
        assert!(serde_json::to_value(&policy).unwrap().get("user").is_none());
        policy.user = Some(WorkloadUserNamespace {
            uid_mappings: vec![WorkloadIdMapping {
                container_id: 0,
                guest_id: 0,
                size: 1,
            }],
            gid_mappings: vec![WorkloadIdMapping {
                container_id: 0,
                guest_id: 0,
                size: 1,
            }],
        });
        let mut encoded = Vec::new();
        ciborium::into_writer(&policy, &mut encoded).unwrap();
        let decoded: WorkloadIsolation = ciborium::from_reader(encoded.as_slice()).unwrap();
        assert_eq!(decoded, policy);
    }

    #[test]
    fn existing_policy_omits_time_and_new_policy_round_trips() {
        let previous = serde_json::json!({
            "pid": true, "mount": true, "ipc": true, "uts": true,
            "cgroup": true, "hostname": null, "resources": {}
        });
        let mut policy: WorkloadIsolation = serde_json::from_value(previous).unwrap();
        assert!(policy.time.is_none());
        assert!(serde_json::to_value(&policy).unwrap().get("time").is_none());

        policy.time = Some(WorkloadTimeNamespace::default());
        let mut encoded = Vec::new();
        ciborium::into_writer(&policy, &mut encoded).unwrap();
        let decoded: WorkloadIsolation = ciborium::from_reader(encoded.as_slice()).unwrap();
        assert_eq!(decoded, policy);
    }
}
