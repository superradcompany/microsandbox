//! Portable CPU placement planning.

use std::collections::{BTreeMap, HashSet};

use microsandbox_types::{CpuPlacement, MemoryPlacement, NumaPlacement};

use super::PlacementRequest;
use super::topology::{CpuTopology, LogicalCpu, LogicalCpuId};
use crate::{RuntimeError, RuntimeResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CpuReservation {
    pub(crate) logical_cpu: LogicalCpuId,
    pub(crate) vcpu_index: Option<u8>,
    pub(crate) role: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResolvedPlacement {
    pub(crate) requested: CpuPlacement,
    pub(crate) resolved: CpuPlacement,
    pub(crate) vcpu_targets: Vec<LogicalCpuId>,
    pub(crate) reservations: Vec<CpuReservation>,
    pub(crate) numa: Option<ResolvedNumaPlacement>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResolvedNumaPlacement {
    pub(crate) nodes: Vec<ResolvedNumaNode>,
    pub(crate) distances: Vec<(u16, u16, u8)>,
    pub(crate) memory: MemoryPlacement,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResolvedNumaNode {
    pub(crate) guest_node_id: u16,
    pub(crate) host_node_id: u32,
    pub(crate) vcpu_indices: Vec<u8>,
    pub(crate) boot_memory_mib: u32,
    pub(crate) max_memory_mib: u32,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn plan(
    topology: &CpuTopology,
    occupied: &HashSet<LogicalCpuId>,
    request: PlacementRequest,
    reserved_memory_mib: &BTreeMap<u32, u64>,
) -> RuntimeResult<ResolvedPlacement> {
    let requested_count = usize::from(request.max_vcpus);
    if requested_count == 0 {
        return Err(RuntimeError::Custom(
            "managed CPU placement requires max_cpus greater than zero".into(),
        ));
    }

    let Some(profile) = request.profile else {
        return plan_cpu(topology, occupied, request.policy, requested_count);
    };
    if matches!(profile.memory, MemoryPlacement::FollowCpu)
        && matches!(request.policy, CpuPlacement::Inherit)
    {
        return Err(RuntimeError::Custom(
            "follow_cpu memory requires auto, spread, or compact CPU placement".into(),
        ));
    }
    if matches!(request.policy, CpuPlacement::Inherit) {
        if matches!(profile.numa, NumaPlacement::Inherit)
            && matches!(profile.memory, MemoryPlacement::Inherit)
        {
            return Err(RuntimeError::Custom(
                "an inherited no-op placement profile must bypass managed planning".into(),
            ));
        }
        return Err(RuntimeError::Custom(
            "managed NUMA placement requires auto, spread, or compact CPU placement".into(),
        ));
    }

    match profile.numa {
        NumaPlacement::PreferSingle | NumaPlacement::StrictSingle => {
            let mut candidates = topology.numa_nodes.iter().collect::<Vec<_>>();
            candidates.sort_by_key(|node| {
                let reserved = reserved_memory_mib.get(&node.id).copied().unwrap_or(0);
                (
                    std::cmp::Reverse(node.available_memory_mib),
                    reserved,
                    node.package,
                    node.id,
                )
            });
            for node in candidates {
                let reserved = reserved_memory_mib.get(&node.id).copied().unwrap_or(0);
                if node.available_memory_mib < u64::from(request.boot_memory_mib)
                    || node.total_memory_mib.saturating_sub(reserved)
                        < u64::from(request.max_memory_mib)
                {
                    continue;
                }
                let scoped = CpuTopology {
                    logical_cpus: topology
                        .logical_cpus
                        .iter()
                        .filter(|cpu| cpu.numa_node == node.id)
                        .cloned()
                        .collect(),
                    numa_nodes: vec![node.clone()],
                    fingerprint: topology.fingerprint.clone(),
                };
                let Ok(mut resolved) = plan_cpu(&scoped, occupied, request.policy, requested_count)
                else {
                    continue;
                };
                resolved.numa = Some(single_node_numa(
                    node.id,
                    request.max_vcpus,
                    request.boot_memory_mib,
                    request.max_memory_mib,
                    profile.memory,
                ));
                return Ok(resolved);
            }

            let mode = match profile.numa {
                NumaPlacement::StrictSingle => "strict_single",
                NumaPlacement::PreferSingle => "prefer_single",
                NumaPlacement::Inherit => unreachable!(),
            };
            Err(RuntimeError::Custom(format!(
                "NUMA placement {mode} cannot fit max_cpus={} and max_memory_mib={} on one allowed host node; multi-node guest placement is not enabled yet",
                request.max_vcpus, request.max_memory_mib
            )))
        }
        NumaPlacement::Inherit => {
            let mut resolved = plan_cpu(topology, occupied, request.policy, requested_count)?;
            if matches!(profile.memory, MemoryPlacement::FollowCpu) {
                let host_nodes = resolved
                    .vcpu_targets
                    .iter()
                    .filter_map(|target| {
                        topology
                            .logical_cpus
                            .iter()
                            .find(|cpu| cpu.id == *target)
                            .map(|cpu| cpu.numa_node)
                    })
                    .collect::<HashSet<_>>();
                if host_nodes.len() != 1 {
                    return Err(RuntimeError::Custom(
                        "follow_cpu memory needs guest NUMA tables when selected CPUs span host nodes; multi-node placement is not enabled yet".into(),
                    ));
                }
                let host_node = *host_nodes.iter().next().ok_or_else(|| {
                    RuntimeError::Custom("resolved CPU placement has no host NUMA node".into())
                })?;
                resolved.numa = Some(single_node_numa(
                    host_node,
                    request.max_vcpus,
                    request.boot_memory_mib,
                    request.max_memory_mib,
                    profile.memory,
                ));
            }
            Ok(resolved)
        }
    }
}

fn plan_cpu(
    topology: &CpuTopology,
    occupied: &HashSet<LogicalCpuId>,
    requested: CpuPlacement,
    requested_count: usize,
) -> RuntimeResult<ResolvedPlacement> {
    let cores = available_cores(topology, occupied);
    match requested {
        CpuPlacement::Auto => plan_auto(cores, requested_count),
        CpuPlacement::Spread => plan_spread(cores, requested, requested_count),
        CpuPlacement::Compact => plan_compact(cores, requested, requested_count),
        CpuPlacement::Inherit => Err(RuntimeError::Custom(
            "inherit must bypass the managed CPU planner".into(),
        )),
    }
}

fn single_node_numa(
    host_node_id: u32,
    max_vcpus: u8,
    boot_memory_mib: u32,
    max_memory_mib: u32,
    memory: MemoryPlacement,
) -> ResolvedNumaPlacement {
    ResolvedNumaPlacement {
        nodes: vec![ResolvedNumaNode {
            guest_node_id: 0,
            host_node_id,
            vcpu_indices: (0..max_vcpus).collect(),
            boot_memory_mib,
            max_memory_mib,
        }],
        distances: vec![(0, 0, 10)],
        memory,
    }
}

#[derive(Debug)]
struct AvailableCore<'a> {
    logical: Vec<&'a LogicalCpu>,
    free: Vec<&'a LogicalCpu>,
    all_free: bool,
    performance_class: u8,
}

fn available_cores<'a>(
    topology: &'a CpuTopology,
    occupied: &HashSet<LogicalCpuId>,
) -> Vec<AvailableCore<'a>> {
    let mut grouped: BTreeMap<(i32, i32, i32), Vec<&LogicalCpu>> = BTreeMap::new();
    for cpu in &topology.logical_cpus {
        grouped
            .entry((cpu.package, cpu.die, cpu.core))
            .or_default()
            .push(cpu);
    }

    let mut cores = grouped
        .into_values()
        .map(|mut logical| {
            logical.sort_by_key(|cpu| cpu.id);
            let free = logical
                .iter()
                .copied()
                .filter(|cpu| !occupied.contains(&cpu.id))
                .collect::<Vec<_>>();
            let all_free = free.len() == logical.len();
            AvailableCore {
                performance_class: logical[0].performance_class,
                logical,
                free,
                all_free,
            }
        })
        .collect::<Vec<_>>();
    cores.sort_by_key(|core| std::cmp::Reverse(core.performance_class));
    cores
}

/// Plan Auto as one stable spread-then-share strategy.
///
/// Pass one uses an untouched physical core. A free sibling beside an existing Auto assignment is
/// a soft hold only in this pass; pass two may consume it when distinct cores are exhausted.
fn plan_auto(
    cores: Vec<AvailableCore<'_>>,
    requested_count: usize,
) -> RuntimeResult<ResolvedPlacement> {
    let mut selected = Vec::with_capacity(requested_count);

    // Prefer one thread from every entirely free physical core. This is the low-contention phase.
    for core in &cores {
        if core.all_free {
            selected.push(core.free[0].id);
            if selected.len() == requested_count {
                break;
            }
        }
    }

    // Density phase: use any remaining free hardware thread, including a derived soft hold beside
    // an older Auto allocation. Keep core order stable so identical snapshots produce identical
    // plans and the existing uniqueness constraint can resolve concurrent races predictably.
    if selected.len() < requested_count {
        for core in &cores {
            for cpu in &core.free {
                if selected.contains(&cpu.id) {
                    continue;
                }
                selected.push(cpu.id);
                if selected.len() == requested_count {
                    break;
                }
            }
            if selected.len() == requested_count {
                break;
            }
        }
    }
    if selected.len() != requested_count {
        return insufficient_capacity(CpuPlacement::Auto, requested_count);
    }

    let reservations = selected
        .iter()
        .enumerate()
        .map(|(vcpu_index, logical_cpu)| CpuReservation {
            logical_cpu: *logical_cpu,
            vcpu_index: Some(vcpu_index as u8),
            role: "assigned",
        })
        .collect();
    Ok(ResolvedPlacement {
        requested: CpuPlacement::Auto,
        resolved: CpuPlacement::Auto,
        vcpu_targets: selected,
        reservations,
        numa: None,
    })
}

fn plan_spread(
    cores: Vec<AvailableCore<'_>>,
    requested: CpuPlacement,
    requested_count: usize,
) -> RuntimeResult<ResolvedPlacement> {
    let selected: Vec<_> = cores
        .into_iter()
        .filter(|core| core.all_free)
        .take(requested_count)
        .collect();
    if selected.len() != requested_count {
        return insufficient_capacity(CpuPlacement::Spread, requested_count);
    }

    let mut vcpu_targets = Vec::with_capacity(requested_count);
    let mut reservations = Vec::new();
    for (vcpu_index, core) in selected.into_iter().enumerate() {
        let assigned = core.logical[0].id;
        vcpu_targets.push(assigned);
        for cpu in core.logical {
            reservations.push(CpuReservation {
                logical_cpu: cpu.id,
                vcpu_index: (cpu.id == assigned).then_some(vcpu_index as u8),
                role: if cpu.id == assigned {
                    "assigned"
                } else {
                    "smt-reserved"
                },
            });
        }
    }

    Ok(ResolvedPlacement {
        requested,
        resolved: CpuPlacement::Spread,
        vcpu_targets,
        reservations,
        numa: None,
    })
}

fn plan_compact(
    cores: Vec<AvailableCore<'_>>,
    requested: CpuPlacement,
    requested_count: usize,
) -> RuntimeResult<ResolvedPlacement> {
    let mut candidates: Vec<_> = cores
        .into_iter()
        .map(|core| core.free)
        .filter(|logical| !logical.is_empty())
        .collect();
    candidates.sort_by_key(|logical| std::cmp::Reverse(logical.len()));

    let mut selected = Vec::with_capacity(requested_count);
    for core in candidates {
        for cpu in core {
            selected.push(cpu.id);
            if selected.len() == requested_count {
                break;
            }
        }
        if selected.len() == requested_count {
            break;
        }
    }
    if selected.len() != requested_count {
        return insufficient_capacity(CpuPlacement::Compact, requested_count);
    }

    let reservations = selected
        .iter()
        .enumerate()
        .map(|(vcpu_index, logical_cpu)| CpuReservation {
            logical_cpu: *logical_cpu,
            vcpu_index: Some(vcpu_index as u8),
            role: "assigned",
        })
        .collect();
    Ok(ResolvedPlacement {
        requested,
        resolved: CpuPlacement::Compact,
        vcpu_targets: selected,
        reservations,
        numa: None,
    })
}

fn insufficient_capacity<T>(policy: CpuPlacement, requested_count: usize) -> RuntimeResult<T> {
    Err(RuntimeError::Custom(format!(
        "CPU placement {policy} cannot reserve {requested_count} vCPUs from the allowed host topology"
    )))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu::topology::HostNumaNode;
    use microsandbox_types::PlacementProfile;

    fn plan(
        topology: &CpuTopology,
        occupied: &HashSet<LogicalCpuId>,
        requested: CpuPlacement,
        max_vcpus: u8,
    ) -> RuntimeResult<ResolvedPlacement> {
        super::plan(
            topology,
            occupied,
            PlacementRequest {
                policy: requested,
                max_vcpus,
                boot_memory_mib: 512,
                max_memory_mib: 512,
                profile: None,
            },
            &BTreeMap::new(),
        )
    }

    fn topology() -> CpuTopology {
        CpuTopology {
            logical_cpus: vec![
                cpu(0, 0),
                cpu(6, 0),
                cpu(1, 1),
                cpu(7, 1),
                cpu(2, 2),
                cpu(8, 2),
            ],
            numa_nodes: vec![HostNumaNode {
                id: 0,
                package: 0,
                total_memory_mib: 16_384,
                available_memory_mib: 16_384,
                distances: BTreeMap::from([(0, 10)]),
            }],
            fingerprint: "fixture".into(),
        }
    }

    fn cpu(id: u16, core: i32) -> LogicalCpu {
        cpu_with_class(id, core, 0)
    }

    fn cpu_with_class(id: u16, core: i32, performance_class: u8) -> LogicalCpu {
        LogicalCpu {
            id: LogicalCpuId::new(id),
            package: 0,
            die: 0,
            core,
            numa_node: 0,
            performance_class,
        }
    }

    fn id(index: u16) -> LogicalCpuId {
        LogicalCpuId::new(index)
    }

    #[test]
    fn spread_uses_distinct_cores_and_reserves_siblings() {
        let plan = plan(&topology(), &HashSet::new(), CpuPlacement::Spread, 2).unwrap();

        assert_eq!(plan.vcpu_targets, vec![id(0), id(1)]);
        assert_eq!(
            plan.reservations
                .iter()
                .map(|reservation| reservation.logical_cpu)
                .collect::<Vec<_>>(),
            vec![id(0), id(6), id(1), id(7)]
        );
    }

    #[test]
    fn compact_consumes_smt_siblings_first() {
        let plan = plan(&topology(), &HashSet::new(), CpuPlacement::Compact, 2).unwrap();

        assert_eq!(plan.vcpu_targets, vec![id(0), id(6)]);
        assert_eq!(plan.reservations.len(), 2);
    }

    #[test]
    fn auto_uses_distinct_cores_before_smt_siblings() {
        let plan = plan(&topology(), &HashSet::new(), CpuPlacement::Auto, 3).unwrap();

        assert_eq!(plan.resolved, CpuPlacement::Auto);
        assert_eq!(plan.vcpu_targets, vec![id(0), id(1), id(2)]);
        assert!(plan.reservations.iter().all(|row| row.role == "assigned"));
    }

    #[test]
    fn auto_consumes_derived_soft_holds_when_untouched_cores_are_exhausted() {
        // A previously took CPU 0 and CPU 1 with Auto. Their free siblings are not occupied rows.
        let occupied = HashSet::from([id(0), id(1)]);
        let plan = plan(&topology(), &occupied, CpuPlacement::Auto, 2).unwrap();

        assert_eq!(plan.vcpu_targets, vec![id(2), id(6)]);
    }

    #[test]
    fn auto_soft_holds_reappear_without_catalog_mutation() {
        let occupied = HashSet::from([id(0), id(1)]);

        let first = plan(&topology(), &occupied, CpuPlacement::Auto, 1).unwrap();
        let after_sibling_user_exits = plan(&topology(), &occupied, CpuPlacement::Auto, 1).unwrap();

        assert_eq!(first.vcpu_targets, vec![id(2)]);
        assert_eq!(after_sibling_user_exits.vcpu_targets, first.vcpu_targets);
    }

    #[test]
    fn spread_does_not_share_a_partially_occupied_core() {
        let occupied = HashSet::from([id(6)]);
        let plan = plan(&topology(), &occupied, CpuPlacement::Spread, 2).unwrap();

        assert_eq!(plan.vcpu_targets, vec![id(1), id(2)]);
    }

    #[test]
    fn managed_policies_prefer_windows_performance_cores() {
        let topology = CpuTopology {
            logical_cpus: vec![cpu_with_class(0, 0, 1), cpu_with_class(1, 1, 4)],
            numa_nodes: vec![HostNumaNode {
                id: 0,
                package: 0,
                total_memory_mib: 16_384,
                available_memory_mib: 16_384,
                distances: BTreeMap::from([(0, 10)]),
            }],
            fingerprint: "heterogeneous".into(),
        };

        let plan = plan(&topology, &HashSet::new(), CpuPlacement::Compact, 1).unwrap();

        assert_eq!(plan.vcpu_targets, vec![id(1)]);
    }

    #[test]
    fn prefer_single_keeps_maximum_capacity_on_one_numa_node() {
        let mut topology = topology();
        topology.numa_nodes = vec![
            HostNumaNode {
                id: 0,
                package: 0,
                total_memory_mib: 4096,
                available_memory_mib: 4096,
                distances: BTreeMap::from([(0, 10), (1, 12)]),
            },
            HostNumaNode {
                id: 1,
                package: 0,
                total_memory_mib: 8192,
                available_memory_mib: 8192,
                distances: BTreeMap::from([(0, 12), (1, 10)]),
            },
        ];
        for cpu in &mut topology.logical_cpus {
            cpu.numa_node = if cpu.core < 2 { 0 } else { 1 };
        }
        let profile = PlacementProfile {
            numa: NumaPlacement::PreferSingle,
            memory: MemoryPlacement::FollowCpu,
        };
        let resolved = super::plan(
            &topology,
            &HashSet::new(),
            PlacementRequest {
                policy: CpuPlacement::Auto,
                max_vcpus: 2,
                boot_memory_mib: 1024,
                max_memory_mib: 4096,
                profile: Some(profile),
            },
            &BTreeMap::new(),
        )
        .unwrap();

        assert!(
            resolved
                .vcpu_targets
                .iter()
                .all(|cpu| [id(2), id(8)].contains(cpu))
        );
        assert_eq!(resolved.numa.unwrap().nodes[0].host_node_id, 1);
    }

    #[test]
    fn strict_single_rejects_reserved_memory_overcommit() {
        let profile = PlacementProfile {
            numa: NumaPlacement::StrictSingle,
            memory: MemoryPlacement::FollowCpu,
        };
        let error = super::plan(
            &topology(),
            &HashSet::new(),
            PlacementRequest {
                policy: CpuPlacement::Auto,
                max_vcpus: 2,
                boot_memory_mib: 1024,
                max_memory_mib: 4096,
                profile: Some(profile),
            },
            &BTreeMap::from([(0, 15_000)]),
        )
        .unwrap_err();

        assert!(error.to_string().contains("strict_single"));
    }
}
