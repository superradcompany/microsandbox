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
    pub(crate) shared: bool,
    pub(crate) fallback: Option<PlacementFallback>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PlacementFallback {
    PreferSingleCapacity,
    FollowCpuCrossNode,
    FollowCpuMemoryCapacity,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResolvedNumaPlacement {
    pub(crate) nodes: Vec<ResolvedNumaNode>,
    pub(crate) distances: Vec<(u16, u16, u8)>,
    pub(crate) memory: MemoryPlacement,
    pub(crate) required: bool,
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
    loads: &BTreeMap<LogicalCpuId, usize>,
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
        return plan_cpu(topology, loads, request.policy, requested_count);
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
                if !node_can_fit_memory(node, reserved, request)
                    || !node_can_fit_unshared_cpus(topology, loads, node.id, requested_count)
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
                let Ok(mut resolved) = plan_cpu(&scoped, loads, request.policy, requested_count)
                else {
                    continue;
                };
                resolved.numa = Some(single_node_numa(
                    node.id,
                    request.max_vcpus,
                    request.boot_memory_mib,
                    request.max_memory_mib,
                    profile.memory,
                    matches!(profile.numa, NumaPlacement::StrictSingle),
                ));
                return Ok(resolved);
            }

            if matches!(profile.numa, NumaPlacement::StrictSingle) {
                return Err(RuntimeError::Custom(format!(
                    "NUMA placement strict_single cannot fit max_cpus={} and max_memory_mib={} on one allowed host node",
                    request.max_vcpus, request.max_memory_mib
                )));
            }

            let mut resolved = plan_cpu(topology, loads, request.policy, requested_count)?;
            resolved.fallback = Some(PlacementFallback::PreferSingleCapacity);
            Ok(resolved)
        }
        NumaPlacement::Inherit => {
            let mut resolved = plan_cpu(topology, loads, request.policy, requested_count)?;
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
                    resolved.fallback = Some(PlacementFallback::FollowCpuCrossNode);
                    return Ok(resolved);
                }
                let host_node = *host_nodes.iter().next().ok_or_else(|| {
                    RuntimeError::Custom("resolved CPU placement has no host NUMA node".into())
                })?;
                let node = topology
                    .numa_nodes
                    .iter()
                    .find(|node| node.id == host_node)
                    .ok_or_else(|| {
                        RuntimeError::Custom(format!(
                            "resolved CPU placement references missing host NUMA node {host_node}"
                        ))
                    })?;
                let reserved = reserved_memory_mib.get(&host_node).copied().unwrap_or(0);
                if node_can_fit_memory(node, reserved, request) {
                    resolved.numa = Some(single_node_numa(
                        host_node,
                        request.max_vcpus,
                        request.boot_memory_mib,
                        request.max_memory_mib,
                        profile.memory,
                        false,
                    ));
                } else {
                    resolved.fallback = Some(PlacementFallback::FollowCpuMemoryCapacity);
                }
            }
            Ok(resolved)
        }
    }
}

fn plan_cpu(
    topology: &CpuTopology,
    loads: &BTreeMap<LogicalCpuId, usize>,
    requested: CpuPlacement,
    requested_count: usize,
) -> RuntimeResult<ResolvedPlacement> {
    let cores = core_loads(topology, loads);
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
    required: bool,
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
        required,
    }
}

#[derive(Debug)]
struct CoreLoad {
    logical: Vec<LogicalLoad>,
    performance_class: u8,
}

#[derive(Debug)]
struct LogicalLoad {
    id: LogicalCpuId,
    assignments: usize,
}

fn core_loads(topology: &CpuTopology, loads: &BTreeMap<LogicalCpuId, usize>) -> Vec<CoreLoad> {
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
            CoreLoad {
                performance_class: logical[0].performance_class,
                logical: logical
                    .into_iter()
                    .map(|cpu| LogicalLoad {
                        id: cpu.id,
                        assignments: loads.get(&cpu.id).copied().unwrap_or(0),
                    })
                    .collect(),
            }
        })
        .collect::<Vec<_>>();
    cores.sort_by_key(|core| std::cmp::Reverse(core.performance_class));
    cores
}

/// Plan Auto as one stable spread-then-share strategy.
fn plan_auto(mut cores: Vec<CoreLoad>, requested_count: usize) -> RuntimeResult<ResolvedPlacement> {
    let mut selected = Vec::with_capacity(requested_count);
    let mut shared = false;

    // Low-contention phase: take one thread from every untouched physical core.
    for core_index in 0..cores.len() {
        if core_total(&cores[core_index]) == 0 {
            select_cpu(&mut cores, core_index, 0, &mut selected, &mut shared);
            if selected.len() == requested_count {
                break;
            }
        }
    }

    // Density phase: consume unused SMT siblings, including soft holds beside older Auto work.
    while selected.len() < requested_count {
        let candidate = cores.iter().enumerate().find_map(|(core_index, core)| {
            core.logical
                .iter()
                .position(|cpu| cpu.assignments == 0)
                .map(|logical_index| (core_index, logical_index))
        });
        let Some((core_index, logical_index)) = candidate else {
            break;
        };
        select_cpu(
            &mut cores,
            core_index,
            logical_index,
            &mut selected,
            &mut shared,
        );
    }

    // Pressure phase: share the least-loaded logical CPUs instead of rejecting creation.
    while selected.len() < requested_count {
        let (core_index, logical_index) = least_loaded_logical(&cores)?;
        select_cpu(
            &mut cores,
            core_index,
            logical_index,
            &mut selected,
            &mut shared,
        );
    }

    Ok(finish_plan(CpuPlacement::Auto, selected, shared))
}

fn plan_spread(
    mut cores: Vec<CoreLoad>,
    requested: CpuPlacement,
    requested_count: usize,
) -> RuntimeResult<ResolvedPlacement> {
    let mut selected = Vec::with_capacity(requested_count);
    let mut shared = false;

    while selected.len() < requested_count {
        let candidate = cores
            .iter()
            .enumerate()
            .filter(|(_, core)| core.logical.iter().any(|cpu| cpu.assignments == 0))
            .min_by_key(|(core_index, core)| (core_total(core), *core_index))
            .map(|(core_index, core)| {
                let logical_index = core
                    .logical
                    .iter()
                    .position(|cpu| cpu.assignments == 0)
                    .expect("candidate core has an unused logical CPU");
                (core_index, logical_index)
            })
            .or_else(|| least_loaded_core_logical(&cores));
        let Some((core_index, logical_index)) = candidate else {
            return no_host_processors(requested);
        };
        select_cpu(
            &mut cores,
            core_index,
            logical_index,
            &mut selected,
            &mut shared,
        );
    }

    Ok(finish_plan(requested, selected, shared))
}

fn plan_compact(
    mut cores: Vec<CoreLoad>,
    requested: CpuPlacement,
    requested_count: usize,
) -> RuntimeResult<ResolvedPlacement> {
    let mut selected = Vec::with_capacity(requested_count);
    let mut shared = false;

    // Fill unused siblings on already active cores before opening another physical core.
    while selected.len() < requested_count {
        let candidate = cores
            .iter()
            .enumerate()
            .filter(|(_, core)| core.logical.iter().any(|cpu| cpu.assignments == 0))
            .min_by_key(|(core_index, core)| {
                (
                    usize::from(core_total(core) == 0),
                    std::cmp::Reverse(core_total(core)),
                    *core_index,
                )
            })
            .map(|(core_index, core)| {
                let logical_index = core
                    .logical
                    .iter()
                    .position(|cpu| cpu.assignments == 0)
                    .expect("candidate core has an unused logical CPU");
                (core_index, logical_index)
            });
        let Some((core_index, logical_index)) = candidate else {
            break;
        };
        select_cpu(
            &mut cores,
            core_index,
            logical_index,
            &mut selected,
            &mut shared,
        );
    }

    // Balance the sharing depth first; compactness is only a tie-breaker under pressure.
    while selected.len() < requested_count {
        let candidate = cores
            .iter()
            .enumerate()
            .flat_map(|(core_index, core)| {
                core.logical
                    .iter()
                    .enumerate()
                    .map(move |(logical_index, cpu)| (core_index, logical_index, cpu))
            })
            .min_by_key(|(core_index, logical_index, cpu)| {
                (
                    cpu.assignments,
                    std::cmp::Reverse(core_total(&cores[*core_index])),
                    *core_index,
                    *logical_index,
                )
            })
            .map(|(core_index, logical_index, _)| (core_index, logical_index));
        let Some((core_index, logical_index)) = candidate else {
            return no_host_processors(requested);
        };
        select_cpu(
            &mut cores,
            core_index,
            logical_index,
            &mut selected,
            &mut shared,
        );
    }

    Ok(finish_plan(requested, selected, shared))
}

fn finish_plan(
    requested: CpuPlacement,
    selected: Vec<LogicalCpuId>,
    shared: bool,
) -> ResolvedPlacement {
    let reservations = selected
        .iter()
        .enumerate()
        .map(|(vcpu_index, logical_cpu)| CpuReservation {
            logical_cpu: *logical_cpu,
            vcpu_index: Some(vcpu_index as u8),
            role: "planned",
        })
        .collect();
    ResolvedPlacement {
        requested,
        resolved: requested,
        vcpu_targets: selected,
        reservations,
        numa: None,
        shared,
        fallback: None,
    }
}

fn select_cpu(
    cores: &mut [CoreLoad],
    core_index: usize,
    logical_index: usize,
    selected: &mut Vec<LogicalCpuId>,
    shared: &mut bool,
) {
    let cpu = &mut cores[core_index].logical[logical_index];
    *shared |= cpu.assignments > 0;
    selected.push(cpu.id);
    cpu.assignments += 1;
}

fn core_total(core: &CoreLoad) -> usize {
    core.logical.iter().map(|cpu| cpu.assignments).sum()
}

fn least_loaded_logical(cores: &[CoreLoad]) -> RuntimeResult<(usize, usize)> {
    cores
        .iter()
        .enumerate()
        .flat_map(|(core_index, core)| {
            core.logical
                .iter()
                .enumerate()
                .map(move |(logical_index, cpu)| (core_index, logical_index, cpu))
        })
        .min_by_key(|(core_index, logical_index, cpu)| {
            (
                cpu.assignments,
                core_total(&cores[*core_index]),
                *core_index,
                *logical_index,
            )
        })
        .map(|(core_index, logical_index, _)| (core_index, logical_index))
        .ok_or_else(|| {
            RuntimeError::Custom("managed CPU placement found no host processors".into())
        })
}

fn least_loaded_core_logical(cores: &[CoreLoad]) -> Option<(usize, usize)> {
    let core_index = cores
        .iter()
        .enumerate()
        .min_by_key(|(core_index, core)| (core_total(core), *core_index))?
        .0;
    let logical_index = cores[core_index]
        .logical
        .iter()
        .enumerate()
        .min_by_key(|(logical_index, cpu)| (cpu.assignments, *logical_index))?
        .0;
    Some((core_index, logical_index))
}

fn node_can_fit_memory(
    node: &super::topology::HostNumaNode,
    reserved_memory_mib: u64,
    request: PlacementRequest,
) -> bool {
    node.available_memory_mib >= u64::from(request.boot_memory_mib)
        && node.total_memory_mib.saturating_sub(reserved_memory_mib)
            >= u64::from(request.max_memory_mib)
}

fn node_can_fit_unshared_cpus(
    topology: &CpuTopology,
    loads: &BTreeMap<LogicalCpuId, usize>,
    host_node_id: u32,
    requested_count: usize,
) -> bool {
    topology
        .logical_cpus
        .iter()
        .filter(|cpu| cpu.numa_node == host_node_id)
        .filter(|cpu| loads.get(&cpu.id).copied().unwrap_or(0) == 0)
        .take(requested_count)
        .count()
        == requested_count
}

fn no_host_processors<T>(policy: CpuPlacement) -> RuntimeResult<T> {
    Err(RuntimeError::Custom(format!(
        "CPU placement {policy} found no allowed host processors"
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
        loads: &BTreeMap<LogicalCpuId, usize>,
        requested: CpuPlacement,
        max_vcpus: u8,
    ) -> RuntimeResult<ResolvedPlacement> {
        super::plan(
            topology,
            loads,
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
    fn spread_uses_distinct_cores_without_hard_sibling_holds() {
        let plan = plan(&topology(), &BTreeMap::new(), CpuPlacement::Spread, 2).unwrap();

        assert_eq!(plan.vcpu_targets, vec![id(0), id(1)]);
        assert_eq!(
            plan.reservations
                .iter()
                .map(|reservation| reservation.logical_cpu)
                .collect::<Vec<_>>(),
            vec![id(0), id(1)]
        );
        assert!(!plan.shared);
    }

    #[test]
    fn compact_consumes_smt_siblings_first() {
        let plan = plan(&topology(), &BTreeMap::new(), CpuPlacement::Compact, 2).unwrap();

        assert_eq!(plan.vcpu_targets, vec![id(0), id(6)]);
        assert_eq!(plan.reservations.len(), 2);
    }

    #[test]
    fn auto_uses_distinct_cores_before_smt_siblings() {
        let plan = plan(&topology(), &BTreeMap::new(), CpuPlacement::Auto, 3).unwrap();

        assert_eq!(plan.resolved, CpuPlacement::Auto);
        assert_eq!(plan.vcpu_targets, vec![id(0), id(1), id(2)]);
        assert!(plan.reservations.iter().all(|row| row.role == "planned"));
    }

    #[test]
    fn auto_consumes_derived_soft_holds_when_untouched_cores_are_exhausted() {
        // A previously took CPU 0 and CPU 1 with Auto. Their free siblings remain soft holds.
        let loads = BTreeMap::from([(id(0), 1), (id(1), 1)]);
        let plan = plan(&topology(), &loads, CpuPlacement::Auto, 2).unwrap();

        assert_eq!(plan.vcpu_targets, vec![id(2), id(6)]);
    }

    #[test]
    fn auto_soft_holds_reappear_without_catalog_mutation() {
        let loads = BTreeMap::from([(id(0), 1), (id(1), 1)]);

        let first = plan(&topology(), &loads, CpuPlacement::Auto, 1).unwrap();
        let after_sibling_user_exits = plan(&topology(), &loads, CpuPlacement::Auto, 1).unwrap();

        assert_eq!(first.vcpu_targets, vec![id(2)]);
        assert_eq!(after_sibling_user_exits.vcpu_targets, first.vcpu_targets);
    }

    #[test]
    fn spread_preserves_the_widest_available_distribution() {
        let loads = BTreeMap::from([(id(6), 1)]);
        let plan = plan(&topology(), &loads, CpuPlacement::Spread, 2).unwrap();

        assert_eq!(plan.vcpu_targets, vec![id(1), id(2)]);
    }

    #[test]
    fn ordinary_policies_share_after_every_logical_cpu_is_used() {
        for policy in [
            CpuPlacement::Auto,
            CpuPlacement::Spread,
            CpuPlacement::Compact,
        ] {
            let resolved = plan(&topology(), &BTreeMap::new(), policy, 8).unwrap();

            assert_eq!(resolved.vcpu_targets.len(), 8);
            assert!(resolved.shared, "{policy} should report pressure sharing");
            assert_eq!(resolved.reservations.len(), 8);
        }
    }

    #[test]
    fn sharing_prefers_the_least_loaded_logical_cpus() {
        let loads = BTreeMap::from([
            (id(0), 2),
            (id(6), 2),
            (id(1), 1),
            (id(7), 1),
            (id(2), 1),
            (id(8), 1),
        ]);
        let resolved = plan(&topology(), &loads, CpuPlacement::Auto, 2).unwrap();

        assert_eq!(resolved.vcpu_targets, vec![id(1), id(2)]);
        assert!(resolved.shared);
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

        let plan = plan(&topology, &BTreeMap::new(), CpuPlacement::Compact, 1).unwrap();

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
            &BTreeMap::new(),
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
        let numa = resolved.numa.unwrap();
        assert_eq!(numa.nodes[0].host_node_id, 1);
        assert!(!numa.required);
    }

    #[test]
    fn prefer_single_falls_back_to_inherited_numa_under_memory_pressure() {
        let profile = PlacementProfile {
            numa: NumaPlacement::PreferSingle,
            memory: MemoryPlacement::FollowCpu,
        };
        let resolved = super::plan(
            &topology(),
            &BTreeMap::new(),
            PlacementRequest {
                policy: CpuPlacement::Auto,
                max_vcpus: 2,
                boot_memory_mib: 1024,
                max_memory_mib: 4096,
                profile: Some(profile),
            },
            &BTreeMap::from([(0, 15_000)]),
        )
        .unwrap();

        assert!(resolved.numa.is_none());
        assert_eq!(
            resolved.fallback,
            Some(PlacementFallback::PreferSingleCapacity)
        );
    }

    #[test]
    fn follow_cpu_falls_back_when_selected_cpus_span_host_nodes() {
        let mut topology = topology();
        topology.numa_nodes.push(HostNumaNode {
            id: 1,
            package: 0,
            total_memory_mib: 16_384,
            available_memory_mib: 16_384,
            distances: BTreeMap::from([(0, 12), (1, 10)]),
        });
        topology.numa_nodes[0].distances.insert(1, 12);
        for cpu in &mut topology.logical_cpus {
            cpu.numa_node = u32::from(cpu.core > 0);
        }
        let resolved = super::plan(
            &topology,
            &BTreeMap::new(),
            PlacementRequest {
                policy: CpuPlacement::Auto,
                max_vcpus: 2,
                boot_memory_mib: 1024,
                max_memory_mib: 4096,
                profile: Some(PlacementProfile {
                    numa: NumaPlacement::Inherit,
                    memory: MemoryPlacement::FollowCpu,
                }),
            },
            &BTreeMap::new(),
        )
        .unwrap();

        assert!(resolved.numa.is_none());
        assert_eq!(
            resolved.fallback,
            Some(PlacementFallback::FollowCpuCrossNode)
        );
    }

    #[test]
    fn strict_single_rejects_reserved_memory_overcommit() {
        let profile = PlacementProfile {
            numa: NumaPlacement::StrictSingle,
            memory: MemoryPlacement::FollowCpu,
        };
        let error = super::plan(
            &topology(),
            &BTreeMap::new(),
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

    #[test]
    fn strict_single_marks_successful_placement_as_required() {
        let resolved = super::plan(
            &topology(),
            &BTreeMap::new(),
            PlacementRequest {
                policy: CpuPlacement::Auto,
                max_vcpus: 2,
                boot_memory_mib: 1024,
                max_memory_mib: 4096,
                profile: Some(PlacementProfile {
                    numa: NumaPlacement::StrictSingle,
                    memory: MemoryPlacement::FollowCpu,
                }),
            },
            &BTreeMap::new(),
        )
        .unwrap();

        assert!(resolved.numa.unwrap().required);
    }

    #[test]
    fn strict_single_does_not_count_cpu_sharing_as_single_node_capacity() {
        let error = super::plan(
            &topology(),
            &BTreeMap::new(),
            PlacementRequest {
                policy: CpuPlacement::Auto,
                max_vcpus: 8,
                boot_memory_mib: 512,
                max_memory_mib: 512,
                profile: Some(PlacementProfile {
                    numa: NumaPlacement::StrictSingle,
                    memory: MemoryPlacement::FollowCpu,
                }),
            },
            &BTreeMap::new(),
        )
        .unwrap_err();

        assert!(error.to_string().contains("strict_single"));
    }

    #[test]
    fn prefer_single_keeps_cpu_plan_but_inherits_numa_when_unshared_capacity_is_short() {
        let resolved = super::plan(
            &topology(),
            &BTreeMap::new(),
            PlacementRequest {
                policy: CpuPlacement::Auto,
                max_vcpus: 8,
                boot_memory_mib: 512,
                max_memory_mib: 512,
                profile: Some(PlacementProfile {
                    numa: NumaPlacement::PreferSingle,
                    memory: MemoryPlacement::FollowCpu,
                }),
            },
            &BTreeMap::new(),
        )
        .unwrap();

        assert_eq!(resolved.vcpu_targets.len(), 8);
        assert!(resolved.shared);
        assert!(resolved.numa.is_none());
        assert_eq!(
            resolved.fallback,
            Some(PlacementFallback::PreferSingleCapacity)
        );
    }
}
