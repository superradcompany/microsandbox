//! Portable CPU placement planning.

use std::collections::{BTreeMap, HashSet};

use microsandbox_types::CpuPlacement;

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
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn plan(
    topology: &CpuTopology,
    occupied: &HashSet<LogicalCpuId>,
    requested: CpuPlacement,
    max_vcpus: u8,
) -> RuntimeResult<ResolvedPlacement> {
    let requested_count = usize::from(max_vcpus);
    if requested_count == 0 {
        return Err(RuntimeError::Custom(
            "managed CPU placement requires max_cpus greater than zero".into(),
        ));
    }

    let cores = available_cores(topology, occupied);
    let resolved = match requested {
        CpuPlacement::Auto => {
            if cores.iter().filter(|core| core.all_free).count() > requested_count {
                CpuPlacement::Spread
            } else {
                CpuPlacement::Compact
            }
        }
        CpuPlacement::Spread | CpuPlacement::Compact => requested,
        CpuPlacement::Inherit => {
            return Err(RuntimeError::Custom(
                "inherit must bypass the managed CPU planner".into(),
            ));
        }
    };

    match resolved {
        CpuPlacement::Spread => plan_spread(cores, requested, requested_count),
        CpuPlacement::Compact => plan_compact(cores, requested, requested_count),
        CpuPlacement::Auto | CpuPlacement::Inherit => unreachable!(),
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
    fn auto_leaves_one_core_outside_spread_allocation() {
        let spread = plan(&topology(), &HashSet::new(), CpuPlacement::Auto, 2).unwrap();
        assert_eq!(spread.resolved, CpuPlacement::Spread);

        let compact = plan(&topology(), &HashSet::new(), CpuPlacement::Auto, 3).unwrap();
        assert_eq!(compact.resolved, CpuPlacement::Compact);
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
            fingerprint: "heterogeneous".into(),
        };

        let plan = plan(&topology, &HashSet::new(), CpuPlacement::Compact, 1).unwrap();

        assert_eq!(plan.vcpu_targets, vec![id(1)]);
    }
}
