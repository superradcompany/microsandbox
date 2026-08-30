use crossbeam_channel::Sender;
use std::collections::VecDeque;
use std::sync::Mutex;

use arch::aarch64::layout::VTIMER_IRQ;
use arch::aarch64::sysreg::*;
use hvf::bindings::{
    hv_sys_reg_t_HV_SYS_REG_CNTHCTL_EL2, hv_sys_reg_t_HV_SYS_REG_MDCCINT_EL1, hv_vcpu_get_sys_reg,
    hv_vcpu_set_sys_reg, HV_SUCCESS,
};
use hvf::{vcpu_request_exit, Vcpus};

// See https://developer.arm.com/documentation/ddi0595/2020-12/AArch64-Registers/ICC-IAR0-EL1--Interrupt-Controller-Interrupt-Acknowledge-Register-0
const GIC_INTID_SPURIOUS: u32 = 1023;

enum VcpuStatus {
    Running,
    Waiting,
}

struct PerCPUInterruptControllerState {
    vcpuid: u64,
    status: VcpuStatus,
    pending_irqs: VecDeque<u32>,
    wfe_sender: Option<Sender<u32>>,
}

impl PerCPUInterruptControllerState {
    fn set_irq_common(&mut self, irq: u32) {
        debug!(
            "[GICv3] SET_IRQ_COMMON vcpuid={}, irq_line={}",
            self.vcpuid, irq
        );
        self.pending_irqs.push_back(irq);

        match self.status {
            VcpuStatus::Waiting => {
                self.wfe_sender
                    .as_mut()
                    .unwrap()
                    .send(self.vcpuid as u32)
                    .unwrap();
                self.status = VcpuStatus::Running;
            }
            VcpuStatus::Running => {
                vcpu_request_exit(self.vcpuid).unwrap();
            }
        }
    }

    fn should_wait(&mut self) -> bool {
        if self.pending_irqs.is_empty() {
            self.status = VcpuStatus::Waiting;
            return true;
        }
        false
    }

    fn has_pending_irq(&self) -> bool {
        !self.pending_irqs.is_empty()
    }

    fn get_pending_irq(&mut self) -> u32 {
        self.pending_irqs.pop_front().unwrap_or(GIC_INTID_SPURIOUS)
    }
}

pub struct VcpuList {
    cpu_count: u64,
    vcpus: Vec<Mutex<PerCPUInterruptControllerState>>,
}

impl VcpuList {
    pub fn new(cpu_count: u64) -> Self {
        let mut vcpus = Vec::with_capacity(cpu_count as usize);
        for vcpuid in 0..cpu_count {
            vcpus.push(Mutex::new(PerCPUInterruptControllerState {
                vcpuid,
                status: VcpuStatus::Running,
                pending_irqs: VecDeque::new(),
                wfe_sender: None,
            }));
        }

        Self { cpu_count, vcpus }
    }

    pub fn get_cpu_count(&self) -> u64 {
        self.cpu_count
    }

    pub fn set_irq_common(&self, vcpuid: u64, irq: u32) {
        assert!(vcpuid < self.cpu_count);
        self.vcpus[vcpuid as usize]
            .lock()
            .unwrap()
            .set_irq_common(irq);
    }

    pub fn set_sgi_irq(&self, vcpuid: u64, irq: u32) {
        assert!(vcpuid < self.cpu_count);
        assert!(irq < 16);
        self.vcpus[vcpuid as usize]
            .lock()
            .unwrap()
            .set_irq_common(irq);
    }

    pub fn register(&self, vcpuid: u64, wfe_sender: Sender<u32>) {
        assert!(vcpuid < self.cpu_count);
        self.vcpus[vcpuid as usize].lock().unwrap().wfe_sender = Some(wfe_sender);
    }
}

impl Vcpus for VcpuList {
    fn set_vtimer_irq(&self, vcpuid: u64) {
        assert!(vcpuid < self.cpu_count);
        self.vcpus[vcpuid as usize]
            .lock()
            .unwrap()
            .set_irq_common(VTIMER_IRQ);
    }

    fn should_wait(&self, vcpuid: u64) -> bool {
        assert!(vcpuid < self.cpu_count);
        self.vcpus[vcpuid as usize].lock().unwrap().should_wait()
    }

    fn has_pending_irq(&self, vcpuid: u64) -> bool {
        assert!(vcpuid < self.cpu_count);
        self.vcpus[vcpuid as usize]
            .lock()
            .unwrap()
            .has_pending_irq()
    }

    fn get_pending_irq(&self, vcpuid: u64) -> u32 {
        assert!(vcpuid < self.cpu_count);
        self.vcpus[vcpuid as usize]
            .lock()
            .unwrap()
            .get_pending_irq()
    }

    fn handle_sysreg_read(&self, vcpuid: u64, reg: u32) -> Option<u64> {
        assert!(vcpuid < self.cpu_count);

        if is_id_sysreg(reg) {
            return Some(0);
        }

        match reg {
            SYSREG_ICC_IAR1_EL1 => Some(
                self.vcpus[vcpuid as usize]
                    .lock()
                    .unwrap()
                    .get_pending_irq() as u64,
            ),
            SYSREG_ICC_PMR_EL1 => Some(0),
            SYSREG_ICC_CTLR_EL1 => Some(
                (1 << ICC_CTLR_EL1_RSS_SHIFT)
                    | (1 << ICC_CTLR_EL1_A3V_SHIFT)
                    | (1 << ICC_CTLR_EL1_ID_BITS_SHIFT)
                    | (4 << ICC_CTLR_EL1_PRI_BITS_SHIFT),
            ),
            SYSREG_CNTHCTL_EL2 => {
                let val: u64 = 0;
                let ret = unsafe {
                    hv_vcpu_get_sys_reg(
                        vcpuid,
                        hv_sys_reg_t_HV_SYS_REG_CNTHCTL_EL2,
                        &val as *const _ as *mut _,
                    )
                };
                if ret == HV_SUCCESS {
                    Some(val)
                } else {
                    None
                }
            }
            SYSREG_MDCCINT_EL1 => {
                let val: u64 = 0;
                let ret = unsafe {
                    hv_vcpu_get_sys_reg(
                        vcpuid,
                        hv_sys_reg_t_HV_SYS_REG_MDCCINT_EL1,
                        &val as *const _ as *mut _,
                    )
                };
                if ret == HV_SUCCESS {
                    Some(val)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn handle_sysreg_write(&self, vcpuid: u64, reg: u32, val: u64) -> bool {
        assert!(vcpuid < self.cpu_count);

        if is_id_sysreg(reg) {
            return true;
        }

        match reg {
            SYSREG_ICC_SGI1R_EL1 => {
                let target_list = val & 0xffff;
                let intid = ((val >> 24) & 0xf) as u32;
                let irm = (val & (1 << 40)) >> 40;
                let is_broadcast = irm == 1;
                let aff3aff2aff1 = val & ((0xff << 48) | (0xff << 32) | (0xff << 16));
                let rs = (val & (0xf << 44)) >> 44;

                debug!("vCPU {vcpuid} GenerateSoftwareInterrupt={intid} (0x{val:x})");

                // A flat core hierarchy should be good enough, but if we ever start using
                // Aff[123] MPIDR fields (currently MPID is configured via DT), GICv3 support
                // will need to be added.
                assert_eq!(
                    aff3aff2aff1, 0,
                    "[GICv3] only flat core hierarchy supported for now"
                );

                assert!(
                    !is_broadcast,
                    "[GICv3] SGI broadcast is not implemented yet"
                );

                // for each core in target list
                for target_id in 0u64..=15u64 {
                    if (target_list >> target_id) & 1 == 1 {
                        self.set_sgi_irq(rs * 16 + target_id, intid)
                    }
                }

                true
            }
            SYSREG_CNTHCTL_EL2 => {
                let ret = unsafe {
                    hv_vcpu_set_sys_reg(vcpuid, hv_sys_reg_t_HV_SYS_REG_CNTHCTL_EL2, val)
                };
                ret == HV_SUCCESS
            }
            SYSREG_MDCCINT_EL1 => {
                let ret = unsafe {
                    hv_vcpu_set_sys_reg(vcpuid, hv_sys_reg_t_HV_SYS_REG_MDCCINT_EL1, val)
                };
                ret == HV_SUCCESS
            }
            SYSREG_ICC_EOIR1_EL1
            | SYSREG_ICC_IGRPEN1_EL1
            | SYSREG_ICC_PMR_EL1
            | SYSREG_ICC_BPR1_EL1
            | SYSREG_ICC_CTLR_EL1
            | SYSREG_ICC_AP1R0_EL1
            | SYSREG_LORC_EL1
            | SYSREG_OSLAR_EL1
            | SYSREG_OSDLR_EL1 => true,
            _ => false,
        }
    }
}
