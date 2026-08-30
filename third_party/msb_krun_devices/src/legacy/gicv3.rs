use std::convert::TryInto;
use std::io;
use std::sync::Arc;

use crate::bus::BusDevice;
use crate::legacy::gic::GICDevice;
use crate::legacy::irqchip::IrqChipT;
use crate::legacy::VcpuList;
use crate::Error as DeviceError;

use utils::eventfd::EventFd;

const IRQ_NUM: u32 = 288;
const MAXIRQ: u32 = 1020;
const BITMAP_SZ: usize = (MAXIRQ as usize).div_ceil(32);

const GIC_INTERNAL: u32 = 32;

const GICD_CTLR: u64 = 0x0000;
const GICD_TYPER: u64 = 0x0004;
const GICD_IIDR: u64 = 0x0008;
const GICD_STATUSR: u64 = 0x0010;
const GICD_IGROUPR: u64 = 0x0080;
const GICD_ISENABLER: u64 = 0x0100;
const GICD_ICENABLER: u64 = 0x0180;
const GICD_ISPENDR: u64 = 0x0200;
const GICD_ICPENDR: u64 = 0x0280;
const GICD_ISACTIVER: u64 = 0x0300;
const GICD_ICACTIVER: u64 = 0x0380;
const GICD_IPRIORITYR: u64 = 0x0400;
const GICD_ITARGETSR: u64 = 0x0800;
const GICD_ICFGR: u64 = 0x0C00;
const GICD_SGIR: u64 = 0x0F00;
const GICD_IROUTER: u64 = 0x6000;
const GICD_IDREGS: u64 = 0xFFD0;

/* GICD_CTLR fields  */
const GICD_CTLR_EN_GRP0: u32 = 1 << 0;
const GICD_CTLR_EN_GRP1NS: u32 = 1 << 1; /* GICv3 5.3.20 */
/* Bit 4 is ARE if the system doesn't support TrustZone, ARE_S otherwise */
const GICD_CTLR_ARE: u32 = 1 << 4;
const GICD_CTLR_DS: u32 = 1 << 6;

/*
 * Redistributor registers, offsets from RD_base
 */
const GICR_CTLR: u64 = 0x0000;
const GICR_TYPER: u64 = 0x0008;
const GICR_WAKER: u64 = 0x0014;
const GICR_IDREGS: u64 = 0xFFD0;

const GICR_WAKER_PROCESSOR_SLEEP: u32 = 1 << 1;
const GICR_WAKER_CHILDREN_ASLEEP: u32 = 1 << 2;

/*
 * Redistributor frame offsets from RD_base
 */
const GICR_SGI_OFFSET: u64 = 0x10000;

/* SGI and PPI Redistributor registers, offsets from RD_base */
const GICR_IGROUPR0: u64 = GICR_SGI_OFFSET + 0x0080;
const GICR_ISENABLER0: u64 = GICR_SGI_OFFSET + 0x0100;
const GICR_ICENABLER0: u64 = GICR_SGI_OFFSET + 0x0180;
const GICR_ICACTIVER0: u64 = GICR_SGI_OFFSET + 0x0380;
const GICR_IPRIORITYR: u64 = GICR_SGI_OFFSET + 0x0400;
const GICR_ICFGR1: u64 = GICR_SGI_OFFSET + 0x0C04;

/* Distributor register fields */
// GICD_TYPER (https://developer.arm.com/documentation/ddi0601/2020-12/External-Registers/GICD-TYPER--Interrupt-Controller-Type-Register?lang=en)
const GICD_TYPER_RSS_SHIFT: u64 = 26;
const GICD_TYPER_NO1N_SHIFT: u64 = 25;
const GICD_TYPER_A3V_SHIFT: u64 = 24;
const GICD_TYPER_ID_BITS_SHIFT: u64 = 19;
const GICD_TYPER_LPIS_SHIFT: u64 = 17;
const GICD_TYPER_IT_LINES_NUMBER_SHIFT: u64 = 0;

/* Redistributor register fields */
// GICR_TYPER (https://developer.arm.com/documentation/ddi0601/2020-12/External-Registers/GICR-TYPER--Redistributor-Type-Register?lang=en)
const GICR_TYPER_AFFINITY_VALUE: u64 = 32;
const GICR_TYPER_COMMON_LPI_AFF_SHIFT: u64 = 24;
const GICR_TYPER_PROCESSOR_NUMBER_SHIFT: u64 = 8;
const GICR_TYPER_LAST_SHIFT: u64 = 4;

/* CoreSight PIDR0 values for ARM GICv3 implementations */
const GICV3_PIDR0_DIST: u8 = 0x92;
const GICV3_PIDR0_REDIST: u8 = 0x93;

// Device tree specific constants
const GICV3_BASE_SIZE: u64 = 0x0001_0000;
const GICV3_MAINT_IRQ: u32 = 8;

#[derive(Clone)]
pub struct GicV3 {
    dist_addr: u64,
    dist_size: u64,
    redist_size: u64,
    redists_addr: u64,
    redists_size: u64,

    gicd_ctlr: u32,
    vcpu_list: Arc<VcpuList>,
    revision: u8,
    edge_trigger: [u32; BITMAP_SZ],
    gicr_waker: u32,
    gicd_irouter: [u64; MAXIRQ as usize],

    /// GIC device properties, to be used for setting up the fdt entry
    properties: [u64; 4],
}

impl GicV3 {
    /// Get the address of the GICv3 distributor.
    pub fn get_dist_addr(&self) -> u64 {
        self.dist_addr
    }

    /// Get the size of the GIC_v3 distributor.
    pub const fn get_dist_size(&self) -> u64 {
        self.dist_size
    }

    pub fn get_redists_addr(&self) -> u64 {
        self.redists_addr
    }

    pub fn get_redists_size(&self) -> u64 {
        self.redists_size
    }

    pub const fn get_redist_size(&self) -> u64 {
        self.redist_size
    }

    pub fn new(vcpu_list: Arc<VcpuList>) -> Self {
        let vcpu_count = vcpu_list.get_cpu_count();
        let dist_size = GICV3_BASE_SIZE;
        let dist_addr = arch::MMIO_MEM_START - 3 * dist_size;
        let redist_size = 2 * dist_size;
        let redists_size = redist_size * vcpu_count;
        let redists_addr = dist_addr - redists_size;

        Self {
            dist_addr,
            dist_size,
            redist_size,
            redists_addr,
            redists_size,

            gicd_ctlr: GICD_CTLR_DS | GICD_CTLR_ARE,
            vcpu_list,
            revision: 3,
            edge_trigger: [0; BITMAP_SZ],
            gicr_waker: GICR_WAKER_PROCESSOR_SLEEP | GICR_WAKER_CHILDREN_ASLEEP,
            gicd_irouter: [0; MAXIRQ as usize],

            properties: [dist_addr, dist_size, redists_addr, redists_size],
        }
    }

    fn handle_dist_read32(&self, _vcpuid: u64, offset: u64, data: &mut [u8]) {
        let mut val: u32 = 0;
        match offset {
            GICD_CTLR => val = self.gicd_ctlr,
            GICD_TYPER => {
                let itlinesnumber = (IRQ_NUM / 32) - 1;
                val = (1 << GICD_TYPER_RSS_SHIFT)
                    | (1 << GICD_TYPER_NO1N_SHIFT)
                    | (1 << GICD_TYPER_A3V_SHIFT)
                    | (1 << GICD_TYPER_LPIS_SHIFT)
                    | (0xf << GICD_TYPER_ID_BITS_SHIFT)
                    | (itlinesnumber << GICD_TYPER_IT_LINES_NUMBER_SHIFT);
            }
            GICD_IIDR => val = 0x43b,
            GICD_STATUSR => {}
            _ if (GICD_IGROUPR..GICD_IGROUPR + 0x7f).contains(&offset) => {}
            _ if (GICD_ISENABLER..GICD_ISENABLER + 0x7f).contains(&offset) => {}
            _ if (GICD_ICENABLER..GICD_ICENABLER + 0x7f).contains(&offset) => {}
            _ if (GICD_ISPENDR..GICD_ISPENDR + 0x7f).contains(&offset) => {}
            _ if (GICD_ICPENDR..GICD_ICPENDR + 0x7f).contains(&offset) => {}
            _ if (GICD_ISACTIVER..GICD_ISACTIVER + 0x7f).contains(&offset) => {}
            _ if (GICD_ICACTIVER..GICD_ICACTIVER + 0x7f).contains(&offset) => {}
            _ if (GICD_IPRIORITYR..GICD_IPRIORITYR + 0x3ff).contains(&offset) => {}
            _ if (GICD_ITARGETSR..GICD_ITARGETSR + 0x3ff).contains(&offset) => {
                panic!("[GICv3] only affinity routing is implemented");
            }
            _ if (GICD_ICFGR..GICD_ICFGR + 0xff).contains(&offset) => {
                let irq = ((offset - GICD_ICFGR) * 4) as u32;
                if !(GIC_INTERNAL..IRQ_NUM).contains(&irq) {
                    val = 0;
                } else {
                    let mut value = self.edge_trigger[((irq & !0x1f) / 32) as usize];
                    value = extract32(value, if (irq & 0x1f) != 0 { 16 } else { 0 }, 16);
                    value = half_shuffle32(value) << 1;
                    val = value;
                }
            }
            _ if (GICD_IDREGS..GICD_IDREGS + 0x2f).contains(&offset) => {
                /* Return the value of the CoreSight ID register at the specified
                 * offset from the first ID register (as found in the distributor
                 * and redistributor register banks).
                 * These values indicate an ARM implementation of a GICv3 or v4.
                 */
                let gicd_ids: [u8; 12] = [
                    0x44, 0x00, 0x00, 0x00, 0x92, 0xB4, 0x0B, 0x00, 0x0D, 0xF0, 0x05, 0xB1,
                ];
                let mut id: u32;
                let regoffset = (offset - GICD_IDREGS) / 4;

                if regoffset == 4 {
                    id = GICV3_PIDR0_DIST as u32;
                } else {
                    id = gicd_ids[regoffset as usize] as u32;
                    if regoffset == 6 {
                        /* PIDR2 bits [7:4] are the GIC architecture revision */
                        id |= (self.revision as u32) << 4;
                    }
                }

                val = id;
            }
            GICD_SGIR => {}
            0xc => {
                // invalid guest read on Qemu
            }
            _ => panic!("Unknown GIC DIST read32 offset=0x{offset:x}"),
        }
        for (i, b) in val.to_le_bytes().iter().enumerate() {
            data[i] = *b;
        }
        debug!("[GICv3] -> read32 DIST offset={offset} val={val}");
    }

    fn handle_dist_write32(&mut self, _vcpuid: u64, offset: u64, data: &[u8]) {
        debug!(
            "[GICv3] write32 DIST offset={} val={}",
            offset,
            u32::from_le_bytes(data.try_into().unwrap())
        );

        let val: u32 = u32::from_le_bytes(data.try_into().unwrap());
        match offset {
            GICD_CTLR => {
                let mask = GICD_CTLR_EN_GRP0 | GICD_CTLR_EN_GRP1NS;
                self.gicd_ctlr = (self.gicd_ctlr & !mask) | (val & mask);
            }
            _ if (GICD_IGROUPR..GICD_IGROUPR + 0x7f).contains(&offset) => {}
            _ if (GICD_ISENABLER..GICD_ISENABLER + 0x7f).contains(&offset) => {}
            _ if (GICD_ICENABLER..GICD_ICENABLER + 0x7f).contains(&offset) => {}
            _ if (GICD_ISPENDR..GICD_ISPENDR + 0x7f).contains(&offset) => {}
            _ if (GICD_ICPENDR..GICD_ICPENDR + 0x7f).contains(&offset) => {}
            _ if (GICD_ISACTIVER..GICD_ISACTIVER + 0x7f).contains(&offset) => {}
            _ if (GICD_ICACTIVER..GICD_ICACTIVER + 0x7f).contains(&offset) => {}
            _ if (GICD_IPRIORITYR..GICD_IPRIORITYR + 0x3ff).contains(&offset) => {}
            _ if (GICD_ITARGETSR..GICD_ITARGETSR + 0x3ff).contains(&offset) => {
                panic!("[GICv3] only affinity routing is implemented");
            }
            _ if (GICD_ICFGR..GICD_ICFGR + 0xff).contains(&offset) => {
                /* Here only the odd bits are used; even bits are RES0 */
                let irq = ((offset - GICD_ICFGR) * 4) as u32;
                let mut mask: u32;

                if !(GIC_INTERNAL..IRQ_NUM).contains(&irq) {
                    return;
                }

                /* Since our edge_trigger bitmap is one bit per irq, our input
                 * 32-bits will compress down into 16 bits which we need
                 * to write into the bitmap.
                 */
                let mut value = half_unshuffle32(val >> 1);
                mask = 0xFFFFFFFFu32;
                if (irq as u64) & 0x1fu64 != 0u64 {
                    value <<= 16;
                    mask &= 0xffff0000u32;
                } else {
                    mask &= 0xffff;
                }
                let idx = (irq & !0x1f) / 32;
                let oldval = self.edge_trigger[idx as usize];
                value = (oldval & !mask) | (value & mask);
                self.edge_trigger[idx as usize] = value;
            }
            _ => panic!("Unknown GIC DIST write32 offset=0x{offset:x}"),
        }
    }

    fn handle_dist_write64(&mut self, _vcpuid: u64, offset: u64, data: &[u8]) {
        let val = u64::from_le_bytes(data.try_into().unwrap());
        debug!("[GICv3] write64 DIST offset=0x{offset:x} value=0x{val:x}");
        match offset {
            _ if (GICD_IROUTER..GICD_IROUTER + 0x1fdf).contains(&offset) => {
                let intid = ((offset - GICD_IROUTER) / 8) as usize;
                self.gicd_irouter[intid] = val;
            }
            _ => panic!("Unknown GIC DIST write64 offset=0x{offset:x}"),
        }
    }

    fn handle_redist_read32(&self, _vcpuid: u64, offset: u64, data: &mut [u8]) {
        let mut val: u32 = 0;
        match offset {
            GICR_CTLR => {
                val = 2;
            }
            GICD_IIDR => {
                val = 0x43b;
            }
            GICD_STATUSR => {}
            GICR_WAKER => {
                val = self.gicr_waker;
            }
            _ if (GICR_IPRIORITYR..GICR_IPRIORITYR + 0x3ff).contains(&offset) => {}
            _ if (GICR_IDREGS..GICR_IDREGS + 0x2f).contains(&offset) => {
                /* Return the value of the CoreSight ID register at the specified
                 * offset from the first ID register (as found in the distributor
                 * and redistributor register banks).
                 * These values indicate an ARM implementation of a GICv3 or v4.
                 */
                let gicd_ids: [u8; 12] = [
                    0x44, 0x00, 0x00, 0x00, 0x92, 0xB4, 0x0B, 0x00, 0x0D, 0xF0, 0x05, 0xB1,
                ];
                let mut id: u32;
                let regoffset = (offset - GICR_IDREGS) / 4;

                if regoffset == 4 {
                    id = GICV3_PIDR0_REDIST as u32;
                } else {
                    id = gicd_ids[regoffset as usize] as u32;
                    if regoffset == 6 {
                        /* PIDR2 bits [7:4] are the GIC architecture revision */
                        id |= (self.revision as u32) << 4;
                    }
                }

                val = id;
            }
            GICR_ICFGR1 => {}
            _ => panic!("Unknown GIC REDIST read32 offset=0x{offset:x}"),
        }
        for (i, b) in val.to_le_bytes().iter().enumerate() {
            data[i] = *b;
        }

        debug!("[GICv3] -> read32 REDIST offset={offset} val={val}");
    }

    fn handle_redist_read64(&self, vcpuid: u64, offset: u64, data: &mut [u8]) {
        let val = match offset {
            GICR_TYPER => {
                let mut typer = (vcpuid << GICR_TYPER_AFFINITY_VALUE)
                    | (1 << GICR_TYPER_COMMON_LPI_AFF_SHIFT)
                    | (vcpuid << GICR_TYPER_PROCESSOR_NUMBER_SHIFT);
                // Assume we have one redistributor range, set last bit for last CPU.
                if vcpuid == self.vcpu_list.get_cpu_count() - 1 {
                    typer |= 1u64 << GICR_TYPER_LAST_SHIFT;
                }
                typer
            }
            _ => panic!("Unknown GIC REDIST read64 offset=0x{offset:x}"),
        };
        for (i, b) in val.to_le_bytes().iter().enumerate() {
            data[i] = *b;
        }

        debug!("[GICv3] -> read64 REDIST offset={offset} val={val}");
    }

    fn handle_redist_write32(&mut self, _vcpuid: u64, offset: u64, data: &[u8]) {
        debug!(
            "[GICv3] write32 REDIST offset={} val={}",
            offset,
            u32::from_le_bytes(data.try_into().unwrap())
        );

        let mut val: u32 = u32::from_le_bytes(data.try_into().unwrap());
        match offset {
            GICR_WAKER => {
                val &= GICR_WAKER_PROCESSOR_SLEEP;
                if (val & GICR_WAKER_PROCESSOR_SLEEP) != 0 {
                    val |= GICR_WAKER_CHILDREN_ASLEEP;
                }
                self.gicr_waker = val;
            }
            GICR_IGROUPR0 | GICR_ISENABLER0 | GICR_ICENABLER0 | GICR_ICACTIVER0 => {}
            _ if (GICR_IPRIORITYR..GICR_IPRIORITYR + 0x1f).contains(&offset) => {}
            _ => panic!("Unknown GIC REDIST write32 offset=0x{offset:x}"),
        }
    }
}

impl IrqChipT for GicV3 {
    fn get_mmio_addr(&self) -> u64 {
        self.redists_addr
    }

    fn get_mmio_size(&self) -> u64 {
        self.dist_size + self.redists_size
    }

    fn set_irq(
        &self,
        irq_line: Option<u32>,
        _interrupt_evt: Option<&EventFd>,
    ) -> Result<(), DeviceError> {
        if let Some(irq_line) = irq_line {
            assert!(irq_line < MAXIRQ, "[GICv3] intid out of range");
            // TODO(p1-0tr): extract full MPID, but for now Aff0 will do
            let mpid = self.gicd_irouter[irq_line as usize] & 0xff;
            self.vcpu_list.set_irq_common(mpid, irq_line);
            Ok(())
        } else {
            Err(DeviceError::FailedSignalingUsedQueue(io::Error::new(
                io::ErrorKind::InvalidData,
                "IRQ not line configured",
            )))
        }
    }
}

impl BusDevice for GicV3 {
    fn read(&mut self, vcpuid: u64, offset: u64, data: &mut [u8]) {
        if offset >= self.redists_size {
            let offset = offset - self.redists_size;
            match data.len() {
                1 => panic!("GIC DIST read8 vcpuid={vcpuid} offset=0x{offset:x}"),
                2 => panic!("GIC DIST read16 vcpuid={vcpuid} offset=0x{offset:x}"),
                4 => self.handle_dist_read32(vcpuid, offset, data),
                8 => panic!("GIC DIST read64 vcpuid={vcpuid} offset=0x{offset:x}"),
                _ => panic!("GIC DIST unsupported read size"),
            }
        } else {
            let vcpuid = offset / self.redist_size;
            let offset = offset % self.redist_size;

            match data.len() {
                1 => panic!("GIC REDIST read8 vcpuid={vcpuid} offset=0x{offset:x}"),
                2 => panic!("GIC REDIST read16 vcpuid={vcpuid} offset=0x{offset:x}"),
                4 => self.handle_redist_read32(vcpuid, offset, data),
                8 => self.handle_redist_read64(vcpuid, offset, data),
                _ => panic!("GIC REDIST unsupported read size"),
            }
        }
    }

    fn write(&mut self, vcpuid: u64, offset: u64, data: &[u8]) {
        if offset >= self.redists_size {
            let offset = offset - self.redists_size;
            match data.len() {
                1 => panic!("GIC DIST write8 vcpuid={vcpuid} offset=0x{offset:x}, data={data:?}"),
                2 => panic!("GIC DIST write16 vcpuid={vcpuid} offset=0x{offset:x}, data={data:?}"),
                4 => self.handle_dist_write32(vcpuid, offset, data),
                8 => self.handle_dist_write64(vcpuid, offset, data),
                _ => panic!("GIC DIST unsupported read size"),
            }
        } else {
            let vcpuid = offset / self.redist_size;
            let offset = offset % self.redist_size;

            match data.len() {
                1 => panic!("GIC REDIST write8 vcpuid={vcpuid} offset=0x{offset:x}, data={data:?}"),
                2 => {
                    panic!("GIC REDIST write16 vcpuid={vcpuid} offset=0x{offset:x}, data={data:?}")
                }
                4 => self.handle_redist_write32(vcpuid, offset, data),
                8 => {
                    panic!("GIC REDIST write64 vcpuid={vcpuid} offset=0x{offset:x}, data={data:?}")
                }
                _ => panic!("GIC REDIST unsupported write size"),
            }
        }
    }
}

impl GICDevice for GicV3 {
    fn device_properties(&self) -> Vec<u64> {
        self.properties.to_vec()
    }

    fn vcpu_count(&self) -> u64 {
        self.vcpu_list.get_cpu_count()
    }

    fn fdt_compatibility(&self) -> String {
        "arm,gic-v3".to_string()
    }

    fn fdt_maint_irq(&self) -> u32 {
        GICV3_MAINT_IRQ
    }

    fn version(&self) -> u32 {
        0
    }
}

fn half_shuffle32(val: u32) -> u32 {
    /* This algorithm is from _Hacker's Delight_ section 7-2 "Shuffling Bits".
     * It ignores any bits set in the top half of the input.
     */
    let mut x = val;
    x = ((x & 0xFF00) << 8) | (x & 0x00FF);
    x = ((x << 4) | x) & 0x0F0F0F0F;
    x = ((x << 2) | x) & 0x33333333;
    x = ((x << 1) | x) & 0x55555555;
    x
}

fn half_unshuffle32(val: u32) -> u32 {
    /* This algorithm is from _Hacker's Delight_ section 7-2 "Shuffling Bits".
     * where it is called an inverse half shuffle.
     */
    let mut x = val;
    x &= 0x55555555;
    x = ((x >> 1) | x) & 0x33333333;
    x = ((x >> 2) | x) & 0x0F0F0F0F;
    x = ((x >> 4) | x) & 0x00FF00FF;
    x = ((x >> 8) | x) & 0x0000FFFF;
    x
}

fn extract32(value: u32, start: u32, length: u32) -> u32 {
    assert!(length <= 32 - start);
    (value >> start) & ((!0u32) >> (32 - length))
}
