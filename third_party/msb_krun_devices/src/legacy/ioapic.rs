use arch::x86_64::layout::IOAPIC_NUM_PINS;
use crossbeam_channel::unbounded;
#[cfg(not(feature = "tdx"))]
use kvm_bindings::{kvm_enable_cap, KVM_CAP_SPLIT_IRQCHIP};
use kvm_bindings::{
    kvm_irq_routing_entry, kvm_irq_routing_entry__bindgen_ty_1, kvm_irq_routing_msi, KvmIrqRouting,
    KVM_IRQ_ROUTING_MSI,
};

use kvm_ioctls::{Error, VmFd};

use utils::eventfd::EventFd;
use utils::worker_message::WorkerMessage;

use crate::bus::BusDevice;
use crate::legacy::irqchip::IrqChipT;
use crate::Error as DeviceError;

const IOAPIC_BASE: u32 = 0xfec0_0000;
const APIC_DEFAULT_ADDRESS: u32 = 0xfee0_0000;
const IRR_WORD_BITS: usize = u64::BITS as usize;
const IRR_WORDS: usize = IOAPIC_NUM_PINS.div_ceil(IRR_WORD_BITS);

const IO_REG_SEL: u64 = 0x00;
const IO_WIN: u64 = 0x10;
const IO_EOI: u64 = 0x40;

const IO_APIC_ID: u8 = 0x00;
const IO_APIC_VER: u8 = 0x01;
const IO_APIC_ARB: u8 = 0x02;

const IOAPIC_LVT_DELIV_MODE_SHIFT: u64 = 8;
const IOAPIC_LVT_DEST_MODE_SHIFT: u64 = 11;
const IOAPIC_LVT_DELIV_STATUS_SHIFT: u64 = 12;
const IOAPIC_LVT_REMOTE_IRR_SHIFT: u64 = 14;
const IOAPIC_LVT_TRIGGER_MODE_SHIFT: u64 = 15;
const IOAPIC_LVT_MASKED_SHIFT: u64 = 16;
const IOAPIC_LVT_DEST_IDX_SHIFT: u64 = 48;

const IOAPIC_VER_ENTRIES_SHIFT: u64 = 16;
const IOAPIC_ID_SHIFT: u64 = 24;

const MSI_DATA_VECTOR_SHIFT: u64 = 0;
const MSI_ADDR_DEST_MODE_SHIFT: u64 = 2;
const MSI_ADDR_DEST_IDX_SHIFT: u64 = 4;
const MSI_DATA_DELIVERY_MODE_SHIFT: u64 = 8;
const MSI_DATA_TRIGGER_SHIFT: u64 = 15;

const IOAPIC_LVT_REMOTE_IRR: u64 = 1 << IOAPIC_LVT_REMOTE_IRR_SHIFT;
const IOAPIC_LVT_TRIGGER_MODE: u64 = 1 << IOAPIC_LVT_TRIGGER_MODE_SHIFT;
const IOAPIC_LVT_DELIV_STATUS: u64 = 1 << IOAPIC_LVT_DELIV_STATUS_SHIFT;

const IOAPIC_RO_BITS: u64 = IOAPIC_LVT_REMOTE_IRR | IOAPIC_LVT_DELIV_STATUS;
const IOAPIC_RW_BITS: u64 = !IOAPIC_RO_BITS;

const IOAPIC_DM_MASK: u64 = 0x7;
const IOAPIC_ID_MASK: u64 = 0xf;
const IOAPIC_VECTOR_MASK: u64 = 0xff;

const IOAPIC_DM_EXTINT: u64 = 0x7;
const IOAPIC_REG_REDTBL_BASE: u64 = 0x10;

const IOAPIC_TRIGGER_EDGE: u64 = 0;

/// 63:56 Destination Field (RW)
/// 55:17 Reserved
/// 16 Interrupt Mask (RW)
/// 15 Trigger Mode (RW)
/// 14 Remote IRR (RO)
/// 13 Interrupt Input Pin Polarity (INTPOL) (RW)
/// 12 Delivery Status (DELIVS) (RO)
/// 11 Destination Mode (DESTMOD) (RW)
/// 10:8 Delivery Mode (DELMOD) (RW)
/// 7:0 Interrupt Vector (INTVEC) (RW)
type RedirectionTableEntry = u64;

#[derive(Debug, Default)]
pub struct IoApicEntryInfo {
    masked: u8,
    trig_mode: u8,
    _dest_idx: u16,
    _dest_mode: u8,
    delivery_mode: u8,
    _vector: u8,

    addr: u32,
    data: u32,
}

#[derive(Default)]
struct MsiMessage {
    address: u64,
    data: u64,
}

#[derive(Debug)]
pub struct IoApic {
    id: u8,
    ioregsel: u8,
    irr: [u64; IRR_WORDS],
    ioredtbl: [u64; IOAPIC_NUM_PINS],
    version: u8,
    irq_routes: Vec<kvm_irq_routing_entry>,
    irq_sender: crossbeam_channel::Sender<WorkerMessage>,
}

impl IoApic {
    pub fn new(
        vm: &VmFd,
        _irq_sender: crossbeam_channel::Sender<WorkerMessage>,
    ) -> Result<Self, Error> {
        #[cfg(not(feature = "tdx"))]
        {
            let mut cap = kvm_enable_cap {
                cap: KVM_CAP_SPLIT_IRQCHIP,
                ..Default::default()
            };
            // args[0] is the number of GSIs reserved for the userspace IOAPIC;
            // must match the emulated IOAPIC's pin count.
            cap.args[0] = IOAPIC_NUM_PINS as u64;
            vm.enable_cap(&cap)?;
        }

        let mut ioapic = Self {
            id: 0,
            ioregsel: 0,
            irr: [0; IRR_WORDS],
            ioredtbl: [1 << IOAPIC_LVT_MASKED_SHIFT; IOAPIC_NUM_PINS],
            version: 0x20,
            irq_routes: Vec::with_capacity(IOAPIC_NUM_PINS),
            irq_sender: _irq_sender,
        };

        (0..IOAPIC_NUM_PINS).for_each(|i| ioapic.add_msi_route(i));

        let mut routing = KvmIrqRouting::new(ioapic.irq_routes.len()).unwrap();
        let routing_entires = routing.as_mut_slice();
        routing_entires.copy_from_slice(ioapic.irq_routes.as_slice());
        vm.set_gsi_routing(&routing)?;

        Ok(ioapic)
    }

    fn add_msi_route(&mut self, virq: usize) {
        let msg = MsiMessage::default();
        let kroute = kvm_irq_routing_entry {
            gsi: virq as u32,
            type_: KVM_IRQ_ROUTING_MSI,
            flags: 0,
            u: kvm_irq_routing_entry__bindgen_ty_1 {
                msi: kvm_irq_routing_msi {
                    address_lo: msg.address as u32,
                    address_hi: (msg.address >> 32) as u32,
                    data: msg.data as u32,
                    ..Default::default()
                },
            },
            ..Default::default()
        };

        // 4095 is the max irq number for kvm (MAX_IRQ_ROUTES - 1)
        if self.irq_routes.len() < 4095 {
            self.irq_routes.push(kroute);
        } else {
            error!("ioapic: not enough space for irq");
        }
    }

    fn fix_edge_remote_irr(&mut self, index: usize) {
        if self.ioredtbl[index] & IOAPIC_LVT_TRIGGER_MODE == IOAPIC_TRIGGER_EDGE {
            self.ioredtbl[index] &= !IOAPIC_LVT_REMOTE_IRR;
        }
    }

    fn parse_entry(&self, entry: &RedirectionTableEntry) -> IoApicEntryInfo {
        let vector = (entry & IOAPIC_VECTOR_MASK) as u8;
        let dest_idx = ((entry >> IOAPIC_LVT_DEST_IDX_SHIFT) & 0xffff) as u16;
        let delivery_mode = ((entry >> IOAPIC_LVT_DELIV_MODE_SHIFT) & IOAPIC_DM_MASK) as u8;
        let trig_mode = ((entry >> IOAPIC_LVT_TRIGGER_MODE_SHIFT) & 1) as u8;
        let dest_mode = ((entry >> IOAPIC_LVT_DEST_MODE_SHIFT) & 1) as u8;

        IoApicEntryInfo {
            masked: ((entry >> IOAPIC_LVT_MASKED_SHIFT) & 1) as u8,
            trig_mode,
            _dest_idx: dest_idx,
            _dest_mode: dest_mode,
            delivery_mode,
            _vector: vector,

            addr: ((APIC_DEFAULT_ADDRESS as u64)
                | ((dest_idx as u64) << MSI_ADDR_DEST_IDX_SHIFT)
                | ((dest_mode as u64) << MSI_ADDR_DEST_MODE_SHIFT)) as u32,
            data: (((vector as u64) << MSI_DATA_VECTOR_SHIFT)
                | ((trig_mode as u64) << MSI_DATA_TRIGGER_SHIFT)
                | ((delivery_mode as u64) << MSI_DATA_DELIVERY_MODE_SHIFT))
                as u32,
        }
    }

    fn update_msi_route(&mut self, virq: usize, msg: &MsiMessage) {
        let kroute = kvm_irq_routing_entry {
            gsi: virq as u32,
            type_: KVM_IRQ_ROUTING_MSI,
            flags: 0,
            u: kvm_irq_routing_entry__bindgen_ty_1 {
                msi: kvm_irq_routing_msi {
                    address_lo: msg.address as u32,
                    address_hi: (msg.address >> 32) as u32,
                    data: msg.data as u32,
                    ..Default::default()
                },
            },
            ..Default::default()
        };

        for entry in self.irq_routes.iter_mut() {
            if entry.gsi == kroute.gsi {
                *entry = kroute;
            }
        }
    }

    fn update_routes(&mut self) {
        for i in 0..IOAPIC_NUM_PINS {
            let info = self.parse_entry(&self.ioredtbl[i]);

            if info.masked == 0 && info.delivery_mode as u64 != IOAPIC_DM_EXTINT {
                let msg = MsiMessage {
                    address: info.addr as u64,
                    data: info.data as u64,
                };

                self.update_msi_route(i, &msg);
            }
        }

        let (response_sender, response_receiver) = unbounded();
        if self
            .irq_sender
            .send(WorkerMessage::GsiRoute(
                response_sender,
                self.irq_routes.clone(),
            ))
            .is_err()
        {
            error!("unable to send GSI routes to the IRQ worker");
            return;
        }
        match response_receiver.recv() {
            Ok(true) => {}
            Ok(false) => error!("unable to set GSI routes for IO APIC"),
            Err(_) => error!("IRQ worker stopped while setting GSI routes"),
        }
    }

    fn irr_is_set(&self, index: usize) -> bool {
        let word = index / IRR_WORD_BITS;
        let bit = index % IRR_WORD_BITS;
        self.irr[word] & (1u64 << bit) != 0
    }

    fn irr_clear(&mut self, index: usize) {
        let word = index / IRR_WORD_BITS;
        let bit = index % IRR_WORD_BITS;
        self.irr[word] &= !(1u64 << bit);
    }

    fn selected_redirection_entry(&self) -> Option<(usize, bool)> {
        let register = usize::from(self.ioregsel).checked_sub(IOAPIC_REG_REDTBL_BASE as usize)?;
        let index = register >> 1;
        (index < IOAPIC_NUM_PINS).then_some((index, register & 1 != 0))
    }

    fn end_of_interrupt(&mut self, vector: u8) {
        let mut cleared_remote_irr = false;
        for entry in &mut self.ioredtbl {
            if (*entry & IOAPIC_VECTOR_MASK) as u8 == vector && *entry & IOAPIC_LVT_REMOTE_IRR != 0
            {
                *entry &= !IOAPIC_LVT_REMOTE_IRR;
                cleared_remote_irr = true;
            }
        }

        // A level-triggered line may still be asserted after EOI. Service it again only when an
        // entry actually transitioned, which avoids unnecessary worker traffic for stray EOIs.
        if cleared_remote_irr {
            self.service();
        }
    }

    fn send_irq_line(&self, virq: usize, active: bool) {
        let (response_sender, response_receiver) = unbounded();
        if self
            .irq_sender
            .send(WorkerMessage::IrqLine(response_sender, virq as u32, active))
            .is_err()
        {
            error!("IRQ worker stopped before IRQ {virq} could be set to {active}");
            return;
        }

        match response_receiver.recv() {
            Ok(true) => {}
            Ok(false) => error!("unable to set IRQ {virq} to {active}"),
            Err(_) => error!("IRQ worker stopped while setting IRQ {virq} to {active}"),
        }
    }

    fn service(&mut self) {
        for i in 0..IOAPIC_NUM_PINS {
            if self.irr_is_set(i) {
                let mut coalesce = 0;

                let entry = self.ioredtbl[i];
                let info = self.parse_entry(&entry);
                if info.masked == 0 && info.delivery_mode as u64 != IOAPIC_DM_EXTINT {
                    if info.trig_mode as u64 == IOAPIC_TRIGGER_EDGE {
                        self.irr_clear(i);
                    } else {
                        coalesce = self.ioredtbl[i] & IOAPIC_LVT_REMOTE_IRR;
                        self.ioredtbl[i] |= IOAPIC_LVT_REMOTE_IRR;
                    }

                    if coalesce > 0 {
                        continue;
                    }

                    if info.trig_mode as u64 == IOAPIC_TRIGGER_EDGE {
                        self.send_irq_line(i, true);
                        self.send_irq_line(i, false);
                    } else {
                        self.send_irq_line(i, true);
                    }
                }
            }
        }
    }
}

impl IrqChipT for IoApic {
    fn get_mmio_addr(&self) -> u64 {
        IOAPIC_BASE as u64
    }

    fn get_mmio_size(&self) -> u64 {
        0x1000
    }

    fn num_pins(&self) -> usize {
        IOAPIC_NUM_PINS
    }

    fn set_irq(
        &self,
        _irq_line: Option<u32>,
        interrupt_evt: Option<&EventFd>,
    ) -> Result<(), DeviceError> {
        if let Some(interrupt_evt) = interrupt_evt {
            if let Err(e) = interrupt_evt.write(1) {
                error!("Failed to signal used queue: {e:?}");
                return Err(DeviceError::FailedSignalingUsedQueue(e));
            }
        } else {
            error!("EventFd not set up for irq line");
            return Err(DeviceError::FailedSignalingUsedQueue(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "EventFd not set up for irq line",
            )));
        }
        Ok(())
    }
}

impl BusDevice for IoApic {
    fn read(&mut self, _vcpuid: u64, offset: u64, data: &mut [u8]) {
        let val = match offset {
            IO_REG_SEL => {
                debug!("ioapic: read: ioregsel");
                self.ioregsel as u32
            }
            IO_WIN => {
                // the data needs to be 32-bits in size
                if data.len() != 4 {
                    error!("ioapic: bad read size {}", data.len());
                    return;
                }

                match self.ioregsel {
                    IO_APIC_ID | IO_APIC_ARB => {
                        debug!("ioapic: read: IOAPIC ID");
                        ((self.id as u64) << IOAPIC_ID_SHIFT) as u32
                    }
                    IO_APIC_VER => {
                        debug!("ioapic: read: IOAPIC version");
                        self.version as u32
                            | ((IOAPIC_NUM_PINS as u32 - 1) << IOAPIC_VER_ENTRIES_SHIFT)
                    }
                    _ => {
                        let Some((index, high)) = self.selected_redirection_entry() else {
                            debug!("ioapic: read: invalid ioregsel {}", self.ioregsel);
                            data.fill(0);
                            return;
                        };
                        debug!("ioapic: read: ioredtbl register {index}");

                        if high {
                            (self.ioredtbl[index] >> 32) as u32
                        } else {
                            (self.ioredtbl[index] & 0xffff_ffffu64) as u32
                        }
                    }
                }
            }
            _ => {
                debug!("ioapic: read: unsupported offset {offset:#x}");
                data.fill(0);
                return;
            }
        };

        // turn the value into native endian byte order and put that value into `data`
        let out_arr = val.to_ne_bytes();
        for i in 0..4 {
            if i < data.len() {
                data[i] = out_arr[i];
            }
        }
    }

    fn write(&mut self, _vcpuid: u64, offset: u64, data: &[u8]) {
        // data needs to be 32-bits in size
        if data.len() != 4 {
            error!("ioapic: bad write size {}", data.len());
            return;
        }

        // convert data into a u32 int with native endianness
        let arr = [data[0], data[1], data[2], data[3]];
        let val = u32::from_ne_bytes(arr);
        match offset {
            IO_REG_SEL => {
                debug!("ioapic: write: ioregsel");
                self.ioregsel = val as u8
            }
            IO_WIN => {
                match self.ioregsel {
                    IO_APIC_ID => {
                        debug!("ioapic: write: IOAPIC ID");
                        self.id = ((val >> IOAPIC_ID_SHIFT) & (IOAPIC_ID_MASK as u32)) as u8
                    }
                    // NOTE: these are read-only registers, so they should never be written to
                    IO_APIC_VER | IO_APIC_ARB => debug!("ioapic: write: IOAPIC VERSION"),
                    _ => {
                        let Some((index, high)) = self.selected_redirection_entry() else {
                            debug!("ioapic: write: invalid ioregsel {}", self.ioregsel);
                            return;
                        };
                        debug!("ioapic: write: ioredtbl register {index}");
                        let ro_bits = self.ioredtbl[index] & IOAPIC_RO_BITS;
                        // check if we are writing to the upper 32-bits of the
                        // register or the lower 32-bits
                        if high {
                            self.ioredtbl[index] &= 0xffff_ffff;
                            self.ioredtbl[index] |= (val as u64) << 32;
                        } else {
                            self.ioredtbl[index] &= !0xffff_ffff;
                            self.ioredtbl[index] |= val as u64;
                        }

                        // restore RO bits
                        self.ioredtbl[index] &= IOAPIC_RW_BITS;
                        self.ioredtbl[index] |= ro_bits;

                        // ExtINT requires a legacy PIC, which libkrun does not emulate. Keep the
                        // entry masked instead of allowing guest-controlled state to panic the VMM.
                        let delivery_mode =
                            (self.ioredtbl[index] >> IOAPIC_LVT_DELIV_MODE_SHIFT) & IOAPIC_DM_MASK;
                        if delivery_mode == IOAPIC_DM_EXTINT {
                            warn!("ioapic: masking unsupported ExtINT route for pin {index}");
                            self.ioredtbl[index] |= 1 << IOAPIC_LVT_MASKED_SHIFT;
                        }

                        // if the trigger mode is EDGE, clear IRR bit
                        self.fix_edge_remote_irr(index);
                        self.update_routes();
                        self.service();
                    }
                }
            }
            IO_EOI => self.end_of_interrupt((val as u64 & IOAPIC_VECTOR_MASK) as u8),
            _ => debug!("ioapic: write: ignoring unsupported offset {offset:#x}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ioapic() -> IoApic {
        let (irq_sender, _irq_receiver) = unbounded();
        IoApic {
            id: 0,
            ioregsel: 0,
            irr: [0; IRR_WORDS],
            ioredtbl: [1 << IOAPIC_LVT_MASKED_SHIFT; IOAPIC_NUM_PINS],
            version: 0x20,
            irq_routes: Vec::new(),
            irq_sender,
        }
    }

    #[test]
    fn irr_tracks_pins_above_31() {
        let mut ioapic = test_ioapic();

        for pin in [32, 63, 64, IOAPIC_NUM_PINS - 1] {
            let word = pin / IRR_WORD_BITS;
            let bit = pin % IRR_WORD_BITS;
            ioapic.irr[word] |= 1u64 << bit;

            assert!(ioapic.irr_is_set(pin));
            ioapic.irr_clear(pin);
            assert!(!ioapic.irr_is_set(pin));
        }
    }

    #[test]
    fn last_pin_is_addressable_through_ioregsel() {
        let mut ioapic = test_ioapic();

        ioapic.ioregsel = 0xfe;
        assert_eq!(ioapic.selected_redirection_entry(), Some((119, false)));
        ioapic.ioregsel = 0xff;
        assert_eq!(ioapic.selected_redirection_entry(), Some((119, true)));
        assert_eq!(IOAPIC_NUM_PINS, 120);
    }

    #[test]
    fn unsupported_mmio_accesses_and_eoi_do_not_panic() {
        let mut ioapic = test_ioapic();
        let mut data = [0xff; 4];

        ioapic.read(0, 0x20, &mut data);
        assert_eq!(data, [0; 4]);
        ioapic.write(0, 0x20, &[0; 4]);
        ioapic.write(0, IO_EOI, &[0; 4]);
    }

    #[test]
    fn eoi_clears_remote_irr_for_the_matching_vector() {
        let mut ioapic = test_ioapic();
        ioapic.ioredtbl[0] = 0x31 | IOAPIC_LVT_REMOTE_IRR;
        ioapic.ioredtbl[1] = 0x32 | IOAPIC_LVT_REMOTE_IRR;

        ioapic.write(0, IO_EOI, &0x31u32.to_ne_bytes());

        assert_eq!(ioapic.ioredtbl[0] & IOAPIC_LVT_REMOTE_IRR, 0);
        assert_ne!(ioapic.ioredtbl[1] & IOAPIC_LVT_REMOTE_IRR, 0);
    }

    #[test]
    fn extint_routes_are_safely_masked() {
        let mut ioapic = test_ioapic();
        ioapic.ioregsel = IOAPIC_REG_REDTBL_BASE as u8;

        ioapic.write(
            0,
            IO_WIN,
            &((IOAPIC_DM_EXTINT as u32) << IOAPIC_LVT_DELIV_MODE_SHIFT).to_ne_bytes(),
        );

        assert_ne!(ioapic.ioredtbl[0] & (1 << IOAPIC_LVT_MASKED_SHIFT), 0);
    }
}
