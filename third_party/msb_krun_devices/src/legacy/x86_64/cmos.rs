// Copyright 2025 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::cmp::min;

use crate::bus::BusDevice;
use crate::legacy::IrqChip;

const INDEX_MASK: u8 = 0x7f;
const INDEX_OFFSET: u64 = 0x0;
const DATA_OFFSET: u64 = 0x1;
const DATA_LEN: usize = 128;

const REG_SECONDS: usize = 0x00;
const REG_MINUTES: usize = 0x02;
const REG_HOURS: usize = 0x04;
const REG_WEEKDAY: usize = 0x06;
const REG_DAY_OF_MONTH: usize = 0x07;
const REG_MONTH: usize = 0x08;
const REG_YEAR: usize = 0x09;
const REG_STATUS_A: usize = 0x0a;
const REG_STATUS_B: usize = 0x0b;
const REG_STATUS_C: usize = 0x0c;
const REG_STATUS_D: usize = 0x0d;
const REG_CENTURY: usize = 0x32;

const STATUS_A_DEFAULT: u8 = 0x26;
const STATUS_B_24_HOUR: u8 = 0x02;
const STATUS_B_BINARY: u8 = 0x04;
const STATUS_B_UPDATE_INTERRUPT: u8 = 0x10;
const STATUS_B_ALARM_INTERRUPT: u8 = 0x20;
const STATUS_B_PERIODIC_INTERRUPT: u8 = 0x40;
const STATUS_C_UPDATE: u8 = 0x10;
const STATUS_C_ALARM: u8 = 0x20;
const STATUS_C_PERIODIC: u8 = 0x40;
const STATUS_C_INTERRUPT_REQUEST: u8 = 0x80;
const STATUS_D_VALID_RAM: u8 = 0x80;

pub struct Cmos {
    index: u8,
    data: [u8; DATA_LEN],
    intc: Option<IrqChip>,
    irq_line: Option<u32>,
}

impl Cmos {
    pub fn new(mem_below_4g: u64, mem_above_4g: u64) -> Cmos {
        debug!("cmos: mem_below_4g={mem_below_4g} mem_above_4g={mem_above_4g}");

        let mut data = [0u8; DATA_LEN];

        // Publish a stable, valid RTC value in binary 24-hour mode. The exact wall clock is less
        // important than avoiding invalid zero date fields during early guest boot.
        data[REG_SECONDS] = 0;
        data[REG_MINUTES] = 0;
        data[REG_HOURS] = 0;
        data[REG_WEEKDAY] = 1;
        data[REG_DAY_OF_MONTH] = 1;
        data[REG_MONTH] = 1;
        data[REG_YEAR] = 26;
        data[REG_CENTURY] = 20;
        data[REG_STATUS_A] = STATUS_A_DEFAULT;
        data[REG_STATUS_B] = STATUS_B_24_HOUR | STATUS_B_BINARY;
        data[REG_STATUS_D] = STATUS_D_VALID_RAM;

        // Extended memory from 16 MB to 4 GB in units of 64 KB
        let ext_mem = min(
            0xFFFF,
            mem_below_4g.saturating_sub(16 * 1024 * 1024) / (64 * 1024),
        );
        data[0x34] = ext_mem as u8;
        data[0x35] = (ext_mem >> 8) as u8;

        // High memory (> 4GB) in units of 64 KB
        let high_mem = min(0xFFFFFF, mem_above_4g / (64 * 1024));
        data[0x5b] = high_mem as u8;
        data[0x5c] = (high_mem >> 8) as u8;
        data[0x5d] = (high_mem >> 16) as u8;

        Cmos {
            index: 0,
            data,
            intc: None,
            irq_line: None,
        }
    }

    pub fn set_intc(&mut self, intc: IrqChip) {
        self.intc = Some(intc);
    }

    pub fn set_irq_line(&mut self, irq: u32) {
        self.irq_line = Some(irq);
    }

    fn read_data(&mut self) -> u8 {
        match (self.index & INDEX_MASK) as usize {
            REG_STATUS_C => {
                let value = self.data[REG_STATUS_C];
                self.data[REG_STATUS_C] = 0;
                value
            }
            index => self.data[index],
        }
    }

    fn write_data(&mut self, value: u8) {
        match (self.index & INDEX_MASK) as usize {
            REG_STATUS_C | REG_STATUS_D => {
                debug!("cmos: ignoring write to read-only RTC register");
            }
            REG_STATUS_B => {
                self.data[REG_STATUS_B] = value;
                self.maybe_trigger_rtc_interrupt();
            }
            index => {
                self.data[index] = value;
            }
        }
    }

    fn maybe_trigger_rtc_interrupt(&mut self) {
        let enabled = self.data[REG_STATUS_B]
            & (STATUS_B_UPDATE_INTERRUPT | STATUS_B_ALARM_INTERRUPT | STATUS_B_PERIODIC_INTERRUPT);
        if enabled == 0 {
            return;
        }

        let mut flags = STATUS_C_INTERRUPT_REQUEST;
        if enabled & STATUS_B_UPDATE_INTERRUPT != 0 {
            flags |= STATUS_C_UPDATE;
        }
        if enabled & STATUS_B_ALARM_INTERRUPT != 0 {
            flags |= STATUS_C_ALARM;
        }
        if enabled & STATUS_B_PERIODIC_INTERRUPT != 0 {
            flags |= STATUS_C_PERIODIC;
        }
        self.data[REG_STATUS_C] |= flags;

        if let Some(intc) = &self.intc {
            let intc = intc.lock().unwrap();
            if let Err(e) = intc.set_irq(self.irq_line, None) {
                warn!("cmos: failed to trigger RTC interrupt: {e:?}");
            }
        }
    }
}

impl BusDevice for Cmos {
    fn read(&mut self, _vcpuid: u64, offset: u64, data: &mut [u8]) {
        if data.len() != 1 {
            error!("cmos: unsupported read length");
            return;
        }

        data[0] = match offset {
            INDEX_OFFSET => {
                debug!("cmos: read index offset");
                self.index
            }
            DATA_OFFSET => {
                debug!("cmos: read data offset from index={:x}", self.index);
                self.read_data()
            }
            _ => {
                debug!("cmos: unsupported read offset");
                0
            }
        };
    }

    fn write(&mut self, _vcpuid: u64, offset: u64, data: &[u8]) {
        if data.len() != 1 {
            error!("cmos: unsupported write length");
            return;
        }

        match offset {
            INDEX_OFFSET => {
                debug!("cmos: update index");
                self.index = data[0] & INDEX_MASK;
            }
            DATA_OFFSET => {
                debug!("cmos: write data offset for index={:x}", self.index);
                self.write_data(data[0]);
            }
            _ => debug!("cmos: ignoring unsupported write to CMOS"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::legacy::DummyIrqChip;

    #[test]
    fn test_status_c_read_clears_interrupt_flags() {
        let mut cmos = Cmos::new(512 * 1024 * 1024, 0);

        cmos.write(0, INDEX_OFFSET, &[REG_STATUS_B as u8]);
        cmos.write(
            0,
            DATA_OFFSET,
            &[STATUS_B_24_HOUR | STATUS_B_BINARY | STATUS_B_UPDATE_INTERRUPT],
        );

        cmos.write(0, INDEX_OFFSET, &[REG_STATUS_C as u8]);
        let mut data = [0];
        cmos.read(0, DATA_OFFSET, &mut data);
        assert_eq!(data[0], STATUS_C_INTERRUPT_REQUEST | STATUS_C_UPDATE);

        cmos.read(0, DATA_OFFSET, &mut data);
        assert_eq!(data[0], 0);
    }

    #[test]
    fn test_rtc_interrupt_can_use_irq_chip() {
        let mut cmos = Cmos::new(512 * 1024 * 1024, 0);
        cmos.set_intc(DummyIrqChip::new().into());
        cmos.set_irq_line(8);

        cmos.write(0, INDEX_OFFSET, &[REG_STATUS_B as u8]);
        cmos.write(
            0,
            DATA_OFFSET,
            &[STATUS_B_24_HOUR | STATUS_B_BINARY | STATUS_B_PERIODIC_INTERRUPT],
        );

        cmos.write(0, INDEX_OFFSET, &[REG_STATUS_C as u8]);
        let mut data = [0];
        cmos.read(0, DATA_OFFSET, &mut data);
        assert_eq!(data[0], STATUS_C_INTERRUPT_REQUEST | STATUS_C_PERIODIC);
    }
}
