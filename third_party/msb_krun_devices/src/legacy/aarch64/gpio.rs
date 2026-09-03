// Copyright 2021 Arm Limited (or its affiliates). All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! ARM PrimeCell General Purpose Input/Output(PL061)
//!
//! This module implements an ARM PrimeCell General Purpose Input/Output(PL061) to support gracefully poweroff microvm from external.
//!

use std::fmt;
use std::os::fd::AsRawFd;
use std::result;

use polly::event_manager::{EventManager, Subscriber};
use utils::byte_order::{read_le_u32, write_le_u32};
use utils::epoll::{EpollEvent, EventSet};
use utils::eventfd::EventFd;

use crate::bus::BusDevice;
use crate::legacy::IrqChip;

const OFS_DATA: u64 = 0x400; // Data Register
const GPIODIR: u64 = 0x400; // Direction Register
const GPIOIS: u64 = 0x404; // Interrupt Sense Register
const GPIOIBE: u64 = 0x408; // Interrupt Both Edges Register
const GPIOIEV: u64 = 0x40c; // Interrupt Event Register
const GPIOIE: u64 = 0x410; // Interrupt Mask Register
const GPIORIE: u64 = 0x414; // Raw Interrupt Status Register
const GPIOMIS: u64 = 0x418; // Masked Interrupt Status Register
const GPIOIC: u64 = 0x41c; // Interrupt Clear Register
const GPIOAFSEL: u64 = 0x420; // Mode Control Select Register
                              // From 0x424 to 0xFDC => reserved space.
                              // From 0xFE0 to 0xFFC => Peripheral and PrimeCell Identification Registers which are Read Only registers.
                              // These registers can conceptually be treated as a 32-bit register, and PartNumber[11:0] is used to identify the peripheral.
                              // We are putting the expected values (look at 'Reset value' column from above mentioned document) in an array.
const GPIO_ID: [u8; 8] = [0x61, 0x10, 0x14, 0x00, 0x0d, 0xf0, 0x05, 0xb1];
// ID Margins
const GPIO_ID_LOW: u64 = 0xfe0;
const GPIO_ID_HIGH: u64 = 0x1000;

#[derive(Debug)]
pub enum Error {
    BadWriteOffset(u64),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::BadWriteOffset(offset) => write!(f, "Bad Write Offset: {offset}"),
        }
    }
}

type Result<T> = result::Result<T, Error>;

/// A GPIO device following the PL061 specification.
pub struct Gpio {
    // Data Register
    data: u32,
    // Direction Register
    dir: u32,
    // Interrupt Sense Register
    isense: u32,
    // Interrupt Both Edges Register
    ibe: u32,
    // Interrupt Event Register
    iev: u32,
    // Interrupt Mask Register
    im: u32,
    // Raw Interrupt Status Register
    istate: u32,
    // Mode Control Select Register
    afsel: u32,
    // GPIO irq_field
    interrupt_evt: EventFd,
    intc: Option<IrqChip>,
    irq_line: Option<u32>,
    shutdown_efd: EventFd,
}

impl Gpio {
    /// Constructs an PL061 GPIO device.
    pub fn new(shutdown_efd: EventFd, interrupt_evt: EventFd) -> Self {
        Self {
            data: 0,
            dir: 0,
            isense: 0,
            ibe: 0,
            iev: 0,
            im: 0,
            istate: 0,
            afsel: 0,
            interrupt_evt,
            intc: None,
            irq_line: None,
            shutdown_efd,
        }
    }

    pub fn set_intc(&mut self, intc: IrqChip) {
        self.intc = Some(intc);
    }

    pub fn set_irq_line(&mut self, irq: u32) {
        debug!("SET_IRQ_LINE (GPIO)={irq}");
        self.irq_line = Some(irq);
    }

    fn handle_write(&mut self, offset: u64, val: u32) -> Result<()> {
        if offset < OFS_DATA {
            // In order to write to data register, the corresponding bits in the mask, resulting
            // from the offsite[9:2], must be HIGH. otherwise the bit values remain unchanged.
            let mask = (offset >> 2) as u32 & self.dir;
            self.data = (self.data & !mask) | (val & mask);
        } else {
            match offset {
                GPIODIR => {
                    /* Direction Register */
                    self.dir = val & 0xff;
                }
                GPIOIS => {
                    /* Interrupt Sense Register */
                    self.isense = val & 0xff;
                }
                GPIOIBE => {
                    /* Interrupt Both Edges Register */
                    self.ibe = val & 0xff;
                }
                GPIOIEV => {
                    /* Interrupt Event Register */
                    self.iev = val & 0xff;
                }
                GPIOIE => {
                    /* Interrupt Mask Register */
                    self.im = val & 0xff;
                }
                GPIOIC => {
                    /* Interrupt Clear Register */
                    self.istate &= !val;
                }
                GPIOAFSEL => {
                    /* Mode Control Select Register */
                    self.afsel = val & 0xff;
                }
                o => {
                    return Err(Error::BadWriteOffset(o));
                }
            }
        }
        Ok(())
    }

    pub fn trigger_restart_key(&mut self, press: bool) {
        if press {
            debug!("Generate a restart key press event");
            self.istate = 0x8;
            self.data = 0x8;
        } else {
            debug!("Generate a restart key release event");
            self.istate = 0x8;
            self.data = 0x0;
        }

        self.trigger_gpio_interrupt();
    }

    fn trigger_gpio_interrupt(&self) {
        if let Some(intc) = &self.intc {
            if let Err(e) = intc
                .lock()
                .unwrap()
                .set_irq(self.irq_line, Some(&self.interrupt_evt))
            {
                warn!("Error signalling irq: {e:?}");
            }
        }
    }
}

impl BusDevice for Gpio {
    fn read(&mut self, _base: u64, offset: u64, data: &mut [u8]) {
        let value;
        let mut read_ok = true;

        if (GPIO_ID_LOW..GPIO_ID_HIGH).contains(&offset) {
            let index = ((offset - GPIO_ID_LOW) >> 2) as usize;
            value = u32::from(GPIO_ID[index]);
        } else if offset < OFS_DATA {
            value = self.data & ((offset >> 2) as u32);
            if value != 0 {
                // Now that the guest has read it, send a key release event.
                self.trigger_restart_key(false);
            }
        } else {
            value = match offset {
                GPIODIR => self.dir,
                GPIOIS => self.isense,
                GPIOIBE => self.ibe,
                GPIOIEV => self.iev,
                GPIOIE => self.im,
                GPIORIE => self.istate,
                GPIOMIS => self.istate & self.im,
                GPIOAFSEL => self.afsel,
                _ => {
                    read_ok = false;
                    0
                }
            };
        }

        if read_ok && data.len() <= 4 {
            write_le_u32(data, value);
        } else {
            warn!(
                "Invalid GPIO PL061 read: offset {}, data length {}",
                offset,
                data.len()
            );
        }
    }

    fn write(&mut self, _base: u64, offset: u64, data: &[u8]) {
        if data.len() <= 4 {
            let value = read_le_u32(data);
            if let Err(e) = self.handle_write(offset, value) {
                warn!("Failed to write to GPIO PL061 device: {e}");
            }
        } else {
            warn!(
                "Invalid GPIO PL061 write: offset {}, data length {}",
                offset,
                data.len()
            );
        }
    }
}

impl Subscriber for Gpio {
    fn process(&mut self, event: &EpollEvent, _event_manager: &mut EventManager) {
        let source = event.fd();

        match source {
            _ if source == self.shutdown_efd.as_raw_fd() => {
                _ = self.shutdown_efd.read();
                // Send a key press event.
                self.trigger_restart_key(true);
            }
            _ => warn!("Unexpected gpio event received: {source:?}"),
        }
    }

    fn interest_list(&self) -> Vec<EpollEvent> {
        vec![EpollEvent::new(
            EventSet::IN,
            self.shutdown_efd.as_raw_fd() as u64,
        )]
    }
}
