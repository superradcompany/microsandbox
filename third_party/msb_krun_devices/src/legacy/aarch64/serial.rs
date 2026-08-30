// Copyright 2021 Arm Limited (or its affiliates). All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! ARM PrimeCell UART(PL011)
//!
//! This module implements an ARM PrimeCell UART(PL011).
//!

use std::collections::VecDeque;
use std::fmt;
use std::{io, result};

use polly::event_manager::{EventManager, Subscriber};
use utils::byte_order::{read_le_u32, write_le_u32};
use utils::epoll::EpollEvent;
#[cfg(unix)]
use utils::epoll::EventSet;
use utils::eventfd::EventFd;

use crate::bus::BusDevice;
use crate::legacy::{IrqChip, ReadableFd};
use crate::Error as DeviceError;

/* Registers */
const UARTDR: u64 = 0;
const UARTRSR_UARTECR: u64 = 1;
const UARTFR: u64 = 6;
const UARTILPR: u64 = 8;
const UARTIBRD: u64 = 9;
const UARTFBRD: u64 = 10;
const UARTLCR_H: u64 = 11;
const UARTCR: u64 = 12;
const UARTIFLS: u64 = 13;
const UARTIMSC: u64 = 14;
const UARTRIS: u64 = 15;
const UARTMIS: u64 = 16;
const UARTICR: u64 = 17;
const UARTDMACR: u64 = 18;
const UARTDEBUG: u64 = 0x3c0;

const PL011_INT_TX: u32 = 0x20;
const PL011_INT_RX: u32 = 0x10;

const PL011_FLAG_RXFF: u32 = 0x40;
const PL011_FLAG_RXFE: u32 = 0x10;
const PL011_FLAG_TXFE: u32 = 0x80;

const PL011_ID: [u8; 8] = [0x11, 0x10, 0x14, 0x00, 0x0d, 0xf0, 0x05, 0xb1];
// We are only interested in the margins.
const AMBA_ID_LOW: u64 = 0x3f8;
const AMBA_ID_HIGH: u64 = 0x401;

#[derive(Debug)]
pub enum Error {
    BadWriteOffset(u64),
    DmaNotImplemented,
    InterruptFailure(DeviceError),
    WriteAllFailure(io::Error),
    FlushFailure(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::BadWriteOffset(offset) => write!(f, "pl011_write: Bad Write Offset: {offset}"),
            Error::DmaNotImplemented => write!(f, "pl011: DMA not implemented."),
            Error::InterruptFailure(e) => write!(f, "Failed to trigger interrupt: {e:?}"),
            Error::WriteAllFailure(e) => write!(f, "Failed to write: {e}"),
            Error::FlushFailure(e) => write!(f, "Failed to flush: {e}"),
        }
    }
}

type Result<T> = result::Result<T, Error>;

/// A PL011 device following the PL011 specification.
pub struct Serial {
    interrupt_evt: EventFd,
    flags: u32,
    lcr: u32,
    rsr: u32,
    cr: u32,
    dmacr: u32,
    debug: u32,
    int_enabled: u32,
    int_level: u32,
    read_fifo: VecDeque<u8>,
    ilpr: u32,
    ibrd: u32,
    fbrd: u32,
    ifl: u32,
    read_count: u32,
    read_trigger: u32,
    out: Option<Box<dyn io::Write + Send>>,
    input: Option<Box<dyn ReadableFd + Send>>,
    intc: Option<IrqChip>,
    irq_line: Option<u32>,
}

impl Serial {
    /// Constructs an AMBA PL011 UART device.
    pub fn new(
        interrupt_evt: EventFd,
        out: Option<Box<dyn io::Write + Send>>,
        input: Option<Box<dyn ReadableFd + Send>>,
    ) -> Self {
        let (
            flags,
            lcr,
            rsr,
            cr,
            dmacr,
            debug,
            int_enabled,
            int_level,
            read_fifo,
            ilpr,
            ibrd,
            fbrd,
            ifl,
            read_count,
            read_trigger,
        ) = (
            0x90,
            0,
            0,
            0x300,
            0,
            0,
            0,
            PL011_INT_TX,
            VecDeque::new(),
            0,
            0,
            0,
            0x12,
            0,
            1,
        );

        Self {
            interrupt_evt,
            flags,
            lcr,
            rsr,
            cr,
            dmacr,
            debug,
            int_enabled,
            int_level,
            read_fifo,
            ilpr,
            ibrd,
            fbrd,
            ifl,
            read_count,
            read_trigger,
            out,
            input,
            intc: None,
            irq_line: None,
        }
    }

    /// Constructs a Serial port ready for input and output.
    pub fn new_in_out(
        interrupt_evt: EventFd,
        input: Box<dyn ReadableFd + Send>,
        out: Box<dyn io::Write + Send>,
    ) -> Serial {
        Self::new(interrupt_evt, Some(out), Some(input))
    }

    /// Constructs a Serial port ready for output but with no input.
    pub fn new_out(interrupt_evt: EventFd, out: Box<dyn io::Write + Send>) -> Serial {
        Self::new(interrupt_evt, Some(out), None)
    }

    /// Constructs a Serial port with no connected input or output.
    pub fn new_sink(interrupt_evt: EventFd) -> Serial {
        Self::new(interrupt_evt, None, None)
    }

    pub fn set_intc(&mut self, intc: IrqChip) {
        self.intc = Some(intc);
    }

    pub fn set_irq_line(&mut self, irq: u32) {
        debug!("SET_IRQ_LINE (SERIAL)={irq}");
        self.irq_line = Some(irq);
    }

    /// Provides a reference to the interrupt event fd.
    pub fn interrupt_evt(&self) -> &EventFd {
        &self.interrupt_evt
    }

    /// Queues raw bytes for the guest to read and signals the interrupt
    pub fn queue_input_bytes(&mut self, c: &[u8]) -> result::Result<(), DeviceError> {
        self.read_fifo.extend(c);
        self.read_count += c.len() as u32;
        self.flags &= !PL011_FLAG_RXFE;

        if ((self.lcr & 0x10) == 0) || (self.read_count == 16) {
            self.flags |= PL011_FLAG_RXFF;
        }

        if self.read_count >= self.read_trigger {
            self.int_level |= PL011_INT_RX;
            self.trigger_interrupt()?;
        }

        Ok(())
    }

    pub fn flush_output(&mut self) -> result::Result<(), io::Error> {
        if let Some(out) = self.out.as_mut() {
            out.flush()?;
        }
        Ok(())
    }

    fn pl011_get_baudrate(&self) -> u32 {
        if self.fbrd == 0 {
            return 0;
        }

        let clk = 24_000_000; // We set the APB_PLCK to 24M in device tree
        (clk / ((self.ibrd << 6) + self.fbrd)) << 2
    }

    fn pl011_trace_baudrate_change(&self) {
        debug!(
            "=== New baudrate: {:#?} (clk: {:#?}Hz, ibrd: {:#?}, fbrd: {:#?}) ===",
            self.pl011_get_baudrate(),
            24_000_000, // We set the APB_PLCK to 24M in device tree
            self.ibrd,
            self.fbrd
        );
    }

    fn pl011_set_read_trigger(&mut self) {
        self.read_trigger = 1;
    }

    fn set_tx_ready(&mut self) {
        self.flags |= PL011_FLAG_TXFE;
        self.int_level |= PL011_INT_TX;
    }

    fn handle_write(&mut self, offset: u64, val: u32) -> Result<()> {
        match offset >> 2 {
            UARTDR => {
                if let Some(out) = self.out.as_mut() {
                    out.write_all(&[val.to_le_bytes()[0]])
                        .map_err(Error::WriteAllFailure)?;
                    out.flush().map_err(Error::FlushFailure)?;
                }
                self.set_tx_ready();
                self.trigger_interrupt().map_err(Error::InterruptFailure)?;
            }
            UARTRSR_UARTECR => {
                self.rsr = 0;
            }
            UARTFR => { /* Writes to Flag register are ignored.*/ }
            UARTILPR => {
                self.ilpr = val;
            }
            UARTIBRD => {
                self.ibrd = val;
                self.pl011_trace_baudrate_change();
            }
            UARTFBRD => {
                self.fbrd = val;
                self.pl011_trace_baudrate_change();
            }
            UARTLCR_H => {
                /* Reset the FIFO state on FIFO enable or disable */
                if ((self.lcr ^ val) & 0x10) != 0 {
                    self.read_count = 0;
                }
                self.lcr = val;
                self.pl011_set_read_trigger();
            }
            UARTCR => {
                self.cr = val;
            }
            UARTIFLS => {
                self.ifl = val;
                self.pl011_set_read_trigger();
            }
            UARTIMSC => {
                self.int_enabled = val;
                self.set_tx_ready();
                self.trigger_interrupt().map_err(Error::InterruptFailure)?;
            }
            UARTICR => {
                self.int_level &= !val;
                self.trigger_interrupt().map_err(Error::InterruptFailure)?;
            }
            UARTDMACR => {
                self.dmacr = val;
                if (val & 3) != 0 {
                    return Err(Error::DmaNotImplemented);
                }
            }
            UARTDEBUG => {
                self.debug = val;
                //self.handle_debug();
            }
            off => {
                debug!("PL011: Bad write offset, offset: {off}");
                return Err(Error::BadWriteOffset(off));
            }
        }
        Ok(())
    }

    fn trigger_interrupt(&mut self) -> result::Result<(), DeviceError> {
        if self.int_level & self.int_enabled == 0 {
            return Ok(());
        }

        if let Some(intc) = &self.intc {
            intc.lock()
                .unwrap()
                .set_irq(self.irq_line, Some(&self.interrupt_evt))?;
        }
        Ok(())
    }
}

impl BusDevice for Serial {
    fn read(&mut self, _base: u64, offset: u64, data: &mut [u8]) {
        debug!("read: offset={offset:x}");
        let mut read_ok = true;
        let v = if (AMBA_ID_LOW..AMBA_ID_HIGH).contains(&(offset >> 2)) {
            let index = ((offset - 0xfe0) >> 2) as usize;
            u32::from(PL011_ID[index])
        } else {
            match offset >> 2 {
                UARTDR => {
                    self.flags &= !PL011_FLAG_RXFF;
                    let c: u32 = self.read_fifo.pop_front().unwrap_or_default().into();
                    if self.read_count > 0 {
                        self.read_count -= 1;
                    }
                    if self.read_count == 0 {
                        self.flags |= PL011_FLAG_RXFE;
                    }
                    if self.read_count == (self.read_trigger - 1) {
                        self.int_level &= !PL011_INT_RX;
                    }
                    self.rsr = c >> 8;
                    c
                }
                UARTRSR_UARTECR => self.rsr,
                UARTFR => self.flags,
                UARTILPR => self.ilpr,
                UARTIBRD => self.ibrd,
                UARTFBRD => self.fbrd,
                UARTLCR_H => self.lcr,
                UARTCR => self.cr,
                UARTIFLS => self.ifl,
                UARTIMSC => self.int_enabled,
                UARTRIS => self.int_level,
                UARTMIS => self.int_level & self.int_enabled,
                UARTDMACR => self.dmacr,
                UARTDEBUG => self.debug,
                _ => {
                    read_ok = false;
                    0
                }
            }
        };

        if read_ok && data.len() <= 4 {
            write_le_u32(data, v);
        } else {
            warn!(
                "Invalid PL011 read: offset {}, data length {}",
                offset,
                data.len()
            );
        }
    }

    fn write(&mut self, _base: u64, offset: u64, data: &[u8]) {
        debug!("write: offset={offset:x}, data={data:?}");
        if data.len() <= 4 {
            let v = read_le_u32(data);
            if let Err(e) = self.handle_write(offset, v) {
                warn!("Failed to write to PL011 device: {e}");
            }
        } else {
            warn!(
                "Invalid PL011 write: offset {}, data length {}",
                offset,
                data.len()
            );
        }
    }
}

impl Subscriber for Serial {
    /// Handle a read event (EPOLLIN) on the serial input fd.
    fn process(&mut self, event: &EpollEvent, _: &mut EventManager) {
        #[cfg(windows)]
        {
            let _ = event;
        }

        #[cfg(unix)]
        {
            let source = event.fd();
            let event_set = event.event_set();

            // TODO: also check for errors. Pending high level discussions on how we want
            // to handle errors in devices.
            let supported_events = EventSet::IN;
            if !supported_events.contains(event_set) {
                warn!("Received unknown event: {event_set:?} from source: {source:?}");
                return;
            }

            if let Some(input) = self.input.as_mut() {
                if input.as_raw_fd() == source {
                    let mut out = [0u8; 32];
                    match input.read(&mut out[..]) {
                        Ok(count) => {
                            self.queue_input_bytes(&out[..count])
                                .unwrap_or_else(|e| warn!("Serial error on input: {e:?}"));
                        }
                        Err(e) => {
                            warn!("error while reading stdin: {e:?}");
                        }
                    }
                }
            }
        }
    }

    /// Initial registration of pollable objects.
    /// If serial input is present, register the serial input FD as readable.
    fn interest_list(&self) -> Vec<EpollEvent> {
        #[cfg(windows)]
        {
            let _ = &self.input;
            Vec::new()
        }

        #[cfg(unix)]
        {
            match &self.input {
                Some(input) => vec![EpollEvent::new(EventSet::IN, input.as_raw_fd() as u64)],
                None => vec![],
            }
        }
    }
}
