// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io;

use arch::x86_64::layout::KVM_IOAPIC_NUM_PINS;

use crate::bus::BusDevice;
use crate::legacy::irqchip::IrqChipT;
use crate::Error as DeviceError;

use kvm_bindings::{kvm_pit_config, KVM_PIT_SPEAKER_DUMMY};
use kvm_ioctls::{Error, VmFd};
use utils::eventfd::EventFd;

pub struct KvmIoapic {}

impl KvmIoapic {
    pub fn new(vm: &VmFd) -> Result<Self, Error> {
        vm.create_irq_chip()?;
        let pit_config = kvm_pit_config {
            // We need to enable the emulation of a dummy speaker port stub so that writing to port
            // 0x61 (i.e. KVM_SPEAKER_BASE_ADDRESS) does not trigger an exit to user space.
            flags: KVM_PIT_SPEAKER_DUMMY,
            ..Default::default()
        };
        vm.create_pit2(pit_config)?;

        Ok(Self {})
    }
}

impl IrqChipT for KvmIoapic {
    fn get_mmio_addr(&self) -> u64 {
        0
    }

    fn get_mmio_size(&self) -> u64 {
        0
    }

    fn num_pins(&self) -> usize {
        KVM_IOAPIC_NUM_PINS
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
            return Err(DeviceError::FailedSignalingUsedQueue(io::Error::new(
                io::ErrorKind::NotFound,
                "EventFd not set up for irq line",
            )));
        }
        Ok(())
    }
}

impl BusDevice for KvmIoapic {
    fn read(&mut self, _vcpuid: u64, _offset: u64, _data: &mut [u8]) {
        unreachable!("MMIO operations are managed in-kernel");
    }

    fn write(&mut self, _vcpuid: u64, _offset: u64, _data: &[u8]) {
        unreachable!("MMIO operations are managed in-kernel");
    }
}
