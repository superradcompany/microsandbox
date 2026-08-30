// Copyright 2025 The libkrun Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io;

use crate::bus::BusDevice;
use crate::legacy::aia::AIADevice;
use crate::legacy::irqchip::IrqChipT;
use crate::Error as DeviceError;

use kvm_ioctls::{DeviceFd, VmFd};
use utils::eventfd::EventFd;

pub struct KvmAia {
    _device_fd: DeviceFd,

    /// Number of CPUs handled by the device
    vcpu_count: u32,
}

impl KvmAia {
    pub fn new(vm: &VmFd, vcpu_count: u32) -> Result<Self, DeviceError> {
        // Create a KVM AIA device
        let mut aia_device = kvm_bindings::kvm_create_device {
            type_: kvm_bindings::kvm_device_type_KVM_DEV_TYPE_RISCV_AIA,
            fd: 0,
            flags: 0,
        };
        let device_fd = vm.create_device(&mut aia_device).unwrap();

        // Setting up the number of wired interrupt sources
        let nr_irqs: u32 = arch::riscv64::layout::IRQ_MAX - arch::riscv64::layout::IRQ_BASE;
        let nr_irqs_ptr = &nr_irqs as *const u32;
        let attr = kvm_bindings::kvm_device_attr {
            group: kvm_bindings::KVM_DEV_RISCV_AIA_GRP_CONFIG,
            attr: u64::from(kvm_bindings::KVM_DEV_RISCV_AIA_CONFIG_SRCS),
            addr: nr_irqs_ptr as u64,
            flags: 0,
        };
        device_fd.set_device_attr(&attr).unwrap();

        // Setting up hart_bits
        let max_hart_index = vcpu_count as u64 - 1;
        let hart_bits = std::cmp::max(64 - max_hart_index.leading_zeros(), 1);
        let hart_bits_ptr = &hart_bits as *const u32;
        let attr = kvm_bindings::kvm_device_attr {
            group: kvm_bindings::KVM_DEV_RISCV_AIA_GRP_CONFIG,
            attr: u64::from(kvm_bindings::KVM_DEV_RISCV_AIA_CONFIG_HART_BITS),
            addr: hart_bits_ptr as u64,
            flags: 0,
        };
        device_fd.set_device_attr(&attr).unwrap();

        // Designate addresses of APLIC and IMSICS

        // Setting up RISC-V APLIC
        let aplic_addr = arch::riscv64::layout::APLIC_START;
        let aplic_addr_ptr = &aplic_addr as *const u64;
        let attr = kvm_bindings::kvm_device_attr {
            group: kvm_bindings::KVM_DEV_RISCV_AIA_GRP_ADDR,
            attr: u64::from(kvm_bindings::KVM_DEV_RISCV_AIA_ADDR_APLIC),
            addr: aplic_addr_ptr as u64,
            flags: 0,
        };
        device_fd.set_device_attr(&attr).unwrap();

        // Setting up RISC-V IMSICs
        for cpu_index in 0..vcpu_count {
            let cpu_imsic_addr = arch::riscv64::layout::IMSIC_START
                + (cpu_index * kvm_bindings::KVM_DEV_RISCV_IMSIC_SIZE) as u64;
            let cpu_imsic_addr_ptr = &cpu_imsic_addr as *const u64;
            let attr = kvm_bindings::kvm_device_attr {
                group: kvm_bindings::KVM_DEV_RISCV_AIA_GRP_ADDR,
                attr: cpu_index as u64 + 1,
                addr: cpu_imsic_addr_ptr as u64,
                flags: 0,
            };
            device_fd.set_device_attr(&attr).unwrap();
        }

        // Finalizing the AIA device
        let attr = kvm_bindings::kvm_device_attr {
            group: kvm_bindings::KVM_DEV_RISCV_AIA_GRP_CTRL,
            attr: u64::from(kvm_bindings::KVM_DEV_RISCV_AIA_CTRL_INIT),
            addr: 0,
            flags: 0,
        };
        device_fd.set_device_attr(&attr).unwrap();

        Ok(Self {
            _device_fd: device_fd,
            vcpu_count,
        })
    }
}

impl IrqChipT for KvmAia {
    fn get_mmio_addr(&self) -> u64 {
        0
    }

    fn get_mmio_size(&self) -> u64 {
        0
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
                "EventFd not set up for irq line".to_string(),
            )));
        }
        Ok(())
    }
}

impl BusDevice for KvmAia {
    fn read(&mut self, _vcpuid: u64, _offset: u64, _data: &mut [u8]) {
        unreachable!("MMIO operations are managed in-kernel");
    }

    fn write(&mut self, _vcpuid: u64, _offset: u64, _data: &[u8]) {
        unreachable!("MMIO operations are managed in-kernel");
    }
}

impl AIADevice for KvmAia {
    fn aplic_compatibility(&self) -> &str {
        "riscv,aplic"
    }

    fn aplic_properties(&self) -> [u32; 4] {
        [
            0,
            arch::riscv64::layout::APLIC_START as u32,
            0,
            kvm_bindings::KVM_DEV_RISCV_APLIC_SIZE,
        ]
    }

    fn imsic_compatibility(&self) -> &str {
        "riscv,imsics"
    }

    fn imsic_properties(&self) -> [u32; 4] {
        [
            0,
            arch::riscv64::layout::IMSIC_START as u32,
            0,
            kvm_bindings::KVM_DEV_RISCV_IMSIC_SIZE * self.vcpu_count,
        ]
    }

    fn vcpu_count(&self) -> u32 {
        self.vcpu_count
    }

    fn msi_compatible(&self) -> bool {
        true
    }
}
