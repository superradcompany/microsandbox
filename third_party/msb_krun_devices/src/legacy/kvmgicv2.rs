// Copyright 2025 The libkrun Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io;

use crate::bus::BusDevice;
use crate::legacy::gic::GICDevice;
use crate::legacy::irqchip::IrqChipT;
use crate::Error as DeviceError;

use kvm_ioctls::{DeviceFd, VmFd};
use utils::eventfd::EventFd;

const KVM_VGIC_V2_DIST_SIZE: u64 = 0x1000;
const KVM_VGIC_V2_CPU_SIZE: u64 = 0x2000;

// Device trees specific constants
const ARCH_GIC_V2_MAINT_IRQ: u32 = 8;

pub struct KvmGicV2 {
    _device_fd: DeviceFd,

    /// GIC device properties, to be used for setting up the fdt entry
    properties: [u64; 4],

    /// Number of CPUs handled by the device
    vcpu_count: u64,
}

impl KvmGicV2 {
    pub fn new(vm: &VmFd, vcpu_count: u64) -> Self {
        let dist_size = KVM_VGIC_V2_DIST_SIZE;
        let dist_addr = arch::MMIO_MEM_START - dist_size;
        let cpu_size = KVM_VGIC_V2_CPU_SIZE;
        let cpu_addr = dist_addr - cpu_size;

        let mut gic_device = kvm_bindings::kvm_create_device {
            type_: kvm_bindings::kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V2,
            fd: 0,
            flags: 0,
        };
        let device_fd = vm.create_device(&mut gic_device).unwrap();

        let attr = kvm_bindings::kvm_device_attr {
            group: kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ADDR,
            attr: u64::from(kvm_bindings::KVM_VGIC_V2_ADDR_TYPE_DIST),
            addr: &dist_addr as *const u64 as u64,
            flags: 0,
        };
        device_fd.set_device_attr(&attr).unwrap();

        let attr = kvm_bindings::kvm_device_attr {
            group: kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ADDR,
            attr: u64::from(kvm_bindings::KVM_VGIC_V2_ADDR_TYPE_CPU),
            addr: &cpu_addr as *const u64 as u64,
            flags: 0,
        };
        device_fd.set_device_attr(&attr).unwrap();

        // GIC nr_irqs includes 32 private interrupts (SGIs + PPIs), so we need
        // the SPI count plus 32, rounded up to a multiple of 32.
        let nr_irqs: u32 = (arch::aarch64::layout::IRQ_MAX + 1).div_ceil(32) * 32;
        let nr_irqs_ptr = &nr_irqs as *const u32;
        let attr = kvm_bindings::kvm_device_attr {
            group: kvm_bindings::KVM_DEV_ARM_VGIC_GRP_NR_IRQS,
            attr: 0,
            addr: nr_irqs_ptr as u64,
            flags: 0,
        };
        device_fd.set_device_attr(&attr).unwrap();

        let attr = kvm_bindings::kvm_device_attr {
            group: kvm_bindings::KVM_DEV_ARM_VGIC_GRP_CTRL,
            attr: u64::from(kvm_bindings::KVM_DEV_ARM_VGIC_CTRL_INIT),
            addr: 0,
            flags: 0,
        };
        device_fd.set_device_attr(&attr).unwrap();

        Self {
            _device_fd: device_fd,
            properties: [dist_addr, dist_size, cpu_addr, cpu_size],
            vcpu_count,
        }
    }
}

impl IrqChipT for KvmGicV2 {
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

impl BusDevice for KvmGicV2 {
    fn read(&mut self, _vcpuid: u64, _offset: u64, _data: &mut [u8]) {
        unreachable!("MMIO operations are managed in-kernel");
    }

    fn write(&mut self, _vcpuid: u64, _offset: u64, _data: &[u8]) {
        unreachable!("MMIO operations are managed in-kernel");
    }
}

impl GICDevice for KvmGicV2 {
    fn device_properties(&self) -> Vec<u64> {
        self.properties.to_vec()
    }

    fn vcpu_count(&self) -> u64 {
        self.vcpu_count
    }

    fn fdt_compatibility(&self) -> String {
        "arm,gic-400".to_string()
    }

    fn fdt_maint_irq(&self) -> u32 {
        ARCH_GIC_V2_MAINT_IRQ
    }

    fn version(&self) -> u32 {
        kvm_bindings::kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V2
    }
}
