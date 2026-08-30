// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::collections::HashMap;
use std::fmt::Debug;
use std::{io, result};

use crate::legacy::gic::GICDevice;
use crate::legacy::IrqChip;
use crate::DeviceType;
use arch::aarch64::layout::{GTIMER_HYP, GTIMER_PHYS, GTIMER_SEC, GTIMER_VIRT};
use arch::{ArchMemoryInfo, InitrdConfig};
use vm_fdt::{Error as FdtError, FdtWriter};
use vm_memory::{Address, Bytes, GuestAddress, GuestMemoryError, GuestMemoryMmap};

// This is a value for uniquely identifying the FDT node declaring the interrupt controller.
const GIC_PHANDLE: u32 = 1;
// This is a value for uniquely identifying the FDT node containing the clock definition.
const CLOCK_PHANDLE: u32 = 2;
// This is a value for uniquely identifying the FDT node containing the gpio controller.
const GPIO_PHANDLE: u32 = 4;
// Read the documentation specified when appending the root node to the FDT.
const ADDRESS_CELLS: u32 = 0x2;
const SIZE_CELLS: u32 = 0x2;

// System restart
const KEY_RESTART: u32 = 0x198;

// As per kvm tool and
// https://www.kernel.org/doc/Documentation/devicetree/bindings/interrupt-controller/arm%2Cgic.txt
// Look for "The 1st cell..."
const GIC_FDT_IRQ_TYPE_SPI: u32 = 0;
const GIC_FDT_IRQ_TYPE_PPI: u32 = 1;

// From https://elixir.bootlin.com/linux/v4.9.62/source/include/dt-bindings/interrupt-controller/irq.h#L17
const IRQ_TYPE_EDGE_RISING: u32 = 1;
const IRQ_TYPE_LEVEL_HI: u32 = 4;

/// Trait for devices to be added to the Flattened Device Tree.
pub trait DeviceInfoForFDT {
    /// Returns the address where this device will be loaded.
    fn addr(&self) -> u64;
    /// Returns the associated interrupt for this device.
    fn irq(&self) -> u32;
    /// Returns the amount of memory that needs to be reserved for this device.
    fn length(&self) -> u64;
}

/// Errors thrown while configuring the Flattened Device Tree for aarch64.
#[derive(Debug)]
pub enum Error {
    /// Creating FDT failed.
    CreateFDT(FdtError),
    /// Failure in calling syscall for terminating this FDT.
    FinishFDTReserveMap(io::Error),
    /// Failure in writing FDT in memory.
    WriteFDTToMemory(GuestMemoryError),
}
type Result<T> = result::Result<T, Error>;

impl From<FdtError> for Error {
    fn from(item: FdtError) -> Self {
        Error::CreateFDT(item)
    }
}

/// Creates the flattened device tree for this aarch64 microVM.
pub fn create_fdt<T: DeviceInfoForFDT + Clone + Debug>(
    guest_mem: &GuestMemoryMmap,
    arch_memory_info: &ArchMemoryInfo,
    vcpu_mpidr: Vec<u64>,
    cmdline: &str,
    device_info: &HashMap<(DeviceType, String), T>,
    gic_device: &IrqChip,
    initrd: &Option<InitrdConfig>,
) -> Result<Vec<u8>> {
    // Alocate stuff necessary for the holding the blob.
    let mut fdt = FdtWriter::new()?;

    // For an explanation why these nodes were introduced in the blob take a look at
    // https://github.com/torvalds/linux/blob/master/Documentation/devicetree/booting-without-of.txt#L845
    // Look for "Required nodes and properties".

    // Header or the root node as per above mentioned documentation.
    let root_node = fdt.begin_node("root")?;
    fdt.property_string("compatible", "linux,dummy-virt")?;
    // For info on #address-cells and size-cells read "Note about cells and address representation"
    // from the above mentioned txt file.
    fdt.property_u32("#address-cells", ADDRESS_CELLS)?;
    fdt.property_u32("#size-cells", SIZE_CELLS)?;
    // This is not mandatory but we use it to point the root node to the node
    // containing description of the interrupt controller for this VM.
    fdt.property_u32("interrupt-parent", GIC_PHANDLE)?;
    create_cpu_nodes(&mut fdt, &vcpu_mpidr)?;
    create_memory_node(&mut fdt, guest_mem, arch_memory_info)?;
    create_chosen_node(&mut fdt, cmdline, initrd, device_info)?;
    create_gic_node(&mut fdt, gic_device)?;
    create_timer_node(&mut fdt)?;
    create_clock_node(&mut fdt)?;
    create_psci_node(&mut fdt)?;
    create_devices_node(&mut fdt, device_info)?;

    // End Header node.
    fdt.end_node(root_node)?;

    // Allocate another buffer so we can format and then write fdt to guest.
    let fdt_final = fdt.finish()?;

    // Write FDT to memory.
    let fdt_address = GuestAddress(arch_memory_info.fdt_addr);
    guest_mem
        .write_slice(fdt_final.as_slice(), fdt_address)
        .map_err(Error::WriteFDTToMemory)?;
    Ok(fdt_final)
}

// Auxiliary functions for writing u32/u64 numbers in big endian order.
fn to_be32(input: u32) -> [u8; 4] {
    u32::to_be_bytes(input)
}

fn to_be64(input: u64) -> [u8; 8] {
    u64::to_be_bytes(input)
}

// Helper functions for generating a properly formatted byte vector using 32-bit/64-bit cells.
fn generate_prop32(cells: &[u32]) -> Vec<u8> {
    let mut ret: Vec<u8> = Vec::new();
    for &e in cells {
        ret.extend(to_be32(e).iter());
    }
    ret
}

fn generate_prop64(cells: &[u64]) -> Vec<u8> {
    let mut ret: Vec<u8> = Vec::new();
    for &e in cells {
        ret.extend(to_be64(e).iter());
    }
    ret
}

// Following are the auxiliary function for creating the different nodes that we append to our FDT.
fn create_cpu_nodes(fdt: &mut FdtWriter, vcpu_mpidr: &[u64]) -> Result<()> {
    // See https://github.com/torvalds/linux/blob/master/Documentation/devicetree/bindings/arm/cpus.yaml.
    let cpu_node = fdt.begin_node("cpus")?;
    // As per documentation, on ARM v8 64-bit systems value should be set to 2.
    fdt.property_u32("#address-cells", 0x02)?;
    fdt.property_u32("#size-cells", 0x0)?;
    let num_cpus = vcpu_mpidr.len();

    for (index, mpidr) in vcpu_mpidr.iter().enumerate() {
        let cpu_name = format!("cpu@{index:x}");
        let cpu_name_node = fdt.begin_node(&cpu_name)?;
        fdt.property_string("device_type", "cpu")?;
        fdt.property_string("compatible", "arm,arm-v8")?;
        if num_cpus > 1 {
            // This is required on armv8 64-bit. See aforementioned documentation.
            fdt.property_string("enable-method", "psci")?;
        }
        // Set the field to first 24 bits of the MPIDR - Multiprocessor Affinity Register.
        // See http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0488c/BABHBJCI.html.
        fdt.property_u64("reg", mpidr & 0x7FFFFF)?;
        fdt.end_node(cpu_name_node)?;
    }
    fdt.end_node(cpu_node)?;
    Ok(())
}

fn create_memory_node(
    fdt: &mut FdtWriter,
    _guest_mem: &GuestMemoryMmap,
    arch_memory_info: &ArchMemoryInfo,
) -> Result<()> {
    let mem_size = arch_memory_info.ram_last_addr - arch_memory_info.ram_start_addr;
    // See https://github.com/torvalds/linux/blob/master/Documentation/devicetree/booting-without-of.txt#L960
    // for an explanation of this.
    let mem_reg_prop = generate_prop64(&[arch_memory_info.ram_start_addr, mem_size]);

    let mem_node = fdt.begin_node("memory")?;
    fdt.property_string("device_type", "memory")?;
    fdt.property("reg", &mem_reg_prop)?;
    fdt.end_node(mem_node)?;
    Ok(())
}

fn create_chosen_node<T: DeviceInfoForFDT + Clone + Debug>(
    fdt: &mut FdtWriter,
    cmdline: &str,
    initrd: &Option<InitrdConfig>,
    dev_info: &HashMap<(DeviceType, String), T>,
) -> Result<()> {
    let chosen_node = fdt.begin_node("chosen")?;
    fdt.property_string("bootargs", cmdline)?;

    // If we have a legacy serial device, tell the guest this is the default console.
    // Clever guests will still switch to a better console (like virtio-console) if
    // it becomes available later, and this gives us a good fallback.
    for ((device_type, _device_id), info) in dev_info {
        if device_type == &DeviceType::Serial {
            fdt.property_string("stdout-path", &format!("/uart@{:x}", info.addr()))?;
        }
    }

    if let Some(initrd_config) = initrd {
        fdt.property_u64("linux,initrd-start", initrd_config.address.raw_value())?;
        fdt.property_u64(
            "linux,initrd-end",
            initrd_config.address.raw_value() + initrd_config.size as u64,
        )?;
    }

    fdt.end_node(chosen_node)?;

    Ok(())
}

fn create_gic_node(fdt: &mut FdtWriter, gic_device: &IrqChip) -> Result<()> {
    let gic_device = gic_device.lock().unwrap();
    let gic_reg_prop = generate_prop64(&gic_device.device_properties());

    let intc_node = fdt.begin_node("intc")?;
    fdt.property_string("compatible", &gic_device.fdt_compatibility())?;
    fdt.property_null("interrupt-controller")?;
    // "interrupt-cells" field specifies the number of cells needed to encode an
    // interrupt source. The type shall be a <u32> and the value shall be 3 if no PPI affinity description
    // is required.
    fdt.property_u32("#interrupt-cells", 3)?;
    fdt.property("reg", &gic_reg_prop)?;
    fdt.property_u32("phandle", GIC_PHANDLE)?;
    fdt.property_u32("#address-cells", 2)?;
    fdt.property_u32("#size-cells", 2)?;
    fdt.property_null("ranges")?;
    let gic_intr = [
        GIC_FDT_IRQ_TYPE_PPI,
        gic_device.fdt_maint_irq(),
        IRQ_TYPE_LEVEL_HI,
    ];
    let gic_intr_prop = generate_prop32(&gic_intr);

    fdt.property("interrupts", &gic_intr_prop)?;
    fdt.end_node(intc_node)?;

    Ok(())
}

fn create_clock_node(fdt: &mut FdtWriter) -> Result<()> {
    // The Advanced Peripheral Bus (APB) is part of the Advanced Microcontroller Bus Architecture
    // (AMBA) protocol family. It defines a low-cost interface that is optimized for minimal power
    // consumption and reduced interface complexity.
    // PCLK is the clock source and this node defines exactly the clock for the APB.
    let node = fdt.begin_node("apb-pclk")?;
    fdt.property_string("compatible", "fixed-clock")?;
    fdt.property_u32("#clock-cells", 0x0)?;
    fdt.property_u32("clock-frequency", 24000000)?;
    fdt.property_string("clock-output-names", "clk24mhz")?;
    fdt.property_u32("phandle", CLOCK_PHANDLE)?;
    fdt.end_node(node)?;

    Ok(())
}

fn create_timer_node(fdt: &mut FdtWriter) -> Result<()> {
    // See
    // https://github.com/torvalds/linux/blob/master/Documentation/devicetree/bindings/interrupt-controller/arch_timer.txt
    // These are fixed interrupt numbers for the timer device.
    let irqs = [GTIMER_SEC, GTIMER_HYP, GTIMER_VIRT, GTIMER_PHYS];
    let compatible = "arm,armv8-timer";

    let mut timer_reg_cells: Vec<u32> = Vec::new();
    for &irq in irqs.iter() {
        timer_reg_cells.push(GIC_FDT_IRQ_TYPE_PPI);
        timer_reg_cells.push(irq);
        timer_reg_cells.push(IRQ_TYPE_LEVEL_HI);
    }
    let timer_reg_prop = generate_prop32(timer_reg_cells.as_slice());

    let node = fdt.begin_node("timer")?;
    fdt.property_string("compatible", compatible)?;
    fdt.property_null("always-on")?;
    fdt.property("interrupts", &timer_reg_prop)?;
    fdt.end_node(node)?;

    Ok(())
}

fn create_psci_node(fdt: &mut FdtWriter) -> Result<()> {
    let compatible = "arm,psci-0.2";
    let node = fdt.begin_node("psci")?;
    fdt.property_string("compatible", compatible)?;
    // Two methods available: hvc and smc.
    // As per documentation, PSCI calls between a guest and hypervisor may use the HVC conduit instead of SMC.
    // So, since we are using kvm, we need to use hvc.
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    fdt.property_string("method", "hvc")?;
    #[cfg(target_os = "macos")]
    fdt.property_string("method", "smc")?;
    fdt.end_node(node)?;

    Ok(())
}

fn create_virtio_node<T: DeviceInfoForFDT + Clone + Debug>(
    fdt: &mut FdtWriter,
    dev_info: &T,
) -> Result<()> {
    let device_reg_prop = generate_prop64(&[dev_info.addr(), dev_info.length()]);
    #[cfg(target_os = "linux")]
    let irq = generate_prop32(&[GIC_FDT_IRQ_TYPE_SPI, dev_info.irq(), IRQ_TYPE_EDGE_RISING]);
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    let irq = generate_prop32(&[
        GIC_FDT_IRQ_TYPE_SPI,
        dev_info.irq() - 32,
        IRQ_TYPE_EDGE_RISING,
    ]);

    let virtio_node = fdt.begin_node(&format!("virtio_mmio@{:x}", dev_info.addr()))?;
    fdt.property_string("compatible", "virtio,mmio")?;
    fdt.property("reg", &device_reg_prop)?;
    fdt.property("interrupts", &irq)?;
    fdt.property_u32("interrupt-parent", GIC_PHANDLE)?;
    fdt.end_node(virtio_node)?;

    Ok(())
}

fn create_serial_node<T: DeviceInfoForFDT + Clone + Debug>(
    fdt: &mut FdtWriter,
    dev_info: &T,
) -> Result<()> {
    let compatible = b"arm,pl011\0arm,primecell\0";
    let clock_names = b"uartclk\0apb_pclk\0";
    let serial_reg_prop = generate_prop64(&[dev_info.addr(), dev_info.length()]);
    #[cfg(target_os = "linux")]
    let irq = generate_prop32(&[GIC_FDT_IRQ_TYPE_SPI, dev_info.irq(), IRQ_TYPE_LEVEL_HI]);
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    let irq = generate_prop32(&[GIC_FDT_IRQ_TYPE_SPI, dev_info.irq() - 32, IRQ_TYPE_LEVEL_HI]);

    let node = fdt.begin_node(&format!("uart@{:x}", dev_info.addr()))?;
    fdt.property("compatible", compatible)?;
    fdt.property_string("status", "okay")?;
    fdt.property("reg", &serial_reg_prop)?;
    fdt.property_array_u32("clocks", &[CLOCK_PHANDLE, CLOCK_PHANDLE])?;
    fdt.property("clock-names", clock_names)?;
    fdt.property("interrupts", &irq)?;
    fdt.end_node(node)?;

    Ok(())
}

fn create_rtc_node<T: DeviceInfoForFDT + Clone + Debug>(
    fdt: &mut FdtWriter,
    dev_info: &T,
) -> Result<()> {
    let compatible = b"arm,pl031\0arm,primecell\0";
    let rtc_reg_prop = generate_prop64(&[dev_info.addr(), dev_info.length()]);
    #[cfg(target_os = "linux")]
    let irq = generate_prop32(&[GIC_FDT_IRQ_TYPE_SPI, dev_info.irq(), IRQ_TYPE_LEVEL_HI]);
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    let irq = generate_prop32(&[GIC_FDT_IRQ_TYPE_SPI, dev_info.irq() - 32, IRQ_TYPE_LEVEL_HI]);
    let rtc_node = fdt.begin_node(&format!("rtc@{:x}", dev_info.addr()))?;
    fdt.property("compatible", compatible)?;
    fdt.property("reg", &rtc_reg_prop)?;
    fdt.property("interrupts", &irq)?;
    fdt.property_u32("clocks", CLOCK_PHANDLE)?;
    fdt.property_string("clock-names", "apb_pclk")?;
    fdt.end_node(rtc_node)?;

    Ok(())
}

fn create_gpio_node<T: DeviceInfoForFDT + Clone + Debug>(
    fdt: &mut FdtWriter,
    dev_info: &T,
) -> Result<()> {
    let compatible = b"arm,pl061\0arm,primecell\0";

    let gpio_reg_prop = generate_prop64(&[dev_info.addr(), dev_info.length()]);
    let irq = generate_prop32(&[
        GIC_FDT_IRQ_TYPE_SPI,
        dev_info.irq() - 32,
        IRQ_TYPE_EDGE_RISING,
    ]);

    let gpio_node = fdt.begin_node(&format!("pl061@{:x}", dev_info.addr()))?;
    fdt.property("compatible", compatible)?;

    fdt.property("reg", &gpio_reg_prop)?;
    fdt.property("interrupts", &irq)?;
    fdt.property_null("gpio-controller")?;
    fdt.property_u32("#gpio-cells", 2)?;
    fdt.property_u32("clocks", CLOCK_PHANDLE)?;
    fdt.property_string("clock-names", "apb_pclk")?;
    fdt.property_u32("phandle", GPIO_PHANDLE)?;
    fdt.end_node(gpio_node)?;

    // gpio-keys node
    let gpio_keys_node = fdt.begin_node("gpio-keys")?;
    fdt.property_string("compatible", "gpio-keys")?;
    fdt.property_u32("#size-cells", 0)?;
    fdt.property_u32("#address-cells", 1)?;
    let gpio_keys_poweroff_node = fdt.begin_node("button@1")?;
    fdt.property_string("label", "GPIO Key Poweroff")?;
    fdt.property_u32("linux,code", KEY_RESTART)?;
    let gpios = [GPIO_PHANDLE, 3, 0];
    fdt.property_array_u32("gpios", &gpios)?;
    fdt.end_node(gpio_keys_poweroff_node)?;
    fdt.end_node(gpio_keys_node)?;

    Ok(())
}

fn create_devices_node<T: DeviceInfoForFDT + Clone + Debug>(
    fdt: &mut FdtWriter,
    dev_info: &HashMap<(DeviceType, String), T>,
) -> Result<()> {
    // Create one temp Vec to store all virtio devices
    let mut ordered_virtio_device: Vec<&T> = Vec::new();

    for ((device_type, _device_id), info) in dev_info {
        match device_type {
            DeviceType::Gpio => create_gpio_node(fdt, info)?,
            DeviceType::RTC => create_rtc_node(fdt, info)?,
            DeviceType::Serial => create_serial_node(fdt, info)?,
            DeviceType::Virtio(_) => {
                ordered_virtio_device.push(info);
            }
        }
    }

    // Sort out virtio devices by address from low to high and insert them into fdt table.
    ordered_virtio_device.sort_by_key(|a| a.addr());
    for ordered_device_info in ordered_virtio_device.drain(..) {
        create_virtio_node(fdt, ordered_device_info)?;
    }

    Ok(())
}
