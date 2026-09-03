#[derive(Debug)]
pub struct MemoryProperties {
    pub gpa: u64,
    pub size: u64,
    pub private: bool,
}

#[derive(Debug)]
pub enum WorkerMessage {
    #[cfg(all(target_arch = "x86_64", not(target_os = "windows")))]
    GsiRoute(
        crossbeam_channel::Sender<bool>,
        Vec<kvm_bindings::kvm_irq_routing_entry>,
    ),
    #[cfg(all(target_arch = "x86_64", not(target_os = "windows")))]
    IrqLine(crossbeam_channel::Sender<bool>, u32, bool),
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    GpuAddMapping(crossbeam_channel::Sender<bool>, u64, u64, u64),
    #[cfg(target_os = "windows")]
    DaxAddMapping(crossbeam_channel::Sender<bool>, u64, u64, u64, bool),
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    GpuRemoveMapping(crossbeam_channel::Sender<bool>, u64, u64),
    ConvertMemory(crossbeam_channel::Sender<bool>, MemoryProperties),
}
