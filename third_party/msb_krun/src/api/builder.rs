//! VM Builder for creating and configuring microVMs using nested builders.

#[cfg(not(feature = "tee"))]
use std::collections::BTreeSet;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::AtomicI32;
use std::sync::Arc;

use utils::eventfd::{EventFd, EFD_NONBLOCK};
use vmm::resources::VirtioConsoleConfigMode;
use vmm::resources::VmResources;
use vmm::vmm_config::machine_config::VmConfig;
use vmm::vmm_config::machine_config::VmConfigError;

#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
use vmm::vmm_config::fs::CustomFsDeviceConfig;
#[cfg(not(feature = "tee"))]
use vmm::vmm_config::fs::FsDeviceConfig;

#[cfg(feature = "blk")]
use super::builders::DiskBuilder;
#[cfg(not(feature = "tee"))]
use super::builders::FsBuilder;
#[cfg(not(feature = "tee"))]
use super::builders::FsConfig;
#[cfg(not(feature = "tee"))]
use super::builders::HostMemoryPolicy;
use super::builders::PlacementObserver;
use super::builders::PlacementReport;
#[cfg(feature = "net")]
use super::builders::{ConfiguredNet, NetBuilder, NetConfig};
use super::builders::{ConsoleBuilder, ExecBuilder, KernelBuilder, MachineBuilder};
use super::builders::{VsockBuilder, VsockRoute};

use super::error::{BuildError, ConfigError, Error, Result};
use super::vm::Vm;

#[cfg(feature = "blk")]
use devices::virtio::block::ImageType;
use devices::virtio::console::is_valid_queue_size;
#[cfg(feature = "blk")]
use devices::virtio::CacheType;
#[cfg(feature = "blk")]
use vmm::vmm_config::block::BlockDeviceConfig;

#[cfg(feature = "net")]
use devices::virtio::net::device::VirtioNetBackend;
#[cfg(all(feature = "net", unix))]
use std::os::fd::IntoRawFd;
#[cfg(feature = "net")]
use vmm::vmm_config::net::NetworkInterfaceConfig;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

#[cfg(not(target_os = "windows"))]
const VSOCK_TIMESYNC_PORT: u32 = 123;
#[cfg(not(target_os = "windows"))]
const TSI_CONTROL_PORT_START: u32 = 1024;
#[cfg(not(target_os = "windows"))]
const TSI_CONTROL_PORT_END: u32 = 1031;
#[cfg(not(feature = "tee"))]
const MAX_HOST_NUMA_NODE_ID: u32 = u16::MAX as u32;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Builder for creating and configuring a microVM.
///
/// Uses nested builders for organized configuration:
///
/// # Example
///
/// ```rust,no_run
/// use msb_krun::VmBuilder;
///
/// let vm = VmBuilder::new()
///     .machine(|m| m.vcpus(4).memory_mib(2048))
///     .fs(|fs| fs.root("/path/to/rootfs"))
///     .exec(|e| e.path("/bin/myapp").args(["--flag"]).env("HOME", "/root"))
///     .build()
///     .expect("Failed to build VM");
/// ```
pub struct VmBuilder {
    machine: MachineBuilder,
    vsock: VsockBuilder,
    kernel: KernelBuilder,
    #[cfg_attr(feature = "tee", allow(dead_code))]
    #[cfg(not(feature = "tee"))]
    fs: FsBuilder,
    console: ConsoleBuilder,
    exec: ExecBuilder,
    #[cfg(feature = "net")]
    net: NetBuilder,
    #[cfg(feature = "blk")]
    disk: DiskBuilder,
    exit_observers: Vec<Box<dyn Fn(i32) + Send + 'static>>,
    placement_observer: Option<PlacementObserver>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl VmBuilder {
    /// Create a new VM builder with default configuration.
    ///
    /// Defaults:
    /// - 1 vCPU
    /// - 512 MiB memory
    /// - Hyperthreading disabled
    /// - Nested virtualization disabled
    pub fn new() -> Self {
        Self {
            machine: MachineBuilder::new(),
            vsock: VsockBuilder::new(),
            kernel: KernelBuilder::new(),
            #[cfg(not(feature = "tee"))]
            fs: FsBuilder::new(),
            console: ConsoleBuilder::new(),
            exec: ExecBuilder::new(),
            #[cfg(feature = "net")]
            net: NetBuilder::new(),
            #[cfg(feature = "blk")]
            disk: DiskBuilder::new(),
            exit_observers: Vec::new(),
            placement_observer: None,
        }
    }

    /// Configure machine settings (vCPUs, memory, etc.).
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use msb_krun::VmBuilder;
    /// VmBuilder::new()
    ///     .machine(|m| {
    ///         m.vcpus(4)
    ///             .memory_mib(2048)
    ///             .hyperthreading(true)
    ///             .nested_virt(true)
    ///     });
    /// ```
    pub fn machine(mut self, f: impl FnOnce(MachineBuilder) -> MachineBuilder) -> Self {
        self.machine = f(self.machine);
        self
    }

    /// Configure host services exposed through virtio-vsock.
    ///
    /// A route or enabled TSI transport automatically attaches the device.
    pub fn vsock(mut self, f: impl FnOnce(VsockBuilder) -> VsockBuilder) -> Self {
        self.vsock = f(self.vsock);
        self
    }

    /// Configure kernel settings.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use msb_krun::VmBuilder;
    /// VmBuilder::new()
    ///     .kernel(|k| {
    ///         k.krunfw_path("/path/to/libkrunfw.dylib")
    ///             .cmdline("debug")
    ///     });
    /// ```
    pub fn kernel(mut self, f: impl FnOnce(KernelBuilder) -> KernelBuilder) -> Self {
        self.kernel = f(self.kernel);
        self
    }

    /// Configure filesystem mounts.
    ///
    /// Can be called multiple times to add multiple mounts.
    ///
    /// # Examples
    ///
    /// Root filesystem only:
    ///
    /// ```rust,no_run
    /// # use msb_krun::VmBuilder;
    /// VmBuilder::new()
    ///     .fs(|fs| fs.root("/path/to/rootfs"));
    /// ```
    ///
    /// Root filesystem with additional named mounts:
    ///
    /// ```rust,no_run
    /// # use msb_krun::VmBuilder;
    /// VmBuilder::new()
    ///     .fs(|fs| fs.root("/path/to/rootfs"))
    ///     .fs(|fs| fs.tag("data").shm_size(1 << 30).path("/host/data"))
    ///     .fs(|fs| fs.tag("logs").path("/host/logs"));
    /// ```
    ///
    /// Custom filesystem backend:
    ///
    /// ```rust,ignore
    /// VmBuilder::new()
    ///     .fs(|fs| fs.tag("myfs").custom(Box::new(my_backend)));
    /// ```
    #[cfg(not(feature = "tee"))]
    pub fn fs(mut self, f: impl FnOnce(FsBuilder) -> FsBuilder) -> Self {
        let new_fs = f(FsBuilder::new());
        self.fs.configs.extend(new_fs.configs);
        self
    }

    /// Configure network devices.
    ///
    /// Can be called multiple times to add multiple devices.
    ///
    /// # Examples
    ///
    /// Unixgram from a pre-opened fd:
    ///
    /// ```rust,ignore
    /// VmBuilder::new()
    ///     .net(|n| n.mac([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]).unixgram(fd));
    /// ```
    ///
    /// Unixgram connecting to a socket path:
    ///
    /// ```rust,ignore
    /// VmBuilder::new()
    ///     .net(|n| n.unixgram_path("/tmp/net.sock", true));
    /// ```
    ///
    /// Windows named pipe:
    ///
    /// ```rust,ignore
    /// VmBuilder::new()
    ///     .net(|n| n.named_pipe(r"\\.\pipe\libkrun-net0"));
    /// ```
    ///
    /// Custom backend:
    ///
    /// ```rust,ignore
    /// VmBuilder::new()
    ///     .net(|n| n.custom(Box::new(my_backend)));
    /// ```
    #[cfg(feature = "net")]
    pub fn net(mut self, f: impl FnOnce(NetBuilder) -> NetBuilder) -> Self {
        let new_net = f(NetBuilder::new());
        self.net.configs.extend(new_net.configs);
        self
    }

    /// Configure block devices.
    ///
    /// Can be called multiple times to add multiple devices. Devices receive
    /// deterministic guest names by attach order (`/dev/vda`, `/dev/vdb`,
    /// ...). For stable addressing across reorderings, set a custom `id()` —
    /// the guest can then reach the disk via `/dev/disk/by-id/virtio-<id>`.
    /// VMDK images must be configured as read-only.
    ///
    /// # Examples
    ///
    /// Single rootfs disk:
    ///
    /// ```rust,no_run
    /// # use msb_krun::VmBuilder;
    /// VmBuilder::new()
    ///     .disk(|d| d.path("/path/to/disk.img").read_only(true));
    /// ```
    ///
    /// Rootfs plus data and cache volumes with stable ids:
    ///
    /// ```rust,no_run
    /// # use msb_krun::{VmBuilder, DiskImageFormat};
    /// VmBuilder::new()
    ///     .disk(|d| d.path("/img/root.raw"))
    ///     .disk(|d| d.path("/img/data.qcow2").format(DiskImageFormat::Qcow2).id("data"))
    ///     .disk(|d| d.path("/img/cache.raw").id("cache").read_only(true));
    /// ```
    #[cfg(feature = "blk")]
    pub fn disk(mut self, f: impl FnOnce(DiskBuilder) -> DiskBuilder) -> Self {
        let new_disk = f(DiskBuilder::new()).finalize();
        self.disk.configs.extend(new_disk.configs);
        self
    }

    /// Configure console and output settings.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use msb_krun::VmBuilder;
    /// VmBuilder::new()
    ///     .console(|c| c.output("/tmp/vm.log"));
    /// ```
    ///
    /// With the `gpu` and `snd` features:
    ///
    /// ```rust,ignore
    /// VmBuilder::new()
    ///     .console(|c| {
    ///         c.output("/tmp/vm.log")
    ///             .sound(true)
    ///             .gpu_virgl_flags(0x1)
    ///             .gpu_shm_size(1 << 28)
    ///     });
    /// ```
    pub fn console(mut self, f: impl FnOnce(ConsoleBuilder) -> ConsoleBuilder) -> Self {
        self.console = f(self.console);
        self
    }

    /// Register a callback that runs synchronously on graceful guest-initiated shutdown.
    ///
    /// Multiple observers are supported and are called in registration order.
    /// User callbacks execute after internal device cleanup (console reset, terminal restore).
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use msb_krun::VmBuilder;
    /// VmBuilder::new()
    ///     .on_exit(|exit_code| {
    ///         // flush logs, write final status, etc.
    ///         eprintln!("VM exited with code {exit_code}");
    ///     });
    /// ```
    pub fn on_exit(mut self, f: impl Fn(i32) + Send + 'static) -> Self {
        self.exit_observers.push(Box::new(f));
        self
    }

    /// Register a callback for the effective host placement established before guest execution.
    ///
    /// The callback runs once after every vCPU thread has attempted affinity and while all vCPUs
    /// are still paused. Best-effort affinity may produce a mix of pinned and inherited entries.
    pub fn on_placement(mut self, f: impl FnOnce(&PlacementReport) + Send + 'static) -> Self {
        self.placement_observer = Some(Box::new(f));
        self
    }

    /// Configure execution settings.
    ///
    /// # Examples
    ///
    /// Setting environment variables one at a time with `.env()`:
    ///
    /// ```rust,no_run
    /// # use msb_krun::VmBuilder;
    /// VmBuilder::new()
    ///     .exec(|e| {
    ///         e.path("/bin/myapp")
    ///             .args(["--flag", "value"])
    ///             .env("HOME", "/root")
    ///             .env("LANG", "en_US.UTF-8")
    ///             .workdir("/app")
    ///             .rlimit("NOFILE", 1024, 4096)
    ///     });
    /// ```
    ///
    /// Setting environment variables in bulk with `.envs()`:
    ///
    /// ```rust,no_run
    /// # use msb_krun::VmBuilder;
    /// VmBuilder::new()
    ///     .exec(|e| {
    ///         e.path("/bin/myapp")
    ///             .envs([("HOME", "/root"), ("LANG", "en_US.UTF-8")])
    ///     });
    /// ```
    pub fn exec(mut self, f: impl FnOnce(ExecBuilder) -> ExecBuilder) -> Self {
        self.exec = f(self.exec);
        self
    }

    /// Build the VM.
    ///
    /// This validates the configuration and creates a `Vm` instance ready to run.
    pub fn build(self) -> Result<Vm> {
        // Validate configuration
        if self.machine.vcpus == 0 {
            return Err(Error::Config(ConfigError::InvalidVcpuCount(0)));
        }

        if self.machine.memory_mib == 0 {
            return Err(Error::Config(ConfigError::InvalidMemorySize(0)));
        }

        if let Some(port) = self
            .console
            .ports
            .iter()
            .find(|port| !is_valid_queue_size(port.queue_size()))
        {
            return Err(Error::Config(ConfigError::Console(format!(
                "queue size {} must be a power of two between 16 and 1024",
                port.queue_size()
            ))));
        }

        #[cfg(target_os = "windows")]
        if self.machine.enable_inet_hijack {
            return Err(Error::Config(ConfigError::Vsock(
                "TSI INET hijack is not supported on Windows".to_string(),
            )));
        }

        #[cfg(not(target_os = "windows"))]
        let (
            vsock_unix_ipc_port_map,
            vsock_custom_port_map,
            vsock_custom_dgram_port_map,
            vsock_host_port_map,
        ) = {
            let mut occupied_stream_ports = HashSet::new();
            let mut occupied_dgram_ports = HashSet::new();
            let mut unix_routes = HashMap::new();
            let mut custom_routes = HashMap::new();
            let mut custom_dgram_routes = HashMap::new();

            for route in self.vsock.routes {
                let (port, path) = match &route {
                    VsockRoute::UnixConnect { port, path }
                    | VsockRoute::UnixListen { port, path } => (*port, Some(path)),
                    VsockRoute::Custom { port, .. } | VsockRoute::CustomDatagram { port, .. } => {
                        (*port, None)
                    }
                };

                if port == 0 || port == u32::MAX {
                    return Err(Error::Config(ConfigError::Vsock(
                        "route port must be between 1 and u32::MAX - 1".to_string(),
                    )));
                }
                if matches!(&route, VsockRoute::CustomDatagram { .. })
                    && port == VSOCK_TIMESYNC_PORT
                {
                    return Err(Error::Config(ConfigError::Vsock(format!(
                        "datagram route port {port} is reserved for guest time synchronization"
                    ))));
                }
                let occupied_ports = match &route {
                    VsockRoute::CustomDatagram { .. } => &mut occupied_dgram_ports,
                    _ => &mut occupied_stream_ports,
                };
                if !occupied_ports.insert(port) {
                    return Err(Error::Config(ConfigError::Vsock(format!(
                        "duplicate route for host port and socket type: {port}"
                    ))));
                }
                if path.is_some_and(|path| path.as_os_str().is_empty()) {
                    return Err(Error::Config(ConfigError::Vsock(format!(
                        "Unix socket path for host port {port} is empty"
                    ))));
                }

                match route {
                    VsockRoute::UnixConnect { port, path } => {
                        unix_routes.insert(port, (path, false));
                    }
                    VsockRoute::UnixListen { port, path } => {
                        unix_routes.insert(port, (path, true));
                    }
                    VsockRoute::Custom { port, backend } => {
                        custom_routes.insert(port, backend);
                    }
                    VsockRoute::CustomDatagram { port, backend } => {
                        custom_dgram_routes.insert(port, backend);
                    }
                }
            }

            let enable_inet_hijack =
                self.machine.enable_inet_hijack || self.vsock.enable_inet_hijack;
            #[cfg(feature = "net")]
            let tsi_inet_active = enable_inet_hijack && self.net.configs.is_empty();
            #[cfg(not(feature = "net"))]
            let tsi_inet_active = enable_inet_hijack;
            if tsi_inet_active {
                if let Some(port) = custom_dgram_routes
                    .keys()
                    .find(|port| (TSI_CONTROL_PORT_START..=TSI_CONTROL_PORT_END).contains(port))
                {
                    return Err(Error::Config(ConfigError::Vsock(format!(
                        "datagram route port {port} conflicts with the active TSI control transport"
                    ))));
                }
            }
            if !self.vsock.tcp_listen_remaps.is_empty() && !enable_inet_hijack {
                return Err(Error::Config(ConfigError::Vsock(
                    "TCP listen remaps require TSI INET hijack".to_string(),
                )));
            }

            #[cfg(feature = "net")]
            if !self.vsock.tcp_listen_remaps.is_empty() && !self.net.configs.is_empty() {
                return Err(Error::Config(ConfigError::Vsock(
                    "TCP listen remaps cannot be used with a virtio-net device because TSI INET hijack is inactive".to_string(),
                )));
            }

            let mut host_map = HashMap::new();
            for (guest_port, host_port) in self.vsock.tcp_listen_remaps {
                if guest_port == 0 || host_port == 0 {
                    return Err(Error::Config(ConfigError::Vsock(
                        "TCP listen remap ports must be non-zero".to_string(),
                    )));
                }
                if host_map.insert(guest_port, host_port).is_some() {
                    return Err(Error::Config(ConfigError::Vsock(format!(
                        "duplicate TCP listen remap for guest port {guest_port}"
                    ))));
                }
            }

            (
                (!unix_routes.is_empty()).then_some(unix_routes),
                (!custom_routes.is_empty()).then_some(custom_routes),
                (!custom_dgram_routes.is_empty()).then_some(custom_dgram_routes),
                (!host_map.is_empty()).then_some(host_map),
            )
        };

        #[cfg(target_os = "windows")]
        let vsock_custom_port_map = {
            let mut occupied_ports = HashSet::new();
            let mut custom_routes = HashMap::new();
            for route in self.vsock.routes {
                let VsockRoute::Custom { port, backend } = route;
                if port == 0 || port == u32::MAX {
                    return Err(Error::Config(ConfigError::Vsock(
                        "route port must be between 1 and u32::MAX - 1".to_string(),
                    )));
                }
                if !occupied_ports.insert(port) {
                    return Err(Error::Config(ConfigError::Vsock(format!(
                        "duplicate stream route for host port: {port}"
                    ))));
                }
                custom_routes.insert(port, backend);
            }
            (!custom_routes.is_empty()).then_some(custom_routes)
        };

        #[cfg(not(target_os = "windows"))]
        let enable_inet_hijack = self.machine.enable_inet_hijack || self.vsock.enable_inet_hijack;
        if let Some(affinity) = &self.machine.vcpu_affinity {
            let expected = self.machine.max_vcpus.unwrap_or(self.machine.vcpus) as usize;
            if affinity.len() != expected {
                return Err(Error::Config(ConfigError::InvalidVcpuAffinityLength {
                    expected,
                    actual: affinity.len(),
                }));
            }

            #[cfg(not(any(target_os = "linux", target_os = "windows")))]
            return Err(Error::Config(ConfigError::VcpuAffinityUnsupported));

            #[cfg(target_os = "linux")]
            if let Some(cpu) = affinity.iter().find(|cpu| cpu.group != 0) {
                return Err(Error::Config(ConfigError::InvalidHostCpuGroup(cpu.group)));
            }
        }

        validate_numa_topology(&self.machine)?;

        // Build VmResources
        let mut vmr = VmResources::default();

        // Apply machine configuration
        let vm_config = VmConfig {
            vcpu_count: Some(self.machine.vcpus),
            mem_size_mib: Some(self.machine.memory_mib),
            max_vcpu_count: self.machine.max_vcpus,
            max_mem_size_mib: self.machine.max_memory_mib,
            ht_enabled: Some(self.machine.hyperthreading),
            ..Default::default()
        };
        vmr.set_vm_config(&vm_config)
            .map_err(|err| map_vm_config_error(&self.machine, err))?;

        #[cfg(any(target_os = "linux", target_os = "windows"))]
        {
            vmr.vcpu_affinity = self.machine.vcpu_affinity;
            vmr.vcpu_affinity_required = self.machine.vcpu_affinity_required;
        }
        vmr.numa_topology = self.machine.numa_topology;

        // Reserved CPU capacity is realized through the private msb-cpu device:
        // the guest driver converges on the requested online count and the
        // device's enforcement state parks vCPUs above it host-side.
        #[cfg(not(feature = "tee"))]
        if self
            .machine
            .max_vcpus
            .is_some_and(|max| max > self.machine.vcpus)
        {
            let cpu = devices::virtio::Cpu::new(
                self.machine.max_vcpus.unwrap_or(self.machine.vcpus) as u32,
                self.machine.vcpus as u32,
            )
            .map_err(|e| {
                Error::Build(BuildError::DeviceRegistration(format!(
                    "virtio-msb-cpu: {e:?}"
                )))
            })?;
            vmr.cpu_device = Some(std::sync::Arc::new(std::sync::Mutex::new(cpu)));
        }

        // Reserved memory capacity is realized through a virtio-mem device; the
        // VMM places its hotplug region during boot and `Vm::control_handle`
        // exposes the live resize knob.
        #[cfg(not(feature = "tee"))]
        if self
            .machine
            .max_memory_mib
            .is_some_and(|max| max > self.machine.memory_mib)
        {
            let mem = devices::virtio::Mem::new().map_err(|e| {
                Error::Build(BuildError::DeviceRegistration(format!("virtio-mem: {e:?}")))
            })?;
            vmr.mem_device = Some(std::sync::Arc::new(std::sync::Mutex::new(mem)));
        }
        vmr.nested_enabled = self.machine.nested_virt;
        vmr.split_irqchip = self.machine.split_irqchip;
        vmr.enable_balloon = self.machine.balloon;
        vmr.balloon_stats_interval = self.machine.balloon_stats_interval;
        vmr.enable_rng = self.machine.rng;
        vmr.enable_msb_metrics = self.machine.msb_metrics;

        // Apply filesystem configuration
        #[cfg(not(feature = "tee"))]
        for config in self.fs.configs {
            match config {
                FsConfig::Path {
                    tag,
                    path,
                    shm_size,
                } => {
                    let fs_config = FsDeviceConfig {
                        fs_id: tag,
                        shared_dir: path.to_string_lossy().to_string(),
                        shm_size,
                        allow_root_dir_delete: false,
                    };
                    vmr.fs.push(fs_config);
                }
                #[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
                FsConfig::Custom { tag, backend } => {
                    let backend: Box<dyn devices::virtio::fs::DynFileSystem> = backend;
                    let custom_config = CustomFsDeviceConfig {
                        fs_id: tag,
                        backend: Arc::from(backend),
                        shm_size: None,
                    };
                    vmr.custom_fs.push(custom_config);
                }
            }
        }

        // Apply console configuration
        if let Some(output) = self.console.output {
            vmr.console_output = Some(output);
        }

        #[cfg(feature = "snd")]
        {
            vmr.set_snd_device(self.console.sound);
        }

        #[cfg(feature = "gpu")]
        {
            if let Some(virgl_flags) = self.console.gpu_virgl_flags {
                vmr.set_gpu_virgl_flags(virgl_flags);
            }

            if let Some(shm_size) = self.console.gpu_shm_size {
                vmr.set_gpu_shm_size(shm_size);
            }

            for (width, height) in self.console.gpu_displays {
                vmr.displays
                    .push(devices::virtio::display::DisplayInfo::new(width, height));
            }

            if let Some(backend) = self.console.gpu_display_backend {
                vmr.display_backend = Some(backend);
            }
        }

        #[cfg(feature = "input")]
        vmr.input_backends.extend(self.console.input_devices);

        // Apply console port configuration
        if !self.console.ports.is_empty() {
            vmr.virtio_consoles
                .push(VirtioConsoleConfigMode::Explicit(self.console.ports));
        }

        if self.console.disable_implicit {
            vmr.disable_implicit_console = true;
        }

        // Apply network configuration
        #[cfg(feature = "net")]
        for (i, config) in self.net.configs.into_iter().enumerate() {
            let ConfiguredNet {
                backend: config,
                rate_limiters,
            } = config;
            let (mac, backend) = match config {
                #[cfg(unix)]
                NetConfig::UnixgramFd { mac, fd } => {
                    (mac, VirtioNetBackend::UnixgramFd(fd.into_raw_fd()))
                }
                #[cfg(unix)]
                NetConfig::UnixgramPath {
                    mac,
                    path,
                    send_vfkit_magic,
                } => (mac, VirtioNetBackend::UnixgramPath(path, send_vfkit_magic)),
                #[cfg(unix)]
                NetConfig::UnixstreamFd { mac, fd } => {
                    (mac, VirtioNetBackend::UnixstreamFd(fd.into_raw_fd()))
                }
                #[cfg(unix)]
                NetConfig::UnixstreamPath { mac, path } => {
                    (mac, VirtioNetBackend::UnixstreamPath(path))
                }
                #[cfg(target_os = "linux")]
                NetConfig::Tap { mac, name } => (mac, VirtioNetBackend::Tap(name)),
                #[cfg(windows)]
                NetConfig::NamedPipe { mac, name } => (mac, VirtioNetBackend::NamedPipe(name)),
                NetConfig::Custom { mac, backend } => (mac, VirtioNetBackend::Custom(backend)),
            };

            let mac = mac.unwrap_or_else(|| generate_mac(i));
            let iface_id = format!("eth{i}");

            let net_config = NetworkInterfaceConfig {
                iface_id,
                backend,
                mac,
                features: 0,
                rate_limiters,
            };

            vmr.net
                .insert(net_config)
                .map_err(|e| Error::Config(ConfigError::Network(e.to_string())))?;
        }

        // Apply block device configuration
        #[cfg(feature = "blk")]
        for (i, configured_disk) in self.disk.configs.into_iter().enumerate() {
            let config = configured_disk.config;
            let block_id = config
                .id
                .clone()
                .unwrap_or_else(|| format!("vd{}", vd_suffix(i)));
            let image_type: ImageType = config.format.into();
            let cache_type: CacheType = config.cache.into();
            let sync_mode: devices::virtio::block::SyncMode = config.sync.into();

            let blk_config = BlockDeviceConfig {
                block_id,
                cache_type,
                disk_image_path: config.path.to_string_lossy().to_string(),
                disk_image_format: image_type,
                is_disk_read_only: config.read_only,
                direct_io: config.direct_io,
                sync_mode,
            };

            let writeback_limit = configured_disk.writeback_limit.or_else(|| {
                configured_disk
                    .writeback_limit_bytes
                    .map(devices::virtio::block::WritebackLimit::new)
            });
            vmr.add_block_device_with_writeback_limit_handle(blk_config, writeback_limit)
                .map_err(|e| Error::Config(ConfigError::Block(e.to_string())))?;
        }

        // Format execution configuration
        let exec_path = self.exec.path;

        let args = if self.exec.args.is_empty() {
            None
        } else {
            Some(
                self.exec
                    .args
                    .iter()
                    .map(|s| format!("\"{}\"", s))
                    .collect::<Vec<_>>()
                    .join(" "),
            )
        };

        // The exec env rides the kernel command line as quoted `KEY="value"` words (api/vm.rs
        // get_env → KRUN_ENV), and the vmm cmdline layer rejects control/non-ASCII bytes — a tab
        // in a perfectly legitimate OCI image env value (e.g. gcc's GPG_KEYS) used to reach an
        // `.unwrap()` there and abort the whole VMM. Validate per variable here, where the name
        // is still known, so the caller gets an actionable error instead of a crash. Carrying
        // such values would need an encoded transport (tracked separately).
        for (key, value) in &self.exec.env {
            validate_cmdline_env(key, value).map_err(|reason| {
                Error::Build(BuildError::Start(format!(
                    "guest env var {key:?} cannot be carried on the kernel command line \
                     ({reason}); sanitize or drop this variable"
                )))
            })?;
        }

        let env = if self.exec.env.is_empty() {
            None
        } else {
            Some(
                self.exec
                    .env
                    .iter()
                    .map(|(k, v)| format!(" {}=\"{}\"", k, v))
                    .collect::<String>(),
            )
        };

        let rlimits = if self.exec.rlimits.is_empty() {
            None
        } else {
            Some(
                self.exec
                    .rlimits
                    .iter()
                    .map(|(r, s, h)| format!("{}:{}:{}", r, s, h))
                    .collect::<Vec<_>>()
                    .join(","),
            )
        };

        let exit_evt = EventFd::new(EFD_NONBLOCK)
            .map_err(|e| Error::Build(BuildError::Start(format!("exit EventFd: {e:?}"))))?;
        let exit_code = Arc::new(AtomicI32::new(i32::MAX));

        Ok(Vm::new(
            vmr,
            self.kernel.cmdline,
            exec_path,
            args,
            env,
            self.exec.workdir,
            rlimits,
            self.kernel.krunfw_path,
            self.kernel.initramfs_path,
            self.kernel.init_path,
            self.exit_observers,
            self.placement_observer,
            exit_evt,
            exit_code,
            #[cfg(not(target_os = "windows"))]
            enable_inet_hijack,
            #[cfg(not(target_os = "windows"))]
            vsock_unix_ipc_port_map,
            vsock_custom_port_map,
            #[cfg(not(target_os = "windows"))]
            vsock_custom_dgram_port_map,
            #[cfg(not(target_os = "windows"))]
            vsock_host_port_map,
        ))
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for VmBuilder {
    fn default() -> Self {
        Self::new()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Generate a locally-administered MAC address from an interface index.
#[cfg(feature = "net")]
fn generate_mac(index: usize) -> [u8; 6] {
    [
        0x52,
        0x54,
        0x00,
        0x12,
        0x34,
        0x56u8.wrapping_add(index as u8),
    ]
}

/// Generate a virtio-blk device suffix matching the Linux kernel's
/// `disk_name()` bijective base-26 scheme from `block/genhd.c`:
/// `0→"a"`, `25→"z"`, `26→"aa"`, `27→"ab"`, `701→"zz"`, `702→"aaa"`.
///
/// The naïve `(b'a' + i) as char` formula rolls over past `z` into
/// invalid characters (`vd{`, `vd|`, ...), so this helper is required
/// once we support more than 26 disks.
#[cfg(feature = "blk")]
fn vd_suffix(mut index: usize) -> String {
    let mut buf = Vec::with_capacity(4);
    loop {
        buf.push(b'a' + (index % 26) as u8);
        if index < 26 {
            break;
        }
        index = index / 26 - 1;
    }
    buf.reverse();
    String::from_utf8(buf).expect("ASCII a-z only")
}

fn map_vm_config_error(machine: &MachineBuilder, err: VmConfigError) -> Error {
    match err {
        VmConfigError::InvalidVcpuCount => {
            Error::Config(ConfigError::InvalidVcpuCount(machine.vcpus))
        }
        VmConfigError::InvalidMemorySize => {
            Error::Config(ConfigError::InvalidMemorySize(machine.memory_mib))
        }
        VmConfigError::InvalidMaxVcpuCount => Error::Config(ConfigError::InvalidMaxVcpuCount(
            machine.max_vcpus.unwrap_or(machine.vcpus),
        )),
        VmConfigError::InvalidMaxMemorySize => Error::Config(ConfigError::InvalidMaxMemorySize(
            machine.max_memory_mib.unwrap_or(machine.memory_mib),
        )),
        VmConfigError::MaxCapacityUnsupported => Error::Config(ConfigError::MaxCapacityUnsupported),
    }
}

fn validate_numa_topology(machine: &MachineBuilder) -> Result<()> {
    if machine.numa_topology.is_none() {
        return Ok(());
    }

    // Confidential-computing memory is constructed by a separate backend. Until that backend can
    // realize the same host-memory contract, reject placement instead of accepting and ignoring it.
    #[cfg(feature = "tee")]
    return Err(Error::Config(ConfigError::NumaUnsupported(
        "host memory placement is unavailable with TEE memory".into(),
    )));

    #[cfg(not(feature = "tee"))]
    validate_numa_topology_inner(
        machine,
        machine
            .numa_topology
            .as_ref()
            .expect("the topology was checked above"),
    )
}

#[cfg(not(feature = "tee"))]
fn validate_numa_topology_inner(
    machine: &MachineBuilder,
    topology: &super::builders::NumaTopology,
) -> Result<()> {
    if topology.nodes.is_empty() {
        return Err(Error::Config(ConfigError::InvalidNumaTopology(
            "at least one guest node is required".into(),
        )));
    }

    // The first implementation deliberately enables truthful one-node locality before guest
    // SRAT/FDT support. A multi-node request must fail rather than silently creating a UMA guest.
    if topology.nodes.len() != 1 {
        return Err(Error::Config(ConfigError::NumaUnsupported(
            "multi-node guest firmware is not enabled in this build".into(),
        )));
    }

    let max_vcpus = machine.max_vcpus.unwrap_or(machine.vcpus);
    let max_memory_mib = machine.max_memory_mib.unwrap_or(machine.memory_mib);
    let mut vcpus = BTreeSet::new();
    let mut boot_memory_mib = 0usize;
    let mut maximum_memory_mib = 0usize;

    for (expected_id, node) in topology.nodes.iter().enumerate() {
        if usize::from(node.guest_node_id) != expected_id {
            return Err(Error::Config(ConfigError::InvalidNumaTopology(
                "guest node IDs must be dense and start at zero".into(),
            )));
        }
        if node.max_memory_mib < node.memory_mib {
            return Err(Error::Config(ConfigError::InvalidNumaTopology(format!(
                "node {} maximum memory is below boot memory",
                node.guest_node_id
            ))));
        }
        if node.memory_mib % 2 != 0 || node.max_memory_mib % 2 != 0 {
            return Err(Error::Config(ConfigError::InvalidNumaTopology(format!(
                "node {} memory must be aligned to 2 MiB",
                node.guest_node_id
            ))));
        }
        boot_memory_mib = boot_memory_mib
            .checked_add(node.memory_mib)
            .ok_or_else(|| {
                Error::Config(ConfigError::InvalidNumaTopology(
                    "boot memory total overflows".into(),
                ))
            })?;
        maximum_memory_mib = maximum_memory_mib
            .checked_add(node.max_memory_mib)
            .ok_or_else(|| {
                Error::Config(ConfigError::InvalidNumaTopology(
                    "maximum memory total overflows".into(),
                ))
            })?;

        for &vcpu in &node.vcpu_indices {
            if vcpu >= max_vcpus || !vcpus.insert(vcpu) {
                return Err(Error::Config(ConfigError::InvalidNumaTopology(format!(
                    "vCPU index {vcpu} is duplicated or outside 0..{max_vcpus}"
                ))));
            }
        }

        match &node.host_memory {
            HostMemoryPolicy::Inherit => {}
            HostMemoryPolicy::Bind { host_nodes }
            | HostMemoryPolicy::PreferredMany { host_nodes } => {
                if host_nodes.is_empty() {
                    return Err(Error::Config(ConfigError::InvalidNumaTopology(
                        "a bind policy requires at least one host node".into(),
                    )));
                }
                if host_nodes
                    .iter()
                    .any(|&host_node| host_node > MAX_HOST_NUMA_NODE_ID)
                {
                    return Err(Error::Config(ConfigError::InvalidNumaTopology(format!(
                        "host NUMA node IDs must not exceed {MAX_HOST_NUMA_NODE_ID}"
                    ))));
                }
                #[cfg(not(all(
                    target_os = "linux",
                    any(target_arch = "x86_64", target_arch = "aarch64")
                )))]
                return Err(Error::Config(ConfigError::NumaUnsupported(
                    "bound host memory requires Linux on x86_64 or AArch64".into(),
                )));
            }
            HostMemoryPolicy::Preferred { host_node } => {
                if *host_node > MAX_HOST_NUMA_NODE_ID {
                    return Err(Error::Config(ConfigError::InvalidNumaTopology(format!(
                        "host NUMA node IDs must not exceed {MAX_HOST_NUMA_NODE_ID}"
                    ))));
                }
                #[cfg(not(all(
                    target_os = "windows",
                    any(target_arch = "x86_64", target_arch = "aarch64")
                )))]
                return Err(Error::Config(ConfigError::NumaUnsupported(
                    "preferred host memory requires Windows on x86_64 or AArch64".into(),
                )));
            }
        }
    }

    if vcpus.len() != usize::from(max_vcpus) || vcpus.iter().copied().ne(0..max_vcpus) {
        return Err(Error::Config(ConfigError::InvalidNumaTopology(format!(
            "vCPU membership must cover every index in 0..{max_vcpus} exactly once"
        ))));
    }
    if boot_memory_mib != machine.memory_mib {
        return Err(Error::Config(ConfigError::InvalidNumaTopology(format!(
            "boot memory totals {boot_memory_mib} MiB, expected {} MiB",
            machine.memory_mib
        ))));
    }
    if maximum_memory_mib != max_memory_mib {
        return Err(Error::Config(ConfigError::InvalidNumaTopology(format!(
            "maximum memory totals {maximum_memory_mib} MiB, expected {max_memory_mib} MiB"
        ))));
    }

    let node_count = topology.nodes.len();
    let expected_distances = node_count.checked_mul(node_count).ok_or_else(|| {
        Error::Config(ConfigError::InvalidNumaTopology(
            "guest node count overflows the distance matrix".into(),
        ))
    })?;
    if topology.distances.len() != expected_distances {
        return Err(Error::Config(ConfigError::InvalidNumaTopology(
            "distance entries must cover the full square matrix".into(),
        )));
    }
    let mut distances = BTreeSet::new();
    for distance in &topology.distances {
        if usize::from(distance.from) >= node_count
            || usize::from(distance.to) >= node_count
            || !distances.insert((distance.from, distance.to))
        {
            return Err(Error::Config(ConfigError::InvalidNumaTopology(
                "distance coordinates are duplicated or outside the guest node range".into(),
            )));
        }
        if distance.from == distance.to && distance.value != 10 {
            return Err(Error::Config(ConfigError::InvalidNumaTopology(
                "local NUMA distance must equal 10".into(),
            )));
        }
    }
    Ok(())
}

/// Check that one exec env pair can be carried as a quoted `KEY="value"` kernel-cmdline word: printable ASCII only (the vmm cmdline layer rejects everything else, and the kernel
/// would misparse it anyway), no double quotes (they would terminate the kernel's quote parsing mid-value), and no whitespace in the key (the kernel splits words on unquoted
/// whitespace, so a spaced key silently becomes two parameters).
fn validate_cmdline_env(key: &str, value: &str) -> std::result::Result<(), &'static str> {
    let printable = |s: &str| s.bytes().all(|b| (0x20..=0x7e).contains(&b));
    if !printable(key) || !printable(value) {
        return Err("it contains control or non-ASCII bytes");
    }
    if key.contains('"') || value.contains('"') {
        return Err("it contains a double quote");
    }
    if key.contains(' ') {
        return Err("the key contains whitespace");
    }
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #[cfg(not(target_os = "windows"))]
    use std::io;

    #[cfg(not(target_os = "windows"))]
    use devices::virtio::vsock::{
        VsockDatagramBackend, VsockDatagramPeer, VsockDatagramPortBackend, VsockNotifier,
    };

    use super::*;
    use crate::api::builders::{
        ConsolePortOptions, HostCpuId, HostMemoryPolicy, NumaDistance, NumaNodeConfig, NumaTopology,
    };
    #[cfg(not(target_os = "windows"))]
    use crate::backends::console::ConsolePortBackend;

    #[cfg(not(target_os = "windows"))]
    struct EmptyConsoleBackend;

    #[cfg(not(target_os = "windows"))]
    impl ConsolePortBackend for EmptyConsoleBackend {
        fn read(&self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::ErrorKind::WouldBlock.into())
        }

        fn write(&self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::WouldBlock.into())
        }

        fn read_wake_fd(&self) -> std::os::fd::RawFd {
            -1
        }
    }

    fn one_node_topology(vcpus: Vec<u8>, memory_mib: usize) -> NumaTopology {
        NumaTopology {
            nodes: vec![NumaNodeConfig {
                guest_node_id: 0,
                vcpu_indices: vcpus,
                memory_mib,
                max_memory_mib: memory_mib,
                host_memory: HostMemoryPolicy::Inherit,
            }],
            distances: vec![NumaDistance {
                from: 0,
                to: 0,
                value: 10,
            }],
        }
    }

    #[cfg(feature = "tee")]
    #[test]
    fn build_rejects_numa_topology_with_tee_memory() {
        let err = VmBuilder::new()
            .machine(|machine| {
                machine
                    .memory_mib(512)
                    .numa_topology(one_node_topology(vec![0], 512))
            })
            .build()
            .err()
            .expect("TEE memory must not silently ignore host placement");

        assert!(matches!(
            err,
            Error::Config(ConfigError::NumaUnsupported(_))
        ));
    }

    #[cfg(not(target_os = "windows"))]
    struct RejectDatagrams;

    #[cfg(not(target_os = "windows"))]
    impl VsockDatagramPortBackend for RejectDatagrams {
        fn open_peer(
            &self,
            _peer: VsockDatagramPeer,
            _notifier: VsockNotifier,
        ) -> io::Result<Box<dyn VsockDatagramBackend>> {
            Err(io::Error::from(io::ErrorKind::ConnectionRefused))
        }
    }

    #[test]
    fn build_rejects_invalid_machine_config() {
        let err = match VmBuilder::new()
            .machine(|machine| machine.vcpus(3).hyperthreading(true))
            .build()
        {
            Ok(_) => panic!("odd vCPU count with hyperthreading should fail"),
            Err(err) => err,
        };

        match err {
            Error::Config(ConfigError::InvalidVcpuCount(3)) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn build_rejects_invalid_console_port_queue_sizes() {
        for queue_size in [15, 24, 2048] {
            let err = VmBuilder::new()
                .console(|console| {
                    console.custom_with_options(
                        "agent",
                        Box::new(EmptyConsoleBackend),
                        ConsolePortOptions::new().queue_size(queue_size),
                    )
                })
                .build()
                .err()
                .expect("invalid console queue size must fail VM construction");

            assert!(
                matches!(err, Error::Config(ConfigError::Console(message)) if message.contains(&queue_size.to_string()))
            );
        }
    }

    #[test]
    fn build_rejects_max_vcpus_below_effective_count() {
        let err = match VmBuilder::new()
            .machine(|machine| machine.vcpus(4).max_vcpus(2))
            .build()
        {
            Ok(_) => panic!("max vCPUs below the effective count should fail"),
            Err(err) => err,
        };

        match err {
            Error::Config(ConfigError::InvalidMaxVcpuCount(2)) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn build_rejects_max_memory_below_effective_size() {
        let err = match VmBuilder::new()
            .machine(|machine| machine.memory_mib(2048).max_memory_mib(1024))
            .build()
        {
            Ok(_) => panic!("max memory below the effective size should fail"),
            Err(err) => err,
        };

        match err {
            Error::Config(ConfigError::InvalidMaxMemorySize(1024)) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn build_rejects_duplicate_vsock_routes() {
        let err = match VmBuilder::new()
            .vsock(|vsock| {
                vsock
                    .unix_connect(5000, "/tmp/a.sock")
                    .unix_listen(5000, "/tmp/b.sock")
            })
            .build()
        {
            Ok(_) => panic!("duplicate routes must fail"),
            Err(err) => err,
        };

        assert!(
            matches!(err, Error::Config(ConfigError::Vsock(message)) if message.contains("duplicate route"))
        );
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn build_allows_stream_and_datagram_on_same_port() {
        VmBuilder::new()
            .vsock(|vsock| {
                vsock
                    .unix_connect(5000, "/tmp/stream.sock")
                    .custom_dgram(5000, Arc::new(RejectDatagrams))
            })
            .build()
            .expect("socket type disambiguates equal port numbers");
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn build_rejects_reserved_timesync_datagram_port() {
        let err = match VmBuilder::new()
            .vsock(|vsock| vsock.custom_dgram(123, Arc::new(RejectDatagrams)))
            .build()
        {
            Ok(_) => panic!("time synchronization owns datagram port 123"),
            Err(err) => err,
        };

        assert!(
            matches!(err, Error::Config(ConfigError::Vsock(message)) if message.contains("reserved"))
        );
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn build_rejects_datagram_routes_over_active_tsi_control_ports() {
        let err = match VmBuilder::new()
            .vsock(|vsock| {
                vsock
                    .inet_hijack(true)
                    .custom_dgram(1024, Arc::new(RejectDatagrams))
            })
            .build()
        {
            Ok(_) => panic!("active TSI owns its datagram control ports"),
            Err(err) => err,
        };

        assert!(
            matches!(err, Error::Config(ConfigError::Vsock(message)) if message.contains("active TSI"))
        );
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn build_rejects_tcp_remap_without_inet_hijack() {
        let err = match VmBuilder::new()
            .vsock(|vsock| vsock.tcp_listen_remap(8080, 18080))
            .build()
        {
            Ok(_) => panic!("inactive TSI remap must fail"),
            Err(err) => err,
        };

        assert!(
            matches!(err, Error::Config(ConfigError::Vsock(message)) if message.contains("require TSI INET"))
        );
    }

    #[test]
    fn validate_cmdline_env_rejects_uncarryable_values() {
        // Ordinary env, including spaces in the value (quoted on the cmdline), is fine.
        assert!(validate_cmdline_env("PATH", "/usr/local/bin:/usr/bin").is_ok());
        assert!(validate_cmdline_env("GREETING", "hello world").is_ok());

        // Regression: gcc:13-bookworm's GPG_KEYS/GCC_MIRRORS carry tab separators, which
        // previously reached the vmm cmdline unwrap and aborted the process (InvalidAscii).
        assert!(validate_cmdline_env("GPG_KEYS", "B215C163\t B3C42148").is_err());

        assert!(validate_cmdline_env("MOTD", "héllo").is_err());
        assert!(validate_cmdline_env("Q", "say \"hi\"").is_err());
        assert!(validate_cmdline_env("BAD KEY", "v").is_err());
        assert!(validate_cmdline_env("NL", "a\nb").is_err());
    }

    #[test]
    fn build_rejects_affinity_that_does_not_cover_max_vcpus() {
        let err = match VmBuilder::new()
            .machine(|machine| {
                machine
                    .vcpus(2)
                    .max_vcpus(4)
                    .vcpu_affinity(vec![HostCpuId::new(0), HostCpuId::new(1)])
            })
            .build()
        {
            Ok(_) => panic!("partial vCPU affinity map should fail"),
            Err(err) => err,
        };

        match err {
            Error::Config(ConfigError::InvalidVcpuAffinityLength {
                expected: 4,
                actual: 2,
            }) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[cfg(not(feature = "tee"))]
    #[test]
    fn build_accepts_consistent_one_node_topology() {
        VmBuilder::new()
            .machine(|machine| {
                machine
                    .vcpus(2)
                    .memory_mib(512)
                    .numa_topology(one_node_topology(vec![0, 1], 512))
            })
            .build()
            .expect("consistent one-node topology should build");
    }

    #[cfg(not(feature = "tee"))]
    #[test]
    fn build_accepts_fluent_one_node_topology() {
        VmBuilder::new()
            .machine(|machine| {
                machine
                    .vcpus(2)
                    .memory_mib(512)
                    .numa(|numa| numa.node(|node| node.vcpus([0, 1]).memory_mib(512)))
            })
            .build()
            .expect("the fluent builder should produce a valid resolved topology");
    }

    #[cfg(not(feature = "tee"))]
    #[test]
    fn build_rejects_incomplete_numa_vcpu_membership() {
        let err = VmBuilder::new()
            .machine(|machine| {
                machine
                    .vcpus(2)
                    .memory_mib(512)
                    .numa_topology(one_node_topology(vec![0], 512))
            })
            .build()
            .err()
            .expect("partial vCPU topology should fail");

        assert!(matches!(
            err,
            Error::Config(ConfigError::InvalidNumaTopology(_))
        ));
    }

    #[cfg(not(feature = "tee"))]
    #[test]
    fn build_rejects_numa_memory_total_mismatch() {
        let err = VmBuilder::new()
            .machine(|machine| {
                machine
                    .vcpus(1)
                    .memory_mib(1024)
                    .numa_topology(one_node_topology(vec![0], 512))
            })
            .build()
            .err()
            .expect("mismatched memory topology should fail");

        assert!(matches!(
            err,
            Error::Config(ConfigError::InvalidNumaTopology(_))
        ));
    }

    #[cfg(not(feature = "tee"))]
    #[test]
    fn build_accepts_one_node_live_memory_capacity() {
        let mut topology = one_node_topology(vec![0, 1], 512);
        topology.nodes[0].max_memory_mib = 1024;

        VmBuilder::new()
            .machine(|machine| {
                machine
                    .vcpus(2)
                    .memory_mib(512)
                    .max_memory_mib(1024)
                    .numa_topology(topology)
            })
            .build()
            .expect("one-node growth should retain the creation-time placement");
    }

    #[cfg(not(feature = "tee"))]
    #[test]
    fn build_rejects_excessive_host_numa_node_id() {
        let mut topology = one_node_topology(vec![0], 512);
        topology.nodes[0].host_memory = HostMemoryPolicy::Bind {
            host_nodes: vec![u32::from(u16::MAX) + 1],
        };
        let err = VmBuilder::new()
            .machine(|machine| machine.memory_mib(512).numa_topology(topology))
            .build()
            .err()
            .expect("an excessive host node ID should fail before allocating a node mask");

        assert!(matches!(
            err,
            Error::Config(ConfigError::InvalidNumaTopology(_))
        ));
    }

    #[cfg(all(target_os = "linux", target_arch = "riscv64", not(feature = "tee")))]
    #[test]
    fn build_rejects_bound_numa_memory_on_riscv64() {
        let mut topology = one_node_topology(vec![0], 512);
        topology.nodes[0].host_memory = HostMemoryPolicy::Bind {
            host_nodes: vec![0],
        };

        let error = VmBuilder::new()
            .machine(|machine| machine.memory_mib(512).numa_topology(topology))
            .build()
            .err()
            .expect("RISC-V must retain inherited memory placement");

        assert!(matches!(
            error,
            Error::Config(ConfigError::NumaUnsupported(_))
        ));
    }

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(feature = "tee")
    ))]
    #[test]
    fn build_accepts_linux_soft_numa_preference() {
        let mut topology = one_node_topology(vec![0], 512);
        topology.nodes[0].host_memory = HostMemoryPolicy::PreferredMany {
            host_nodes: vec![0],
        };

        VmBuilder::new()
            .machine(|machine| machine.memory_mib(512).numa_topology(topology))
            .build()
            .expect("Linux should accept a spillable host-node preference");
    }

    #[cfg(all(not(feature = "tee"), not(target_os = "windows")))]
    #[test]
    fn build_rejects_windows_preferred_memory_policy() {
        let mut topology = one_node_topology(vec![0], 512);
        topology.nodes[0].host_memory = HostMemoryPolicy::Preferred { host_node: 0 };
        let err = VmBuilder::new()
            .machine(|machine| machine.memory_mib(512).numa_topology(topology))
            .build()
            .err()
            .expect("preferred-node backing is Windows-only");

        assert!(matches!(
            err,
            Error::Config(ConfigError::NumaUnsupported(_))
        ));
    }

    #[cfg(all(not(feature = "tee"), target_os = "windows"))]
    #[test]
    fn build_accepts_windows_preferred_memory_policy() {
        let mut topology = one_node_topology(vec![0], 512);
        topology.nodes[0].host_memory = HostMemoryPolicy::Preferred { host_node: 0 };

        VmBuilder::new()
            .machine(|machine| machine.memory_mib(512).numa_topology(topology))
            .build()
            .expect("Windows should accept preferred-node backing");
    }

    #[cfg(not(feature = "tee"))]
    #[test]
    fn build_rejects_multi_node_topology_until_guest_tables_land() {
        let topology = NumaTopology {
            nodes: vec![
                NumaNodeConfig {
                    guest_node_id: 0,
                    vcpu_indices: vec![0],
                    memory_mib: 256,
                    max_memory_mib: 256,
                    host_memory: HostMemoryPolicy::Inherit,
                },
                NumaNodeConfig {
                    guest_node_id: 1,
                    vcpu_indices: vec![1],
                    memory_mib: 256,
                    max_memory_mib: 256,
                    host_memory: HostMemoryPolicy::Inherit,
                },
            ],
            distances: vec![
                NumaDistance {
                    from: 0,
                    to: 0,
                    value: 10,
                },
                NumaDistance {
                    from: 0,
                    to: 1,
                    value: 20,
                },
                NumaDistance {
                    from: 1,
                    to: 0,
                    value: 20,
                },
                NumaDistance {
                    from: 1,
                    to: 1,
                    value: 10,
                },
            ],
        };
        let err = VmBuilder::new()
            .machine(|machine| machine.vcpus(2).memory_mib(512).numa_topology(topology))
            .build()
            .err()
            .expect("multi-node topology should fail closed");

        assert!(matches!(
            err,
            Error::Config(ConfigError::NumaUnsupported(_))
        ));
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    #[test]
    fn build_rejects_vcpu_affinity_on_unsupported_hosts() {
        let err = match VmBuilder::new()
            .machine(|machine| machine.vcpu_affinity(vec![HostCpuId::new(0)]))
            .build()
        {
            Ok(_) => panic!("vCPU affinity should fail on unsupported hosts"),
            Err(err) => err,
        };

        match err {
            Error::Config(ConfigError::VcpuAffinityUnsupported) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn build_rejects_nonzero_processor_group_on_linux() {
        let err = match VmBuilder::new()
            .machine(|machine| machine.vcpu_affinity(vec![HostCpuId::in_group(1, 0)]))
            .build()
        {
            Ok(_) => panic!("nonzero processor group should fail on Linux"),
            Err(err) => err,
        };

        match err {
            Error::Config(ConfigError::InvalidHostCpuGroup(1)) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[cfg(feature = "blk")]
    #[test]
    fn vd_suffix_matches_kernel_scheme() {
        assert_eq!(vd_suffix(0), "a");
        assert_eq!(vd_suffix(25), "z");
        assert_eq!(vd_suffix(26), "aa");
        assert_eq!(vd_suffix(27), "ab");
        assert_eq!(vd_suffix(51), "az");
        assert_eq!(vd_suffix(52), "ba");
        assert_eq!(vd_suffix(701), "zz");
        assert_eq!(vd_suffix(702), "aaa");
    }

    #[cfg(feature = "blk")]
    #[test]
    fn disk_builder_preserves_insertion_order() {
        use crate::api::builders::DiskImageFormat;

        let builder = VmBuilder::new()
            .disk(|d| d.path("/a.raw"))
            .disk(|d| d.path("/b.qcow2").format(DiskImageFormat::Qcow2))
            .disk(|d| {
                d.path("/c.vmdk")
                    .format(DiskImageFormat::Vmdk)
                    .read_only(true)
            });

        let paths: Vec<_> = builder
            .disk
            .configs
            .iter()
            .map(|c| c.config.path.to_string_lossy().into_owned())
            .collect();
        assert_eq!(paths, vec!["/a.raw", "/b.qcow2", "/c.vmdk"]);
        assert_eq!(
            builder.disk.configs[1].config.format,
            DiskImageFormat::Qcow2
        );
        assert!(builder.disk.configs[2].config.read_only);
    }

    #[cfg(feature = "blk")]
    #[test]
    fn disk_builder_auto_id_then_custom() {
        let builder = VmBuilder::new()
            .disk(|d| d.path("/a.raw"))
            .disk(|d| d.path("/b.raw").id("data"))
            .disk(|d| d.path("/c.raw"));

        assert!(builder.disk.configs[0].config.id.is_none());
        assert_eq!(builder.disk.configs[1].config.id.as_deref(), Some("data"));
        assert!(builder.disk.configs[2].config.id.is_none());
    }

    #[cfg(feature = "blk")]
    #[test]
    fn disk_builder_per_disk_settings_dont_leak() {
        use crate::api::builders::{CacheMode, SyncMode};

        let builder = VmBuilder::new()
            .disk(|d| {
                d.path("/a.raw")
                    .read_only(true)
                    .cache(CacheMode::Unsafe)
                    .direct_io(true)
                    .sync(SyncMode::None)
                    .writeback_limit_bytes(128 * 1024 * 1024)
            })
            .disk(|d| d.path("/b.raw"));

        assert!(builder.disk.configs[0].config.read_only);
        assert_eq!(builder.disk.configs[0].config.cache, CacheMode::Unsafe);
        assert!(builder.disk.configs[0].config.direct_io);
        assert_eq!(builder.disk.configs[0].config.sync, SyncMode::None);
        assert_eq!(
            builder.disk.configs[0].writeback_limit_bytes,
            Some(128 * 1024 * 1024)
        );

        assert!(!builder.disk.configs[1].config.read_only);
        assert_eq!(builder.disk.configs[1].config.cache, CacheMode::Writeback);
        assert!(!builder.disk.configs[1].config.direct_io);
        assert_eq!(builder.disk.configs[1].config.sync, SyncMode::Full);
        assert_eq!(builder.disk.configs[1].writeback_limit_bytes, None);
    }

    #[cfg(feature = "blk")]
    #[test]
    fn disk_builder_keeps_live_writeback_handle_shared_and_per_disk() {
        use crate::api::builders::WritebackLimit;

        let limit = WritebackLimit::new(256 * 1024 * 1024);
        let builder = VmBuilder::new()
            .disk(|d| d.path("/a.raw").writeback_limit(limit.clone()))
            .disk(|d| d.path("/b.raw"));

        let configured = builder.disk.configs[0]
            .writeback_limit
            .as_ref()
            .expect("first disk must retain its live limit");
        assert_eq!(configured.maximum_bytes(), 256 * 1024 * 1024);
        assert_eq!(configured.target_bytes(), 256 * 1024 * 1024);
        assert_eq!(builder.disk.configs[0].writeback_limit_bytes, None);
        assert!(builder.disk.configs[1].writeback_limit.is_none());

        limit.set_target_bytes(128 * 1024 * 1024).unwrap();
        assert_eq!(configured.target_bytes(), 128 * 1024 * 1024);
    }
}
