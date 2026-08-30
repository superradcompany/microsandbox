//! Sub-builders for VmBuilder nested configuration.

use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(not(target_os = "windows"))]
use devices::virtio::console::port_io::{
    ConsolePortBackend, ConsolePortBackendInputAdapter, ConsolePortBackendOutputAdapter,
};
use devices::virtio::console::DEFAULT_QUEUE_SIZE;
use vmm::resources::PortConfig;
pub use vmm::resources::{
    HostMemoryPolicy, MemoryPlacementResult, NumaDistance, NumaNodeConfig, NumaTopology,
    PlacementReport, VcpuPlacementResult,
};
pub use vmm::vmm_config::machine_config::HostCpuId;

pub(crate) type PlacementObserver = Box<dyn FnOnce(&PlacementReport) + Send + 'static>;

#[cfg(feature = "blk")]
pub use devices::virtio::block::WritebackLimit;

#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
use crate::backends::fs::DynFileSystem;

#[cfg(all(feature = "net", unix))]
use std::os::fd::OwnedFd;
#[cfg(not(target_os = "windows"))]
use std::os::fd::RawFd;
use std::sync::Arc;

#[cfg(feature = "net")]
use crate::backends::net::NetBackend;
#[cfg(not(target_os = "windows"))]
use crate::backends::vsock::VsockDatagramPortBackend;
use crate::backends::vsock::VsockPortBackend;
#[cfg(feature = "net")]
use devices::virtio::net::rate_limit::{RateLimiterConfig, RateLimiters};

//--------------------------------------------------------------------------------------------------
// Types: Machine Builder
//--------------------------------------------------------------------------------------------------

/// Builder for machine configuration (vCPUs, memory, etc.).
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
#[derive(Debug, Clone)]
pub struct MachineBuilder {
    pub(crate) vcpus: u8,
    pub(crate) memory_mib: usize,
    pub(crate) max_vcpus: Option<u8>,
    pub(crate) max_memory_mib: Option<usize>,
    pub(crate) hyperthreading: bool,
    pub(crate) nested_virt: bool,
    pub(crate) split_irqchip: bool,
    pub(crate) balloon: bool,
    pub(crate) balloon_stats_interval: Option<Duration>,
    pub(crate) rng: bool,
    pub(crate) msb_metrics: bool,
    pub(crate) enable_inet_hijack: bool,
    pub(crate) vcpu_affinity: Option<Vec<HostCpuId>>,
    pub(crate) vcpu_affinity_required: bool,
    pub(crate) numa_topology: Option<NumaTopology>,
}

/// Builder for a resolved guest NUMA topology.
///
/// Guest node IDs are assigned by insertion order. Local distance entries are generated with the
/// standard value `10`, so callers only need to provide non-local distances for multi-node guests.
#[derive(Debug, Clone, Default)]
pub struct NumaBuilder {
    nodes: Vec<NumaNodeConfig>,
    distances: Vec<NumaDistance>,
}

/// Builder for one guest NUMA node.
#[derive(Debug, Clone)]
pub struct NumaNodeBuilder {
    vcpu_indices: Vec<u8>,
    memory_mib: usize,
    max_memory_mib: Option<usize>,
    host_memory: HostMemoryPolicy,
}

//--------------------------------------------------------------------------------------------------
// Types: Vsock Builder
//--------------------------------------------------------------------------------------------------

/// Builder for host services exposed through virtio-vsock.
///
/// # Example
///
/// ```rust,ignore
/// use std::sync::Arc;
/// use msb_krun::VmBuilder;
///
/// VmBuilder::new().vsock(|vsock| {
///     vsock
///         .unix_connect(5000, "/run/supervisor.sock")
///         .unix_listen(5001, "/run/events.sock")
///         .custom(6000, Arc::new(my_service))
/// });
/// ```
#[derive(Default)]
pub struct VsockBuilder {
    pub(crate) routes: Vec<VsockRoute>,
    #[cfg(not(target_os = "windows"))]
    pub(crate) tcp_listen_remaps: Vec<(u16, u16)>,
    #[cfg(not(target_os = "windows"))]
    pub(crate) enable_inet_hijack: bool,
}

/// One typed host-side route for a guest vsock destination port.
pub(crate) enum VsockRoute {
    #[cfg(not(target_os = "windows"))]
    UnixConnect { port: u32, path: PathBuf },
    #[cfg(not(target_os = "windows"))]
    UnixListen { port: u32, path: PathBuf },
    Custom {
        port: u32,
        backend: Arc<dyn VsockPortBackend>,
    },
    #[cfg(not(target_os = "windows"))]
    CustomDatagram {
        port: u32,
        backend: Arc<dyn VsockDatagramPortBackend>,
    },
}

//--------------------------------------------------------------------------------------------------
// Types: Kernel Builder
//--------------------------------------------------------------------------------------------------

/// Builder for kernel configuration.
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
#[derive(Debug, Clone, Default)]
pub struct KernelBuilder {
    pub(crate) cmdline: Option<String>,
    pub(crate) krunfw_path: Option<PathBuf>,
    pub(crate) initramfs_path: Option<PathBuf>,
    pub(crate) init_path: Option<String>,
}

//--------------------------------------------------------------------------------------------------
// Types: Filesystem Builder
//--------------------------------------------------------------------------------------------------

/// Builder for filesystem configuration.
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
pub struct FsBuilder {
    pub(crate) configs: Vec<FsConfig>,
    current_tag: Option<String>,
    current_shm_size: Option<usize>,
}

/// Configuration for a single filesystem mount.
pub enum FsConfig {
    /// Path-based filesystem (passthrough).
    Path {
        tag: String,
        path: PathBuf,
        shm_size: Option<usize>,
    },
    /// Custom filesystem backend.
    #[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
    Custom {
        tag: String,
        backend: Box<dyn DynFileSystem + Send + Sync>,
    },
}

//--------------------------------------------------------------------------------------------------
// Types: Network Builder
//--------------------------------------------------------------------------------------------------

/// Builder for network configuration.
///
/// # Example
///
/// ```rust,ignore
/// VmBuilder::new()
///     .net(|n| n.mac([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]).custom(my_backend));
/// ```
#[cfg(feature = "net")]
pub struct NetBuilder {
    pub(crate) configs: Vec<ConfiguredNet>,
    current_mac: Option<[u8; 6]>,
    current_rate_limiters: RateLimiters,
}

/// Configuration for a single network device.
#[cfg(feature = "net")]
pub(crate) struct ConfiguredNet {
    pub(crate) backend: NetConfig,
    pub(crate) rate_limiters: RateLimiters,
}

/// Backend configuration for a single network device.
#[cfg(feature = "net")]
pub enum NetConfig {
    /// Unixgram backend from a pre-opened fd.
    #[cfg(unix)]
    UnixgramFd { mac: Option<[u8; 6]>, fd: OwnedFd },
    /// Unixgram backend connecting to a socket path.
    #[cfg(unix)]
    UnixgramPath {
        mac: Option<[u8; 6]>,
        path: PathBuf,
        send_vfkit_magic: bool,
    },
    /// Unixstream backend from a pre-opened fd.
    #[cfg(unix)]
    UnixstreamFd { mac: Option<[u8; 6]>, fd: OwnedFd },
    /// Unixstream backend connecting to a socket path.
    #[cfg(unix)]
    UnixstreamPath { mac: Option<[u8; 6]>, path: PathBuf },
    /// TAP backend (Linux only).
    #[cfg(target_os = "linux")]
    Tap { mac: Option<[u8; 6]>, name: String },
    /// Windows named-pipe backend connecting to a helper-created message-mode pipe.
    #[cfg(windows)]
    NamedPipe { mac: Option<[u8; 6]>, name: String },
    /// Custom network backend.
    Custom {
        mac: Option<[u8; 6]>,
        backend: Box<dyn NetBackend + Send>,
    },
}

//--------------------------------------------------------------------------------------------------
// Types: Console Builder
//--------------------------------------------------------------------------------------------------

/// Builder for console/output configuration.
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
#[derive(Default)]
pub struct ConsoleBuilder {
    pub(crate) output: Option<PathBuf>,
    pub(crate) ports: Vec<PortConfig>,
    pub(crate) disable_implicit: bool,
    #[cfg(feature = "snd")]
    pub(crate) sound: bool,
    #[cfg(feature = "gpu")]
    pub(crate) gpu_virgl_flags: Option<u32>,
    #[cfg(feature = "gpu")]
    pub(crate) gpu_shm_size: Option<usize>,
    #[cfg(feature = "gpu")]
    pub(crate) gpu_displays: Vec<(u32, u32)>,
    #[cfg(feature = "gpu")]
    pub(crate) gpu_display_backend: Option<krun_display::DisplayBackend<'static>>,
    #[cfg(feature = "input")]
    pub(crate) input_devices: Vec<(
        krun_input::InputConfigBackend<'static>,
        krun_input::InputEventProviderBackend<'static>,
    )>,
}

/// Options for one named virtio-console port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsolePortOptions {
    pub(crate) queue_size: u16,
}

//--------------------------------------------------------------------------------------------------
// Types: Exec Builder
//--------------------------------------------------------------------------------------------------

/// Builder for execution configuration.
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
#[derive(Debug, Clone, Default)]
pub struct ExecBuilder {
    pub(crate) path: Option<String>,
    pub(crate) args: Vec<String>,
    pub(crate) env: Vec<(String, String)>,
    pub(crate) workdir: Option<String>,
    pub(crate) rlimits: Vec<(String, u64, u64)>,
}

//--------------------------------------------------------------------------------------------------
// Types: Disk Builder
//--------------------------------------------------------------------------------------------------

/// Supported disk image formats.
///
/// VMDK images are currently read-only.
#[cfg(feature = "blk")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskImageFormat {
    /// A raw block image.
    Raw,

    /// A qcow2 image.
    Qcow2,

    /// A VMDK image. VMDK is currently read-only.
    Vmdk,
}

/// Host-side cache behavior for a block device.
///
/// Mirrors libkrun's internal `CacheType`. `Writeback` honors guest flush
/// requests via `fsync`; `Unsafe` advertises flush but makes it a noop.
#[cfg(feature = "blk")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheMode {
    Writeback,
    Unsafe,
}

/// Host-side sync behavior for a block device.
///
/// `None` skips all host sync (fastest, data-loss risk). `Relaxed` honors
/// `VIRTIO_BLK_F_FLUSH` but relaxes hardware sync. `Full` forces strict
/// hardware flush.
#[cfg(feature = "blk")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncMode {
    None,
    Relaxed,
    Full,
}

/// Builder for block device configuration.
///
/// # Example
///
/// ```rust,no_run
/// # use msb_krun::VmBuilder;
/// VmBuilder::new()
///     .disk(|d| d.path("/path/to/disk.img").read_only(true));
/// ```
#[cfg(feature = "blk")]
#[derive(Debug, Clone)]
pub struct DiskBuilder {
    pub(crate) configs: Vec<ConfiguredDisk>,
    current_path: Option<PathBuf>,
    current_id: Option<String>,
    current_read_only: bool,
    current_format: DiskImageFormat,
    current_cache: CacheMode,
    current_direct_io: bool,
    current_sync: SyncMode,
    current_writeback_limit_bytes: Option<u64>,
    current_writeback_limit: Option<WritebackLimit>,
}

/// Configuration for a single block device.
#[cfg(feature = "blk")]
#[derive(Debug, Clone)]
pub struct DiskConfig {
    pub path: PathBuf,
    /// Caller-chosen block id. When `None`, the builder auto-assigns
    /// `vd<suffix>` using the kernel's bijective base-26 scheme.
    pub id: Option<String>,
    pub read_only: bool,
    pub format: DiskImageFormat,
    pub cache: CacheMode,
    pub direct_io: bool,
    pub sync: SyncMode,
}

/// Internal disk configuration paired with host-only tuning state.
#[cfg(feature = "blk")]
#[derive(Debug, Clone)]
pub(crate) struct ConfiguredDisk {
    pub(crate) config: DiskConfig,
    pub(crate) writeback_limit_bytes: Option<u64>,
    pub(crate) writeback_limit: Option<WritebackLimit>,
}

//--------------------------------------------------------------------------------------------------
// Methods: Machine Builder
//--------------------------------------------------------------------------------------------------

impl MachineBuilder {
    /// Create a new machine builder with defaults.
    pub fn new() -> Self {
        Self {
            vcpus: 1,
            memory_mib: 512,
            max_vcpus: None,
            max_memory_mib: None,
            hyperthreading: false,
            nested_virt: false,
            split_irqchip: false,
            balloon: true,
            balloon_stats_interval: Some(Duration::from_secs(1)),
            rng: true,
            msb_metrics: true,
            enable_inet_hijack: false,
            vcpu_affinity: None,
            vcpu_affinity_required: true,
            numa_topology: None,
        }
    }

    /// Set the number of virtual CPUs.
    pub fn vcpus(mut self, count: u8) -> Self {
        self.vcpus = count;
        self
    }

    /// Set the memory size in MiB.
    pub fn memory_mib(mut self, mib: usize) -> Self {
        self.memory_mib = mib;
        self
    }

    /// Set the maximum possible virtual CPUs.
    ///
    /// The VM boots with this full topology described to the guest but only
    /// [`vcpus`](Self::vcpus) online (`maxcpus=` boot parameter); the guest can
    /// online the remaining CPUs later through CPU hotplug. Defaults to the
    /// effective vCPU count, which reserves no extra capacity.
    pub fn max_vcpus(mut self, count: u8) -> Self {
        self.max_vcpus = Some(count);
        self
    }

    /// Pins each possible vCPU thread to one resolved host logical processor.
    ///
    /// The map must contain one entry for every possible vCPU, including reserved capacity declared
    /// with [`max_vcpus`](Self::max_vcpus). This is supported on Linux and Windows hosts.
    pub fn vcpu_affinity(mut self, affinity: Vec<HostCpuId>) -> Self {
        self.vcpu_affinity = Some(affinity);
        self.vcpu_affinity_required = true;
        self
    }

    /// Prefer to pin each possible vCPU thread to one resolved host logical processor.
    ///
    /// The map has the same shape as [`vcpu_affinity`](Self::vcpu_affinity), but an operating
    /// system rejection is treated as a placement fallback instead of a VM-start failure.
    pub fn try_vcpu_affinity(mut self, affinity: Vec<HostCpuId>) -> Self {
        self.vcpu_affinity = Some(affinity);
        self.vcpu_affinity_required = false;
        self
    }

    /// Supply a resolved guest NUMA topology and host-memory policy.
    ///
    /// Guest node IDs, vCPU membership, memory totals and distances are validated by
    /// [`VmBuilder::build`](crate::VmBuilder::build). Omitting this option retains the ordinary
    /// guest-memory construction path.
    pub fn numa_topology(mut self, topology: NumaTopology) -> Self {
        self.numa_topology = Some(topology);
        self
    }

    /// Configure a resolved guest NUMA topology with the fluent API.
    ///
    /// Use [`numa_topology`](Self::numa_topology) when the caller already has a fully resolved
    /// topology value.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use msb_krun::VmBuilder;
    /// VmBuilder::new().machine(|machine| {
    ///     machine
    ///         .vcpus(2)
    ///         .memory_mib(4096)
    ///         .max_memory_mib(8192)
    ///         .numa(|numa| {
    ///             numa.node(|node| {
    ///                 node.vcpus([0, 1])
    ///                     .memory_mib(4096)
    ///                     .max_memory_mib(8192)
    ///                     .bind_host_nodes([0])
    ///             })
    ///         })
    /// });
    /// ```
    pub fn numa(mut self, configure: impl FnOnce(NumaBuilder) -> NumaBuilder) -> Self {
        self.numa_topology = Some(configure(NumaBuilder::new()).finish());
        self
    }

    /// Set the maximum guest memory in MiB reserved for future memory hotplug.
    ///
    /// Currently configuration plumbing only: capacity above
    /// [`memory_mib`](Self::memory_mib) is validated and recorded but not yet
    /// consumed until the virtio-mem device lands. Defaults to the effective
    /// memory size, which reserves no extra capacity.
    pub fn max_memory_mib(mut self, mib: usize) -> Self {
        self.max_memory_mib = Some(mib);
        self
    }

    /// Enable or disable hyperthreading.
    pub fn hyperthreading(mut self, enabled: bool) -> Self {
        self.hyperthreading = enabled;
        self
    }

    /// Enable or disable nested virtualization.
    pub fn nested_virt(mut self, enabled: bool) -> Self {
        self.nested_virt = enabled;
        self
    }

    /// Enable the userspace split irqchip on x86_64.
    ///
    /// The default in-kernel IOAPIC is hardcoded by KVM to 24 pins, leaving
    /// only 11 IRQs for virtio-mmio devices. The userspace split irqchip
    /// emulates a larger IOAPIC (256 pins) and raises the usable range to
    /// 219 IRQs, which is needed for VMs with many virtio-mmio devices
    /// (e.g. lots of virtio-fs mounts or block devices). No effect on
    /// aarch64 or riscv64.
    pub fn split_irqchip(mut self, enabled: bool) -> Self {
        self.split_irqchip = enabled;
        self
    }

    /// Enable or disable the virtio-balloon device.
    ///
    /// The device is enabled by default for general-purpose VMs. Latency-sensitive
    /// guests that never resize memory can disable it to avoid one virtio-mmio
    /// device and its guest-side probe.
    pub fn balloon(mut self, enabled: bool) -> Self {
        self.balloon = enabled;
        self
    }

    /// Set the virtio-balloon guest memory statistics polling interval.
    ///
    /// `Some(interval)` advertises and drives the stats queue at the requested
    /// cadence. `None` disables balloon stats polling while still allowing the
    /// balloon device itself to be attached.
    pub fn balloon_stats_interval(mut self, interval: Option<Duration>) -> Self {
        self.balloon_stats_interval = interval;
        self
    }

    /// Enable or disable the virtio-rng device.
    ///
    /// The device is enabled by default. Guests with a known nonblocking boot
    /// path can disable it to remove one virtio-mmio device from cold start.
    pub fn rng(mut self, enabled: bool) -> Self {
        self.rng = enabled;
        self
    }

    /// Enable or disable the private microsandbox metrics virtio device.
    ///
    /// The device is enabled by default so protected guest filesystem metrics
    /// are available for bundled microsandbox kernels.
    pub fn msb_metrics(mut self, enabled: bool) -> Self {
        self.msb_metrics = enabled;
        self
    }

    /// Enable the automatic TSI INET hijack fallback.
    ///
    /// When set to `true` and no virtio-net device is configured,
    /// `TsiFlags::HIJACK_INET` is enabled so the guest's INET socket
    /// calls are transparently bridged to the host through vsock. This
    /// is useful for guests that need outbound connectivity without the
    /// caller setting up a virtio-net backend.
    ///
    /// Defaults to `false` — guests with no virtio-net are air-gapped
    /// by default. Callers must opt in to TSI when they want host
    /// network access without an explicit network device.
    ///
    /// Note: `HIJACK_UNIX` (used by virtio-fs on Linux for AF_UNIX
    /// hijack) is gated on `HIJACK_INET` already being set, so leaving
    /// INET hijack off also leaves the UNIX hijack auto-enable path off.
    pub fn enable_inet_hijack(mut self, enabled: bool) -> Self {
        self.enable_inet_hijack = enabled;
        self
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: NUMA Builder
//--------------------------------------------------------------------------------------------------

impl NumaBuilder {
    /// Create an empty resolved topology builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add one guest node. Its dense guest node ID is its insertion index.
    pub fn node(mut self, configure: impl FnOnce(NumaNodeBuilder) -> NumaNodeBuilder) -> Self {
        let guest_node_id = u16::try_from(self.nodes.len()).unwrap_or(u16::MAX);
        self.nodes
            .push(configure(NumaNodeBuilder::new()).finish(guest_node_id));
        self
    }

    /// Set one directed non-local guest distance.
    ///
    /// Local entries are generated automatically with value `10`. A later call for the same pair
    /// replaces the earlier value.
    pub fn distance(mut self, from: u16, to: u16, value: u8) -> Self {
        if let Some(distance) = self
            .distances
            .iter_mut()
            .find(|distance| distance.from == from && distance.to == to)
        {
            distance.value = value;
        } else {
            self.distances.push(NumaDistance { from, to, value });
        }
        self
    }

    fn finish(mut self) -> NumaTopology {
        for node in &self.nodes {
            if !self.distances.iter().any(|distance| {
                distance.from == node.guest_node_id && distance.to == node.guest_node_id
            }) {
                self.distances.push(NumaDistance {
                    from: node.guest_node_id,
                    to: node.guest_node_id,
                    value: 10,
                });
            }
        }

        NumaTopology {
            nodes: self.nodes,
            distances: self.distances,
        }
    }
}

impl NumaNodeBuilder {
    /// Create an empty guest node with inherited host-memory placement.
    pub fn new() -> Self {
        Self {
            vcpu_indices: Vec::new(),
            memory_mib: 0,
            max_memory_mib: None,
            host_memory: HostMemoryPolicy::Inherit,
        }
    }

    /// Assign the possible vCPU indices belonging to this guest node.
    pub fn vcpus(mut self, indices: impl IntoIterator<Item = u8>) -> Self {
        self.vcpu_indices = indices.into_iter().collect();
        self
    }

    /// Set the memory available on this node at boot, in MiB.
    pub fn memory_mib(mut self, mib: usize) -> Self {
        self.memory_mib = mib;
        self
    }

    /// Set the maximum memory promised to this node after live growth, in MiB.
    ///
    /// This defaults to the node's boot memory.
    pub fn max_memory_mib(mut self, mib: usize) -> Self {
        self.max_memory_mib = Some(mib);
        self
    }

    /// Preserve the operating system's ordinary host-memory policy.
    pub fn inherit_host_memory(mut self) -> Self {
        self.host_memory = HostMemoryPolicy::Inherit;
        self
    }

    /// Bind future Linux page faults to the selected absolute host NUMA node IDs.
    pub fn bind_host_nodes(mut self, nodes: impl IntoIterator<Item = u32>) -> Self {
        self.host_memory = HostMemoryPolicy::Bind {
            host_nodes: nodes.into_iter().collect(),
        };
        self
    }

    /// Prefer Linux page faults on the selected host NUMA nodes without making VM startup depend
    /// on the kernel accepting the binding.
    pub fn prefer_host_nodes(mut self, nodes: impl IntoIterator<Item = u32>) -> Self {
        self.host_memory = HostMemoryPolicy::PreferredMany {
            host_nodes: nodes.into_iter().collect(),
        };
        self
    }

    /// Prefer one Windows NUMA node while allowing the host to fall back under pressure.
    pub fn prefer_host_node(mut self, node: u32) -> Self {
        self.host_memory = HostMemoryPolicy::Preferred { host_node: node };
        self
    }

    /// Set an already resolved host-memory policy.
    pub fn host_memory(mut self, policy: HostMemoryPolicy) -> Self {
        self.host_memory = policy;
        self
    }

    fn finish(self, guest_node_id: u16) -> NumaNodeConfig {
        NumaNodeConfig {
            guest_node_id,
            vcpu_indices: self.vcpu_indices,
            memory_mib: self.memory_mib,
            max_memory_mib: self.max_memory_mib.unwrap_or(self.memory_mib),
            host_memory: self.host_memory,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: Vsock Builder
//--------------------------------------------------------------------------------------------------

impl VsockBuilder {
    /// Create an empty vsock service builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Route guest connections to `port` into an existing host Unix socket.
    #[cfg(not(target_os = "windows"))]
    pub fn unix_connect(mut self, port: u32, path: impl AsRef<Path>) -> Self {
        self.routes.push(VsockRoute::UnixConnect {
            port,
            path: path.as_ref().to_path_buf(),
        });
        self
    }

    /// Listen on a host Unix socket and inject accepted streams into guest `port`.
    #[cfg(not(target_os = "windows"))]
    pub fn unix_listen(mut self, port: u32, path: impl AsRef<Path>) -> Self {
        self.routes.push(VsockRoute::UnixListen {
            port,
            path: path.as_ref().to_path_buf(),
        });
        self
    }

    /// Serve guest connections to `port` with a custom in-process backend.
    ///
    /// Unlike a Unix route, this does not ask libkrun to create or map a data
    /// socket. The backend supplies a nonblocking byte stream and readiness
    /// source; libkrun retains virtio-vsock framing and flow control.
    pub fn custom(mut self, port: u32, backend: Arc<dyn VsockPortBackend>) -> Self {
        self.routes.push(VsockRoute::Custom { port, backend });
        self
    }

    /// Serve guest datagrams to `port` with a custom message-oriented backend.
    #[cfg(not(target_os = "windows"))]
    pub fn custom_dgram(mut self, port: u32, backend: Arc<dyn VsockDatagramPortBackend>) -> Self {
        self.routes
            .push(VsockRoute::CustomDatagram { port, backend });
        self
    }

    /// Remap a guest TCP listen port to a host port through TSI.
    ///
    /// This requires [`inet_hijack(true)`](Self::inet_hijack); validation
    /// rejects remaps that would otherwise be silently ignored.
    #[cfg(not(target_os = "windows"))]
    pub fn tcp_listen_remap(mut self, guest_port: u16, host_port: u16) -> Self {
        self.tcp_listen_remaps.push((guest_port, host_port));
        self
    }

    /// Enable or disable TSI interception of guest INET sockets.
    #[cfg(not(target_os = "windows"))]
    pub fn inet_hijack(mut self, enabled: bool) -> Self {
        self.enable_inet_hijack = enabled;
        self
    }
}

impl Default for MachineBuilder {
    fn default() -> Self {
        Self::new()
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: Kernel Builder
//--------------------------------------------------------------------------------------------------

impl KernelBuilder {
    /// Create a new kernel builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append to the kernel command line.
    pub fn cmdline(mut self, cmdline: &str) -> Self {
        if let Some(ref mut existing) = self.cmdline {
            existing.push(' ');
            existing.push_str(cmdline);
        } else {
            self.cmdline = Some(cmdline.to_string());
        }
        self
    }

    /// Set an explicit path to the libkrunfw shared library.
    ///
    /// When not set, the OS dynamic linker's default search path is used.
    pub fn krunfw_path(mut self, path: impl AsRef<Path>) -> Self {
        self.krunfw_path = Some(path.as_ref().to_path_buf());
        self
    }

    /// Set an explicit path to an initramfs image.
    ///
    /// The image is copied into guest memory and advertised through the device
    /// tree on architectures that support direct kernel boot.
    pub fn initramfs_path(mut self, path: impl AsRef<Path>) -> Self {
        self.initramfs_path = Some(path.as_ref().to_path_buf());
        self
    }

    /// Set the path to the init binary inside the guest.
    ///
    /// This controls the kernel `init=` parameter. When not set, defaults
    /// to `/init.krun`.
    pub fn init_path(mut self, path: impl AsRef<Path>) -> Self {
        self.init_path = Some(path.as_ref().to_string_lossy().to_string());
        self
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: Filesystem Builder
//--------------------------------------------------------------------------------------------------

impl FsBuilder {
    /// Create a new filesystem builder.
    pub fn new() -> Self {
        Self {
            configs: Vec::new(),
            current_tag: None,
            current_shm_size: None,
        }
    }

    /// Set the root filesystem path.
    ///
    /// Uses the virtiofs tag `/dev/root`, matching the kernel's expected root device name.
    pub fn root(mut self, path: impl AsRef<Path>) -> Self {
        self.configs.push(FsConfig::Path {
            tag: "/dev/root".to_string(),
            path: path.as_ref().to_path_buf(),
            shm_size: None,
        });
        self
    }

    /// Set the tag for the next mount.
    pub fn tag(mut self, tag: &str) -> Self {
        self.current_tag = Some(tag.to_string());
        self
    }

    /// Set the path for a filesystem mount.
    ///
    /// If `tag()` was called previously, uses that tag; otherwise generates one.
    pub fn path(mut self, path: impl AsRef<Path>) -> Self {
        let tag = self
            .current_tag
            .take()
            .unwrap_or_else(|| format!("fs{}", self.configs.len()));
        let shm_size = self.current_shm_size.take();

        self.configs.push(FsConfig::Path {
            tag,
            path: path.as_ref().to_path_buf(),
            shm_size,
        });
        self
    }

    /// Set the DAX shared memory size for the next mount.
    pub fn shm_size(mut self, size: usize) -> Self {
        self.current_shm_size = Some(size);
        self
    }

    /// Use a custom filesystem backend.
    #[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
    pub fn custom(mut self, backend: Box<dyn DynFileSystem + Send + Sync>) -> Self {
        let tag = self
            .current_tag
            .take()
            .unwrap_or_else(|| format!("fs{}", self.configs.len()));

        self.configs.push(FsConfig::Custom { tag, backend });
        self
    }
}

impl Default for FsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: Network Builder
//--------------------------------------------------------------------------------------------------

#[cfg(feature = "net")]
impl NetBuilder {
    /// Create a new network builder.
    pub fn new() -> Self {
        Self {
            configs: Vec::new(),
            current_mac: None,
            current_rate_limiters: RateLimiters::default(),
        }
    }

    /// Set the MAC address for the next network device.
    pub fn mac(mut self, mac: [u8; 6]) -> Self {
        self.current_mac = Some(mac);
        self
    }

    /// Limit frames received by the guest on the next network device.
    pub fn rx_rate_limiter(mut self, config: RateLimiterConfig) -> Self {
        self.current_rate_limiters.rx = Some(config);
        self
    }

    /// Limit frames transmitted by the guest on the next network device.
    pub fn tx_rate_limiter(mut self, config: RateLimiterConfig) -> Self {
        self.current_rate_limiters.tx = Some(config);
        self
    }

    /// Attach a unixgram network backend from a pre-opened fd.
    #[cfg(unix)]
    pub fn unixgram(mut self, fd: OwnedFd) -> Self {
        let mac = self.current_mac.take();
        self.push_config(NetConfig::UnixgramFd { mac, fd });
        self
    }

    /// Attach a unixgram network backend connecting to a socket path.
    #[cfg(unix)]
    pub fn unixgram_path(mut self, path: impl AsRef<Path>, send_vfkit_magic: bool) -> Self {
        let mac = self.current_mac.take();
        self.push_config(NetConfig::UnixgramPath {
            mac,
            path: path.as_ref().to_path_buf(),
            send_vfkit_magic,
        });
        self
    }

    /// Attach a unixstream network backend from a pre-opened fd.
    #[cfg(unix)]
    pub fn unixstream(mut self, fd: OwnedFd) -> Self {
        let mac = self.current_mac.take();
        self.push_config(NetConfig::UnixstreamFd { mac, fd });
        self
    }

    /// Attach a unixstream network backend connecting to a socket path.
    #[cfg(unix)]
    pub fn unixstream_path(mut self, path: impl AsRef<Path>) -> Self {
        let mac = self.current_mac.take();
        self.push_config(NetConfig::UnixstreamPath {
            mac,
            path: path.as_ref().to_path_buf(),
        });
        self
    }

    /// Attach a TAP network backend.
    #[cfg(target_os = "linux")]
    pub fn tap(mut self, name: impl Into<String>) -> Self {
        let mac = self.current_mac.take();
        self.push_config(NetConfig::Tap {
            mac,
            name: name.into(),
        });
        self
    }

    /// Attach a Windows named-pipe network backend.
    #[cfg(windows)]
    pub fn named_pipe(mut self, name: impl Into<String>) -> Self {
        let mac = self.current_mac.take();
        self.push_config(NetConfig::NamedPipe {
            mac,
            name: name.into(),
        });
        self
    }

    /// Use a custom network backend.
    pub fn custom(mut self, backend: Box<dyn NetBackend + Send>) -> Self {
        let mac = self.current_mac.take();
        self.push_config(NetConfig::Custom { mac, backend });
        self
    }

    fn push_config(&mut self, backend: NetConfig) {
        let rate_limiters = std::mem::take(&mut self.current_rate_limiters);
        self.configs.push(ConfiguredNet {
            backend,
            rate_limiters,
        });
    }
}

#[cfg(feature = "net")]
impl Default for NetBuilder {
    fn default() -> Self {
        Self::new()
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: Console Builder
//--------------------------------------------------------------------------------------------------

impl ConsoleBuilder {
    /// Create a new console builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the path to send console output.
    pub fn output(mut self, path: impl AsRef<Path>) -> Self {
        self.output = Some(path.as_ref().to_path_buf());
        self
    }

    /// Add an output-only virtio-console device backed by a host file.
    ///
    /// On Windows this creates a real guest console port, so guests can use it as `hvc0` when the implicit serial console is disabled or `krun_set_kernel_console` selects it.
    #[cfg(target_os = "windows")]
    pub fn virtio_output(mut self, path: impl AsRef<Path>) -> Self {
        self.ports.push(PortConfig::ConsoleOutputFile {
            path: path.as_ref().to_path_buf(),
            queue_size: DEFAULT_QUEUE_SIZE,
        });
        self
    }

    /// Add a bidirectional virtio-console port backed by a Windows named pipe.
    ///
    /// The guest sees the port as `/dev/virtio-ports/<name>`. The host connects to `pipe_name` as a client, so the helper should create the pipe server first.
    #[cfg(target_os = "windows")]
    pub fn named_pipe(self, name: &str, pipe_name: impl Into<String>) -> Self {
        self.named_pipe_with_options(name, pipe_name, ConsolePortOptions::default())
    }

    /// Add a Windows named-pipe console port with explicit device queue options.
    #[cfg(target_os = "windows")]
    pub fn named_pipe_with_options(
        mut self,
        name: &str,
        pipe_name: impl Into<String>,
        options: ConsolePortOptions,
    ) -> Self {
        self.ports.push(PortConfig::NamedPipe {
            name: name.to_string(),
            pipe_name: pipe_name.into(),
            queue_size: options.queue_size,
        });
        self
    }

    /// Enable the virtio-snd device.
    #[cfg(feature = "snd")]
    pub fn sound(mut self, enabled: bool) -> Self {
        self.sound = enabled;
        self
    }

    /// Set GPU virgl flags.
    #[cfg(feature = "gpu")]
    pub fn gpu_virgl_flags(mut self, flags: u32) -> Self {
        self.gpu_virgl_flags = Some(flags);
        self
    }

    /// Set GPU shared memory size.
    #[cfg(feature = "gpu")]
    pub fn gpu_shm_size(mut self, size: usize) -> Self {
        self.gpu_shm_size = Some(size);
        self
    }

    /// Add a virtio-gpu scanout of `width` x `height` pixels.
    ///
    /// Each call adds one display (up to `VIRTIO_GPU_MAX_SCANOUTS`). Without any
    /// display the guest driver disables KMS and exposes a render-only node.
    /// Frames go to the VMM's display backend (a no-op sink unless one is set).
    #[cfg(feature = "gpu")]
    pub fn gpu_display(mut self, width: u32, height: u32) -> Self {
        self.gpu_displays.push((width, height));
        self
    }

    /// Receive scanout frames in a `krun_display` backend (see
    /// `krun_display::IntoDisplayBackend`). Without one, frames are dropped.
    #[cfg(feature = "gpu")]
    pub fn gpu_display_backend(mut self, backend: krun_display::DisplayBackend<'static>) -> Self {
        self.gpu_display_backend = Some(backend);
        self
    }

    /// Attach a virtio-input device described by `config` whose events come
    /// from `events` (see `krun_input::IntoInputConfig` / `IntoInputEvents`).
    /// Each call adds one device.
    #[cfg(feature = "input")]
    pub fn input_device(
        mut self,
        config: krun_input::InputConfigBackend<'static>,
        events: krun_input::InputEventProviderBackend<'static>,
    ) -> Self {
        self.input_devices.push((config, events));
        self
    }

    /// Add a bidirectional I/O port to the console device.
    ///
    /// Creates a named port accessible in the guest via `/sys/class/virtio-ports/<name>`.
    /// The host reads from `input_fd` and writes to `output_fd`. Pass the same FD for both
    /// when using a bidirectional socket.
    #[cfg(not(target_os = "windows"))]
    pub fn port(mut self, name: &str, input_fd: RawFd, output_fd: RawFd) -> Self {
        self.ports.push(PortConfig::InOut {
            name: name.to_string(),
            input_fd,
            output_fd,
            queue_size: DEFAULT_QUEUE_SIZE,
        });
        self
    }

    /// Add a TTY port to the console device.
    ///
    /// Creates a named port accessible in the guest via `/sys/class/virtio-ports/<name>`.
    /// The `tty_fd` must be a valid terminal file descriptor. Terminal raw mode is configured
    /// automatically.
    #[cfg(not(target_os = "windows"))]
    pub fn port_tty(mut self, name: &str, tty_fd: RawFd) -> Self {
        self.ports.push(PortConfig::Tty {
            name: name.to_string(),
            tty_fd,
            queue_size: DEFAULT_QUEUE_SIZE,
        });
        self
    }

    /// Disable the implicit console device.
    ///
    /// By default libkrun creates an implicit console that reads from `STDIN_FILENO`.
    /// Call this to suppress that console when using only explicit ports.
    pub fn disable_implicit(mut self) -> Self {
        self.disable_implicit = true;
        self
    }

    /// Add a custom console port backend.
    ///
    /// The backend provides bidirectional byte I/O without file descriptors
    /// on the data path, matching the pattern of
    /// [`NetBuilder::custom()`](NetBuilder::custom) and
    /// [`FsBuilder::custom()`](FsBuilder::custom).
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// VmBuilder::new()
    ///     .console(|c| c.custom("agent", Box::new(my_backend)))
    /// ```
    #[cfg(not(target_os = "windows"))]
    pub fn custom(self, name: &str, backend: Box<dyn ConsolePortBackend>) -> Self {
        self.custom_with_options(name, backend, ConsolePortOptions::default())
    }

    /// Add a custom console port backend with explicit device queue options.
    #[cfg(not(target_os = "windows"))]
    pub fn custom_with_options(
        mut self,
        name: &str,
        backend: Box<dyn ConsolePortBackend>,
        options: ConsolePortOptions,
    ) -> Self {
        let backend: Arc<dyn ConsolePortBackend> = Arc::from(backend);
        let input = Box::new(ConsolePortBackendInputAdapter::new(Arc::clone(&backend)));
        let output = Box::new(ConsolePortBackendOutputAdapter::new(backend));
        self.ports.push(PortConfig::Custom {
            name: name.to_string(),
            input,
            output,
            queue_size: options.queue_size,
        });
        self
    }
}

impl ConsolePortOptions {
    /// Create options that preserve libkrun's existing queue size.
    pub fn new() -> Self {
        Self::default()
    }

    /// Request the descriptor count for both directions of this port.
    ///
    /// Validation happens during [`VmBuilder::build`](crate::VmBuilder::build).
    pub fn queue_size(mut self, queue_size: u16) -> Self {
        self.queue_size = queue_size;
        self
    }
}

impl Default for ConsolePortOptions {
    fn default() -> Self {
        Self {
            queue_size: DEFAULT_QUEUE_SIZE,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: Exec Builder
//--------------------------------------------------------------------------------------------------

impl ExecBuilder {
    /// Create a new exec builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the executable path.
    pub fn path(mut self, path: impl AsRef<Path>) -> Self {
        self.path = Some(path.as_ref().to_string_lossy().to_string());
        self
    }

    /// Set command line arguments.
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.args = args.into_iter().map(|s| s.as_ref().to_string()).collect();
        self
    }

    /// Add a single environment variable.
    pub fn env(mut self, key: &str, value: &str) -> Self {
        self.env.push((key.to_string(), value.to_string()));
        self
    }

    /// Add multiple environment variables.
    pub fn envs<I, K, V>(mut self, envs: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        self.env.extend(
            envs.into_iter()
                .map(|(k, v)| (k.as_ref().to_string(), v.as_ref().to_string())),
        );
        self
    }

    /// Set the working directory.
    pub fn workdir(mut self, path: impl AsRef<Path>) -> Self {
        self.workdir = Some(path.as_ref().to_string_lossy().to_string());
        self
    }

    /// Set a resource limit.
    pub fn rlimit(mut self, resource: &str, soft: u64, hard: u64) -> Self {
        self.rlimits.push((resource.to_string(), soft, hard));
        self
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: Disk Builder
//--------------------------------------------------------------------------------------------------

#[cfg(feature = "blk")]
impl DiskBuilder {
    /// Create a new disk builder.
    pub fn new() -> Self {
        Self {
            configs: Vec::new(),
            current_path: None,
            current_id: None,
            current_read_only: false,
            current_format: DiskImageFormat::Raw,
            current_cache: CacheMode::Writeback,
            current_direct_io: false,
            current_sync: SyncMode::Full,
            current_writeback_limit_bytes: None,
            current_writeback_limit: None,
        }
    }

    /// Set the disk image format for the current disk.
    pub fn format(mut self, format: DiskImageFormat) -> Self {
        self.current_format = format;
        self
    }

    /// Set a stable block id for the current disk.
    ///
    /// When unset, the builder auto-assigns `vd<suffix>` by insertion order
    /// (matching the kernel's bijective base-26 scheme: `vda`..`vdz`,
    /// `vdaa`..`vdzz`, `vdaaa`...). Setting a custom id lets the guest
    /// address the device via `/dev/disk/by-id/virtio-<id>` independent of
    /// attach order.
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.current_id = Some(id.into());
        self
    }

    /// Set the path for a block device.
    pub fn path(mut self, path: impl AsRef<Path>) -> Self {
        // Finalize any pending config
        if let Some(pending_path) = self.current_path.take() {
            self.configs.push(ConfiguredDisk {
                config: DiskConfig {
                    path: pending_path,
                    id: self.current_id.take(),
                    read_only: self.current_read_only,
                    format: self.current_format,
                    cache: self.current_cache,
                    direct_io: self.current_direct_io,
                    sync: self.current_sync,
                },
                writeback_limit_bytes: self.current_writeback_limit_bytes,
                writeback_limit: self.current_writeback_limit.clone(),
            });
            self.current_read_only = false;
            self.current_format = DiskImageFormat::Raw;
            self.current_cache = CacheMode::Writeback;
            self.current_direct_io = false;
            self.current_sync = SyncMode::Full;
            self.current_writeback_limit_bytes = None;
            self.current_writeback_limit = None;
        }

        self.current_path = Some(path.as_ref().to_path_buf());
        self
    }

    /// Set read-only mode for the current disk.
    pub fn read_only(mut self, ro: bool) -> Self {
        self.current_read_only = ro;
        self
    }

    /// Set the host-side cache behavior for the current disk.
    pub fn cache(mut self, mode: CacheMode) -> Self {
        self.current_cache = mode;
        self
    }

    /// Enable or disable `O_DIRECT` on the host backing file for the current disk.
    pub fn direct_io(mut self, enabled: bool) -> Self {
        self.current_direct_io = enabled;
        self
    }

    /// Set the host-side sync behavior for the current disk.
    pub fn sync(mut self, mode: SyncMode) -> Self {
        self.current_sync = mode;
        self
    }

    /// Limit outstanding buffered host dirty data to this many bytes.
    ///
    /// This Linux-only policy is valid for writable raw disks using writeback caching, buffered
    /// I/O and an active sync mode. The minimum active budget is 128 MiB; zero disables the policy.
    /// Libkrun derives smaller internal batches, retires their data and allocation metadata on a
    /// background helper, and applies backpressure before this per-device, page-aligned dirty-data
    /// budget can be exceeded. Guest flushes still perform the existing full durability sync.
    ///
    /// While this policy is active, host hole punching is not exposed to the guest: discard and
    /// write-zeroes-with-unmap are unavailable, while ordinary write-zeroes requests use accounted
    /// data writes. On supporting Linux kernels and filesystems, writes also request best-effort
    /// cache pruning; that hint is an optimization, not a bound on clean page-cache residency.
    /// Invalid combinations fail explicitly when the VM is built.
    pub fn writeback_limit_bytes(mut self, bytes: u64) -> Self {
        self.current_writeback_limit_bytes = (bytes > 0).then_some(bytes);
        self.current_writeback_limit = None;
        self
    }

    /// Attach a live writeback limit to the current disk.
    ///
    /// Clones of the handle may change the pressure target while the VM is running. The immutable
    /// maximum receives the same validation as [`Self::writeback_limit_bytes`].
    pub fn writeback_limit(mut self, limit: WritebackLimit) -> Self {
        self.current_writeback_limit_bytes = None;
        self.current_writeback_limit = Some(limit);
        self
    }

    /// Finalize the builder (called internally).
    pub(crate) fn finalize(mut self) -> Self {
        if let Some(path) = self.current_path.take() {
            self.configs.push(ConfiguredDisk {
                config: DiskConfig {
                    path,
                    id: self.current_id.take(),
                    read_only: self.current_read_only,
                    format: self.current_format,
                    cache: self.current_cache,
                    direct_io: self.current_direct_io,
                    sync: self.current_sync,
                },
                writeback_limit_bytes: self.current_writeback_limit_bytes,
                writeback_limit: self.current_writeback_limit.take(),
            });
        }
        self
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations: Builders
//--------------------------------------------------------------------------------------------------

impl Default for NumaNodeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "blk")]
impl Default for DiskBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "blk")]
impl From<DiskImageFormat> for devices::virtio::block::ImageType {
    fn from(format: DiskImageFormat) -> Self {
        match format {
            DiskImageFormat::Raw => devices::virtio::block::ImageType::Raw,
            DiskImageFormat::Qcow2 => devices::virtio::block::ImageType::Qcow2,
            DiskImageFormat::Vmdk => devices::virtio::block::ImageType::Vmdk,
        }
    }
}

#[cfg(feature = "blk")]
impl From<CacheMode> for devices::virtio::CacheType {
    fn from(mode: CacheMode) -> Self {
        match mode {
            CacheMode::Writeback => devices::virtio::CacheType::Writeback,
            CacheMode::Unsafe => devices::virtio::CacheType::Unsafe,
        }
    }
}

#[cfg(feature = "blk")]
impl From<SyncMode> for devices::virtio::block::SyncMode {
    fn from(mode: SyncMode) -> Self {
        match mode {
            SyncMode::None => devices::virtio::block::SyncMode::None,
            SyncMode::Relaxed => devices::virtio::block::SyncMode::Relaxed,
            SyncMode::Full => devices::virtio::block::SyncMode::Full,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_cpu_id_defaults_to_group_zero() {
        assert_eq!(HostCpuId::new(7), HostCpuId::in_group(0, 7));
        assert_eq!(HostCpuId::in_group(3, 11).group, 3);
    }

    #[test]
    fn machine_builder_records_vcpu_affinity() {
        let affinity = vec![HostCpuId::new(2), HostCpuId::new(6)];
        let builder = MachineBuilder::new()
            .vcpus(2)
            .vcpu_affinity(affinity.clone());

        assert_eq!(builder.vcpu_affinity, Some(affinity));
        assert!(builder.vcpu_affinity_required);
    }

    #[test]
    fn machine_builder_records_best_effort_vcpu_affinity() {
        let affinity = vec![HostCpuId::new(2), HostCpuId::new(6)];
        let builder = MachineBuilder::new()
            .vcpus(2)
            .try_vcpu_affinity(affinity.clone());

        assert_eq!(builder.vcpu_affinity, Some(affinity));
        assert!(!builder.vcpu_affinity_required);
    }

    #[test]
    fn numa_node_builder_records_best_effort_linux_memory_policy() {
        let linux = NumaNodeBuilder::new().prefer_host_nodes([2, 3]);
        assert_eq!(
            linux.host_memory,
            HostMemoryPolicy::PreferredMany {
                host_nodes: vec![2, 3]
            }
        );
    }

    #[test]
    fn machine_builder_resolves_fluent_numa_topology() {
        let topology = MachineBuilder::new()
            .numa(|numa| {
                numa.node(|node| {
                    node.vcpus([0, 1])
                        .memory_mib(4096)
                        .max_memory_mib(8192)
                        .bind_host_nodes([2, 3])
                })
            })
            .numa_topology
            .unwrap();

        assert_eq!(
            topology,
            NumaTopology {
                nodes: vec![NumaNodeConfig {
                    guest_node_id: 0,
                    vcpu_indices: vec![0, 1],
                    memory_mib: 4096,
                    max_memory_mib: 8192,
                    host_memory: HostMemoryPolicy::Bind {
                        host_nodes: vec![2, 3],
                    },
                }],
                distances: vec![NumaDistance {
                    from: 0,
                    to: 0,
                    value: 10,
                }],
            }
        );
    }

    #[test]
    fn numa_node_max_memory_defaults_to_boot_memory() {
        let topology = NumaBuilder::new()
            .node(|node| node.vcpus([0]).memory_mib(512))
            .finish();

        assert_eq!(topology.nodes[0].max_memory_mib, 512);
    }

    #[test]
    fn machine_builder_msb_metrics_defaults_on_and_can_be_disabled() {
        assert!(MachineBuilder::new().msb_metrics);
        assert!(!MachineBuilder::new().msb_metrics(false).msb_metrics);
        assert!(MachineBuilder::new().msb_metrics(true).msb_metrics);
    }

    #[cfg(all(feature = "net", unix))]
    #[test]
    fn network_rate_limiters_apply_only_to_the_next_device() {
        use std::os::fd::OwnedFd;
        use std::os::unix::net::UnixDatagram;

        let (first, _) = UnixDatagram::pair().unwrap();
        let (second, _) = UnixDatagram::pair().unwrap();
        let limiter = RateLimiterConfig {
            bandwidth: Some(devices::virtio::net::rate_limit::TokenBucketConfig {
                size: 1_048_576,
                refill_time: Duration::from_secs(1),
                one_time_burst: 524_288,
            }),
            ops: Some(devices::virtio::net::rate_limit::TokenBucketConfig {
                size: 1_000,
                refill_time: Duration::from_secs(1),
                one_time_burst: 0,
            }),
        };

        let builder = NetBuilder::new()
            .rx_rate_limiter(limiter.clone())
            .tx_rate_limiter(limiter.clone())
            .unixgram(OwnedFd::from(first))
            .unixgram(OwnedFd::from(second));

        assert_eq!(builder.configs[0].rate_limiters.rx, Some(limiter.clone()));
        assert_eq!(builder.configs[0].rate_limiters.tx, Some(limiter));
        assert!(builder.configs[1].rate_limiters.is_empty());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_virtio_output_records_file_backed_console_port() {
        let path = PathBuf::from(r"C:\logs\guest-console.log");
        let mut builder = ConsoleBuilder::new().virtio_output(&path);

        assert_eq!(builder.ports.len(), 1);
        match builder.ports.pop().unwrap() {
            PortConfig::ConsoleOutputFile {
                path: actual,
                queue_size,
            } => {
                assert_eq!(actual, path);
                assert_eq!(queue_size, DEFAULT_QUEUE_SIZE);
            }
            _ => panic!("unexpected console port config"),
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_named_pipe_records_pipe_backed_console_port() {
        let mut builder = ConsoleBuilder::new().named_pipe("agent", r"\\.\pipe\msb-agent-console");

        assert_eq!(builder.ports.len(), 1);
        match builder.ports.pop().unwrap() {
            PortConfig::NamedPipe {
                name,
                pipe_name,
                queue_size,
            } => {
                assert_eq!(name, "agent");
                assert_eq!(pipe_name, r"\\.\pipe\msb-agent-console");
                assert_eq!(queue_size, DEFAULT_QUEUE_SIZE);
            }
            _ => panic!("unexpected console port config"),
        }
    }
}
