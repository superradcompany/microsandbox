//! VM handle for entering microVMs.

use std::collections::HashMap;
use std::convert::Infallible;
use std::path::PathBuf;
use std::sync::atomic::AtomicI32;
use std::sync::Arc;
use std::time::{Instant, SystemTime};

#[cfg(target_os = "linux")]
use std::env;
#[cfg(target_os = "linux")]
use std::ffi::CString;

use crossbeam_channel::unbounded;
#[cfg(not(target_os = "windows"))]
use devices::virtio::vsock::VsockDatagramPortBackend;
use devices::virtio::vsock::VsockPortBackend;
use log::error;
use polly::event_manager::EventManager;
use utils::eventfd::EventFd;
#[cfg(not(target_os = "windows"))]
use vmm::resources::TsiFlags;
use vmm::resources::VmResources;
use vmm::vmm_config::kernel_bundle::InitrdBundle;
use vmm::vmm_config::kernel_bundle::KernelBundle;
use vmm::vmm_config::kernel_cmdline::KernelCmdlineConfig;
use vmm::vmm_config::vsock::VsockDeviceConfig;

use super::builders::PlacementObserver;
use super::error::{BuildError, Error, Result, RuntimeError};
use super::exit_handle::ExitHandle;
use super::metrics::MetricsHandle;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const INIT_PATH: &str = "/init.krun";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Handle to a configured VM ready to enter.
///
/// Created via [`VmBuilder::build()`](super::builder::VmBuilder::build).
pub struct Vm {
    vmr: VmResources,
    kernel_cmdline: Option<String>,
    exec_path: Option<String>,
    args: Option<String>,
    env: Option<String>,
    workdir: Option<String>,
    rlimits: Option<String>,
    krunfw_path: Option<PathBuf>,
    initramfs_path: Option<PathBuf>,
    init_path: Option<String>,
    exit_observers: Vec<Box<dyn Fn(i32) + Send + 'static>>,
    placement_observer: Option<PlacementObserver>,
    /// Pre-created exit event fd for triggering VM shutdown.
    exit_evt: EventFd,
    /// Shared exit code — written by the VMM, readable by exit observers.
    exit_code: Arc<AtomicI32>,
    /// Opt in to the automatic `TsiFlags::HIJACK_INET` fallback that
    /// bridges guest INET sockets to the host via vsock when no
    /// virtio-net device is configured. Set via
    /// [`MachineBuilder::enable_inet_hijack`](super::builders::MachineBuilder::enable_inet_hijack).
    #[cfg(not(target_os = "windows"))]
    enable_inet_hijack: bool,
    #[cfg(not(target_os = "windows"))]
    vsock_unix_ipc_port_map: Option<HashMap<u32, (PathBuf, bool)>>,
    vsock_custom_port_map: Option<HashMap<u32, Arc<dyn VsockPortBackend>>>,
    #[cfg(not(target_os = "windows"))]
    vsock_custom_dgram_port_map: Option<HashMap<u32, Arc<dyn VsockDatagramPortBackend>>>,
    #[cfg(not(target_os = "windows"))]
    vsock_host_port_map: Option<HashMap<u16, u16>>,
    /// Keeps the libkrunfw library loaded so kernel memory pointers remain valid.
    _krunfw_library: Option<libloading::Library>,
    /// Keeps an explicit initramfs allocation alive until it is copied to guest memory.
    _initramfs_data: Option<Vec<u8>>,
}

/// Cloneable handle for live VM resource control.
///
/// Obtained through [`Vm::control_handle`] before `enter()`; background
/// threads use it to drive live resizes while the VM runs. Memory resize is
/// backed by virtio-mem and only available when the machine reserved capacity
/// with [`max_memory_mib`](super::builders::MachineBuilder::max_memory_mib).
#[cfg(not(feature = "tee"))]
#[derive(Clone)]
pub struct VmControl {
    boot_mib: u64,
    mem: Option<Arc<std::sync::Mutex<devices::virtio::Mem>>>,
    cpu: Option<Arc<std::sync::Mutex<devices::virtio::Cpu>>>,
}

/// Point-in-time CPU sizing of a running VM as seen through [`VmControl`].
/// `actual` is what the guest driver last reported; `enforced` is what the
/// VMM allows to execute regardless of guest cooperation.
#[cfg(not(feature = "tee"))]
#[derive(Debug, Clone, Copy)]
pub struct VmCpuState {
    /// CPUs possible in this boot.
    pub possible: u32,

    /// Online count the host asked the guest to converge on.
    pub requested_online: u32,

    /// Online count the guest driver last reported.
    pub actual_online: u32,

    /// Online count the VMM currently enforces.
    pub enforced: u32,
}

/// Point-in-time memory sizing of a running VM, in MiB, as seen through
/// [`VmControl`]. `current` trails `target` while the guest converges.
#[cfg(not(feature = "tee"))]
#[derive(Debug, Clone, Copy)]
pub struct VmMemoryState {
    /// Memory the VM booted with.
    pub boot_mib: u64,

    /// Total memory the host asked the guest to converge on.
    pub target_mib: u64,

    /// Total memory currently usable by the guest (boot + plugged).
    pub current_mib: u64,

    /// Boot-time ceiling for live growth (boot + hotplug capacity).
    pub max_mib: u64,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Vm {
    /// Create a new Vm instance.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        vmr: VmResources,
        kernel_cmdline: Option<String>,
        exec_path: Option<String>,
        args: Option<String>,
        env: Option<String>,
        workdir: Option<String>,
        rlimits: Option<String>,
        krunfw_path: Option<PathBuf>,
        initramfs_path: Option<PathBuf>,
        init_path: Option<String>,
        exit_observers: Vec<Box<dyn Fn(i32) + Send + 'static>>,
        placement_observer: Option<PlacementObserver>,
        exit_evt: EventFd,
        exit_code: Arc<AtomicI32>,
        #[cfg(not(target_os = "windows"))] enable_inet_hijack: bool,
        #[cfg(not(target_os = "windows"))] vsock_unix_ipc_port_map: Option<
            HashMap<u32, (PathBuf, bool)>,
        >,
        vsock_custom_port_map: Option<HashMap<u32, Arc<dyn VsockPortBackend>>>,
        #[cfg(not(target_os = "windows"))] vsock_custom_dgram_port_map: Option<
            HashMap<u32, Arc<dyn VsockDatagramPortBackend>>,
        >,
        #[cfg(not(target_os = "windows"))] vsock_host_port_map: Option<HashMap<u16, u16>>,
    ) -> Self {
        Self {
            vmr,
            kernel_cmdline,
            exec_path,
            args,
            env,
            workdir,
            rlimits,
            krunfw_path,
            initramfs_path,
            init_path,
            exit_observers,
            placement_observer,
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
            _krunfw_library: None,
            _initramfs_data: None,
        }
    }

    /// Get a cloneable handle that triggers VM exit from any thread.
    ///
    /// Must be called **before** [`enter()`](Self::enter). Background tasks
    /// use this to shut down the VMM (e.g. idle timeout, max duration).
    pub fn exit_handle(&self) -> ExitHandle {
        ExitHandle::from_event_fd(&self.exit_evt)
            .expect("Failed to create ExitHandle from exit EventFd")
    }

    /// Get a shared reference to the VM exit code.
    ///
    /// The VMM writes the guest exit code here before invoking exit
    /// observers. Read it inside an [`on_exit`](super::builder::VmBuilder::on_exit)
    /// closure to record the exit status.
    ///
    /// Sentinel value `i32::MAX` means "not yet set".
    pub fn exit_code(&self) -> Arc<AtomicI32> {
        Arc::clone(&self.exit_code)
    }

    /// Get a cloneable handle for VM metrics.
    ///
    /// Must be called before [`enter()`](Self::enter) if the caller needs to
    /// sample metrics while the VM is running, because `enter()` never returns
    /// on a successful boot.
    pub fn metrics_handle(&self) -> MetricsHandle {
        self.vmr.metrics.handle()
    }

    /// Get a cloneable handle for live VM resource control.
    ///
    /// Must be called **before** [`enter()`](Self::enter), because `enter()`
    /// never returns on a successful boot. Live memory resize is only
    /// available when the machine reserved capacity with
    /// [`max_memory_mib`](super::builders::MachineBuilder::max_memory_mib)
    /// above the boot memory size.
    #[cfg(not(feature = "tee"))]
    pub fn control_handle(&self) -> VmControl {
        VmControl {
            boot_mib: self.vmr.vm_config().mem_size_mib.unwrap_or(128) as u64,
            mem: self.vmr.mem_device.clone(),
            cpu: self.vmr.cpu_device.clone(),
        }
    }

    /// Start the VM. This call never returns on success — the VMM calls
    /// `_exit()` when the guest shuts down, killing the entire process.
    ///
    /// Only returns `Err` if something fails before the VMM takes over.
    pub fn enter(mut self) -> Result<Infallible> {
        let mut trace = BootTrace::new("api");
        trace.mark("enter.start");

        // Set process name on Linux
        #[cfg(target_os = "linux")]
        {
            let prname = match env::var("HOSTNAME") {
                Ok(val) => CString::new(format!("VM:{val}")).unwrap_or_default(),
                Err(_) => CString::new("libkrun VM").unwrap_or_default(),
            };
            unsafe { libc::prctl(libc::PR_SET_NAME, prname.as_ptr()) };
        }

        // Create event manager
        let mut event_manager = EventManager::new()
            .map_err(|e| Error::Build(BuildError::Start(format!("EventManager: {e:?}"))))?;
        trace.mark("event_manager.ready");

        // Load kernel from libkrunfw if not already configured
        if self.vmr.external_kernel.is_none()
            && self.vmr.kernel_bundle.is_none()
            && self.vmr.firmware_config.is_none()
            && cfg!(not(feature = "efi"))
        {
            self.load_krunfw()?;
        }
        trace.mark("kernel.ready");

        // Capture boot start timestamp (epoch nanoseconds) for guest-side timing.
        let boot_start_ns = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        // Build kernel command line
        let kernel_cmdline = self.build_kernel_cmdline(boot_start_ns);

        self.vmr
            .set_kernel_cmdline(kernel_cmdline)
            .map_err(|e| Error::Build(BuildError::Start(format!("kernel cmdline: {e:?}"))))?;
        trace.mark("kernel_cmdline.ready");

        // Configure vsock
        self.configure_vsock()?;
        trace.mark("vsock.configured");

        // Create shutdown EventFd on macOS aarch64 (needed for GPIO shutdown device)
        let shutdown_efd = if cfg!(target_arch = "aarch64") && cfg!(target_os = "macos") {
            Some(
                EventFd::new(utils::eventfd::EFD_NONBLOCK)
                    .map_err(|e| Error::Build(BuildError::Start(format!("shutdown_efd: {e:?}"))))?,
            )
        } else {
            None
        };

        // Build the microVM
        let (sender, _receiver) = unbounded();

        let (_vmm, placement_report) = vmm::builder::build_microvm_paused(
            &mut self.vmr,
            &mut event_manager,
            shutdown_efd,
            sender,
            self.exit_evt,
            self.exit_code,
        )
        .map_err(|e| Error::Build(BuildError::Start(format!("build_microvm: {e:?}"))))?;
        trace.mark("build_microvm.ready");

        if let Some(observer) = self.placement_observer.take() {
            observer(&placement_report);
        }
        trace.mark("placement.reconciled");

        _vmm.lock()
            .expect("Poisoned VMM mutex")
            .resume_vcpus()
            .map_err(|e| Error::Build(BuildError::Start(format!("resume_vcpus: {e:?}"))))?;
        trace.mark("vcpus.resumed");

        // Register user exit observers
        {
            let mut vmm = _vmm.lock().expect("Poisoned VMM mutex");
            for observer in self.exit_observers {
                vmm.add_exit_observer(observer);
            }
        }
        trace.mark("observers.ready");

        // Start worker threads if needed
        #[cfg(target_os = "macos")]
        if self.vmr.gpu_virgl_flags.is_some() {
            vmm::worker::start_worker_thread(_vmm.clone(), _receiver)
                .map_err(|e| Error::Runtime(RuntimeError::EventLoop(format!("{e:?}"))))?;
        }

        #[cfg(target_arch = "x86_64")]
        if self.vmr.split_irqchip {
            vmm::worker::start_worker_thread(_vmm.clone(), _receiver.clone())
                .map_err(|e| Error::Runtime(RuntimeError::EventLoop(format!("{e:?}"))))?;
        }

        #[cfg(all(not(feature = "tee"), target_os = "windows"))]
        if self.vmr.fs.iter().any(|fs| fs.shm_size.is_some()) {
            vmm::worker::start_worker_thread(_vmm.clone(), _receiver.clone())
                .map_err(|e| Error::Runtime(RuntimeError::EventLoop(format!("{e:?}"))))?;
        }

        #[cfg(any(feature = "amd-sev", feature = "tdx"))]
        vmm::worker::start_worker_thread(_vmm.clone(), _receiver.clone())
            .map_err(|e| Error::Runtime(RuntimeError::EventLoop(format!("{e:?}"))))?;
        trace.mark("event_loop.start");

        // Run the event loop. On normal guest exit, the VMM calls _exit() directly.
        loop {
            match event_manager.run() {
                Ok(_) => {}
                Err(e) => {
                    error!("Error in EventManager loop: {e:?}");
                    // Run exit observers before returning so cleanup (terminal
                    // restore, console reset, user callbacks) still fires.
                    _vmm.lock()
                        .expect("Poisoned VMM mutex")
                        .notify_exit_observers(1);
                    return Err(Error::Runtime(RuntimeError::EventLoop(format!("{e:?}"))));
                }
            }
        }
    }

    /// Load kernel from libkrunfw.
    fn load_krunfw(&mut self) -> Result<()> {
        let krunfw = load_krunfw_library(self.krunfw_path.as_deref())?;

        // Get kernel from libkrunfw
        let mut kernel_guest_addr: u64 = 0;
        let mut kernel_entry_addr: u64 = 0;
        let mut kernel_size: usize = 0;

        let kernel_host_addr = unsafe {
            (krunfw.get_kernel)(
                &mut kernel_guest_addr as *mut u64,
                &mut kernel_entry_addr as *mut u64,
                &mut kernel_size as *mut usize,
            )
        };

        let kernel_bundle = KernelBundle {
            host_addr: kernel_host_addr as u64,
            guest_addr: kernel_guest_addr,
            entry_addr: kernel_entry_addr,
            size: kernel_size,
        };

        self.vmr
            .set_kernel_bundle(kernel_bundle)
            .map_err(|e| Error::Build(BuildError::Krunfw(format!("{e:?}"))))?;

        if let Some(initramfs_path) = &self.initramfs_path {
            let initramfs_data = std::fs::read(initramfs_path)?;
            let initrd_bundle = InitrdBundle {
                host_addr: initramfs_data.as_ptr() as u64,
                size: initramfs_data.len(),
            };

            self.vmr
                .set_initrd_bundle(initrd_bundle)
                .map_err(|e| Error::Build(BuildError::Krunfw(format!("{e:?}"))))?;
            self._initramfs_data = Some(initramfs_data);
        }

        // Keep the library alive so the kernel memory pointers remain valid.
        self._krunfw_library = Some(krunfw.library);

        Ok(())
    }

    /// Configure the vsock device.
    ///
    /// The device is only attached when a typed host route exists or the
    /// caller enabled TSI as a transport. This keeps the per-VM IRQ/MMIO
    /// budget free when nothing uses vsock.
    #[cfg(not(target_os = "windows"))]
    fn configure_vsock(&mut self) -> Result<()> {
        let tsi_flags = self.compute_tsi_flags();

        if self.vsock_unix_ipc_port_map.is_none()
            && self.vsock_custom_port_map.is_none()
            && self.vsock_custom_dgram_port_map.is_none()
            && tsi_flags.is_empty()
        {
            return Ok(());
        }

        let vsock_config = VsockDeviceConfig {
            vsock_id: "vsock0".to_string(),
            guest_cid: 3,
            host_port_map: self.vsock_host_port_map.take(),
            unix_ipc_port_map: self.vsock_unix_ipc_port_map.take(),
            custom_port_map: self.vsock_custom_port_map.take(),
            custom_dgram_port_map: self.vsock_custom_dgram_port_map.take(),
            tsi_flags,
        };

        self.vmr
            .set_vsock_device(vsock_config)
            .map_err(|e| Error::Build(BuildError::DeviceRegistration(format!("vsock: {e:?}"))))?;

        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn configure_vsock(&mut self) -> Result<()> {
        if self.vsock_custom_port_map.is_none() {
            return Ok(());
        }

        self.vmr
            .set_vsock_device(VsockDeviceConfig {
                vsock_id: "vsock0".to_string(),
                guest_cid: 3,
                host_port_map: None,
                unix_ipc_port_map: None,
                custom_port_map: self.vsock_custom_port_map.take(),
                tsi_flags: vmm::resources::TsiFlags::empty(),
            })
            .map_err(|err| {
                Error::Build(BuildError::DeviceRegistration(format!("vsock: {err:?}")))
            })?;
        Ok(())
    }

    /// Decide which `TsiFlags` should be enabled for this VM.
    ///
    /// Extracted from [`configure_vsock`](Self::configure_vsock) so the
    /// flag-selection logic can be exercised by unit tests without
    /// touching `VmResources::set_vsock_device`.
    #[cfg(not(target_os = "windows"))]
    fn compute_tsi_flags(&self) -> TsiFlags {
        let mut tsi_flags = TsiFlags::empty();

        // Enable TSI INET hijack as a fallback when no virtio-net is
        // configured and the caller opted in via
        // `MachineBuilder::enable_inet_hijack(true)`. Default is air-gap.
        #[cfg(feature = "net")]
        if self.enable_inet_hijack && self.vmr.net.list.is_empty() {
            tsi_flags |= TsiFlags::HIJACK_INET;
        }

        #[cfg(not(feature = "net"))]
        if self.enable_inet_hijack {
            tsi_flags |= TsiFlags::HIJACK_INET;
        }

        // Enable TSI for AF_UNIX if single root virtio-fs
        #[cfg(all(not(feature = "tee"), not(target_os = "windows")))]
        {
            tsi_flags = self.maybe_enable_hijack_unix(tsi_flags);
        }

        tsi_flags
    }

    fn get_exec_path(&self) -> String {
        self.exec_path
            .as_ref()
            .map(|p| format!("KRUN_INIT={p}"))
            .unwrap_or_default()
    }

    fn get_workdir(&self) -> String {
        self.workdir
            .as_ref()
            .map(|p| format!("KRUN_WORKDIR={p}"))
            .unwrap_or_default()
    }

    fn get_rlimits(&self) -> String {
        self.rlimits
            .as_ref()
            .map(|r| format!("KRUN_RLIMITS={r}"))
            .unwrap_or_default()
    }

    fn get_env(&self) -> String {
        self.env
            .as_ref()
            .map(|e| format!("KRUN_ENV={e}"))
            .unwrap_or_default()
    }

    fn get_args(&self) -> String {
        self.args.clone().unwrap_or_default()
    }

    fn build_kernel_cmdline(&self, boot_start_ns: u64) -> KernelCmdlineConfig {
        let init = self.init_path.as_deref().unwrap_or(INIT_PATH);
        let user_cmdline = self
            .kernel_cmdline
            .as_deref()
            .map(|cmdline| format!(" {cmdline}"))
            .unwrap_or_default();
        // Escape hatch for boot debugging: appended last so it can override earlier parameters (e.g. `ignore_loglevel`, `maxcpus=1`) without any API plumbing.
        let debug_cmdline = std::env::var("MSB_KRUN_KERNEL_CMDLINE")
            .map(|extra| format!(" {extra}"))
            .unwrap_or_default();

        KernelCmdlineConfig {
            prolog: Some(format!(
                "{}{}{debug_cmdline} root=/dev/root init={init}",
                vmm::vmm_config::kernel_cmdline::DEFAULT_KERNEL_CMDLINE,
                user_cmdline,
            )),
            krun_env: Some(format!(
                " {} {} {} {} KRUN_BOOT_START_NS={boot_start_ns}",
                self.get_exec_path(),
                self.get_workdir(),
                self.get_rlimits(),
                self.get_env(),
            )),
            epilog: Some(format!(" -- {}", self.get_args())),
        }
    }

    #[cfg(all(not(feature = "tee"), not(target_os = "windows")))]
    fn maybe_enable_hijack_unix(&self, mut tsi_flags: TsiFlags) -> TsiFlags {
        if cfg!(target_os = "macos") {
            return tsi_flags;
        }

        if tsi_flags.contains(TsiFlags::HIJACK_INET)
            && self.vmr.fs.len() == 1
            && self.vmr.fs[0].fs_id == "/dev/root"
        {
            tsi_flags |= TsiFlags::HIJACK_UNIX;
        }

        tsi_flags
    }
}

struct BootTrace {
    enabled: bool,
    scope: &'static str,
    start: Instant,
    last: Instant,
}

impl BootTrace {
    fn new(scope: &'static str) -> Self {
        let now = Instant::now();
        Self {
            enabled: std::env::var_os("MSB_KRUN_BOOT_TRACE").is_some(),
            scope,
            start: now,
            last: now,
        }
    }

    fn mark(&mut self, label: &'static str) {
        if !self.enabled {
            return;
        }

        let now = Instant::now();
        eprintln!(
            "krun.boot scope={} label={} elapsed_us={} delta_us={}",
            self.scope,
            label,
            now.duration_since(self.start).as_micros(),
            now.duration_since(self.last).as_micros(),
        );
        self.last = now;
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Bindings to libkrunfw functions.
struct KrunfwBindings {
    get_kernel: unsafe extern "C" fn(*mut u64, *mut u64, *mut usize) -> *mut std::ffi::c_char,
    library: libloading::Library,
}

/// Library name for libkrunfw.
#[cfg(target_os = "linux")]
const KRUNFW_NAME: &str = "libkrunfw.so.5";
#[cfg(target_os = "macos")]
const KRUNFW_NAME: &str = "libkrunfw.5.dylib";
#[cfg(target_os = "windows")]
const KRUNFW_NAME: &str = "libkrunfw.dll";

/// Load the libkrunfw library.
///
/// If `path` is provided, loads from that exact path. Otherwise falls back to the
/// default library name, which lets the OS dynamic linker search standard paths.
fn load_krunfw_library(path: Option<&std::path::Path>) -> Result<KrunfwBindings> {
    let name = path
        .map(|p| p.as_os_str().to_os_string())
        .unwrap_or_else(|| std::ffi::OsString::from(KRUNFW_NAME));
    let library = unsafe { libloading::Library::new(&name) }.map_err(|e| {
        Error::Build(BuildError::Krunfw(format!(
            "load {}: {e}",
            name.to_string_lossy()
        )))
    })?;

    let get_kernel = unsafe {
        *library
            .get::<unsafe extern "C" fn(*mut u64, *mut u64, *mut usize) -> *mut std::ffi::c_char>(
                b"krunfw_get_kernel\0",
            )
            .map_err(|e| Error::Build(BuildError::Krunfw(format!("krunfw_get_kernel: {e}"))))?
    };

    Ok(KrunfwBindings {
        get_kernel,
        library,
    })
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(target_os = "windows"))]
    use crate::VmBuilder;
    use utils::eventfd::EFD_NONBLOCK;
    #[cfg(not(target_os = "windows"))]
    use vmm::resources::TsiFlags;
    #[cfg(all(not(feature = "tee"), not(target_os = "windows")))]
    use vmm::vmm_config::fs::FsDeviceConfig;

    fn make_vm() -> Vm {
        Vm::new(
            VmResources::default(),
            Some("debug loglevel=7".to_string()),
            None,
            Some("\"--flag\"".to_string()),
            None,
            None,
            None,
            None,
            None,
            None,
            Vec::new(),
            None,
            EventFd::new(EFD_NONBLOCK).unwrap(),
            Arc::new(AtomicI32::new(i32::MAX)),
            #[cfg(not(target_os = "windows"))]
            false,
            #[cfg(not(target_os = "windows"))]
            None,
            None,
            #[cfg(not(target_os = "windows"))]
            None,
            #[cfg(not(target_os = "windows"))]
            None,
        )
    }

    #[cfg(not(target_os = "windows"))]
    fn make_vm_with(enable_inet_hijack: bool) -> Vm {
        Vm::new(
            VmResources::default(),
            Some("debug loglevel=7".to_string()),
            None,
            Some("\"--flag\"".to_string()),
            None,
            None,
            None,
            None,
            None,
            None,
            Vec::new(),
            None,
            EventFd::new(EFD_NONBLOCK).unwrap(),
            Arc::new(AtomicI32::new(i32::MAX)),
            enable_inet_hijack,
            None,
            None,
            None,
            None,
        )
    }

    #[test]
    fn build_kernel_cmdline_keeps_user_cmdline() {
        let vm = make_vm();
        let cmdline = vm.build_kernel_cmdline(42);

        let prolog = cmdline.prolog.expect("missing prolog");
        assert!(prolog.contains("debug loglevel=7"));
        assert!(prolog.contains("init=/init.krun"));
    }

    #[cfg(all(not(feature = "tee"), not(target_os = "windows")))]
    #[test]
    fn maybe_enable_hijack_unix_respects_platform_support() {
        let mut vm = make_vm();
        vm.vmr.fs.push(FsDeviceConfig {
            fs_id: "/dev/root".to_string(),
            shared_dir: "/tmp/rootfs".to_string(),
            shm_size: None,
            allow_root_dir_delete: false,
        });

        let flags = vm.maybe_enable_hijack_unix(TsiFlags::HIJACK_INET);

        #[cfg(target_os = "macos")]
        assert!(!flags.contains(TsiFlags::HIJACK_UNIX));

        #[cfg(not(target_os = "macos"))]
        assert!(flags.contains(TsiFlags::HIJACK_UNIX));
    }

    #[cfg(all(
        not(feature = "tee"),
        not(target_os = "macos"),
        not(target_os = "windows")
    ))]
    #[test]
    fn maybe_enable_hijack_unix_requires_root_fs_id() {
        let mut vm = make_vm();
        vm.vmr.fs.push(FsDeviceConfig {
            fs_id: "data".to_string(),
            shared_dir: "/".to_string(),
            shm_size: None,
            allow_root_dir_delete: false,
        });

        let flags = vm.maybe_enable_hijack_unix(TsiFlags::HIJACK_INET);

        assert!(!flags.contains(TsiFlags::HIJACK_UNIX));
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn compute_tsi_flags_air_gaps_by_default_with_no_net() {
        let vm = make_vm();
        let flags = vm.compute_tsi_flags();
        assert!(!flags.contains(TsiFlags::HIJACK_INET));
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn compute_tsi_flags_enables_inet_hijack_when_opted_in() {
        let vm = make_vm_with(true);
        let flags = vm.compute_tsi_flags();
        assert!(flags.contains(TsiFlags::HIJACK_INET));
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn typed_vsock_routes_imply_attachment_and_reach_vm_config() {
        use std::io;

        use devices::virtio::vsock::{
            VsockConnectRequest, VsockNotifier, VsockPortBackend, VsockStreamBackend,
        };

        struct RejectService;

        impl VsockPortBackend for RejectService {
            fn connect(
                &self,
                _request: VsockConnectRequest,
                _notifier: VsockNotifier,
            ) -> io::Result<Box<dyn VsockStreamBackend>> {
                Err(io::Error::from(io::ErrorKind::ConnectionRefused))
            }
        }

        let vm = VmBuilder::new()
            .vsock(|vsock| {
                vsock
                    .unix_connect(5000, "/tmp/supervisor.sock")
                    .unix_listen(5001, "/tmp/events.sock")
                    .custom(6000, Arc::new(RejectService))
                    .inet_hijack(true)
                    .tcp_listen_remap(8080, 18080)
            })
            .build()
            .expect("typed vsock configuration should build");

        assert_eq!(
            vm.vsock_unix_ipc_port_map
                .as_ref()
                .and_then(|routes| routes.get(&5000)),
            Some(&(PathBuf::from("/tmp/supervisor.sock"), false))
        );
        assert_eq!(
            vm.vsock_unix_ipc_port_map
                .as_ref()
                .and_then(|routes| routes.get(&5001)),
            Some(&(PathBuf::from("/tmp/events.sock"), true))
        );
        assert!(vm
            .vsock_custom_port_map
            .as_ref()
            .is_some_and(|routes| routes.contains_key(&6000)));
        assert_eq!(
            vm.vsock_host_port_map
                .as_ref()
                .and_then(|routes| routes.get(&8080)),
            Some(&18080)
        );
        assert!(vm.compute_tsi_flags().contains(TsiFlags::HIJACK_INET));
    }

    #[cfg(all(
        not(feature = "tee"),
        not(target_os = "macos"),
        not(target_os = "windows")
    ))]
    #[test]
    fn compute_tsi_flags_unix_hijack_follows_inet_hijack() {
        let mut vm = make_vm();
        vm.vmr.fs.push(FsDeviceConfig {
            fs_id: "/dev/root".to_string(),
            shared_dir: "/tmp/rootfs".to_string(),
            shm_size: None,
            allow_root_dir_delete: false,
        });

        let flags = vm.compute_tsi_flags();

        // `maybe_enable_hijack_unix` gates UNIX hijack on INET hijack
        // already being set, so the default (no opt-in) drops both.
        assert!(!flags.contains(TsiFlags::HIJACK_INET));
        assert!(!flags.contains(TsiFlags::HIJACK_UNIX));
    }
}

#[cfg(not(feature = "tee"))]
impl VmControl {
    /// Whether the running VM can resize memory live.
    pub fn memory_resize_supported(&self) -> bool {
        self.mem.is_some()
    }

    /// Whether the running VM can resize its online CPU count live.
    pub fn cpu_resize_supported(&self) -> bool {
        self.cpu.is_some()
    }

    /// Ask the guest to converge on `online` CPUs and enforce that ceiling
    /// host-side. Returns the accepted target (clamped to 1..=possible), or
    /// `None` when the VM booted without CPU capacity. The guest driver
    /// onlines/offlines asynchronously; poll [`cpu_state`](Self::cpu_state)
    /// for convergence — enforcement applies immediately either way.
    pub fn set_cpu_target(&self, online: u32) -> Option<u32> {
        let cpu = self.cpu.as_ref()?;
        Some(cpu.lock().unwrap().set_requested_online(online))
    }

    /// Current CPU sizing, or `None` when the VM booted without capacity.
    pub fn cpu_state(&self) -> Option<VmCpuState> {
        let cpu = self.cpu.as_ref()?;
        let snap = cpu.lock().unwrap().state_snapshot();
        Some(VmCpuState {
            possible: snap.possible,
            requested_online: snap.requested_online,
            actual_online: snap.actual_online,
            enforced: snap.enforced,
        })
    }

    /// Ask the guest to converge on `total_mib` of usable memory.
    ///
    /// Returns the accepted target in MiB (clamped to the boot..max range and
    /// rounded down to hotplug block granularity), or `None` when the VM
    /// booted without hotplug capacity. The guest plugs/unplugs blocks
    /// asynchronously; poll [`memory_state`](Self::memory_state) for
    /// convergence.
    pub fn set_memory_target_mib(&self, total_mib: u64) -> Option<u64> {
        let mem = self.mem.as_ref()?;
        let hotplug_target = total_mib.saturating_sub(self.boot_mib) << 20;
        let accepted = mem.lock().unwrap().set_requested_size(hotplug_target);
        Some(self.boot_mib + (accepted >> 20))
    }

    /// Current memory sizing, or `None` when the VM booted without capacity.
    pub fn memory_state(&self) -> Option<VmMemoryState> {
        let mem = self.mem.as_ref()?;
        let snap = mem.lock().unwrap().state_snapshot();
        Some(VmMemoryState {
            boot_mib: self.boot_mib,
            target_mib: self.boot_mib + (snap.requested_size >> 20),
            current_mib: self.boot_mib + (snap.plugged_size >> 20),
            max_mib: self.boot_mib + (snap.region_size >> 20),
        })
    }
}
