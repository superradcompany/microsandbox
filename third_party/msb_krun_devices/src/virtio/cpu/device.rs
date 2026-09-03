use std::cmp;
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use utils::eventfd::EventFd;
use vm_memory::{ByteValued, GuestMemoryMmap};

use super::super::{
    ActivateError, ActivateResult, CpuDeviceError, DeviceQueue, DeviceState, QueueConfig,
    VirtioDevice,
};
use super::{defs, defs::uapi};
use crate::virtio::InterruptTransport;

pub(crate) const BASE_AVAIL_FEATURES: u64 = 1 << uapi::VIRTIO_F_VERSION_1 as u64;

/// How long a vCPU above the enforced count keeps running before it is
/// throttled, giving a cooperative guest time to offline it cleanly.
pub const ENFORCEMENT_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

/// How long an enforced-off vCPU parks between emulation steps once the grace window expires.
///
/// Enforcement throttles instead of freezing the vCPU outright: a guest without the msb-cpu driver keeps the CPU online, and fully parking an online CPU deadlocks the whole
/// guest — cross-CPU synchronization (IPIs, TLB shootdowns, RCU) waits forever for the parked CPU, wedging the initiating CPUs too. Waking for one emulation step per park
/// interval keeps that machinery draining at a duty cycle too small to matter for compute.
pub const THROTTLE_PARK: std::time::Duration = std::time::Duration::from_millis(100);

/// How long an enforced vCPU may stay inside a single emulation step before the kicker forces it back to the host.
///
/// A hard-spinning guest takes no VM exits at all (on HVF even the vtimer is hardware-virtualized), so without a forced exit an enforced vCPU's run loop would never observe
/// enforcement. Together with [`THROTTLE_PARK`] this bounds an uncooperative vCPU's duty cycle to roughly `slice / (slice + park)`.
const ENFORCED_RUN_SLICE: Duration = Duration::from_millis(5);

/// How often the kicker thread scans for enforced vCPUs overstaying their run slice. It only runs while some vCPU is enforced off.
const KICK_INTERVAL: Duration = Duration::from_millis(5);

/// Sentinel for [`CpuKickSlot::entered_ns`]: the vCPU is not inside an emulation step.
const NOT_IN_GUEST: u64 = u64::MAX;

// Config space offsets (three little-endian u32 fields).
const CONFIG_ACTUAL_ONLINE_OFFSET: u64 = 8;

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioCpuConfig {
    possible: u32,
    requested_online: u32,
    actual_online: u32,
}

// Safe because it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioCpuConfig {}

/// Host-authoritative CPU count shared with every vCPU run loop.
///
/// vCPUs whose index is at or above `enforced` are throttled between emulation
/// steps until the count is raised again, so a guest that refuses to offline a
/// CPU loses almost all execution time on it while the guest as a whole stays
/// live (see [`THROTTLE_PARK`]). Run loops grant a short grace window
/// ([`ENFORCEMENT_GRACE`]) before throttling, because a graceful offline needs
/// the dying CPU to execute its own PSCI CPU_OFF path. The boot CPU is always
/// runnable: `enforced` is clamped to at least 1.
pub struct CpuEnforcement {
    possible: u32,
    enforced: AtomicU32,
    gate: Mutex<()>,
    raised: Condvar,
    kick_slots: Mutex<Vec<Arc<CpuKickSlot>>>,
    kicker_running: AtomicBool,
}

/// A vCPU's registration with the enforcement kicker.
///
/// The vCPU run loop brackets every emulation step with [`enter_guest`](Self::enter_guest)/[`leave_guest`](Self::leave_guest); the kicker forces an exit only on vCPUs that
/// have been inside one step longer than [`ENFORCED_RUN_SLICE`], so parked or event-waiting vCPUs never accumulate spurious cancellations that would swallow their next
/// (progress-making) emulation step.
pub struct CpuKickSlot {
    cpu_index: u32,
    /// Monotonic timestamp (ns) when the current emulation step started, or [`NOT_IN_GUEST`].
    entered_ns: AtomicU64,
    kick: Box<dyn Fn() + Send + Sync>,
}

impl CpuKickSlot {
    /// Mark this vCPU as entering an emulation step.
    pub fn enter_guest(&self) {
        self.entered_ns.store(monotonic_ns(), Ordering::Release);
    }

    /// Mark this vCPU as back on the host.
    pub fn leave_guest(&self) {
        self.entered_ns.store(NOT_IN_GUEST, Ordering::Release);
    }
}

impl CpuEnforcement {
    fn new(possible: u32, enforced: u32) -> Arc<Self> {
        Arc::new(Self {
            possible,
            enforced: AtomicU32::new(enforced.max(1)),
            gate: Mutex::new(()),
            raised: Condvar::new(),
            kick_slots: Mutex::new(Vec::new()),
            kicker_running: AtomicBool::new(false),
        })
    }

    fn set(this: &Arc<Self>, enforced: u32) {
        let enforced = enforced.max(1);
        this.enforced.store(enforced, Ordering::Release);
        {
            let _guard = this.gate.lock().unwrap();
            this.raised.notify_all();
        }
        if enforced < this.possible {
            Self::spawn_kicker(this);
        }
    }

    /// Register the calling vCPU thread for forced exits. `kick` must make the vCPU's in-flight emulation step return to the host (`hv_vcpus_exit` on macOS, the vCPU kick
    /// signal on Linux) and be callable from any thread.
    pub fn register_kicker(
        self: &Arc<Self>,
        cpu_index: u32,
        kick: Box<dyn Fn() + Send + Sync>,
    ) -> Arc<CpuKickSlot> {
        let slot = Arc::new(CpuKickSlot {
            cpu_index,
            entered_ns: AtomicU64::new(NOT_IN_GUEST),
            kick,
        });
        self.kick_slots.lock().unwrap().push(slot.clone());
        // The VM may boot (or a guest may CPU_ON a vCPU) with enforcement already below the possible count; make sure the kicker covers that from the start.
        if self.enforced() < self.possible {
            Self::spawn_kicker(self);
        }
        slot
    }

    /// Start the kicker thread if some vCPU is enforced off and no kicker is running.
    ///
    /// The kicker periodically forces enforced vCPUs that overstay [`ENFORCED_RUN_SLICE`] out of guest mode so their run loops observe enforcement even when the guest takes
    /// no VM exits on its own. It exits once enforcement covers every possible vCPU again (holding only a `Weak`, so it also dies with the device).
    fn spawn_kicker(this: &Arc<Self>) {
        if this
            .kicker_running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let weak = Arc::downgrade(this);
        thread::Builder::new()
            .name("msb-cpu kicker".into())
            .spawn(move || loop {
                thread::sleep(KICK_INTERVAL);
                let Some(this) = weak.upgrade() else { return };
                let enforced = this.enforced();
                if enforced >= this.possible {
                    this.kicker_running.store(false, Ordering::Release);
                    // set() may have lowered enforcement between the check above and the store; reclaim the flag rather than leave that lowering unkicked.
                    if this.enforced() < this.possible
                        && this
                            .kicker_running
                            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                            .is_ok()
                    {
                        continue;
                    }
                    return;
                }
                let now = monotonic_ns();
                let slice_ns = ENFORCED_RUN_SLICE.as_nanos() as u64;
                for slot in this.kick_slots.lock().unwrap().iter() {
                    if slot.cpu_index < enforced {
                        continue;
                    }
                    let entered = slot.entered_ns.load(Ordering::Acquire);
                    if entered != NOT_IN_GUEST && now.saturating_sub(entered) >= slice_ns {
                        (slot.kick)();
                    }
                }
            })
            .expect("failed to spawn msb-cpu kicker thread");
    }

    /// Current enforced online count.
    pub fn enforced(&self) -> u32 {
        self.enforced.load(Ordering::Acquire)
    }

    /// Whether the vCPU with this index may run right now. Cheap enough for
    /// the per-iteration check in vCPU run loops.
    pub fn runnable(&self, cpu_index: u32) -> bool {
        cpu_index < self.enforced()
    }

    /// Park the calling vCPU thread for one throttle interval ([`THROTTLE_PARK`]), returning early if its index becomes runnable. The caller runs one emulation step
    /// between parks so guest-wide synchronization that involves this CPU still completes.
    pub fn throttle(&self, cpu_index: u32) {
        let deadline = std::time::Instant::now() + THROTTLE_PARK;
        let mut guard = self.gate.lock().unwrap();
        while cpu_index >= self.enforced.load(Ordering::Acquire) {
            let now = std::time::Instant::now();
            if now >= deadline {
                return;
            }
            let (next, _timeout) = self.raised.wait_timeout(guard, deadline - now).unwrap();
            guard = next;
        }
    }
}

/// Monotonic nanoseconds since the first call; only ever compared against itself.
fn monotonic_ns() -> u64 {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    EPOCH.get_or_init(Instant::now).elapsed().as_nanos() as u64
}

/// Point-in-time view of the device for host-side control and reporting.
#[derive(Debug, Clone, Copy)]
pub struct CpuStateSnapshot {
    /// CPUs possible in this boot.
    pub possible: u32,

    /// Online count the host asked the guest to converge on.
    pub requested_online: u32,

    /// Online count the guest last reported.
    pub actual_online: u32,

    /// Online count the VMM currently enforces.
    pub enforced: u32,
}

pub struct Cpu {
    pub(crate) queues: Option<Vec<DeviceQueue>>,
    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,
    pub(crate) activate_evt: EventFd,
    pub(crate) device_state: DeviceState,
    config: VirtioCpuConfig,
    enforcement: Arc<CpuEnforcement>,
}

impl Cpu {
    /// Create the CPU capacity device for a VM booting `initial_online` of
    /// `possible` CPUs. Enforcement starts at the initial count.
    pub fn new(possible: u32, initial_online: u32) -> super::Result<Cpu> {
        Ok(Cpu {
            queues: None,
            avail_features: BASE_AVAIL_FEATURES,
            acked_features: 0,
            activate_evt: EventFd::new(utils::eventfd::EFD_NONBLOCK)
                .map_err(CpuDeviceError::EventFd)?,
            device_state: DeviceState::Inactive,
            config: VirtioCpuConfig {
                possible,
                requested_online: initial_online,
                actual_online: initial_online,
            },
            enforcement: CpuEnforcement::new(possible, initial_online),
        })
    }

    pub fn id(&self) -> &str {
        defs::CPU_DEV_ID
    }

    /// The enforcement state vCPU run loops consult. Cloned once per vCPU at
    /// creation time.
    pub fn enforcement(&self) -> Arc<CpuEnforcement> {
        self.enforcement.clone()
    }

    /// Host control: ask the guest to converge on `online` CPUs and enforce
    /// that ceiling host-side. Clamps to 1..=possible; signals a config change
    /// when the device is active. Returns the accepted target.
    pub fn set_requested_online(&mut self, online: u32) -> u32 {
        let online = cmp::min(online.max(1), self.config.possible);
        self.config.requested_online = online;
        CpuEnforcement::set(&self.enforcement, online);
        if let DeviceState::Activated(_, ref interrupt) = self.device_state {
            interrupt.signal_config_change();
        }
        online
    }

    /// Host control: current requested/actual/enforced view.
    pub fn state_snapshot(&self) -> CpuStateSnapshot {
        CpuStateSnapshot {
            possible: self.config.possible,
            requested_online: self.config.requested_online,
            actual_online: self.config.actual_online,
            enforced: self.enforcement.enforced(),
        }
    }
}

impl VirtioDevice for Cpu {
    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features
    }

    fn device_type(&self) -> u32 {
        uapi::VIRTIO_ID_MSB_CPU
    }

    fn device_name(&self) -> &str {
        "msb-cpu"
    }

    fn queue_config(&self) -> &[QueueConfig] {
        &defs::QUEUE_CONFIG
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config_slice = self.config.as_slice();
        let config_len = config_slice.len() as u64;
        if offset >= config_len {
            error!("virtio-msb-cpu: failed to read config space");
            return;
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against config_len.
            data.write_all(&config_slice[offset as usize..cmp::min(end, config_len) as usize])
                .unwrap();
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        // The guest driver reports the online count it converged on; that is
        // the only writable field.
        if offset == CONFIG_ACTUAL_ONLINE_OFFSET && data.len() == 4 {
            self.config.actual_online = u32::from_le_bytes(data.try_into().unwrap());
            return;
        }
        warn!(
            "virtio-msb-cpu: rejected guest config write (offset={:x}, len={:x})",
            offset,
            data.len()
        );
    }

    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
    ) -> ActivateResult {
        if queues.len() != defs::NUM_QUEUES {
            error!(
                "Cannot perform activate. Expected {} queue(s), got {}",
                defs::NUM_QUEUES,
                queues.len()
            );
            return Err(ActivateError::BadActivate);
        }

        if self.activate_evt.write(1).is_err() {
            error!("Cannot write to activate_evt");
            return Err(ActivateError::BadActivate);
        }

        self.queues = Some(queues);
        self.device_state = DeviceState::Activated(mem, interrupt);

        Ok(())
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }
}
