//! Host-scoped shared filesystem watching for followed log streams.
//!
//! A [`LogRegistry`] owns a single [`notify::RecommendedWatcher`]
//! (one inotify instance + one thread on Linux) and multiplexes it
//! across every followed sandbox log stream on the host. Each sandbox
//! log directory is watched once regardless of how many streams tail
//! it; a filesystem event bumps a per-directory coalescing signal that
//! wakes exactly the engines reading that directory.
//!
//! This exists because the standalone path builds one watcher per
//! followed stream (see `super::stream::FollowMode::Standalone`), which
//! exhausts `fs.inotify.max_user_instances` once a host holds enough
//! sandboxes. Host orchestrators managing many sandboxes opt in by
//! constructing one registry and registering each sandbox's logger.
//!
//! The registry is a wake signal only: log files remain the source of
//! truth, so over-waking is merely a wasted parse and a missed event is
//! caught by the engine's fallback poll.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};

use notify::Watcher;
use tokio::sync::{oneshot, watch};

use super::logger::{RegisteredSandboxLogger, SandboxLogger};
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Host-scoped registry sharing one filesystem watcher across many
/// followed log streams. Cheap to clone — every clone points at the
/// same underlying watcher and routing table.
#[derive(Clone)]
pub struct LogRegistry {
    inner: Arc<RegistryInner>,
}

struct RegistryInner {
    /// Serializes registrations so only the first registrant of a new
    /// directory issues a `watch`. A tokio mutex because `register` holds
    /// it across the admin-thread round-trip await; NEVER taken by the
    /// event callback or by Drop, so it gates neither routing nor
    /// teardown.
    admin: tokio::sync::Mutex<()>,
    /// Commands to the watcher-admin thread that owns the single watcher.
    /// `watch`/`unwatch` run there in FIFO order, off every runtime
    /// thread.
    admin_tx: mpsc::Sender<AdminCommand>,
    /// Routing table. A plain `Mutex` suffices: its only users are
    /// notify's single callback thread — which delivers events serially,
    /// so events never contend event-vs-event — and the rare cold-path
    /// register/Drop mutators. The callback locks it just to look up and
    /// clone the signal `Arc`(s); every wake happens after the lock is
    /// released.
    dirs: Arc<Mutex<HashMap<PathBuf, DirEntry>>>,
    /// `dirs.len()` mirrored so [`stats`](LogRegistry::stats) never
    /// locks the map.
    registered_dirs: Arc<AtomicUsize>,
    stats: Arc<RegistryStats>,
}

/// A watch-lifecycle request for the watcher-admin thread. `Watch`
/// carries a reply channel so `register` learns the outcome; `Unwatch` is
/// fire-and-forget because Drop cannot await. FIFO delivery keeps a later
/// re-`watch` of a path ordered after its `unwatch`.
enum AdminCommand {
    Watch {
        dir: PathBuf,
        reply: oneshot::Sender<notify::Result<()>>,
    },
    Unwatch {
        dir: PathBuf,
    },
}

/// One watched directory: a coalescing wake signal plus the refcount of
/// live loggers and streams keeping it registered.
struct DirEntry {
    /// Bumped counter; subscribers await `changed()`. `Arc` so the
    /// callback can wake outside the map lock.
    signal: Arc<watch::Sender<u64>>,
    /// Live loggers + live streams for this directory. The watch is torn
    /// down when this reaches zero.
    registrations: usize,
}

#[derive(Default)]
struct RegistryStats {
    total_registrations: AtomicUsize,
    wake_all_events: AtomicU64,
    route_misses: AtomicU64,
    watch_failures: AtomicU64,
}

/// Point-in-time counters for host-side instrumentation. All fields are
/// cumulative except `registered_dirs` and `total_registrations`, which
/// are current gauges.
#[derive(Debug, Clone, Copy)]
pub struct RegistryStatsSnapshot {
    /// Directories currently watched (== inotify watch descriptors).
    pub registered_dirs: usize,
    /// Sum of refcounts across all directories (live loggers + streams).
    pub total_registrations: usize,
    /// Overflow/error recoveries that woke every subscriber to rescan.
    pub wake_all_events: u64,
    /// Filesystem events that matched no registered directory.
    pub route_misses: u64,
    /// `watcher.watch()` failures during registration.
    pub watch_failures: u64,
}

/// RAII token keeping a sandbox log directory registered. Cloning bumps
/// the directory's refcount; dropping the last outstanding token removes
/// the watch. Held inside a [`RegisteredSandboxLogger`] and inside every
/// `LogSubscription` a stream carries.
pub struct LogRegistration {
    inner: Arc<RegistryInner>,
    dir: PathBuf,
}

/// A followed stream's handle on the shared watcher: the wake receiver
/// plus a registration clone that keeps the directory watched for as
/// long as the stream lives.
pub(crate) struct LogSubscription {
    rx: watch::Receiver<u64>,
    _registration: LogRegistration,
}

//--------------------------------------------------------------------------------------------------
// LogRegistry
//--------------------------------------------------------------------------------------------------

impl LogRegistry {
    /// Build a registry with one shared watcher and its watcher-admin
    /// thread. Fails if the platform watcher cannot be created or the
    /// thread cannot be spawned.
    pub fn new() -> MicrosandboxResult<Self> {
        let dirs: Arc<Mutex<HashMap<PathBuf, DirEntry>>> = Arc::new(Mutex::new(HashMap::new()));
        let stats = Arc::new(RegistryStats::default());

        let cb_dirs = Arc::clone(&dirs);
        let cb_stats = Arc::clone(&stats);
        let watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
            route_event(&cb_dirs, &cb_stats, res);
        })
        .map_err(|e| MicrosandboxError::Custom(format!("log watch registry init failed: {e}")))?;

        // A dedicated thread owns the watcher so watch/unwatch never run on
        // a runtime thread and stay serialized. It exits once the last
        // command sender (held via RegistryInner) drops.
        let (admin_tx, admin_rx) = mpsc::channel();
        std::thread::Builder::new()
            .name("log-watch-admin".into())
            .spawn(move || admin_loop(watcher, admin_rx))
            .map_err(|e| {
                MicrosandboxError::Custom(format!("log watch admin thread spawn failed: {e}"))
            })?;

        Ok(Self {
            inner: Arc::new(RegistryInner {
                admin: tokio::sync::Mutex::new(()),
                admin_tx,
                dirs,
                registered_dirs: Arc::new(AtomicUsize::new(0)),
                stats,
            }),
        })
    }

    /// Register `logger` with the shared watcher and return a
    /// registry-backed logger whose followed streams share one watch
    /// descriptor. Returns [`MicrosandboxError::SandboxNotFound`] if the
    /// log directory does not exist.
    ///
    /// Async and non-blocking: the blocking `watch()` runs on the
    /// watcher-admin thread and `register` only awaits its reply, so a
    /// caller on the tokio runtime never stalls a worker.
    pub async fn register(
        &self,
        logger: SandboxLogger,
    ) -> MicrosandboxResult<RegisteredSandboxLogger> {
        // Canonicalize so different spellings of one directory share a
        // single watch, and use the lookup as the existence check.
        let dir = tokio::fs::canonicalize(logger.log_dir())
            .await
            .map_err(|_| MicrosandboxError::SandboxNotFound(logger.name().to_string()))?;

        let inner = &self.inner;
        let _admin = inner.admin.lock().await;

        // Fast path: directory already watched — just bump the refcount.
        {
            let mut map = lock(&inner.dirs);
            if let Some(entry) = map.get_mut(&dir) {
                entry.registrations += 1;
                inner
                    .stats
                    .total_registrations
                    .fetch_add(1, Ordering::Relaxed);
                return Ok(RegisteredSandboxLogger::new(
                    logger,
                    LogRegistration {
                        inner: Arc::clone(inner),
                        dir,
                    },
                ));
            }
        }

        // New directory: hand the blocking `watch` to the admin thread and
        // await its result. `admin` (held) guarantees no other registrant
        // observes this directory until the watch succeeds and the entry
        // is inserted, so a failed watch needs no rollback.
        let (reply_tx, reply_rx) = oneshot::channel();
        inner
            .admin_tx
            .send(AdminCommand::Watch {
                dir: dir.clone(),
                reply: reply_tx,
            })
            .map_err(|_| MicrosandboxError::Custom("log watch admin thread stopped".into()))?;
        reply_rx
            .await
            .map_err(|_| MicrosandboxError::Custom("log watch admin thread dropped reply".into()))?
            .map_err(|e| {
                inner.stats.watch_failures.fetch_add(1, Ordering::Relaxed);
                MicrosandboxError::Custom(format!(
                    "log watch subscribe failed for {}: {e}",
                    dir.display()
                ))
            })?;

        {
            let (tx, _rx) = watch::channel(0u64);
            lock(&inner.dirs).insert(
                dir.clone(),
                DirEntry {
                    signal: Arc::new(tx),
                    registrations: 1,
                },
            );
        }
        inner.registered_dirs.fetch_add(1, Ordering::Relaxed);
        inner
            .stats
            .total_registrations
            .fetch_add(1, Ordering::Relaxed);

        Ok(RegisteredSandboxLogger::new(
            logger,
            LogRegistration {
                inner: Arc::clone(inner),
                dir,
            },
        ))
    }

    /// Snapshot the instrumentation counters.
    pub fn stats(&self) -> RegistryStatsSnapshot {
        let s = &self.inner.stats;
        RegistryStatsSnapshot {
            registered_dirs: self.inner.registered_dirs.load(Ordering::Relaxed),
            total_registrations: s.total_registrations.load(Ordering::Relaxed),
            wake_all_events: s.wake_all_events.load(Ordering::Relaxed),
            route_misses: s.route_misses.load(Ordering::Relaxed),
            watch_failures: s.watch_failures.load(Ordering::Relaxed),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// LogRegistration
//--------------------------------------------------------------------------------------------------

impl LogRegistration {
    /// Subscribe a new followed stream to this directory's wake signal.
    /// The returned subscription carries a registration clone, so the
    /// directory stays watched until the stream drops.
    pub(crate) fn subscribe(&self) -> LogSubscription {
        // The source registration keeps the entry alive, so this lookup
        // always hits.
        let rx = lock(&self.inner.dirs)
            .get(&self.dir)
            .map(|entry| entry.signal.subscribe())
            .expect("registration keeps its dir entry alive");
        LogSubscription {
            rx,
            _registration: self.clone(),
        }
    }
}

impl Clone for LogRegistration {
    fn clone(&self) -> Self {
        // Brief map lock, no `admin`, no syscall: the source handle keeps
        // this directory's refcount >= 1, so no concurrent drop can
        // remove the entry mid-clone.
        {
            let mut map = lock(&self.inner.dirs);
            if let Some(entry) = map.get_mut(&self.dir) {
                entry.registrations += 1;
                self.inner
                    .stats
                    .total_registrations
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
        Self {
            inner: Arc::clone(&self.inner),
            dir: self.dir.clone(),
        }
    }
}

impl Drop for LogRegistration {
    fn drop(&mut self) {
        // Decrement under the map lock; on the last drop remove the entry
        // and enqueue the unwatch under the SAME lock, so the command's
        // FIFO order matches the map-state order — a later re-watch of this
        // path is guaranteed to enqueue after this unwatch. Non-blocking:
        // the watcher round-trip happens on the admin thread.
        let mut map = lock(&self.inner.dirs);
        let Some(entry) = map.get_mut(&self.dir) else {
            return;
        };
        entry.registrations -= 1;
        self.inner
            .stats
            .total_registrations
            .fetch_sub(1, Ordering::Relaxed);
        if entry.registrations > 0 {
            return;
        }

        map.remove(&self.dir);
        self.inner.registered_dirs.fetch_sub(1, Ordering::Relaxed);
        let _ = self.inner.admin_tx.send(AdminCommand::Unwatch {
            dir: self.dir.clone(),
        });
    }
}

//--------------------------------------------------------------------------------------------------
// LogSubscription
//--------------------------------------------------------------------------------------------------

impl LogSubscription {
    /// Await the next wake for this directory. Returns `Err` only if the
    /// sender has closed, which the held registration clone prevents
    /// while the stream lives.
    pub(crate) async fn changed(&mut self) -> Result<(), watch::error::RecvError> {
        self.rx.changed().await
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Own the single watcher and serve watch/unwatch requests in FIFO
/// order. Runs on a dedicated thread so these (possibly slow) calls never
/// touch a runtime thread. Exits when every [`RegistryInner`] — and thus
/// every command sender — has dropped.
fn admin_loop(mut watcher: notify::RecommendedWatcher, rx: mpsc::Receiver<AdminCommand>) {
    while let Ok(command) = rx.recv() {
        match command {
            AdminCommand::Watch { dir, reply } => {
                let result = watcher.watch(&dir, notify::RecursiveMode::NonRecursive);
                let _ = reply.send(result);
            }
            AdminCommand::Unwatch { dir } => {
                let _ = watcher.unwatch(&dir);
            }
        }
    }
}

/// Route one watcher callback. Runs on notify's single callback thread,
/// so events are handled serially — one at a time. Fans out to every
/// subscriber on overflow/error, otherwise wakes only the directories the
/// event touched. Signals are cloned under the map lock and woken after it
/// is released, so routing never holds the map across a wake.
fn route_event(
    dirs: &Mutex<HashMap<PathBuf, DirEntry>>,
    stats: &RegistryStats,
    res: notify::Result<notify::Event>,
) {
    let event = match res {
        Ok(event) => {
            if event.need_rescan() {
                wake_all(dirs, stats);
                return;
            }
            event
        }
        // A watcher-level error may mean dropped events; rescan all.
        Err(_) => {
            wake_all(dirs, stats);
            return;
        }
    };

    use notify::EventKind;
    if !matches!(
        event.kind,
        EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_)
    ) {
        return;
    }

    let signals = collect_signals(dirs, stats, &event.paths);
    for signal in signals {
        signal.send_modify(|v| *v = v.wrapping_add(1));
    }
}

/// Resolve each event path to its owning directory (the path itself, or
/// its parent for a child entry) and collect the matching wake signals.
fn collect_signals(
    dirs: &Mutex<HashMap<PathBuf, DirEntry>>,
    stats: &RegistryStats,
    paths: &[PathBuf],
) -> Vec<Arc<watch::Sender<u64>>> {
    let map = lock(dirs);
    let mut signals = Vec::new();
    for path in paths {
        let entry = map
            .get(path.as_path())
            .or_else(|| path.parent().and_then(|parent| map.get(parent)));
        match entry {
            Some(entry) => signals.push(Arc::clone(&entry.signal)),
            None => {
                stats.route_misses.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    signals
}

/// Snapshot every signal under one brief lock, then wake them all — used
/// for inotify overflow and watcher errors so readers rescan their files.
fn wake_all(dirs: &Mutex<HashMap<PathBuf, DirEntry>>, stats: &RegistryStats) {
    let signals: Vec<Arc<watch::Sender<u64>>> =
        { lock(dirs).values().map(|e| Arc::clone(&e.signal)).collect() };
    for signal in &signals {
        signal.send_modify(|v| *v = v.wrapping_add(1));
    }
    stats.wake_all_events.fetch_add(1, Ordering::Relaxed);
}

/// Lock a mutex, recovering the guard through a poisoned lock. Registry
/// critical sections never unwind, so poisoning only means a prior panic
/// elsewhere left the guard — the data itself stays consistent.
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a `dirs` map with the given directories, each with a fresh
    /// signal and refcount 1, plus a retained receiver per dir so the
    /// senders observe changes.
    fn map_with(
        dirs: &[&std::path::Path],
    ) -> (
        Arc<Mutex<HashMap<PathBuf, DirEntry>>>,
        Vec<watch::Receiver<u64>>,
    ) {
        let map = Arc::new(Mutex::new(HashMap::new()));
        let mut receivers = Vec::new();
        {
            let mut guard = map.lock().unwrap();
            for dir in dirs {
                let (tx, rx) = watch::channel(0u64);
                receivers.push(rx);
                guard.insert(
                    dir.to_path_buf(),
                    DirEntry {
                        signal: Arc::new(tx),
                        registrations: 1,
                    },
                );
            }
        }
        (map, receivers)
    }

    fn synthetic_event(kind: notify::EventKind, paths: Vec<PathBuf>) -> notify::Event {
        notify::Event {
            kind,
            paths,
            attrs: Default::default(),
        }
    }

    #[test]
    fn routes_child_event_to_only_its_directory() {
        let a = PathBuf::from("/tmp/msb-a/logs");
        let b = PathBuf::from("/tmp/msb-b/logs");
        let (map, receivers) = map_with(&[&a, &b]);
        let stats = RegistryStats::default();

        let event = synthetic_event(
            notify::EventKind::Modify(notify::event::ModifyKind::Data(
                notify::event::DataChange::Content,
            )),
            vec![a.join("exec.log")],
        );
        route_event(&map, &stats, Ok(event));

        assert_eq!(*receivers[0].borrow(), 1, "dir a woke");
        assert_eq!(*receivers[1].borrow(), 0, "dir b untouched");
        assert_eq!(stats.route_misses.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn unmatched_path_counts_a_route_miss() {
        let a = PathBuf::from("/tmp/msb-a/logs");
        let (map, _receivers) = map_with(&[&a]);
        let stats = RegistryStats::default();

        let event = synthetic_event(
            notify::EventKind::Create(notify::event::CreateKind::File),
            vec![PathBuf::from("/tmp/msb-other/logs/exec.log")],
        );
        route_event(&map, &stats, Ok(event));

        assert_eq!(stats.route_misses.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn error_wakes_all_directories() {
        let a = PathBuf::from("/tmp/msb-a/logs");
        let b = PathBuf::from("/tmp/msb-b/logs");
        let (map, receivers) = map_with(&[&a, &b]);
        let stats = RegistryStats::default();

        route_event(&map, &stats, Err(notify::Error::generic("dropped events")));

        assert_eq!(*receivers[0].borrow(), 1);
        assert_eq!(*receivers[1].borrow(), 1);
        assert_eq!(stats.wake_all_events.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn ignored_event_kinds_do_not_wake() {
        let a = PathBuf::from("/tmp/msb-a/logs");
        let (map, receivers) = map_with(&[&a]);
        let stats = RegistryStats::default();

        let event = synthetic_event(
            notify::EventKind::Access(notify::event::AccessKind::Read),
            vec![a.join("exec.log")],
        );
        route_event(&map, &stats, Ok(event));

        assert_eq!(*receivers[0].borrow(), 0);
    }

    #[tokio::test]
    async fn register_missing_dir_is_sandbox_not_found() {
        let registry = LogRegistry::new().unwrap();
        let logger = SandboxLogger::new(
            "sbx".to_string(),
            PathBuf::from("/tmp/msb-nonexistent-xyz/logs"),
        );
        match registry.register(logger).await {
            Err(MicrosandboxError::SandboxNotFound(_)) => {}
            Err(other) => panic!("expected SandboxNotFound, got {other:?}"),
            Ok(_) => panic!("expected SandboxNotFound, got Ok"),
        }
        assert_eq!(registry.stats().registered_dirs, 0);
    }

    // Exercises a real OS watch via `register`. On Linux (the production
    // target) `inotify_add_watch` is instant; on macOS `notify`'s FSEvents
    // `watch()` can take tens of seconds on some hosts (security agents
    // hooking stream creation), so it is skipped there by default — run
    // with `--ignored` to include it.
    #[cfg_attr(
        target_os = "macos",
        ignore = "FSEvents watch() latency; runs on Linux CI"
    )]
    #[tokio::test]
    async fn one_directory_two_registrations_share_one_descriptor() {
        let registry = LogRegistry::new().unwrap();
        let dir = tempfile::tempdir().unwrap();

        let first = registry
            .register(SandboxLogger::new("sbx".into(), dir.path().to_path_buf()))
            .await
            .unwrap();
        let second = registry
            .register(SandboxLogger::new("sbx".into(), dir.path().to_path_buf()))
            .await
            .unwrap();

        // Same directory → one watch descriptor, two registrations.
        assert_eq!(registry.stats().registered_dirs, 1);
        assert_eq!(registry.stats().total_registrations, 2);

        // Last registration standing keeps the watch.
        drop(first);
        assert_eq!(registry.stats().registered_dirs, 1);
        assert_eq!(registry.stats().total_registrations, 1);

        // Final drop removes it; the directory can be re-registered.
        drop(second);
        assert_eq!(registry.stats().registered_dirs, 0);
        let third = registry
            .register(SandboxLogger::new("sbx".into(), dir.path().to_path_buf()))
            .await
            .unwrap();
        assert_eq!(registry.stats().registered_dirs, 1);
        drop(third);
        assert_eq!(registry.stats().registered_dirs, 0);
    }

    #[cfg_attr(
        target_os = "macos",
        ignore = "FSEvents watch() latency; runs on Linux CI"
    )]
    #[tokio::test]
    async fn stream_keeps_directory_registered_after_logger_drops() {
        use crate::logs::LogStreamOptions;

        let registry = LogRegistry::new().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let logger = registry
            .register(SandboxLogger::new("sbx".into(), dir.path().to_path_buf()))
            .await
            .unwrap();

        let stream = logger
            .stream(&LogStreamOptions {
                follow: true,
                ..Default::default()
            })
            .await
            .unwrap();

        // Logger + stream both hold the directory.
        assert_eq!(registry.stats().registered_dirs, 1);
        assert_eq!(registry.stats().total_registrations, 2);

        // Dropping the logger must NOT tear down the watch — the live
        // stream's registration clone keeps it.
        drop(logger);
        assert_eq!(registry.stats().registered_dirs, 1);
        assert_eq!(registry.stats().total_registrations, 1);

        // Dropping the last stream removes the watch.
        drop(stream);
        assert_eq!(registry.stats().registered_dirs, 0);
        assert_eq!(registry.stats().total_registrations, 0);
    }
}
