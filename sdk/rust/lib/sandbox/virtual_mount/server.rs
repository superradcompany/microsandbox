//! In-process virtual-mount provider servers and lifecycle hooks.
//!
//! [`VirtualMountServer`] runs [`microsandbox_filesystem::rpc::serve`] on the
//! parent end of a socketpair. Use [`SandboxBuilder::virtual_mount_with_provider`]
//! for the ergonomic path (mirrors the Go SDK's `WithVirtualMount`), or pass the
//! child fd from [`VirtualMountServer::spawn`] to
//! [`SandboxBuilder::virtual_mount_fd`](super::SandboxBuilder::virtual_mount_fd).
//!
//! If any provider serve loop exits unexpectedly, the SDK requests sandbox stop
//! so the guest does not keep running against a dead mount. With multiple
//! virtual mounts, one provider failure shuts down every provider in the bundle
//! and requests sandbox stop.

use std::io;
use std::net::Shutdown;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use microsandbox_filesystem::PathFs;
use microsandbox_filesystem::rpc;

use super::registry::VirtualMountSession;
use crate::{MicrosandboxResult, db::entity::sandbox::SandboxStatus};

/// Maximum time to wait for a serve thread and in-flight provider calls during
/// teardown before abandoning the join (mirrors `virtualMountServeShutdownWait` in
/// `sdk/go/vfs/shutdown.go`; defined in `crates/filesystem/lib/backends/vfs/rpc/serve.rs`).
const SHUTDOWN_JOIN_TIMEOUT: Duration = rpc::SERVE_SHUTDOWN_JOIN_TIMEOUT;

/// Maximum total time to wait for terminal sandbox state before stopping the
/// background teardown waiter. Providers stay active after this point until the
/// sandbox stops or the last handle is released. Keep in sync with
/// `virtualMountTeardownMaxWait` in `sdk/go/virtual_mount_registry.go`.
const MAX_TEARDOWN_WAIT: Duration = Duration::from_secs(30 * 60);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A background `rpc::serve` loop for one virtual mount.
pub struct VirtualMountServer {
    child: Mutex<Option<OwnedFd>>,
    /// Parent end of the socketpair; shut down to unblock the serve thread.
    parent: Mutex<Option<UnixStream>>,
    join: Mutex<Option<JoinHandle<io::Result<()>>>>,
    /// Signals when the serve thread exits (closed when the thread drops its sender).
    serve_done: Mutex<Option<mpsc::Receiver<()>>>,
    /// Join helpers kept alive when bounded shutdown times out.
    background_joins: Mutex<Vec<JoinHandle<()>>>,
}

/// Owns every in-process provider server for one sandbox create.
pub struct VirtualMountServers {
    servers: Mutex<Vec<Arc<VirtualMountServer>>>,
    /// At most one background stopped-state waiter per bundle.
    teardown_when_stopped_once: std::sync::Once,
    /// At most one bundle-wide shutdown when any provider serve loop exits.
    provider_exit_once: std::sync::Once,
    /// At most one stop request and deferred teardown waiter per bundle.
    provider_exit_stop_once: std::sync::Once,
}

impl std::fmt::Debug for VirtualMountServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VirtualMountServer").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for VirtualMountServers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VirtualMountServers")
            .finish_non_exhaustive()
    }
}

/// Owns in-process provider servers attached to a [`SandboxConfig`] until create
/// consumes them. Shuts down serve threads when dropped while holding the last
/// `Arc` reference (e.g. a built config that is never passed to create).
#[derive(Clone, Debug, Default)]
pub(crate) struct RuntimeVirtualMountServers(Option<Arc<VirtualMountServers>>);

impl RuntimeVirtualMountServers {
    pub(crate) fn is_some(&self) -> bool {
        self.0.is_some()
    }

    pub(crate) fn take(&mut self) -> Option<Arc<VirtualMountServers>> {
        self.0.take()
    }

    pub(crate) fn set(&mut self, servers: Arc<VirtualMountServers>) {
        self.0 = Some(servers);
    }

    pub(crate) fn clone_inner(&self) -> Option<Arc<VirtualMountServers>> {
        self.0.clone()
    }
}

impl Drop for RuntimeVirtualMountServers {
    fn drop(&mut self) {
        if let Some(servers) = self.0.take()
            && Arc::strong_count(&servers) == 1
        {
            servers.shutdown_all();
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: VirtualMountServer
//--------------------------------------------------------------------------------------------------

impl VirtualMountServer {
    /// Create a socketpair, spawn `rpc::serve` on the parent end, and return
    /// the server handle plus the runtime-side (child) fd.
    pub fn spawn<P: PathFs + 'static>(provider: P) -> io::Result<(Self, RawFd)> {
        let (parent, child) = UnixStream::pair()?;
        let parent_for_shutdown = parent.try_clone()?;
        let child_fd = child.as_raw_fd();
        let child = OwnedFd::from(child);
        let provider: Arc<dyn PathFs> = Arc::new(provider);
        let (done_tx, done_rx) = mpsc::sync_channel(0);
        let join = thread::Builder::new()
            .name("microsandbox-virtual-mount-provider".into())
            .spawn(move || {
                let result = rpc::serve_unix(parent, provider);
                drop(done_tx);
                result
            })?;
        Ok((
            Self {
                child: Mutex::new(Some(child)),
                parent: Mutex::new(Some(parent_for_shutdown)),
                join: Mutex::new(Some(join)),
                serve_done: Mutex::new(Some(done_rx)),
                background_joins: Mutex::new(Vec::new()),
            },
            child_fd,
        ))
    }

    /// Close the inherited child fd after the runtime has dup'd it (mirrors Go).
    pub fn close_child_after_spawn(&self) {
        *self.child.lock().expect("virtual mount server poisoned") = None;
    }

    fn wait_for_serve_done(&self) {
        let done_rx = self
            .serve_done
            .lock()
            .expect("virtual mount server poisoned")
            .take();
        if let Some(rx) = done_rx {
            let _ = rx.recv();
        }
    }

    fn join_serve_thread_bounded(&self) {
        let join = self
            .join
            .lock()
            .expect("virtual mount server poisoned")
            .take();
        let Some(join) = join else {
            return;
        };
        let (tx, rx) = mpsc::sync_channel(0);
        let helper = thread::spawn(move || {
            let _ = join.join();
            let _ = tx.send(());
        });
        match rx.recv_timeout(SHUTDOWN_JOIN_TIMEOUT) {
            Ok(()) => {}
            Err(_) => {
                tracing::warn!(
                    "timed out waiting for virtual mount serve thread to exit after {:?}; continuing join in background",
                    SHUTDOWN_JOIN_TIMEOUT
                );
                self.background_joins
                    .lock()
                    .expect("virtual mount server poisoned")
                    .push(helper);
            }
        }
    }

    /// Shut down the parent connection and join the serve thread with a timeout.
    pub fn shutdown(&self) {
        *self.child.lock().expect("virtual mount server poisoned") = None;
        if let Some(parent) = self
            .parent
            .lock()
            .expect("virtual mount server poisoned")
            .take()
        {
            let _ = parent.shutdown(Shutdown::Both);
        }
        self.join_serve_thread_bounded();
    }

    /// Whether the serve thread is still running.
    ///
    /// The parent shutdown socket stays open until explicit teardown, so fd
    /// presence alone is not a reliable liveness signal.
    pub(crate) fn is_serve_thread_running(&self) -> bool {
        let guard = self
            .serve_done
            .lock()
            .expect("virtual mount server poisoned");
        match guard.as_ref() {
            Some(rx) => matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)),
            None => false,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: VirtualMountServers
//--------------------------------------------------------------------------------------------------

impl VirtualMountServers {
    /// Create an empty server bundle.
    pub fn new() -> Self {
        Self {
            servers: Mutex::new(Vec::new()),
            teardown_when_stopped_once: std::sync::Once::new(),
            provider_exit_once: std::sync::Once::new(),
            provider_exit_stop_once: std::sync::Once::new(),
        }
    }

    /// Register one server spawned for a mount.
    pub fn push(&self, server: Arc<VirtualMountServer>) {
        self.servers
            .lock()
            .expect("virtual mount servers poisoned")
            .push(server);
    }

    /// Whether any provider servers are registered.
    pub fn is_empty(&self) -> bool {
        self.servers
            .lock()
            .expect("virtual mount servers poisoned")
            .is_empty()
    }

    /// Close runtime-side child fds after spawn has inherited them.
    pub fn close_children_after_spawn(&self) {
        for server in self
            .servers
            .lock()
            .expect("virtual mount servers poisoned")
            .iter()
        {
            server.close_child_after_spawn();
        }
    }

    /// Shut down every parent connection and join serve threads.
    pub fn shutdown_all(&self) {
        for server in self
            .servers
            .lock()
            .expect("virtual mount servers poisoned")
            .iter()
        {
            server.shutdown();
        }
    }

    /// Whether every registered provider still has a running serve thread.
    pub(crate) fn all_providers_serving(&self) -> bool {
        let servers = self.servers.lock().expect("virtual mount servers poisoned");
        !servers.is_empty() && servers.iter().all(|s| s.is_serve_thread_running())
    }

    /// When any provider server exits unexpectedly, request sandbox stop if the
    /// VM may still be running (mirrors Go `watchVirtualMountProvidersStopped`).
    pub fn spawn_provider_exit_watches(
        self: &Arc<Self>,
        sandbox_name: String,
        backend: Arc<dyn crate::backend::Backend>,
        session: Option<Arc<VirtualMountSession>>,
    ) {
        let servers = self
            .servers
            .lock()
            .expect("virtual mount servers poisoned")
            .clone();
        let bundle = Arc::clone(self);
        for server in servers {
            let name = sandbox_name.clone();
            let backend = Arc::clone(&backend);
            let session = session.clone();
            let server = Arc::clone(&server);
            let bundle = Arc::clone(&bundle);
            tokio::spawn(async move {
                let server_for_wait = Arc::clone(&server);
                let Ok(()) = tokio::task::spawn_blocking(move || {
                    server_for_wait.wait_for_serve_done();
                })
                .await
                else {
                    tracing::warn!(
                        sandbox = %name,
                        "virtual mount provider wait task failed; not treating as provider exit"
                    );
                    return;
                };
                bundle.provider_exit_once.call_once(|| {
                    bundle.shutdown_all();
                    super::registry::teardown_bundle(&name, &bundle);
                });
                bundle.provider_exit_stop_once.call_once(|| {
                    let name = name.clone();
                    let backend = Arc::clone(&backend);
                    let bundle = Arc::clone(&bundle);
                    let session = session.clone();
                    tokio::spawn(async move {
                        let should_stop = match session.as_deref() {
                            Some(session) => super::registry::is_live_session(&name, session),
                            None => super::registry::is_live_bundle(&name, &bundle),
                        };
                        if !should_stop {
                            return;
                        }
                        if let Err(err) =
                            request_stop_if_provider_exited(&name, &backend, session.as_deref())
                                .await
                        {
                            tracing::warn!(
                                sandbox = %name,
                                error = %err,
                                "virtual mount provider exited but stop request failed"
                            );
                        }
                        bundle.schedule_teardown_when_stopped(name, backend);
                    });
                });
            });
        }
    }

    /// Tear down provider sockets once the sandbox reaches a terminal state.
    ///
    /// At most one background waiter runs per bundle.
    pub fn schedule_teardown_when_stopped(
        self: &Arc<Self>,
        sandbox_name: String,
        backend: Arc<dyn crate::backend::Backend>,
    ) {
        self.teardown_when_stopped_once.call_once(|| {
            let sandbox_name = sandbox_name.clone();
            let bundle = Arc::clone(self);
            tokio::spawn(async move {
                let deadline = std::time::Instant::now() + MAX_TEARDOWN_WAIT;
                loop {
                    match wait_until_sandbox_stopped(&backend, &sandbox_name).await {
                        Ok(()) => {
                            super::registry::teardown_bundle(
                                &sandbox_name,
                                &bundle,
                            );
                            return;
                        }
                        Err(err) => {
                            if std::time::Instant::now() >= deadline {
                                tracing::error!(
                                    sandbox = %sandbox_name,
                                    error = %err,
                                    ?MAX_TEARDOWN_WAIT,
                                    "stopped waiting for sandbox to stop; forcing virtual mount provider shutdown"
                                );
                                super::registry::teardown_bundle(
                                    &sandbox_name,
                                    &bundle,
                                );
                                return;
                            }
                            tracing::warn!(
                                sandbox = %sandbox_name,
                                error = %err,
                                "timed out waiting for sandbox to stop before tearing down virtual mounts; retrying"
                            );
                        }
                    }
                }
            });
        });
    }
}

impl Default for VirtualMountServers {
    fn default() -> Self {
        Self::new()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn request_stop_if_provider_exited(
    name: &str,
    backend: &Arc<dyn crate::backend::Backend>,
    session: Option<&VirtualMountSession>,
) -> MicrosandboxResult<()> {
    if let Some(session) = session
        && !super::registry::is_live_session(name, session)
    {
        return Ok(());
    }

    let handle = backend.sandboxes().get(Arc::clone(backend), name).await?;
    let status = handle.status_snapshot();
    if matches!(status, SandboxStatus::Stopped | SandboxStatus::Crashed) {
        return Ok(());
    }

    backend.sandboxes().stop(Arc::clone(backend), name).await?;
    Ok(())
}

async fn wait_until_sandbox_stopped(
    backend: &Arc<dyn crate::backend::Backend>,
    name: &str,
) -> MicrosandboxResult<()> {
    let timeout = Duration::from_secs(300);
    let start = std::time::Instant::now();
    let poll = Duration::from_millis(100);
    loop {
        let handle = backend.sandboxes().get(Arc::clone(backend), name).await;
        match handle {
            Ok(h) => {
                let status = h.status_snapshot();
                if matches!(status, SandboxStatus::Stopped | SandboxStatus::Crashed) {
                    return Ok(());
                }
            }
            Err(crate::MicrosandboxError::SandboxNotFound(_)) => return Ok(()),
            Err(err) => return Err(err),
        }
        if start.elapsed() >= timeout {
            return Err(crate::MicrosandboxError::Runtime(format!(
                "timed out waiting for sandbox '{name}' to stop"
            )));
        }
        tokio::time::sleep(poll).await;
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod max_teardown_wait_tests {
    use super::MAX_TEARDOWN_WAIT;

    #[test]
    fn max_teardown_wait_matches_go() {
        // Keep in sync with virtualMountTeardownMaxWait in sdk/go/virtual_mount_registry.go.
        assert_eq!(MAX_TEARDOWN_WAIT.as_secs(), 30 * 60);
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::Arc;

    use microsandbox_filesystem::{VAttr, VDirEntry};

    use super::*;

    struct StubProvider;

    impl PathFs for StubProvider {
        fn getattr(&self, path: &Path) -> io::Result<VAttr> {
            if path == Path::new("/") {
                Ok(VAttr::dir(0o755))
            } else {
                Err(io::Error::from_raw_os_error(libc::ENOENT))
            }
        }

        fn readdir(&self, path: &Path) -> io::Result<Vec<VDirEntry>> {
            if path == Path::new("/") {
                Ok(Vec::new())
            } else {
                Err(io::Error::from_raw_os_error(libc::ENOENT))
            }
        }

        fn read(&self, _path: &Path, _offset: u64, _size: u32) -> io::Result<Vec<u8>> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn spawn_returns_socket_child_fd() {
        let (server, child_fd) = VirtualMountServer::spawn(StubProvider).unwrap();
        assert!(child_fd >= 0);
        server.shutdown();
    }

    #[test]
    fn all_providers_serving_false_after_shutdown() {
        let (server, _child_fd) = VirtualMountServer::spawn(StubProvider).unwrap();
        let bundle = VirtualMountServers::new();
        bundle.push(Arc::new(server));
        assert!(bundle.all_providers_serving());
        bundle.shutdown_all();
        assert!(!bundle.all_providers_serving());
    }

    #[test]
    fn all_providers_serving_false_after_serve_thread_exits() {
        use std::time::Duration;

        let (server, _child_fd) = VirtualMountServer::spawn(StubProvider).unwrap();
        let server = Arc::new(server);
        let bundle = VirtualMountServers::new();
        bundle.push(Arc::clone(&server));
        assert!(bundle.all_providers_serving());

        // Close the runtime-side fd without shutting down the parent connection.
        server.close_child_after_spawn();
        for _ in 0..50 {
            if !bundle.all_providers_serving() {
                bundle.shutdown_all();
                return;
            }
            thread::sleep(Duration::from_millis(20));
        }
        bundle.shutdown_all();
        panic!("expected all_providers_serving to become false after serve thread exit");
    }

    #[test]
    fn runtime_socket_roundtrip_over_virtual_mount_server() {
        use std::ffi::CString;
        use std::os::fd::FromRawFd;
        use std::os::unix::net::UnixStream;

        use microsandbox_filesystem::{
            Context, DynFileSystem, FsOptions, rpc::unix_socket_backend,
        };

        let (server, child_fd) = VirtualMountServer::spawn(StubProvider).unwrap();
        let runtime_fd = unsafe { libc::dup(child_fd) };
        assert!(runtime_fd >= 0, "dup: {}", std::io::Error::last_os_error());
        let runtime_side = unsafe { UnixStream::from_raw_fd(runtime_fd) };
        let fs = unix_socket_backend(runtime_side).expect("connect runtime backend");
        fs.init(FsOptions::empty()).expect("init");
        let ctx = Context {
            uid: 0,
            gid: 0,
            pid: 1,
        };
        let dot = CString::new(".").unwrap();
        let root = fs.lookup(ctx, 1, dot.as_c_str()).expect("lookup root");
        assert_eq!(root.attr.st_mode & libc::S_IFMT, libc::S_IFDIR);
        server.shutdown();
    }

    #[test]
    fn shutdown_unblocks_serve_thread_without_peer() {
        let (server, _child_fd) = VirtualMountServer::spawn(StubProvider).unwrap();
        let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let done_flag = Arc::clone(&done);
        let handle = thread::spawn(move || {
            server.shutdown();
            done_flag.store(true, std::sync::atomic::Ordering::Release);
        });
        handle.join().unwrap();
        assert!(done.load(std::sync::atomic::Ordering::Acquire));
    }

    #[tokio::test]
    async fn request_stop_if_provider_exited_ignores_stale_session() {
        use super::super::registry;
        use crate::backend::LocalBackend;

        let backend: Arc<dyn crate::backend::Backend> =
            Arc::new(LocalBackend::builder().build().await.unwrap());
        let name = format!("virtual-mount-stale-stop-{}", std::process::id());
        registry::clear_live_slot(&name);
        let stale = registry::install_session(&name);
        let _live = registry::install_session(&name);
        request_stop_if_provider_exited(&name, &backend, Some(stale.as_ref()))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn provider_exit_clears_live_registry_servers() {
        use super::super::registry;
        use crate::backend::LocalBackend;

        let (server1, _) = VirtualMountServer::spawn(StubProvider).unwrap();
        let (server2, _) = VirtualMountServer::spawn(StubProvider).unwrap();
        let server1 = Arc::new(server1);
        let bundle = Arc::new(VirtualMountServers::new());
        bundle.push(Arc::clone(&server1));
        bundle.push(Arc::new(server2));
        let name = format!("virtual-mount-exit-live-{}", std::process::id());
        registry::clear_live_slot(&name);
        registry::register_servers(&name, Arc::clone(&bundle));
        assert!(registry::has_live_servers(&name));

        let backend: Arc<dyn crate::backend::Backend> =
            Arc::new(LocalBackend::builder().build().await.unwrap());
        bundle.spawn_provider_exit_watches(name.clone(), Arc::clone(&backend), None);
        server1.shutdown();

        for _ in 0..100 {
            if !registry::has_live_servers(&name) {
                registry::clear_live_slot(&name);
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("expected has_live_servers to clear after provider exit");
    }

    #[tokio::test]
    async fn provider_exit_shuts_down_siblings_before_registry() {
        use std::os::fd::FromRawFd;
        use std::os::unix::net::UnixStream;

        use super::super::registry;

        let (server1, _) = VirtualMountServer::spawn(StubProvider).unwrap();
        let (server2, child2) = VirtualMountServer::spawn(StubProvider).unwrap();
        let server1 = Arc::new(server1);
        let bundle = Arc::new(VirtualMountServers::new());
        bundle.push(Arc::clone(&server1));
        bundle.push(Arc::new(server2));
        let name = format!("virtual-mount-pre-reg-{}", std::process::id());
        registry::clear_live_slot(&name);

        let backend: Arc<dyn crate::backend::Backend> = Arc::new(
            crate::backend::LocalBackend::builder()
                .build()
                .await
                .unwrap(),
        );
        bundle.spawn_provider_exit_watches(name.clone(), Arc::clone(&backend), None);

        let runtime_fd = unsafe { libc::dup(child2) };
        assert!(runtime_fd >= 0);
        let mut runtime_side = unsafe { UnixStream::from_raw_fd(runtime_fd) };

        server1.shutdown();

        let closed = tokio::task::spawn_blocking(move || {
            use std::io::Read;

            runtime_side
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set read timeout");
            let mut buf = [0u8; 1];
            matches!(runtime_side.read(&mut buf), Ok(0))
        })
        .await
        .expect("join runtime read probe");

        registry::clear_live_slot(&name);
        assert!(
            closed,
            "expected sibling provider socket to close after first provider exit"
        );
    }
}
