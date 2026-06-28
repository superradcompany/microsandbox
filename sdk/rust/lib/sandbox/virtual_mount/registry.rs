//! Process-local registry for sandboxes created with programmable virtual mounts.
//!
//! The provider socket (or peer end) lives only in the creating process. This
//! registry tracks which sandbox names still have an active in-process session
//! so [`check_virtual_mount_connect`] can allow [`SandboxHandle::connect`] from
//! the same process while refusing cross-process reconnects.
//!
//! Each [`VirtualMountSession`] holds a release token for one registry
//! generation. Releasing goes through that token, not by sandbox name, so a
//! same-name [`.replace()`](super::SandboxBuilder::replace) cannot disturb a
//! still-live session from an earlier generation. The registry gates
//! [`SandboxHandle::connect`] only — it does not own or tear down provider
//! sockets; keep the parent end of each virtual-mount socket served for the
//! VM's lifetime. [`register_servers`] also tracks provider bundles for teardown
//! on sandbox removal and shuts down a prior generation on same-name replace.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock},
};

use crate::MicrosandboxResult;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct EntryState {
    refs: usize,
}

struct LiveRegistry {
    slots: HashMap<String, Arc<Mutex<EntryState>>>,
    servers: HashMap<String, std::sync::Weak<super::server::VirtualMountServers>>,
}

/// Holds one reference-counted session for a sandbox with virtual mounts.
///
/// Dropping this handle decrements the registry generation it was acquired
/// from. Stale tokens from a replaced same-name sandbox do not affect the live
/// slot.
pub struct VirtualMountSession {
    name: String,
    entry: Arc<Mutex<EntryState>>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn registry() -> &'static Mutex<LiveRegistry> {
    static REG: OnceLock<Mutex<LiveRegistry>> = OnceLock::new();
    REG.get_or_init(|| {
        Mutex::new(LiveRegistry {
            slots: HashMap::new(),
            servers: HashMap::new(),
        })
    })
}

pub(crate) fn connect_error(name: &str) -> crate::MicrosandboxError {
    crate::MicrosandboxError::InvalidConfig(format!(
        "connect to sandbox '{name}': virtual mount provider is not active in this process; \
         keep a lifecycle-owning Sandbox handle open in the process that created the mount, \
         use Connect from that same process while providers are still running, or remove the \
         sandbox record and create a new one with virtual_mount_with_provider"
    ))
}

fn release(name: &str, entry: &Arc<Mutex<EntryState>>) {
    let refs = {
        let mut state = entry.lock().expect("virtual mount entry poisoned");
        if state.refs == 0 {
            return;
        }
        state.refs -= 1;
        state.refs
    };
    if refs == 0 {
        let mut reg = registry().lock().expect("virtual mount registry poisoned");
        if reg
            .slots
            .get(name)
            .is_some_and(|live| Arc::ptr_eq(live, entry))
            && !has_live_servers_locked(&mut reg, name)
        {
            reg.slots.remove(name);
        }
    }
}

fn has_live_servers_locked(reg: &mut LiveRegistry, name: &str) -> bool {
    let Some(weak) = reg.servers.get(name) else {
        return false;
    };
    let Some(servers) = weak.upgrade() else {
        reg.servers.remove(name);
        return false;
    };
    if servers.all_providers_serving() {
        return true;
    }
    reg.servers.remove(name);
    false
}

/// Whether in-process provider servers for `name` are still registered and alive.
pub fn has_live_servers(name: &str) -> bool {
    let mut reg = registry().lock().expect("virtual mount registry poisoned");
    has_live_servers_locked(&mut reg, name)
}

/// Install a fresh registry entry for `name` (refs = 1) and return its session
/// handle.
///
/// When `name` already has a live slot (e.g. after [`.replace()`](super::SandboxBuilder::replace)),
/// the previous generation is detached from the map. Handles that still hold
/// the old token release only that detached generation.
pub fn install_session(name: &str) -> Arc<VirtualMountSession> {
    let cell = Arc::new(Mutex::new(EntryState { refs: 1 }));
    registry()
        .lock()
        .expect("virtual mount registry poisoned")
        .slots
        .insert(name.to_string(), Arc::clone(&cell));
    Arc::new(VirtualMountSession {
        name: name.to_string(),
        entry: cell,
    })
}

/// Take an additional reference on the live in-process session for `name`.
pub fn try_acquire(name: &str) -> Option<Arc<VirtualMountSession>> {
    let mut reg = registry().lock().expect("virtual mount registry poisoned");
    let cell = reg.slots.get(name)?.clone();
    let servers_live = has_live_servers_locked(&mut reg, name);
    let mut state = cell.lock().expect("virtual mount entry poisoned");
    if state.refs == 0 {
        if !servers_live {
            return None;
        }
        state.refs = 1;
    } else {
        state.refs += 1;
    }
    drop(state);
    Some(Arc::new(VirtualMountSession {
        name: name.to_string(),
        entry: cell,
    }))
}

/// Take an additional reference on the live session, or return a connect error.
pub fn acquire_session(name: &str) -> MicrosandboxResult<Arc<VirtualMountSession>> {
    if !has_live_servers(name) {
        return Err(connect_error(name));
    }
    try_acquire(name).ok_or_else(|| connect_error(name))
}

/// Remove the live map slot for `name` without disturbing detached generations
/// still held by stale session tokens (e.g. after sandbox removal from the DB).
pub fn clear_live_slot(name: &str) {
    let mut reg = registry().lock().expect("virtual mount registry poisoned");
    reg.slots.remove(name);
    reg.servers.remove(name);
}

/// Remember in-process provider servers for teardown on sandbox removal.
///
/// When `name` already has registered servers (e.g. after
/// [`.replace()`](super::SandboxBuilder::replace)), the previous generation is
/// shut down before the new one is registered (mirrors Go `registerVirtualMountServers`).
pub fn register_servers(name: &str, servers: Arc<super::server::VirtualMountServers>) {
    let mut reg = registry().lock().expect("virtual mount registry poisoned");
    if let Some(prev) = reg.servers.remove(name).and_then(|weak| weak.upgrade()) {
        prev.shutdown_all();
    }
    reg.servers
        .insert(name.to_string(), Arc::downgrade(&servers));
}

/// Shut down one registered provider bundle. When `bundle` is still the live
/// registered generation for `name`, it is removed from the registry map.
pub fn teardown_bundle(name: &str, bundle: &Arc<super::server::VirtualMountServers>) {
    bundle.shutdown_all();
    let mut reg = registry().lock().expect("virtual mount registry poisoned");
    if reg
        .servers
        .get(name)
        .and_then(|weak| weak.upgrade())
        .is_some_and(|live| Arc::ptr_eq(&live, bundle))
    {
        reg.servers.remove(name);
    }
}

/// Snapshot the live registered provider bundle for `name`, if any.
pub fn snapshot_servers(name: &str) -> Option<Arc<super::server::VirtualMountServers>> {
    registry()
        .lock()
        .expect("virtual mount registry poisoned")
        .servers
        .get(name)
        .and_then(|weak| weak.upgrade())
}

/// Whether `bundle` is still the live registered provider generation for `name`.
pub fn is_live_bundle(name: &str, bundle: &Arc<super::server::VirtualMountServers>) -> bool {
    registry()
        .lock()
        .expect("virtual mount registry poisoned")
        .servers
        .get(name)
        .and_then(|weak| weak.upgrade())
        .is_some_and(|live| Arc::ptr_eq(&live, bundle))
}

/// Shut down any registered provider servers for `name`.
pub fn teardown_servers(name: &str) {
    if let Some(servers) = registry()
        .lock()
        .expect("virtual mount registry poisoned")
        .servers
        .remove(name)
        .and_then(|weak| weak.upgrade())
    {
        servers.shutdown_all();
    }
}

/// Whether this process still has an active virtual-mount session for `name`.
#[cfg(test)]
pub fn has_active_session(name: &str) -> bool {
    let reg = registry().lock().expect("virtual mount registry poisoned");
    let Some(cell) = reg.slots.get(name) else {
        return false;
    };
    cell.lock().expect("virtual mount entry poisoned").refs > 0
}

/// Whether `session` is still the live registry slot for `name`.
pub fn is_live_session(name: &str, session: &VirtualMountSession) -> bool {
    let reg = registry().lock().expect("virtual mount registry poisoned");
    reg.slots
        .get(name)
        .is_some_and(|cell| Arc::ptr_eq(cell, &session.entry))
}

/// Reject connect when the persisted sandbox used virtual mounts but this
/// process has no live provider servers for it.
///
/// Session refcounts alone are not enough: a handle may still hold a release
/// token after its provider sockets were torn down (for example when a serve
/// thread exited). Go's `connectVirtualMounts` gates on live servers the same way.
pub fn check_virtual_mount_connect(name: &str, had_virtual_mounts: bool) -> MicrosandboxResult<()> {
    if !had_virtual_mounts {
        return Ok(());
    }
    if has_live_servers(name) {
        return Ok(());
    }
    Err(connect_error(name))
}

impl Drop for VirtualMountSession {
    fn drop(&mut self) {
        release(&self.name, &self.entry);
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_refcount_allows_acquire_while_alive() {
        let name = format!("virtual-mount-reg-{}", std::process::id());
        clear_live_slot(&name);

        let a = install_session(&name);
        let b = try_acquire(&name).expect("acquire while session alive");
        assert!(has_active_session(&name));

        drop(a);
        assert!(has_active_session(&name));
        assert!(try_acquire(&name).is_some());

        drop(b);
        assert!(!has_active_session(&name));
        assert!(try_acquire(&name).is_none());
    }

    #[test]
    fn check_connect_rejected_after_all_sessions_dropped() {
        let name = format!("virtual-mount-reg-connect-{}", std::process::id());
        clear_live_slot(&name);

        let session = install_session(&name);
        drop(session);
        assert!(!has_active_session(&name));

        let err = check_virtual_mount_connect(&name, true).unwrap_err();
        assert!(
            err.to_string()
                .contains("virtual mount provider is not active")
        );
    }

    #[test]
    fn check_connect_rejects_session_without_live_providers() {
        let name = format!("virtual-mount-reg-dead-providers-{}", std::process::id());
        clear_live_slot(&name);

        let _session = install_session(&name);
        assert!(has_active_session(&name));
        assert!(!has_live_servers(&name));

        let err = check_virtual_mount_connect(&name, true).unwrap_err();
        assert!(
            err.to_string()
                .contains("virtual mount provider is not active")
        );
        match acquire_session(&name) {
            Err(err) => assert!(
                err.to_string()
                    .contains("virtual mount provider is not active")
            ),
            Ok(_) => panic!("expected acquire_session to fail without live providers"),
        }
    }

    #[test]
    fn acquire_session_rejects_without_live_entry() {
        let name = format!("virtual-mount-acquire-{}", std::process::id());
        clear_live_slot(&name);
        match acquire_session(&name) {
            Err(err) => assert!(
                err.to_string()
                    .contains("virtual mount provider is not active")
            ),
            Ok(_) => panic!("expected acquire_session to fail without a live entry"),
        }
    }

    #[test]
    fn replace_does_not_disturb_live_session_when_stale_token_drops() {
        let name = format!("virtual-mount-replace-{}", std::process::id());
        clear_live_slot(&name);

        let stale = install_session(&name);
        let replacement = install_session(&name);
        assert!(has_active_session(&name));

        drop(stale);
        assert!(
            has_active_session(&name),
            "dropping a stale pre-replace token must not clear the live slot"
        );
        assert!(try_acquire(&name).is_some());

        drop(replacement);
        assert!(!has_active_session(&name));
    }

    #[test]
    fn is_live_session_rejects_stale_token_after_replace() {
        let name = format!("virtual-mount-stale-session-{}", std::process::id());
        clear_live_slot(&name);

        let stale = install_session(&name);
        let live = install_session(&name);
        assert!(!is_live_session(&name, &stale));
        assert!(is_live_session(&name, &live));
    }

    #[test]
    fn teardown_and_clear_slot_drop_registry_servers() {
        use std::path::Path;
        use std::sync::Arc;

        use microsandbox_filesystem::{PathFs, VAttr, VDirEntry};

        use super::super::server::{VirtualMountServer, VirtualMountServers};

        struct StubProvider;

        impl PathFs for StubProvider {
            fn getattr(&self, path: &Path) -> std::io::Result<VAttr> {
                if path == Path::new("/") {
                    Ok(VAttr::dir(0o755))
                } else {
                    Err(std::io::Error::from_raw_os_error(libc::ENOENT))
                }
            }

            fn readdir(&self, path: &Path) -> std::io::Result<Vec<VDirEntry>> {
                if path == Path::new("/") {
                    Ok(Vec::new())
                } else {
                    Err(std::io::Error::from_raw_os_error(libc::ENOENT))
                }
            }

            fn read(&self, _path: &Path, _offset: u64, _size: u32) -> std::io::Result<Vec<u8>> {
                Ok(Vec::new())
            }
        }

        let name = format!("virtual-mount-teardown-clear-{}", std::process::id());
        clear_live_slot(&name);

        let (server, _) = VirtualMountServer::spawn(StubProvider).unwrap();
        let bundle = Arc::new(VirtualMountServers::new());
        bundle.push(Arc::new(server));
        register_servers(&name, Arc::clone(&bundle));
        assert!(has_live_servers(&name));

        teardown_servers(&name);
        assert!(!has_live_servers(&name));
        clear_live_slot(&name);
        bundle.shutdown_all();
    }

    #[test]
    fn try_acquire_succeeds_after_session_drop_while_providers_registered() {
        use std::path::Path;
        use std::sync::Arc;

        use microsandbox_filesystem::{PathFs, VAttr, VDirEntry};

        use super::super::server::{VirtualMountServer, VirtualMountServers};

        struct StubProvider;

        impl PathFs for StubProvider {
            fn getattr(&self, path: &Path) -> std::io::Result<VAttr> {
                if path == Path::new("/") {
                    Ok(VAttr::dir(0o755))
                } else {
                    Err(std::io::Error::from_raw_os_error(libc::ENOENT))
                }
            }

            fn readdir(&self, path: &Path) -> std::io::Result<Vec<VDirEntry>> {
                if path == Path::new("/") {
                    Ok(Vec::new())
                } else {
                    Err(std::io::Error::from_raw_os_error(libc::ENOENT))
                }
            }

            fn read(&self, _path: &Path, _offset: u64, _size: u32) -> std::io::Result<Vec<u8>> {
                Ok(Vec::new())
            }
        }

        let name = format!("virtual-mount-acquire-servers-{}", std::process::id());
        clear_live_slot(&name);

        let session = install_session(&name);
        let (server, _) = VirtualMountServer::spawn(StubProvider).unwrap();
        let bundle = Arc::new(VirtualMountServers::new());
        bundle.push(Arc::new(server));
        register_servers(&name, Arc::clone(&bundle));

        drop(session);
        assert!(!has_active_session(&name));
        assert!(has_live_servers(&name));
        assert!(try_acquire(&name).is_some());
        check_virtual_mount_connect(&name, true).unwrap();

        teardown_servers(&name);
        assert!(!has_live_servers(&name));
        clear_live_slot(&name);
        bundle.shutdown_all();
    }

    #[test]
    fn register_servers_replaces_prior_generation() {
        use std::path::Path;
        use std::sync::Arc;

        use microsandbox_filesystem::{PathFs, VAttr, VDirEntry};

        use super::super::server::{VirtualMountServer, VirtualMountServers};

        struct StubProvider;

        impl PathFs for StubProvider {
            fn getattr(&self, path: &Path) -> std::io::Result<VAttr> {
                if path == Path::new("/") {
                    Ok(VAttr::dir(0o755))
                } else {
                    Err(std::io::Error::from_raw_os_error(libc::ENOENT))
                }
            }

            fn readdir(&self, path: &Path) -> std::io::Result<Vec<VDirEntry>> {
                if path == Path::new("/") {
                    Ok(Vec::new())
                } else {
                    Err(std::io::Error::from_raw_os_error(libc::ENOENT))
                }
            }

            fn read(&self, _path: &Path, _offset: u64, _size: u32) -> std::io::Result<Vec<u8>> {
                Ok(Vec::new())
            }
        }

        let name = format!("virtual-mount-reg-servers-{}", std::process::id());
        clear_live_slot(&name);

        let (s1, _) = VirtualMountServer::spawn(StubProvider).unwrap();
        let bundle1 = Arc::new(VirtualMountServers::new());
        bundle1.push(Arc::new(s1));
        register_servers(&name, Arc::clone(&bundle1));

        let (s2, _) = VirtualMountServer::spawn(StubProvider).unwrap();
        let bundle2 = Arc::new(VirtualMountServers::new());
        bundle2.push(Arc::new(s2));
        register_servers(&name, Arc::clone(&bundle2));

        teardown_servers(&name);
        bundle2.shutdown_all();
    }

    #[test]
    fn teardown_bundle_does_not_disturb_replacement_generation() {
        use std::path::Path;
        use std::sync::Arc;

        use microsandbox_filesystem::{PathFs, VAttr, VDirEntry};

        use super::super::server::{VirtualMountServer, VirtualMountServers};

        struct StubProvider;

        impl PathFs for StubProvider {
            fn getattr(&self, path: &Path) -> std::io::Result<VAttr> {
                if path == Path::new("/") {
                    Ok(VAttr::dir(0o755))
                } else {
                    Err(std::io::Error::from_raw_os_error(libc::ENOENT))
                }
            }

            fn readdir(&self, path: &Path) -> std::io::Result<Vec<VDirEntry>> {
                if path == Path::new("/") {
                    Ok(Vec::new())
                } else {
                    Err(std::io::Error::from_raw_os_error(libc::ENOENT))
                }
            }

            fn read(&self, _path: &Path, _offset: u64, _size: u32) -> std::io::Result<Vec<u8>> {
                Ok(Vec::new())
            }
        }

        let name = format!("virtual-mount-teardown-bundle-{}", std::process::id());
        clear_live_slot(&name);

        let (s1, _) = VirtualMountServer::spawn(StubProvider).unwrap();
        let bundle1 = Arc::new(VirtualMountServers::new());
        bundle1.push(Arc::new(s1));
        register_servers(&name, Arc::clone(&bundle1));

        let (s2, _) = VirtualMountServer::spawn(StubProvider).unwrap();
        let bundle2 = Arc::new(VirtualMountServers::new());
        bundle2.push(Arc::new(s2));
        register_servers(&name, Arc::clone(&bundle2));

        teardown_bundle(&name, &bundle1);
        assert!(
            has_live_servers(&name),
            "stale bundle teardown must not remove the live replacement"
        );

        teardown_bundle(&name, &bundle2);
        assert!(!has_live_servers(&name));
        clear_live_slot(&name);
    }
}
