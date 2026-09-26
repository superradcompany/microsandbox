//! Microsandbox construction and host-process discovery for OCI containers.

use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Result;
use microsandbox::sandbox::Sandbox;
use microsandbox_runtime::oci::{OciBundle, sandbox_name_for_container};

use crate::console::process_console_size;
use crate::process::{env_pairs, process_args};
use crate::requests::{OCI_INIT_SESSION, OCI_SIGNAL_REQUEST, OCI_START_REQUEST};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const OCI_FORWARD_STDIO_LABEL: &str = "oci.microsandbox.forward_stdio";
const OCI_CONSOLE_ROWS_LABEL: &str = "oci.microsandbox.console_rows";
const OCI_CONSOLE_COLS_LABEL: &str = "oci.microsandbox.console_cols";
const OCI_INIT_SESSION_PATH_LABEL: &str = "oci.microsandbox.init_session_path";
const OCI_ISOLATE_NETWORK_NAMESPACE_LABEL: &str = "oci.microsandbox.isolate_network_namespace";
const OCI_SIGNAL_PATH_LABEL: &str = "oci.microsandbox.signal_path";
const OCI_STARTUP_CWD_LABEL: &str = "oci.microsandbox.startup_cwd";
const OCI_START_SIGNAL_PATH_LABEL: &str = "oci.microsandbox.start_signal_path";

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) async fn create_sandbox_for_bundle(
    id: &str,
    bundle: &OciBundle,
    state_dir: &Path,
    console: Option<OwnedFd>,
) -> Result<Sandbox> {
    let process = bundle.process();
    let mut builder = Sandbox::builder(sandbox_name_for_container(id))
        .image(bundle.rootfs_path())
        .detached(true)
        .label("oci.container.id", id)
        .label("oci.bundle", bundle.path.display().to_string())
        .label(OCI_FORWARD_STDIO_LABEL, "true")
        .label(
            OCI_START_SIGNAL_PATH_LABEL,
            state_dir.join(OCI_START_REQUEST).display().to_string(),
        )
        .label(
            OCI_INIT_SESSION_PATH_LABEL,
            state_dir.join(OCI_INIT_SESSION).display().to_string(),
        )
        .label(
            OCI_SIGNAL_PATH_LABEL,
            state_dir.join(OCI_SIGNAL_REQUEST).display().to_string(),
        );

    if let Some(console) = console {
        builder = builder.inherited_startup_console(console);
        if let Some(size) = process.and_then(process_console_size) {
            builder = builder
                .label(OCI_CONSOLE_ROWS_LABEL, size.rows.to_string())
                .label(OCI_CONSOLE_COLS_LABEL, size.cols.to_string());
        }
    }

    if requires_fresh_network_namespace(bundle) {
        builder = builder.label(OCI_ISOLATE_NETWORK_NAMESPACE_LABEL, "true");
        builder = builder.network(|network| {
            network.ipv4_pool("172.16.0.0/12".parse().expect("valid OCI IPv4 pool"))
        });
    }

    if let Some(process) = process {
        builder = builder.background_command(process_args(process)?.iter().cloned());
        let cwd = process.cwd().display().to_string();
        builder = builder.label(OCI_STARTUP_CWD_LABEL, cwd.clone());
        if cwd != "/" {
            builder = builder.workdir(cwd);
        }
        let user = process.user();
        if user.uid() != 0 || user.gid() != 0 {
            builder = builder.user(format!("{}:{}", user.uid(), user.gid()));
        }
        for (key, value) in env_pairs(process.env().as_deref().unwrap_or_default())? {
            builder = builder.env(key, value);
        }
    }

    for mount in bundle.mounts() {
        if is_runtime_managed_mount(mount.destination()) {
            continue;
        }

        match mount.typ().as_deref() {
            Some("bind") => {
                let Some(source) = mount.source().as_ref() else {
                    continue;
                };
                let destination = mount.destination().display().to_string();
                let source = absolutize_mount_source(&bundle.path, source);
                let readonly = mount
                    .options()
                    .as_deref()
                    .unwrap_or_default()
                    .iter()
                    .any(|opt| opt == "ro");
                builder = builder.volume(destination, |mount| {
                    let mount = mount.bind(source);
                    if readonly { mount.readonly() } else { mount }
                });
            }
            Some("tmpfs") => {
                let destination = mount.destination().display().to_string();
                builder = builder.volume(destination, |mount| mount.tmpfs());
            }
            _ => {}
        }
    }

    builder.create_detached().await.map_err(Into::into)
}

pub(crate) async fn resolve_created_sandbox_host_pid(id: &str, sandbox: &Sandbox) -> Option<i32> {
    const PID_WAIT_ATTEMPTS: usize = 50;
    const PID_WAIT_INTERVAL: Duration = Duration::from_millis(20);

    if let Some(pid) = sandbox_host_pid(sandbox).await {
        return Some(pid);
    }

    for _ in 0..PID_WAIT_ATTEMPTS {
        if let Some(pid) = sandbox_host_pid_from_handle(id).await {
            return Some(pid);
        }
        tokio::time::sleep(PID_WAIT_INTERVAL).await;
    }

    None
}

pub(crate) async fn sandbox_host_pid_from_handle(id: &str) -> Option<i32> {
    let handle = Sandbox::get(&sandbox_name_for_container(id)).await.ok()?;
    handle.local().and_then(|local| local.pid)
}

pub(crate) fn requires_fresh_network_namespace(bundle: &OciBundle) -> bool {
    bundle
        .spec
        .linux()
        .as_ref()
        .and_then(|linux| linux.namespaces().as_ref())
        .is_some_and(|namespaces| {
            namespaces.iter().any(|namespace| {
                namespace.typ() == oci_spec::runtime::LinuxNamespaceType::Network
                    && namespace.path().is_none()
            })
        })
}

async fn sandbox_host_pid(sandbox: &Sandbox) -> Option<i32> {
    let local = sandbox.local()?;
    let handle = local.handle.as_ref()?;
    Some(handle.lock().await.pid() as i32)
}

fn is_runtime_managed_mount(destination: &Path) -> bool {
    matches!(
        normalize_guest_path(destination).as_str(),
        "/dev" | "/dev/pts" | "/dev/ptmx" | "/dev/console" | "/proc" | "/sys" | "/sys/fs/cgroup"
    )
}

fn normalize_guest_path(path: &Path) -> String {
    let mut normalized = path.display().to_string();
    if normalized.is_empty() {
        return "/".to_string();
    }
    if !normalized.starts_with('/') {
        normalized.insert(0, '/');
    }
    while normalized.len() > 1 && normalized.ends_with('/') {
        normalized.pop();
    }
    normalized
}

fn absolutize_mount_source(bundle: &Path, source: &Path) -> PathBuf {
    if source.is_absolute() {
        source.to_path_buf()
    } else {
        bundle.join(source)
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_relative_mount_source_against_bundle() {
        assert_eq!(
            absolutize_mount_source(Path::new("/bundle"), Path::new("data")),
            PathBuf::from("/bundle/data")
        );
        assert_eq!(
            absolutize_mount_source(Path::new("/bundle"), Path::new("/host/data")),
            PathBuf::from("/host/data")
        );
    }

    #[test]
    fn detects_fresh_oci_network_namespace() {
        let temp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(temp.path().join("rootfs")).expect("rootfs");
        std::fs::write(
            temp.path().join("config.json"),
            r#"{
                "ociVersion": "1.2.0",
                "root": { "path": "rootfs" },
                "process": {
                    "user": { "uid": 0, "gid": 0 },
                    "cwd": "/",
                    "args": ["/bin/sh"]
                },
                "linux": {
                    "namespaces": [{ "type": "network" }]
                }
            }"#,
        )
        .expect("config");
        let bundle = OciBundle::load(temp.path()).expect("load bundle");

        assert!(requires_fresh_network_namespace(&bundle));
    }

    #[test]
    fn skips_runtime_managed_oci_mounts() {
        for destination in [
            "/dev",
            "/dev/",
            "/dev/pts",
            "/dev/ptmx",
            "/dev/console",
            "/proc",
            "/sys",
            "/sys/fs/cgroup",
        ] {
            assert!(
                is_runtime_managed_mount(Path::new(destination)),
                "{destination} should be runtime-managed"
            );
        }

        for destination in ["/dev/shm", "/etc/hosts", "/etc/resolv.conf", "/tmp"] {
            assert!(
                !is_runtime_managed_mount(Path::new(destination)),
                "{destination} should be forwarded from the OCI bundle"
            );
        }
    }
}
