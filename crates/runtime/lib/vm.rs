//! MicroVM configuration and entry point.
//!
//! The `enter()` function takes over the calling process via `Vm::enter()`
//! from msb_krun and never returns. The calling process is effectively
//! replaced by the VMM event loop, which calls `_exit()` on guest shutdown.

use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::path::PathBuf;

use microsandbox_filesystem::{PassthroughConfig, PassthroughFs};
use msb_krun::{NetBackend, VmBuilder};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Configuration for the microVM process.
#[derive(Debug, Clone)]
pub struct VmConfig {
    /// Path to the libkrunfw shared library.
    pub libkrunfw_path: PathBuf,

    /// Number of virtual CPUs.
    pub vcpus: u8,

    /// Memory in MiB.
    pub memory_mib: u32,

    /// Root filesystem layer paths (single = passthrough, multiple = overlay).
    pub rootfs_layers: Vec<PathBuf>,

    /// Additional mounts as `tag:host_path` pairs.
    pub mounts: Vec<String>,

    /// Path to the init binary in the guest.
    pub init_path: Option<PathBuf>,

    /// Environment variables as `KEY=VALUE` pairs.
    pub env: Vec<String>,

    /// Working directory inside the guest.
    pub workdir: Option<PathBuf>,

    /// Path to the executable to run in the guest.
    pub exec_path: Option<PathBuf>,

    /// Arguments to the executable.
    pub exec_args: Vec<String>,

    /// Socket pair FD for network backend (msbnet communication via Unixgram).
    pub net_fd: Option<RawFd>,

    /// Agent FD for virtio-console (agentd communication).
    pub agent_fd: Option<RawFd>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Enter the microVM.
///
/// This function **never returns** — it takes over the calling process
/// via `Vm::enter()` (from msb_krun) and calls `_exit()` on guest shutdown.
pub fn enter(config: VmConfig) -> ! {
    let result = build_and_enter(config);
    match result {
        Ok(infallible) => match infallible {},
        Err(e) => {
            eprintln!("microvm error: {e}");
            std::process::exit(1);
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

fn build_and_enter(config: VmConfig) -> msb_krun::Result<std::convert::Infallible> {
    let mut builder = VmBuilder::new()
        .machine(|m| {
            m.vcpus(config.vcpus)
                .memory_mib(config.memory_mib as usize)
        })
        .kernel(|k| {
            let k = k.krunfw_path(&config.libkrunfw_path);
            if let Some(ref init_path) = config.init_path {
                k.init_path(init_path)
            } else {
                k
            }
        });

    // Root filesystem — single layer uses passthrough via virtio-fs with stat virtualization.
    // TODO: Multiple layers should use OverlayFs via `fs.custom(Box::new(overlay))`
    // from the microsandbox-filesystem crate (DynFileSystem backend with COW and whiteouts).
    if let Some(first_layer) = config.rootfs_layers.first() {
        let cfg = PassthroughConfig {
            root_dir: first_layer.clone(),
            ..Default::default()
        };
        let backend = PassthroughFs::new(cfg)?;
        builder = builder
            .fs(move |fs| fs.tag("/dev/root").custom(Box::new(backend)));
    }

    // Additional mounts (tag:host_path format).
    for mount_spec in &config.mounts {
        if let Some((tag, path)) = mount_spec.split_once(':') {
            let tag = tag.to_string();
            let cfg = PassthroughConfig {
                root_dir: PathBuf::from(path),
                ..Default::default()
            };
            let backend = PassthroughFs::new(cfg)?;
            builder = builder
                .fs(move |fs| fs.tag(&tag).custom(Box::new(backend)));
        } else {
            tracing::warn!(mount = %mount_spec, "skipping malformed mount spec (expected tag:path)");
        }
    }

    // Execution configuration.
    builder = builder.exec(|mut e| {
        if let Some(ref path) = config.exec_path {
            e = e.path(path);
        }
        if !config.exec_args.is_empty() {
            e = e.args(&config.exec_args);
        }
        for env_str in &config.env {
            if let Some((key, value)) = env_str.split_once('=') {
                e = e.env(key, value);
            } else {
                tracing::warn!(env = %env_str, "skipping malformed env var (expected KEY=VALUE)");
            }
        }
        if let Some(ref workdir) = config.workdir {
            e = e.workdir(workdir);
        }
        e
    });

    // Agent — wire agent_fd through virtio-console multi-port.
    // Guest discovers port by name via /sys/class/virtio-ports/.
    // Disable the implicit console — microsandbox VMs are headless and only use
    // the explicit agent port for host↔guest communication.
    builder = builder.console(|c| {
        let c = c.disable_implicit();
        if let Some(agent_fd) = config.agent_fd {
            c.port(microsandbox_protocol::AGENT_PORT_NAME, agent_fd, agent_fd)
        } else {
            c
        }
    });

    // Network — use msb_krun's built-in Unixgram backend to relay frames to msbnet.
    if let Some(raw_fd) = config.net_fd {
        // SAFETY: The supervisor creates a socketpair and passes one end as net_fd.
        // This process owns the FD (inherited across fork+exec with CLOEXEC cleared).
        let owned_fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        let backend = msb_krun::backends::net::Unixgram::new(owned_fd);
        builder = builder.net(|n| n.custom(Box::new(backend) as Box<dyn NetBackend + Send>));
    }

    builder.build()?.enter()
}
