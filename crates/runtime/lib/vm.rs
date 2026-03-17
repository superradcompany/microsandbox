//! MicroVM configuration and entry point.
//!
//! The `enter()` function takes over the calling process via `Vm::enter()`
//! from msb_krun and never returns. The calling process is effectively
//! replaced by the VMM event loop, which calls `_exit()` on guest shutdown.

use std::{
    os::fd::{FromRawFd, OwnedFd, RawFd},
    path::PathBuf,
};

use microsandbox_filesystem::{DynFileSystem, OverlayFs, PassthroughConfig, PassthroughFs};
use msb_krun::{NetBackend, VmBuilder};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Configuration for the microVM process.
pub struct VmConfig {
    /// Path to the libkrunfw shared library.
    pub libkrunfw_path: PathBuf,

    /// Number of virtual CPUs.
    pub vcpus: u8,

    /// Memory in MiB.
    pub memory_mib: u32,

    /// Root filesystem path for direct passthrough mounts.
    pub rootfs_path: Option<PathBuf>,

    /// Root filesystem lower layer paths in bottom-to-top order.
    pub rootfs_lowers: Vec<PathBuf>,

    /// Writable upper layer directory for OverlayFs rootfs.
    pub rootfs_upper: Option<PathBuf>,

    /// Private staging directory for OverlayFs atomic operations.
    pub rootfs_staging: Option<PathBuf>,

    /// Disk image path for virtio-blk rootfs.
    pub rootfs_disk: Option<PathBuf>,

    /// Disk image format string ("qcow2", "raw", "vmdk").
    pub rootfs_disk_format: Option<String>,

    /// Whether the disk image is read-only.
    pub rootfs_disk_readonly: bool,

    /// Additional mounts as `tag:host_path[:ro]` strings.
    pub mounts: Vec<String>,

    /// Pre-built filesystem backends as `(tag, backend)` pairs.
    ///
    /// These bypass the string-based mount path and are registered directly
    /// with the VM builder.
    pub backends: Vec<(String, Box<dyn DynFileSystem + Send + Sync>)>,

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
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl std::fmt::Debug for VmConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmConfig")
            .field("libkrunfw_path", &self.libkrunfw_path)
            .field("vcpus", &self.vcpus)
            .field("memory_mib", &self.memory_mib)
            .field("rootfs_path", &self.rootfs_path)
            .field("rootfs_lowers", &self.rootfs_lowers)
            .field("rootfs_upper", &self.rootfs_upper)
            .field("rootfs_staging", &self.rootfs_staging)
            .field("rootfs_disk", &self.rootfs_disk)
            .field("rootfs_disk_format", &self.rootfs_disk_format)
            .field("rootfs_disk_readonly", &self.rootfs_disk_readonly)
            .field("mounts", &self.mounts)
            .field("backends", &format!("[{} backend(s)]", self.backends.len()))
            .field("init_path", &self.init_path)
            .field("env", &self.env)
            .field("workdir", &self.workdir)
            .field("exec_path", &self.exec_path)
            .field("exec_args", &self.exec_args)
            .field("net_fd", &self.net_fd)
            .field("agent_fd", &self.agent_fd)
            .finish()
    }
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

fn validate_disk_format(format: Option<&str>) -> msb_krun::Result<msb_krun::DiskImageFormat> {
    match format.unwrap_or("raw") {
        "qcow2" => Ok(msb_krun::DiskImageFormat::Qcow2),
        "raw" => Ok(msb_krun::DiskImageFormat::Raw),
        "vmdk" => Ok(msb_krun::DiskImageFormat::Vmdk),
        other => Err(msb_krun::Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("unknown disk image format: {other}"),
        ))),
    }
}

fn append_block_root_env(env: &mut Vec<String>) {
    let prefix = format!("{}=", microsandbox_protocol::ENV_BLOCK_ROOT);
    if env.iter().any(|entry| entry.starts_with(&prefix)) {
        return;
    }

    env.push(format!("{prefix}/dev/vda"));
}

fn build_and_enter(config: VmConfig) -> msb_krun::Result<std::convert::Infallible> {
    let mut exec_env = config.env.clone();

    let mut builder = VmBuilder::new()
        .machine(|m| m.vcpus(config.vcpus).memory_mib(config.memory_mib as usize))
        .kernel(|k| {
            let k = k.krunfw_path(&config.libkrunfw_path);
            if let Some(ref init_path) = config.init_path {
                k.init_path(init_path)
            } else {
                k
            }
        });

    // Root filesystem — either direct passthrough or OverlayFs, never both.
    if let Some(rootfs_path) = config.rootfs_path.as_ref() {
        if !config.rootfs_lowers.is_empty()
            || config.rootfs_upper.is_some()
            || config.rootfs_staging.is_some()
        {
            return Err(msb_krun::Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "rootfs_path cannot be combined with overlay rootfs fields",
            )));
        }

        let cfg = PassthroughConfig {
            root_dir: rootfs_path.clone(),
            ..Default::default()
        };
        let backend = PassthroughFs::new(cfg)?;
        builder = builder.fs(move |fs| fs.tag("/dev/root").custom(Box::new(backend)));
    } else if !config.rootfs_lowers.is_empty() {
        let overlay = build_overlay_rootfs(
            &config.rootfs_lowers,
            config.rootfs_upper.as_deref(),
            config.rootfs_staging.as_deref(),
        )?;
        builder = builder.fs(move |fs| fs.tag("/dev/root").custom(Box::new(overlay)));
    } else if config.rootfs_upper.is_some() || config.rootfs_staging.is_some() {
        return Err(msb_krun::Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "overlay rootfs requires at least one lower layer",
        )));
    } else if let Some(ref disk_path) = config.rootfs_disk {
        // Empty trampoline: PassthroughFs injects /init.krun (agentd) automatically.
        let empty_trampoline = tempfile::tempdir().map_err(msb_krun::Error::Io)?;
        let cfg = PassthroughConfig {
            root_dir: empty_trampoline.path().to_path_buf(),
            ..Default::default()
        };
        let backend = PassthroughFs::new(cfg)?;
        builder = builder.fs(move |fs| fs.tag("/dev/root").custom(Box::new(backend)));

        let format = validate_disk_format(config.rootfs_disk_format.as_deref())?;
        let disk_path = disk_path.clone();
        let readonly = config.rootfs_disk_readonly;
        builder = builder.disk(move |d| d.path(&disk_path).format(format).read_only(readonly));
        append_block_root_env(&mut exec_env);

        // Keep the trampoline directory alive until VM exits.
        // enter() never returns, so we prevent cleanup on drop.
        let _ = empty_trampoline.keep();
    }

    // Additional mounts (tag:host_path[:ro] format).
    for mount_spec in &config.mounts {
        let (spec, _readonly) = match mount_spec.strip_suffix(":ro") {
            Some(s) => (s, true),
            None => (mount_spec.as_str(), false),
        };

        if let Some((tag, path)) = spec.split_once(':') {
            let tag = tag.to_string();
            let cfg = PassthroughConfig {
                root_dir: PathBuf::from(path),
                ..Default::default()
            };
            let backend = PassthroughFs::new(cfg)?;
            builder = builder.fs(move |fs| fs.tag(&tag).custom(Box::new(backend)));
        } else {
            tracing::warn!(mount = %mount_spec, "skipping malformed mount spec (expected tag:path)");
        }
    }

    // Pre-built backend mounts.
    for (tag, backend) in config.backends {
        builder = builder.fs(move |fs| fs.tag(&tag).custom(backend));
    }

    // Execution configuration.
    builder = builder.exec(|mut e| {
        if let Some(ref path) = config.exec_path {
            e = e.path(path);
        }
        if !config.exec_args.is_empty() {
            e = e.args(&config.exec_args);
        }
        for env_str in &exec_env {
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

/// Build an OverlayFs backend from rootfs lower layers.
///
/// Layers are ordered bottom-to-top: the first entry is the lowest (base) layer.
fn build_overlay_rootfs(
    layers: &[PathBuf],
    upper_dir: Option<&std::path::Path>,
    staging_dir: Option<&std::path::Path>,
) -> msb_krun::Result<OverlayFs> {
    debug_assert!(
        !layers.is_empty(),
        "overlay rootfs requires at least one lower layer"
    );

    let mut overlay_builder = OverlayFs::builder();

    for layer in layers {
        // Check if a sidecar index exists for this layer.
        let index_path = layer.with_extension("index");
        if index_path.exists() {
            overlay_builder = overlay_builder.layer_with_index(layer, &index_path);
        } else {
            overlay_builder = overlay_builder.layer(layer);
        }
    }

    match (upper_dir, staging_dir) {
        (Some(upper), Some(staging)) => {
            overlay_builder = overlay_builder.writable(upper).staging(staging);
        }
        (None, None) => {
            overlay_builder = overlay_builder.read_only();
        }
        _ => {
            return Err(msb_krun::Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "overlay rootfs: upper_dir and staging_dir must both be set or both be omitted",
            )));
        }
    }

    overlay_builder.build().map_err(msb_krun::Error::Io)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use microsandbox_utils::index::IndexBuilder;
    use tempfile::tempdir;

    use super::{
        VmConfig, append_block_root_env, build_and_enter, build_overlay_rootfs,
        validate_disk_format,
    };

    #[test]
    fn test_build_and_enter_rejects_rootfs_path_combined_with_overlay_fields() {
        let err = build_and_enter(VmConfig {
            libkrunfw_path: PathBuf::from("/tmp/libkrunfw"),
            vcpus: 1,
            memory_mib: 512,
            rootfs_path: Some(PathBuf::from("/tmp/rootfs")),
            rootfs_lowers: vec![PathBuf::from("/tmp/layer0")],
            rootfs_upper: Some(PathBuf::from("/tmp/rw")),
            rootfs_staging: Some(PathBuf::from("/tmp/staging")),
            rootfs_disk: None,
            rootfs_disk_format: None,
            rootfs_disk_readonly: false,
            mounts: Vec::new(),
            backends: Vec::new(),
            init_path: None,
            env: Vec::new(),
            workdir: None,
            exec_path: None,
            exec_args: Vec::new(),
            net_fd: None,
            agent_fd: None,
        })
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("rootfs_path cannot be combined with overlay rootfs fields")
        );
    }

    #[test]
    fn test_build_and_enter_rejects_overlay_dirs_without_lowers() {
        let err = build_and_enter(VmConfig {
            libkrunfw_path: PathBuf::from("/tmp/libkrunfw"),
            vcpus: 1,
            memory_mib: 512,
            rootfs_path: None,
            rootfs_lowers: Vec::new(),
            rootfs_upper: Some(PathBuf::from("/tmp/rw")),
            rootfs_staging: Some(PathBuf::from("/tmp/staging")),
            rootfs_disk: None,
            rootfs_disk_format: None,
            rootfs_disk_readonly: false,
            mounts: Vec::new(),
            backends: Vec::new(),
            init_path: None,
            env: Vec::new(),
            workdir: None,
            exec_path: None,
            exec_args: Vec::new(),
            net_fd: None,
            agent_fd: None,
        })
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("overlay rootfs requires at least one lower layer")
        );
    }

    #[test]
    fn test_build_overlay_rootfs_rejects_mismatched_upper_staging() {
        let temp = tempdir().unwrap();
        let lower = create_dir(temp.path(), "lower.extracted");
        let staging = create_dir(temp.path(), "staging");

        // upper missing but staging present → error
        match build_overlay_rootfs(&[lower.clone()], None, Some(&staging)) {
            Ok(_) => panic!("expected mismatched upper/staging to be rejected"),
            Err(err) => assert!(err.to_string().contains("both be set or both be omitted")),
        }

        // upper present but staging missing → error
        let upper = create_dir(temp.path(), "rw");
        match build_overlay_rootfs(&[lower], Some(&upper), None) {
            Ok(_) => panic!("expected mismatched upper/staging to be rejected"),
            Err(err) => assert!(err.to_string().contains("both be set or both be omitted")),
        }
    }

    #[test]
    fn test_build_overlay_rootfs_read_only() {
        let temp = tempdir().unwrap();
        let lower = create_dir(temp.path(), "lower.extracted");

        // Both None → read-only mode (should succeed).
        build_overlay_rootfs(&[lower], None, None).unwrap();
    }

    #[test]
    fn test_build_overlay_rootfs_accepts_single_lower_without_index() {
        let temp = tempdir().unwrap();
        let lower = create_dir(temp.path(), "lower.extracted");
        let upper = create_dir(temp.path(), "rw");
        let staging = create_dir(temp.path(), "staging");

        assert!(build_overlay_rootfs(&[lower], Some(&upper), Some(&staging)).is_ok());
    }

    #[test]
    fn test_build_overlay_rootfs_accepts_single_lower_with_conventional_index() {
        let temp = tempdir().unwrap();
        let lower = create_dir(temp.path(), "lower.extracted");
        let upper = create_dir(temp.path(), "rw");
        let staging = create_dir(temp.path(), "staging");
        let index_path = lower.with_extension("index");
        let index = IndexBuilder::new()
            .dir("")
            .file("", "hello.txt", 0o644)
            .build();
        std::fs::write(&index_path, index).unwrap();

        assert!(build_overlay_rootfs(&[lower], Some(&upper), Some(&staging)).is_ok());
    }

    #[test]
    fn test_validate_disk_format_rejects_unknown_values() {
        let err = validate_disk_format(Some("iso")).unwrap_err();
        assert!(err.to_string().contains("unknown disk image format"));
    }

    #[test]
    fn test_append_block_root_env_adds_default_device() {
        let mut env = vec!["FOO=bar".to_string()];
        append_block_root_env(&mut env);

        assert!(env.contains(&"FOO=bar".to_string()));
        assert!(env.contains(&format!(
            "{}=/dev/vda",
            microsandbox_protocol::ENV_BLOCK_ROOT
        )));
    }

    #[test]
    fn test_append_block_root_env_preserves_existing_value() {
        let existing = format!(
            "{}=/dev/vdb,fstype=xfs",
            microsandbox_protocol::ENV_BLOCK_ROOT
        );
        let mut env = vec![existing.clone()];
        append_block_root_env(&mut env);

        assert_eq!(env, vec![existing]);
    }

    #[test]
    fn test_build_overlay_rootfs_falls_back_when_conventional_index_is_corrupt() {
        let temp = tempdir().unwrap();
        let lower = create_dir(temp.path(), "lower.extracted");
        let upper = create_dir(temp.path(), "rw");
        let staging = create_dir(temp.path(), "staging");
        let index_path = lower.with_extension("index");
        std::fs::write(&index_path, b"definitely not a valid index").unwrap();

        assert!(build_overlay_rootfs(&[lower], Some(&upper), Some(&staging)).is_ok());
    }

    fn create_dir(root: &Path, name: &str) -> PathBuf {
        let path = root.join(name);
        std::fs::create_dir_all(&path).unwrap();
        path
    }
}
