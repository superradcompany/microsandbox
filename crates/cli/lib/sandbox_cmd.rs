//! Handler for the `msb sandbox` subcommand.
//!
//! Parses CLI arguments, builds a [`microsandbox_runtime::vm::Config`], and delegates to
//! [`microsandbox_runtime::vm::enter()`]. This command **never returns**
//! — the VMM calls `_exit()` on guest shutdown.

use std::path::PathBuf;

use clap::Args;
use microsandbox_runtime::{
    logging::LogLevel,
    vm::{Config, DiskMountSpec, VmConfig},
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Arguments for the `msb sandbox` subcommand.
#[derive(Debug, Args)]
pub struct SandboxArgs {
    /// Name of the sandbox.
    #[arg(long = "name")]
    pub sandbox_name: String,

    /// Database ID of the sandbox.
    #[arg(long = "sandbox-id")]
    pub sandbox_id: i32,

    /// Path to the sandbox database file.
    #[arg(long = "db-path")]
    pub sandbox_db_path: PathBuf,

    /// Timeout when acquiring a sandbox database connection from the pool.
    #[arg(long = "db-connect-timeout-secs", default_value_t = 30)]
    pub sandbox_db_connect_timeout_secs: u64,

    /// Directory for log files.
    #[arg(long)]
    pub log_dir: PathBuf,

    /// Runtime directory (scripts, heartbeat).
    #[arg(long)]
    pub runtime_dir: PathBuf,

    /// Path to the Unix domain socket for the agent relay.
    #[arg(long)]
    pub agent_sock: PathBuf,

    /// Forward VM console output to stdout.
    #[arg(long = "forward")]
    pub forward_output: bool,

    /// Hard cap on total sandbox lifetime in seconds.
    #[arg(long)]
    pub max_duration: Option<u64>,

    /// Idle timeout in seconds.
    #[arg(long)]
    pub idle_timeout: Option<u64>,

    // ── VM configuration ─────────────────────────────────────────────────
    /// Path to the libkrunfw shared library.
    #[arg(long)]
    pub libkrunfw_path: PathBuf,

    /// Number of virtual CPUs.
    #[arg(long, default_value_t = 1)]
    pub vcpus: u8,

    /// Memory in MiB.
    #[arg(long, default_value_t = 512)]
    pub memory_mib: u32,

    /// Metrics sampling interval in milliseconds. `0` disables sampling entirely.
    #[arg(long = "metrics-sample-interval-ms", default_value_t = 1000)]
    pub metrics_sample_interval_ms: u64,

    /// Root filesystem path for direct passthrough mounts.
    #[arg(long)]
    pub rootfs_path: Option<PathBuf>,

    /// Disk image file path for virtio-blk rootfs.
    #[arg(long)]
    pub rootfs_disk: Option<PathBuf>,

    /// Disk image format (qcow2, raw, vmdk).
    #[arg(long)]
    pub rootfs_disk_format: Option<String>,

    /// Mount disk image as read-only.
    #[arg(long)]
    pub rootfs_disk_readonly: bool,

    /// Writable upper ext4 block device for OCI rootfs overlay.
    #[arg(long = "rootfs-blk")]
    pub rootfs_upper: Option<PathBuf>,

    /// Additional mounts as `tag:host_path` (repeatable).
    #[arg(long)]
    pub mount: Vec<String>,

    /// Disk-image volume mounts as `id:host_path:format[:ro]` (repeatable).
    #[arg(long)]
    pub disk: Vec<String>,

    /// Path to the init binary in the guest.
    #[arg(long)]
    pub init_path: Option<PathBuf>,

    /// Environment variables as `KEY=VALUE` (repeatable).
    #[arg(long)]
    pub env: Vec<String>,

    /// Working directory inside the guest.
    #[arg(long)]
    pub workdir: Option<PathBuf>,

    /// Path to the executable to run in the guest.
    #[arg(long)]
    pub exec_path: Option<PathBuf>,

    /// Network configuration as JSON.
    #[cfg(feature = "net")]
    #[arg(long)]
    pub network_config: Option<String>,

    /// Sandbox slot for deterministic network address derivation.
    #[cfg(feature = "net")]
    #[arg(long, default_value_t = 0)]
    pub sandbox_slot: u64,

    /// Arguments to pass to the executable.
    #[arg(last = true)]
    pub exec_args: Vec<String>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Run the sandbox process. This function **never returns**.
pub fn run(args: SandboxArgs, log_level: Option<LogLevel>) -> ! {
    let is_vmdk = args.rootfs_disk_format.as_deref() == Some("vmdk");
    let vm_config = VmConfig {
        libkrunfw_path: args.libkrunfw_path,
        vcpus: args.vcpus,
        memory_mib: args.memory_mib,
        rootfs_path: args.rootfs_path,
        rootfs_vmdk: if is_vmdk {
            args.rootfs_disk.clone()
        } else {
            None
        },
        rootfs_upper: args.rootfs_upper,
        rootfs_upper_spec: None,
        rootfs_disk: if is_vmdk { None } else { args.rootfs_disk },
        rootfs_disk_format: if is_vmdk {
            None
        } else {
            args.rootfs_disk_format
        },
        rootfs_disk_readonly: args.rootfs_disk_readonly,
        mounts: args.mount,
        disks: parse_disk_args(&args.disk),
        backends: vec![],
        init_path: args.init_path,
        env: args.env,
        workdir: args.workdir,
        exec_path: args.exec_path,
        exec_args: args.exec_args,
        #[cfg(feature = "net")]
        network: args
            .network_config
            .as_deref()
            .map(|json| {
                serde_json::from_str::<microsandbox_network::config::NetworkConfig>(json)
                    .expect("invalid network config JSON")
            })
            .unwrap_or_default(),
        #[cfg(feature = "net")]
        sandbox_slot: args.sandbox_slot,
    };

    let config = Config {
        sandbox_name: args.sandbox_name,
        sandbox_id: args.sandbox_id,
        log_level,
        sandbox_db_path: args.sandbox_db_path,
        sandbox_db_connect_timeout_secs: args.sandbox_db_connect_timeout_secs,
        log_dir: args.log_dir,
        runtime_dir: args.runtime_dir,
        agent_sock_path: args.agent_sock,
        forward_output: args.forward_output,
        idle_timeout_secs: args.idle_timeout,
        max_duration_secs: args.max_duration,
        metrics_sample_interval_ms: args.metrics_sample_interval_ms,
        vm: vm_config,
    };

    microsandbox_runtime::vm::enter(config)
}

/// Parse `--disk id:host_path:format[:ro]` entries into typed specs.
///
/// `guest` and `fstype` are not in this arg — they travel in the
/// `MSB_DISK_MOUNTS` env var and are consumed by agentd, so the runtime
/// only needs what `DiskBuilder` will set.
///
/// Malformed entries are skipped with a stderr warning rather than
/// panicking, but every rejection path emits a diagnostic so users get
/// a clear signal if a CLI flag is dropped.
fn parse_disk_args(entries: &[String]) -> Vec<DiskMountSpec> {
    entries
        .iter()
        .filter_map(|entry| parse_one_disk_arg(entry))
        .collect()
}

fn parse_one_disk_arg(entry: &str) -> Option<DiskMountSpec> {
    let parts: Vec<&str> = entry.split(':').collect();
    if parts.len() < 3 || parts.len() > 4 {
        eprintln!("ignoring --disk entry, expected id:host:format[:ro], got: {entry:?}");
        return None;
    }

    let id = parts[0];
    if id.is_empty() {
        eprintln!("ignoring --disk entry with empty id: {entry:?}");
        return None;
    }
    let host = parts[1];
    if host.is_empty() {
        eprintln!("ignoring --disk entry with empty host path: {entry:?}");
        return None;
    }
    let fmt_str = parts[2];
    let format = match microsandbox_runtime::vm::validate_disk_format(Some(fmt_str)) {
        Ok(f) => f,
        Err(_) => {
            eprintln!("ignoring --disk entry with unknown format {fmt_str:?}: {entry:?}");
            return None;
        }
    };

    let readonly = match parts.get(3) {
        None => false,
        Some(&"ro") => true,
        Some(&other) => {
            eprintln!(
                "ignoring --disk entry with unknown flag {other:?} (expected 'ro'): {entry:?}"
            );
            return None;
        }
    };

    Some(DiskMountSpec {
        id: id.to_string(),
        host: PathBuf::from(host),
        guest: String::new(), // consumed only by agentd via env
        format,
        fstype: None, // ditto
        readonly,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fmt(s: &str) -> String {
        format!(
            "{:?}",
            microsandbox_runtime::vm::validate_disk_format(Some(s)).unwrap()
        )
    }

    #[test]
    fn test_parse_one_disk_arg_happy() {
        let spec = parse_one_disk_arg("data_abc:/host/data.qcow2:qcow2").unwrap();
        assert_eq!(spec.id, "data_abc");
        assert_eq!(spec.host, PathBuf::from("/host/data.qcow2"));
        assert_eq!(format!("{:?}", spec.format), fmt("qcow2"));
        assert!(!spec.readonly);
    }

    #[test]
    fn test_parse_one_disk_arg_with_ro() {
        let spec = parse_one_disk_arg("seed:/host/seed.raw:raw:ro").unwrap();
        assert!(spec.readonly);
        assert_eq!(format!("{:?}", spec.format), fmt("raw"));
    }

    #[test]
    fn test_parse_one_disk_arg_missing_format_field() {
        // Two-field entries are rejected (no format token).
        assert!(parse_one_disk_arg("id:/host").is_none());
    }

    #[test]
    fn test_parse_one_disk_arg_too_many_fields() {
        assert!(parse_one_disk_arg("id:/host:raw:ro:extra").is_none());
    }

    #[test]
    fn test_parse_one_disk_arg_empty_id() {
        assert!(parse_one_disk_arg(":/host:raw").is_none());
    }

    #[test]
    fn test_parse_one_disk_arg_empty_host() {
        assert!(parse_one_disk_arg("id::raw").is_none());
    }

    #[test]
    fn test_parse_one_disk_arg_unknown_format() {
        assert!(parse_one_disk_arg("id:/host:bogus").is_none());
    }

    #[test]
    fn test_parse_one_disk_arg_unknown_flag() {
        // "rw" / typos are rejected explicitly so they don't silently coerce
        // to readonly=false.
        assert!(parse_one_disk_arg("id:/host:raw:rw").is_none());
        assert!(parse_one_disk_arg("id:/host:raw:RO").is_none());
    }

    #[test]
    fn test_parse_disk_args_skips_bad_entries_keeps_good() {
        let entries = vec![
            "good:/host/g.raw:raw".to_string(),
            "bad".to_string(),
            "another:/host/a.qcow2:qcow2:ro".to_string(),
        ];
        let specs = parse_disk_args(&entries);
        assert_eq!(specs.len(), 2);
        assert_eq!(specs[0].id, "good");
        assert_eq!(specs[1].id, "another");
        assert!(specs[1].readonly);
    }
}
