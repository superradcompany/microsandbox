//! Handler for the `msb sandbox` subcommand.
//!
//! Parses CLI arguments, builds a [`microsandbox_runtime::vm::Config`], and delegates to
//! [`microsandbox_runtime::vm::enter()`]. This command **never returns**
//! — the VMM calls `_exit()` on guest shutdown.

use std::mem::MaybeUninit;
use std::path::PathBuf;
use std::{os::fd::FromRawFd, os::fd::OwnedFd};

use clap::Args;
use microsandbox_runtime::{
    logging::LogLevel,
    vm::{Config, DiskMountSpec, MetricsSlotHandoff, StartupCommand, VmConfig},
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

    /// Log verbosity for the sandbox runtime (error, warn, info, debug, trace).
    #[arg(long = "log-level", value_name = "LOG_LEVEL", value_parser = parse_log_level)]
    pub log_level: Option<LogLevel>,

    /// Runtime directory (scripts, heartbeat).
    #[arg(long)]
    pub runtime_dir: PathBuf,

    /// Path to the Unix domain socket for the agent relay.
    #[arg(long)]
    pub agent_sock: PathBuf,

    /// Read end of the attached-parent watchdog pipe.
    #[arg(long = "parent-watch-fd", hide = true)]
    pub parent_watch_fd: Option<i32>,

    /// Write end of the startup JSON pipe.
    #[arg(long = "startup-fd", hide = true)]
    pub startup_fd: Option<i32>,

    /// Startup workload command to execute after agentd is ready.
    #[arg(long = "startup-cmd", hide = true)]
    pub startup_cmd: Option<String>,

    /// Startup workload arguments.
    #[arg(long = "startup-arg", hide = true)]
    pub startup_args: Vec<String>,

    /// Startup workload environment variables as `KEY=VALUE`.
    #[arg(long = "startup-env", hide = true)]
    pub startup_env: Vec<String>,

    /// Startup workload working directory.
    #[arg(long = "startup-cwd", hide = true)]
    pub startup_cwd: Option<String>,

    /// Startup workload guest user.
    #[arg(long = "startup-user", hide = true)]
    pub startup_user: Option<String>,

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

    /// Metrics sampling interval in milliseconds; `0` disables sampling.
    #[arg(long = "metrics-sample-interval-ms", default_value_t = 1000)]
    pub metrics_sample_interval_ms: u64,

    /// Disable metrics sampling; overrides `--metrics-sample-interval-ms`.
    #[arg(long = "disable-metrics-sample")]
    pub disable_metrics_sample: bool,

    /// Name of the POSIX shared-memory metrics registry, passed in by the host.
    #[arg(long = "metrics-shm-name", hide = true)]
    pub metrics_shm_name: Option<String>,

    /// Reserved slot index inside the metrics registry.
    #[arg(long = "metrics-slot", hide = true)]
    pub metrics_slot: Option<u32>,

    /// Generation stamp paired with the reserved slot.
    #[arg(long = "metrics-generation", hide = true)]
    pub metrics_generation: Option<u64>,

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

/// Parse a sandbox runtime log level.
fn parse_log_level(s: &str) -> Result<LogLevel, String> {
    match s {
        "error" => Ok(LogLevel::Error),
        "warn" => Ok(LogLevel::Warn),
        "info" => Ok(LogLevel::Info),
        "debug" => Ok(LogLevel::Debug),
        "trace" => Ok(LogLevel::Trace),
        _ => Err(format!(
            "invalid log level: {s} (expected: error, warn, info, debug, trace)"
        )),
    }
}

/// Run the sandbox process. This function **never returns**.
pub fn run(args: SandboxArgs) -> ! {
    let parent_watchdog = match args
        .parent_watch_fd
        .map(parent_watchdog_from_fd)
        .transpose()
    {
        Ok(fd) => fd,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(2);
        }
    };
    let startup_fd = match args.startup_fd.map(startup_from_fd).transpose() {
        Ok(fd) => fd,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(2);
        }
    };
    let is_vmdk = args.rootfs_disk_format.as_deref() == Some("vmdk");
    let disks = match parse_disk_args(&args.disk) {
        Ok(disks) => disks,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(2);
        }
    };
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
        disks,
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
        log_level: args.log_level,
        sandbox_db_path: args.sandbox_db_path,
        sandbox_db_connect_timeout_secs: args.sandbox_db_connect_timeout_secs,
        log_dir: args.log_dir,
        runtime_dir: args.runtime_dir,
        agent_sock_path: args.agent_sock,
        startup_command: args.startup_cmd.map(|cmd| StartupCommand {
            cmd,
            args: args.startup_args,
            env: args.startup_env,
            cwd: args.startup_cwd,
            user: args.startup_user,
        }),
        startup_fd,
        parent_watchdog,
        forward_output: args.forward_output,
        idle_timeout_secs: args.idle_timeout,
        max_duration_secs: args.max_duration,
        metrics_sample_interval_ms: if args.disable_metrics_sample {
            None
        } else {
            std::num::NonZero::new(args.metrics_sample_interval_ms)
        },
        metrics_slot: match (
            args.metrics_shm_name,
            args.metrics_slot,
            args.metrics_generation,
        ) {
            (Some(shm_name), Some(slot), Some(generation)) => Some(MetricsSlotHandoff {
                shm_name,
                slot,
                generation,
            }),
            _ => None,
        },
        vm: vm_config,
    };

    microsandbox_runtime::vm::enter(config)
}

fn parent_watchdog_from_fd(fd: i32) -> Result<OwnedFd, String> {
    validate_pipe_fd(
        fd,
        microsandbox_runtime::vm::PARENT_WATCH_FD,
        "parent-watch-fd",
    )?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn startup_from_fd(fd: i32) -> Result<OwnedFd, String> {
    validate_pipe_fd(fd, microsandbox_runtime::vm::STARTUP_FD, "startup-fd")?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn validate_pipe_fd(fd: i32, expected_fd: i32, arg_name: &str) -> Result<(), String> {
    if fd < 0 {
        return Err(format!(
            "invalid --{arg_name}: fd must be non-negative, got {fd}"
        ));
    }
    if fd != expected_fd {
        return Err(format!(
            "invalid --{arg_name}: expected {expected_fd}, got {fd}",
        ));
    }

    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(format!(
            "invalid --{arg_name} {fd}: {}",
            std::io::Error::last_os_error()
        ));
    }

    let mut stat = MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
        return Err(format!(
            "invalid --{arg_name} {fd}: {}",
            std::io::Error::last_os_error()
        ));
    }
    let stat = unsafe { stat.assume_init() };
    let file_type = stat.st_mode & libc::S_IFMT as libc::mode_t;
    if file_type != libc::S_IFIFO as libc::mode_t {
        return Err(format!("invalid --{arg_name} {fd}: fd is not a pipe"));
    }

    Ok(())
}

/// Parse `--disk id:host_path:format[:ro]` entries into typed specs.
///
/// `guest` and `fstype` are not in this arg — they travel in the
/// `MSB_DISK_MOUNTS` env var and are consumed by agentd, so the runtime
/// only needs what `DiskBuilder` will set.
///
/// Malformed entries are hard errors so the host-side `MSB_DISK_MOUNTS`
/// handoff cannot mention a disk that the runtime silently failed to attach.
fn parse_disk_args(entries: &[String]) -> Result<Vec<DiskMountSpec>, String> {
    entries
        .iter()
        .map(|entry| parse_one_disk_arg(entry))
        .collect()
}

fn parse_one_disk_arg(entry: &str) -> Result<DiskMountSpec, String> {
    let parts: Vec<&str> = entry.split(':').collect();
    if parts.len() < 3 || parts.len() > 4 {
        return Err(format!(
            "invalid --disk entry, expected id:host:format[:ro], got: {entry:?}"
        ));
    }

    let id = parts[0];
    if id.is_empty() {
        return Err(format!("invalid --disk entry with empty id: {entry:?}"));
    }
    let host = parts[1];
    if host.is_empty() {
        return Err(format!(
            "invalid --disk entry with empty host path: {entry:?}"
        ));
    }
    let fmt_str = parts[2];
    let format = match microsandbox_runtime::vm::validate_disk_format(Some(fmt_str)) {
        Ok(f) => f,
        Err(_) => {
            return Err(format!(
                "invalid --disk entry with unknown format {fmt_str:?}: {entry:?}"
            ));
        }
    };

    let readonly = match parts.get(3) {
        None => false,
        Some(&"ro") => true,
        Some(&other) => {
            return Err(format!(
                "invalid --disk entry with unknown flag {other:?} (expected 'ro'): {entry:?}"
            ));
        }
    };

    Ok(DiskMountSpec {
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
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    use clap::Parser;

    use super::*;

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        args: SandboxArgs,
    }

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
        assert!(parse_one_disk_arg("id:/host").is_err());
    }

    #[test]
    fn test_parse_one_disk_arg_too_many_fields() {
        assert!(parse_one_disk_arg("id:/host:raw:ro:extra").is_err());
    }

    #[test]
    fn test_parse_one_disk_arg_empty_id() {
        assert!(parse_one_disk_arg(":/host:raw").is_err());
    }

    #[test]
    fn test_parse_one_disk_arg_empty_host() {
        assert!(parse_one_disk_arg("id::raw").is_err());
    }

    #[test]
    fn test_parse_one_disk_arg_unknown_format() {
        assert!(parse_one_disk_arg("id:/host:bogus").is_err());
    }

    #[test]
    fn test_parse_one_disk_arg_unknown_flag() {
        // "rw" / typos are rejected explicitly so they don't silently coerce
        // to readonly=false.
        assert!(parse_one_disk_arg("id:/host:raw:rw").is_err());
        assert!(parse_one_disk_arg("id:/host:raw:RO").is_err());
    }

    #[test]
    fn test_parse_disk_args_rejects_bad_entries() {
        let entries = vec![
            "good:/host/g.raw:raw".to_string(),
            "bad".to_string(),
            "another:/host/a.qcow2:qcow2:ro".to_string(),
        ];
        let err = parse_disk_args(&entries).unwrap_err();
        assert!(err.contains("invalid --disk entry"));
    }

    #[test]
    fn test_hidden_startup_args_accept_hyphen_values() {
        let parsed = TestCli::parse_from([
            "test",
            "--name",
            "sandbox",
            "--sandbox-id",
            "7",
            "--db-path",
            "/tmp/msb.db",
            "--log-dir",
            "/tmp/logs",
            "--runtime-dir",
            "/tmp/runtime",
            "--agent-sock",
            "/tmp/agent.sock",
            "--libkrunfw-path",
            "/tmp/libkrunfw.dylib",
            "--startup-cmd=/bin/sh",
            "--startup-arg=-lc",
            "--startup-arg=echo ok",
        ]);

        assert_eq!(parsed.args.startup_cmd.as_deref(), Some("/bin/sh"));
        assert_eq!(parsed.args.startup_args, vec!["-lc", "echo ok"]);
    }

    #[test]
    fn test_parse_disk_args_keeps_good_entries() {
        let entries = vec![
            "good:/host/g.raw:raw".to_string(),
            "another:/host/a.qcow2:qcow2:ro".to_string(),
        ];
        let specs = parse_disk_args(&entries).unwrap();
        assert_eq!(specs.len(), 2);
        assert_eq!(specs[0].id, "good");
        assert_eq!(specs[1].id, "another");
        assert!(specs[1].readonly);
    }

    #[test]
    fn test_validate_parent_watchdog_fd_rejects_negative_fd() {
        let err = validate_pipe_fd(
            -1,
            microsandbox_runtime::vm::PARENT_WATCH_FD,
            "parent-watch-fd",
        )
        .unwrap_err();

        assert!(err.contains("non-negative"));
    }

    #[test]
    fn test_validate_parent_watchdog_fd_rejects_wrong_fd_number() {
        let err = validate_pipe_fd(
            0,
            microsandbox_runtime::vm::PARENT_WATCH_FD,
            "parent-watch-fd",
        )
        .unwrap_err();

        assert!(err.contains("expected 97"));
    }

    #[test]
    fn test_validate_parent_watchdog_fd_rejects_regular_file() {
        let file = tempfile::tempfile().unwrap();
        let fd = file.as_raw_fd();

        let err = validate_pipe_fd(fd, fd, "parent-watch-fd").unwrap_err();

        assert!(err.contains("not a pipe"));
    }

    #[test]
    fn test_validate_parent_watchdog_fd_accepts_pipe() {
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let read_fd = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let _write_fd = unsafe { OwnedFd::from_raw_fd(fds[1]) };

        validate_pipe_fd(read_fd.as_raw_fd(), read_fd.as_raw_fd(), "parent-watch-fd").unwrap();
    }
}
