//! Handler for the `msb sandbox` subcommand.
//!
//! Parses CLI arguments, builds a [`microsandbox_runtime::vm::Config`], and delegates to
//! [`microsandbox_runtime::vm::enter()`]. This command **never returns**
//! — the VMM calls `_exit()` on guest shutdown.

#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::io::Read;
#[cfg(unix)]
use std::mem::MaybeUninit;
use std::path::PathBuf;
#[cfg(unix)]
use std::{os::fd::FromRawFd, os::fd::OwnedFd};

use clap::Args;
use microsandbox_runtime::{
    launch::LaunchConfig,
    logging::LogLevel,
    vm::{Config, DiskMountSpec, VmConfig},
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Arguments for the `msb sandbox` subcommand.
///
/// Only the operator-readable labels and the real inherited fds live on argv.
/// The bulk of the configuration — paths, env (incl. secrets), mounts, network
/// config — arrives as a JSON [`LaunchConfig`] over `--config-fd` (or
/// `--config-file` for manual invocation). See issue #997.
#[derive(Debug, Args)]
pub struct SandboxArgs {
    /// Name of the sandbox.
    #[arg(long = "name")]
    pub sandbox_name: String,

    /// Database ID of the sandbox.
    #[arg(long = "sandbox-id")]
    pub sandbox_id: i32,

    /// Log verbosity for the sandbox runtime (error, warn, info, debug, trace).
    #[arg(long = "log-level", value_name = "LOG_LEVEL", value_parser = parse_log_level)]
    pub log_level: Option<LogLevel>,

    /// Read end of the attached-parent watchdog pipe.
    #[cfg(unix)]
    #[arg(long = "parent-watch-fd", hide = true)]
    pub parent_watch_fd: Option<i32>,

    /// Write end of the startup JSON pipe.
    #[cfg(unix)]
    #[arg(long = "startup-fd", hide = true)]
    pub startup_fd: Option<i32>,

    /// Windows named pipe used to write startup JSON.
    #[cfg(windows)]
    #[arg(long = "startup-pipe", hide = true)]
    pub startup_pipe: Option<String>,

    /// Forward VM console output to stdout.
    #[arg(long = "forward")]
    pub forward_output: bool,

    /// Number of virtual CPUs.
    #[arg(long, default_value_t = 1)]
    pub vcpus: u8,

    /// Memory in MiB.
    #[arg(long, default_value_t = 512)]
    pub memory_mib: u32,

    /// Inherited fd carrying the JSON [`LaunchConfig`] (set by the SDK).
    #[cfg(unix)]
    #[arg(long = "config-fd", hide = true)]
    pub config_fd: Option<i32>,

    /// Path to a JSON [`LaunchConfig`] file (manual invocation / debugging).
    #[arg(long = "config-file", hide = true)]
    pub config_file: Option<PathBuf>,
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
    let launch = match load_launch_config(&args) {
        Ok(launch) => launch,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(2);
        }
    };
    #[cfg(unix)]
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
    #[cfg(unix)]
    let startup_fd = match args.startup_fd.map(startup_from_fd).transpose() {
        Ok(fd) => fd,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(2);
        }
    };
    let is_vmdk = launch.rootfs.disk_format.as_deref() == Some("vmdk");
    let disks = match parse_disk_args(&launch.disks) {
        Ok(disks) => disks,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(2);
        }
    };
    let vm_config = VmConfig {
        libkrunfw_path: launch.libkrunfw_path,
        vcpus: args.vcpus,
        memory_mib: args.memory_mib,
        rootfs_path: launch.rootfs.path,
        rootfs_vmdk: if is_vmdk {
            launch.rootfs.disk.clone()
        } else {
            None
        },
        rootfs_upper: launch.rootfs.upper,
        rootfs_upper_spec: None,
        rootfs_disk: if is_vmdk { None } else { launch.rootfs.disk },
        rootfs_disk_format: if is_vmdk {
            None
        } else {
            launch.rootfs.disk_format
        },
        rootfs_disk_readonly: launch.rootfs.disk_readonly,
        mounts: launch.mounts,
        disks,
        #[cfg(unix)]
        backends: vec![],
        init_path: launch.init_path,
        env: launch.env,
        workdir: launch.workdir,
        exec_path: launch.exec_path,
        exec_args: launch.exec_args,
        #[cfg(feature = "net")]
        network: launch.network.unwrap_or_default(),
        #[cfg(feature = "net")]
        sandbox_slot: launch.sandbox_slot,
    };

    let config = Config {
        sandbox_name: args.sandbox_name,
        sandbox_id: args.sandbox_id,
        log_level: args.log_level,
        sandbox_db_path: launch.db_path,
        sandbox_db_connect_timeout_secs: launch.db_connect_timeout_secs,
        log_dir: launch.log_dir,
        runtime_dir: launch.runtime_dir,
        sandboxes_dir: launch.sandboxes_dir,
        agent_sock_path: launch.agent_sock,
        startup_command: launch.startup,
        #[cfg(unix)]
        startup_fd,
        #[cfg(windows)]
        startup_pipe: args.startup_pipe,
        #[cfg(unix)]
        parent_watchdog,
        forward_output: args.forward_output,
        idle_timeout_secs: launch.lifecycle.idle_timeout_secs,
        max_duration_secs: launch.lifecycle.max_duration_secs,
        metrics_sample_interval_ms: if launch.metrics.disabled {
            None
        } else {
            std::num::NonZero::new(launch.metrics.sample_interval_ms)
        },
        metrics_slot: launch.metrics.slot,
        vm: vm_config,
    };

    microsandbox_runtime::vm::enter(config)
}

/// Load the JSON [`LaunchConfig`] for this sandbox from the inherited config
/// fd, or from `--config-file <path>` for manual invocation.
///
/// The launcher keeps only operator-readable labels on the real argv and
/// serializes the rest — network config, env (including secrets), mounts, and
/// paths — to an inherited fd, so they no longer appear in `ps` or
/// `/proc/<pid>/cmdline`. See issue #997.
fn load_launch_config(args: &SandboxArgs) -> Result<LaunchConfig, String> {
    #[cfg(unix)]
    let bytes = match (args.config_fd, &args.config_file) {
        (Some(fd), _) => read_config_fd(fd)?,
        (None, Some(path)) => std::fs::read(path)
            .map_err(|e| format!("failed to read --config-file {}: {e}", path.display()))?,
        (None, None) => {
            return Err("missing --config-fd or --config-file for `msb sandbox`".to_string());
        }
    };
    #[cfg(windows)]
    let bytes = match &args.config_file {
        Some(path) => std::fs::read(path)
            .map_err(|e| format!("failed to read --config-file {}: {e}", path.display()))?,
        None => return Err("missing --config-file for `msb sandbox`".to_string()),
    };
    serde_json::from_slice(&bytes).map_err(|e| format!("invalid launch config: {e}"))
}

/// Read the full contents of the inherited config fd, taking ownership so it
/// is closed once consumed.
#[cfg(unix)]
fn read_config_fd(fd: i32) -> Result<Vec<u8>, String> {
    if fd < 0 {
        return Err(format!(
            "invalid --config-fd: must be non-negative, got {fd}"
        ));
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|e| format!("failed to read --config-fd {fd}: {e}"))?;
    Ok(bytes)
}

#[cfg(unix)]
fn parent_watchdog_from_fd(fd: i32) -> Result<OwnedFd, String> {
    validate_pipe_fd(
        fd,
        microsandbox_runtime::vm::PARENT_WATCH_FD,
        "parent-watch-fd",
    )?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

#[cfg(unix)]
fn startup_from_fd(fd: i32) -> Result<OwnedFd, String> {
    validate_pipe_fd(fd, microsandbox_runtime::vm::STARTUP_FD, "startup-fd")?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

#[cfg(unix)]
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
    let (id, rest) = entry.split_once(':').ok_or_else(|| {
        format!("invalid --disk entry, expected id:host:format[:ro], got: {entry:?}")
    })?;
    if id.is_empty() {
        return Err(format!("invalid --disk entry with empty id: {entry:?}"));
    }

    let (rest, readonly) = match rest.strip_suffix(":ro") {
        Some(rest) => (rest, true),
        None => (rest, false),
    };
    let (host, fmt_str) = rest.rsplit_once(':').ok_or_else(|| {
        format!("invalid --disk entry, expected id:host:format[:ro], got: {entry:?}")
    })?;
    if host.is_empty() {
        return Err(format!(
            "invalid --disk entry with empty host path: {entry:?}"
        ));
    }
    let format = match microsandbox_runtime::vm::validate_disk_format(Some(fmt_str)) {
        Ok(f) => f,
        Err(_) => {
            return Err(format!(
                "invalid --disk entry with unknown format {fmt_str:?}: {entry:?}"
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
    #[cfg(unix)]
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

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
    #[cfg(windows)]
    fn test_parse_one_disk_arg_with_windows_drive_path() {
        let spec = parse_one_disk_arg(r"seed:C:\Users\Stephen\seed.raw:raw:ro").unwrap();
        assert_eq!(spec.host, PathBuf::from(r"C:\Users\Stephen\seed.raw"));
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
    #[cfg(unix)]
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
    #[cfg(unix)]
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
    #[cfg(unix)]
    fn test_validate_parent_watchdog_fd_rejects_regular_file() {
        let file = tempfile::tempfile().unwrap();
        let fd = file.as_raw_fd();

        let err = validate_pipe_fd(fd, fd, "parent-watch-fd").unwrap_err();

        assert!(err.contains("not a pipe"));
    }

    #[test]
    #[cfg(unix)]
    fn test_validate_parent_watchdog_fd_accepts_pipe() {
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let read_fd = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let _write_fd = unsafe { OwnedFd::from_raw_fd(fds[1]) };

        validate_pipe_fd(read_fd.as_raw_fd(), read_fd.as_raw_fd(), "parent-watch-fd").unwrap();
    }

    /// Build a `SandboxArgs` carrying only a config source; the rest is unused
    /// by `load_launch_config`.
    fn args_with(config_fd: Option<i32>, config_file: Option<PathBuf>) -> SandboxArgs {
        #[cfg(not(unix))]
        let _ = config_fd;

        SandboxArgs {
            sandbox_name: "test".to_string(),
            sandbox_id: 1,
            log_level: None,
            #[cfg(unix)]
            parent_watch_fd: None,
            #[cfg(unix)]
            startup_fd: None,
            #[cfg(windows)]
            startup_pipe: None,
            forward_output: false,
            vcpus: 1,
            memory_mib: 512,
            #[cfg(unix)]
            config_fd,
            config_file,
        }
    }

    #[test]
    fn test_load_launch_config_from_file() {
        use std::io::Write;

        let launch = LaunchConfig {
            db_path: PathBuf::from("/tmp/x.db"),
            env: vec!["TOKEN=secret".to_string()],
            ..Default::default()
        };
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&serde_json::to_vec(&launch).unwrap())
            .unwrap();

        let args = args_with(None, Some(file.path().to_path_buf()));
        let loaded = load_launch_config(&args).unwrap();

        assert_eq!(loaded.db_path, PathBuf::from("/tmp/x.db"));
        assert_eq!(loaded.env, vec!["TOKEN=secret".to_string()]);
    }

    #[test]
    #[cfg(unix)]
    fn test_load_launch_config_from_fd() {
        use std::io::{Seek, SeekFrom, Write};
        use std::os::fd::IntoRawFd;

        let launch = LaunchConfig {
            workdir: Some(PathBuf::from("/srv")),
            ..Default::default()
        };
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&serde_json::to_vec(&launch).unwrap())
            .unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        let fd = file.into_raw_fd();

        let args = args_with(Some(fd), None);
        let loaded = load_launch_config(&args).unwrap();

        assert_eq!(loaded.workdir, Some(PathBuf::from("/srv")));
    }

    #[test]
    fn test_load_launch_config_missing_source() {
        let err = load_launch_config(&args_with(None, None)).unwrap_err();
        assert!(err.contains("missing"));
    }

    #[test]
    #[cfg(unix)]
    fn test_load_launch_config_rejects_negative_fd() {
        let err = load_launch_config(&args_with(Some(-1), None)).unwrap_err();
        assert!(err.contains("config-fd"));
    }

    #[test]
    fn test_load_launch_config_rejects_garbage() {
        use std::io::Write;
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"not json").unwrap();
        let err =
            load_launch_config(&args_with(None, Some(file.path().to_path_buf()))).unwrap_err();
        assert!(err.contains("invalid launch config"));
    }
}
