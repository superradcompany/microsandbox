//! Construction and ownership coverage without entering a VM or requiring a hypervisor.

use std::path::Path;
use std::sync::{Arc, Mutex};

use microsandbox_filesystem::DynFileSystem;

use super::{
    AgentConsoleBackend, AgentConsoleBackends, AgentTransportProfile, Config, ConsoleSharedState,
    HostPlacement, TrampolineRootfsGuard, VmBuildOutput, VmBuildRuntime, VmConfig, build_vm,
};
use crate::RuntimeResult;
use crate::ipc::acquire_lifecycle_guard;
use crate::launch::{CheckpointRestoreConfig, FileMountConfig};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct TrackedFilesystem {
    name: &'static str,
    dropped: Arc<Mutex<Vec<&'static str>>>,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl DynFileSystem for TrackedFilesystem {}

impl Drop for TrackedFilesystem {
    fn drop(&mut self) {
        self.dropped.lock().unwrap().push(self.name);
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn custom_backends_move_into_vm_and_live_until_vm_is_dropped() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path());
    let dropped = Arc::new(Mutex::new(Vec::new()));
    for (name, tag) in [("first", "first".into()), ("second", "é".repeat(18))] {
        config.vm.backends.push((
            tag,
            Box::new(TrackedFilesystem {
                name,
                dropped: dropped.clone(),
            }),
        ));
    }

    let vm = build(&mut config).unwrap();

    assert!(config.vm.backends.is_empty());
    drop(config);
    assert!(dropped.lock().unwrap().is_empty());

    drop(vm);
    let mut dropped = dropped.lock().unwrap().clone();
    dropped.sort_unstable();
    assert_eq!(dropped, ["first", "second"]);
}

#[tokio::test]
async fn custom_backends_reject_invalid_and_conflicting_tags_before_consumption() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path());
    // These paths need not exist: invalid custom tags must fail before opening mounts.
    config.vm.mounts.push("directory:/missing-directory".into());
    config.vm.file_mounts.push(FileMountConfig {
        mount: "file:/missing-file-directory".into(),
        filename: "data".into(),
    });

    for tag in [
        String::new(),
        "x".repeat(37),
        "é".repeat(19),
        "x\0y".into(),
        "/dev/root".into(),
        microsandbox_protocol::RUNTIME_FS_TAG.into(),
        "directory".into(),
        "file".into(),
        "duplicate".into(),
    ] {
        let dropped = Arc::new(Mutex::new(Vec::new()));
        config.vm.backends = vec![
            (
                "duplicate".into(),
                Box::new(TrackedFilesystem {
                    name: "first",
                    dropped: dropped.clone(),
                }),
            ),
            (
                tag.clone(),
                Box::new(TrackedFilesystem {
                    name: "second",
                    dropped: dropped.clone(),
                }),
            ),
        ];

        let error = match build(&mut config) {
            Ok(_) => panic!("invalid custom filesystem tag {tag:?} was accepted"),
            Err(error) => error.to_string(),
        };

        assert!(error.contains("custom filesystem tag"), "{tag:?}: {error}");
        assert_eq!(config.vm.backends.len(), 2);
        assert!(dropped.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn custom_backends_refuse_full_restore_before_opening_checkpoint() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path());
    config.vm.checkpoint_restore = Some(CheckpointRestoreConfig::default());
    config.vm.backends.push((
        "custom".into(),
        Box::new(TrackedFilesystem {
            name: "custom",
            dropped: Arc::default(),
        }),
    ));

    let error = match build(&mut config) {
        Ok(_) => panic!("custom filesystems must not be silently added to a restored topology"),
        Err(error) => error.to_string(),
    };

    assert!(
        error.contains("not supported during checkpoint restore"),
        "{error}"
    );
    assert_eq!(config.vm.backends.len(), 1);
}

#[tokio::test]
async fn empty_custom_backends_preserve_vm_construction() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path());

    build(&mut config).unwrap();

    assert!(config.vm.backends.is_empty());
}

fn build(config: &mut Config) -> RuntimeResult<VmBuildOutput> {
    let mut trampoline_rootfs = TrampolineRootfsGuard {
        rootfs_dirs: Vec::new(),
    };
    build_vm(
        config,
        AgentConsoleBackends {
            control: AgentConsoleBackend::new(Arc::new(ConsoleSharedState::new())),
            bulk: None,
        },
        |_| {},
        |_| {},
        VmBuildRuntime {
            tokio_handle: tokio::runtime::Handle::current(),
            startup_progress: Arc::new(|_| {}),
        },
        HostPlacement {
            vcpu_targets: None,
            required: false,
            numa_topology: None,
        },
        None,
        &mut trampoline_rootfs.rootfs_dirs,
    )
}

fn config(directory: &Path) -> Config {
    Config {
        agent_transport: AgentTransportProfile::Combined,
        sandbox_name: "custom-backends".into(),
        sandbox_id: 1,
        log_level: None,
        sandbox_db_path: directory.join("unused.db"),
        sandbox_db_connect_timeout_secs: 1,
        log_dir: directory.into(),
        runtime_dir: directory.into(),
        sandboxes_dir: directory.into(),
        run_dir: directory.into(),
        lifecycle_guard: acquire_lifecycle_guard(directory, "custom-backends").unwrap(),
        cpu_lease_dir: directory.into(),
        writeback_lease_dir: directory.into(),
        block_writeback_pool_bytes: None,
        agent_sock_path: directory.join("agent.sock"),
        startup_command: None,
        #[cfg(unix)]
        startup_fd: None,
        #[cfg(windows)]
        startup_pipe: None,
        #[cfg(unix)]
        parent_watchdog: None,
        forward_output: false,
        idle_timeout_secs: None,
        max_duration_secs: None,
        metrics_sample_interval_ms: None,
        metrics_slot: None,
        vm: VmConfig {
            libkrunfw_path: Default::default(),
            thp: Default::default(),
            guest_clock: Default::default(),
            memory_cache_dir: None,
            vcpus: 1,
            memory_mib: 256,
            max_cpus: 1,
            max_memory_mib: 256,
            cpu_placement: Default::default(),
            placement_profile_name: None,
            placement_profile: None,
            fs_state_limit_bytes: None,
            block_writeback_limit_bytes: None,
            rootfs_path: None,
            rootfs_follow_root_symlinks: false,
            rootfs_disk: None,
            rootfs_disk_format: None,
            rootfs_disk_readonly: false,
            rootfs_disk_spec: None,
            rootfs_disk_runtime_owned: false,
            rootfs_vmdk: None,
            rootfs_upper: None,
            rootfs_upper_spec: None,
            mounts: Vec::new(),
            file_mounts: Vec::new(),
            owned_volumes: Vec::new(),
            disks: Vec::new(),
            vsock: Vec::new(),
            backends: Vec::new(),
            init_path: None,
            bootstrap: Default::default(),
            exec_path: None,
            exec_args: Vec::new(),
            #[cfg(feature = "net")]
            network: microsandbox_network::ResolvedNetworkConfig::new(
                microsandbox_network::config::NetworkConfig {
                    enabled: false,
                    ..Default::default()
                },
                None,
            ),
            #[cfg(feature = "net")]
            deployment_profile: Default::default(),
            #[cfg(feature = "net")]
            sandbox_slot: 1,
            checkpoint_restore: None,
        },
    }
}
