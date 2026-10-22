//! Retained resize reads must never perform guest I/O on the ordinary control queue.

use std::sync::{Arc, atomic::AtomicBool};
use std::time::Duration;

use microsandbox_protocol::resize::{ResizeObservation, ResizeOutcome};
use tokio::{net::UnixListener, time::timeout};

use super::*;
use crate::runner::workload_control::WorkloadControl;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn executor(root: &Path, socket: &Path) -> Arc<RuntimeControlExecutor> {
    // Construction only: no firmware, hypervisor or guest process is entered by this fixture.
    let vm = msb_krun::VmBuilder::new().build().unwrap();
    let config = VmConfig {
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
        #[cfg(unix)]
        backends: Vec::new(),
        init_path: None,
        bootstrap: Default::default(),
        exec_path: None,
        exec_args: Vec::new(),
        #[cfg(feature = "net")]
        network: Default::default(),
        #[cfg(feature = "net")]
        deployment_profile: Default::default(),
        #[cfg(feature = "net")]
        sandbox_slot: 1,
        checkpoint_restore: None,
    };

    Arc::new(
        RuntimeControlExecutor::new(
            vm.control_handle(),
            #[cfg(feature = "net")]
            None,
            &root.join("run"),
            &config,
            &GuestBootstrap::default(),
            tokio::runtime::Handle::current(),
            socket,
            WorkloadControl::new(),
            Arc::new(AtomicBool::new(false)),
            None,
            BTreeMap::new(),
            ConfirmedMemoryLimit::boot(256 << 20, vm.metrics_handle()),
        )
        .unwrap(),
    )
}

fn pending(executor: &RuntimeControlExecutor) -> ResizeRequest {
    let mut state = executor.state.lock().unwrap();
    let target = ResizeTarget::Cpus { online: 2 };
    state.resize.accepted(
        "pending".into(),
        target.clone(),
        target,
        ResourceResizeStatus {
            resource: ResourceKind::Cpus,
            requested: "2".into(),
            actual: "1".into(),
            enforced: "1".into(),
            state: ResourceConvergenceState::Accepted,
        },
    );
    ResizeRequest::Read {
        runtime_boot_id: state.runtime_boot_id.clone(),
        id: "pending".into(),
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn pending_reads_return_without_connecting_to_the_guest() {
    let root = tempfile::tempdir().unwrap();
    let socket = root.path().join("agent.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let executor = executor(root.path(), &socket);
    let request = pending(&executor);
    let read = Arc::clone(&executor);
    let response = timeout(
        Duration::from_millis(500),
        tokio::task::spawn_blocking(move || read.resize_request(request)),
    )
    .await
    .expect("a retained read waited for guest I/O")
    .unwrap()
    .unwrap();
    assert_eq!(response.operations.len(), 1);
    assert_eq!(response.operations[0].outcome, ResizeOutcome::Pending);
    assert_eq!(
        response.operations[0].observation,
        ResizeObservation::Unavailable
    );
    assert_eq!(response.operations[0].status.actual, "1");
    assert!(
        timeout(Duration::from_millis(30), listener.accept())
            .await
            .is_err()
    );
    // Many reads coalesce to a wake permit; they do not launch per-reader queries.
    timeout(
        Duration::from_millis(100),
        executor.resize_observer.wake.notified(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn pending_reads_and_host_observation_continue_while_background_guest_io_stalls() {
    let root = tempfile::tempdir().unwrap();
    let socket = root.path().join("agent.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let executor = executor(root.path(), &socket);
    let request = pending(&executor);
    executor.start_resize_observer();
    // The real observer connects to a peer that deliberately never answers its handshake.
    let (stalled, _) = timeout(Duration::from_secs(2), listener.accept())
        .await
        .unwrap()
        .unwrap();
    let reads = Arc::clone(&executor);
    let responses = timeout(
        Duration::from_millis(500),
        tokio::task::spawn_blocking(move || {
            let mut responses = Vec::new();
            for _ in 0..16 {
                responses.push(reads.resize_request(request.clone()).unwrap());
                responses.push(
                    reads
                        .resize_request(ResizeRequest::Current {
                            runtime_boot_id: reads.state().runtime_boot_id,
                        })
                        .unwrap(),
                );
                assert!(reads.execute_legacy(ControlRequest::PauseState).ok);
            }
            responses
        }),
    )
    .await
    .expect("guest observation blocked host control")
    .unwrap();
    assert!(
        responses
            .iter()
            .all(|response| response.operations[0].outcome == ResizeOutcome::Pending)
    );
    assert!(
        timeout(Duration::from_millis(30), listener.accept())
            .await
            .is_err()
    );
    drop(stalled);
}

#[tokio::test]
async fn retained_reads_report_paused_without_fabricating_completion() {
    let root = tempfile::tempdir().unwrap();
    let executor = executor(root.path(), &root.path().join("missing.sock"));
    let request = pending(&executor);
    executor.state.lock().unwrap().lifecycle = RuntimeLifecycle::Quiescing;
    let read = Arc::clone(&executor);
    let response = tokio::task::spawn_blocking(move || read.resize_request(request))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.operations[0].outcome, ResizeOutcome::Pending);
    assert_eq!(
        response.operations[0].observation,
        ResizeObservation::Paused
    );
    assert_eq!(response.operations[0].status.actual, "1");
}
