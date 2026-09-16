//! Opt-in OCI writable-upper attachment qualification with real VMs.
//! CI uses the standard `msb_test` isolated-home setup and installed candidate binary.
//! For manual runs, set an isolated MSB_HOME, the freshly built MSB_PATH, matching
//! MSB_AGENTD_PATH and MSB_LIBKRUNFW_PATH. Test disks use the portable ext4 formatter.
//! On Windows use `scripts/smoke/oci-upper-lock.ps1`: build with Cargo, then run
//! the test executable directly. Cargo's Job Object does not permit the breakaway
//! required by detached VMs, so running this matrix inside `cargo test` is invalid.

#![cfg(all(feature = "local", any(unix, windows)))]

#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

use microsandbox::Sandbox;
use microsandbox::sandbox::SandboxBuilder;
use microsandbox_types::DiskImageFormat;
use test_utils::msb_test;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct Cleanup {
    binary: PathBuf,
    names: Vec<String>,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for Cleanup {
    fn drop(&mut self) {
        // Scope emergency cleanup to this test's exact names, including unfinished creates.
        // Never read fallible setup or panic while unwinding an assertion failure.
        for name in &self.names {
            let _ = std::process::Command::new(&self.binary)
                .args(["stop", "--force", name])
                .output();
            let _ = std::process::Command::new(&self.binary)
                .args(["remove", name])
                .output();
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn builder(name: &str, disk: &Path) -> SandboxBuilder {
    Sandbox::builder(name)
        .image("mirror.gcr.io/library/alpine")
        .cpus(1)
        .memory(256_u32)
        .root_disk_with(|root| root.disk_image(disk).format(DiskImageFormat::Raw))
}

fn format_upper(path: &Path) {
    microsandbox_image::ext4::format_ext4(
        path,
        &microsandbox_image::ext4::Ext4FormatOptions {
            size_bytes: 128 * 1024 * 1024,
            ..Default::default()
        },
    )
    .unwrap();
}

async fn assert_conflict(name: &str, disk: &Path) {
    let error = builder(name, disk)
        .create()
        .await
        .err()
        .expect("second writable attachment succeeded");
    assert!(
        error.to_string().contains("incompatible disk mode"),
        "{error}"
    );
    Sandbox::remove(name).await.unwrap();
}

async fn assert_running(sandbox: &Sandbox) {
    assert!(sandbox.shell("true").await.unwrap().status().success);
}

async fn wait_for_disk_admission(disk: &Path) {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if disk_is_attached(disk) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("startup never acquired the upper");
}

#[cfg(unix)]
fn disk_is_attached(disk: &Path) -> bool {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(disk)
        .unwrap();
    // Drop a successful probe immediately, never across an await. The probe must
    // observe the actual advisory lock, not infer ownership from a status row.
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result == 0 {
        return false;
    }
    let error = std::io::Error::last_os_error();
    assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock, "{error}");
    true
}

#[cfg(windows)]
fn disk_is_attached(disk: &Path) -> bool {
    use std::os::windows::fs::OpenOptionsExt;

    let canonical = std::fs::canonicalize(disk).unwrap();
    let mut name = canonical.file_name().unwrap().to_os_string();
    name.push(".lock");
    // Match the runtime's sidecar sharing policy without creating a new sidecar.
    // Only ERROR_SHARING_VIOLATION proves ownership; other I/O failures are errors.
    match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(0)
        .open(canonical.with_file_name(name))
    {
        Ok(_) => false,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) if error.raw_os_error() == Some(32) => true,
        Err(error) => panic!("unexpected disk admission probe failure: {error}"),
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[msb_test]
async fn oci_upper_attachment_lifecycle_live() {
    // Validate manual-run prerequisites before creating disks, VMs or cleanup guards.
    // In nextest CI, msb_test supplies these using the installed candidate runtime.
    let binary = PathBuf::from(
        std::env::var_os("MSB_PATH")
            .expect("set MSB_PATH to the candidate msb binary, or use MSB_TEST_ISOLATE_HOME"),
    );
    assert!(
        binary.is_file(),
        "candidate msb binary missing: {}",
        binary.display()
    );
    let home = PathBuf::from(
        std::env::var_os("MSB_HOME")
            .expect("set an isolated MSB_HOME, or use MSB_TEST_ISOLATE_HOME"),
    );
    assert!(
        home.is_dir(),
        "isolated MSB_HOME missing: {}",
        home.display()
    );
    let probe = std::process::Command::new(&binary)
        .arg("--version")
        .output()
        .expect("candidate msb binary must be executable");
    assert!(
        probe.status.success(),
        "candidate msb --version failed: {}",
        String::from_utf8_lossy(&probe.stderr)
    );
    let prefix = format!("oci-lock-{}", std::process::id());
    let names: Vec<_> = [
        "a",
        "b",
        "sibling",
        "duplicate",
        "detached",
        "after",
        "cancel",
        "failed",
        "recovered",
    ]
    .map(|suffix| format!("{prefix}-{suffix}"))
    .into();
    let disk_dir = tempfile::tempdir().unwrap();
    let disk = disk_dir.path().join("upper.ext4");
    let sibling_disk = disk_dir.path().join("sibling.ext4");
    format_upper(&disk);
    format_upper(&sibling_disk);
    // Keep disk storage alive through cleanup, even if the assertion task panics.
    let disk_path = disk_dir.path().to_owned();
    let mut cleanup = Cleanup {
        binary: binary.clone(),
        names: names.clone(),
    };

    // Keep admission probes and acquisition on one executor: a concurrent probe
    // could itself briefly reserve the disk and make nonblocking admission fail.
    // Run assertions in a child task so panic cleanup can still await rollback.
    let result = tokio::spawn(async move {
    tokio::time::timeout(Duration::from_secs(180), async {
        // Two distinct names race on one upper, not on the sandbox-name reservation.
        let (a, b) = tokio::join!(builder(&names[0], &disk).create(), builder(&names[1], &disk).create());
        let (owner, contender) = match (a, b) {
            (Ok(owner), Err(error)) => (owner, (&names[1], error)),
            (Err(error), Ok(owner)) => (owner, (&names[0], error)),
            (a, b) => panic!("expected exactly one successful attachment: first={:?}, second={:?}", a.err(), b.err()),
        };
        assert!(contender.1.to_string().contains("incompatible disk mode"));
        Sandbox::remove(contender.0).await.unwrap();
        assert_running(&owner).await;
        let sibling = builder(&names[2], &sibling_disk).create().await.unwrap();

        let canonical_alias = disk_path.join(".").join("upper.ext4");
        assert_conflict(contender.0, &canonical_alias).await;
        #[cfg(unix)]
        {
            let symlink = disk_path.join("symlink.ext4");
            let hardlink = disk_path.join("hardlink.ext4");
            std::os::unix::fs::symlink(&disk, &symlink).unwrap();
            std::fs::hard_link(&disk, &hardlink).unwrap();
            assert_conflict(contender.0, &symlink).await;
            assert_conflict(contender.0, &hardlink).await;
        }
        owner.stop().await.unwrap();
        assert!(!disk_is_attached(&disk), "stop returned before releasing the OCI upper");
        // Keep owner and sibling alive: neither SDK retention nor an unrelated VM may pin it.
        let next = builder(contender.0, &disk).create().await.unwrap();
        assert_running(&sibling).await;
        next.kill().await.unwrap();
        assert!(!disk_is_attached(&disk), "kill returned before releasing the OCI upper");
        let after = builder(&names[5], &disk).create().await.unwrap();
        assert_running(&after).await;
        assert_running(&sibling).await;
        after.stop().await.unwrap();
        assert!(!disk_is_attached(&disk), "stop returned before releasing the OCI upper");
        println!("PASS concurrent names, path aliases, stop and force-kill with retained SDK objects and live sibling");

        let error = builder(&names[3], &disk)
            .volume("/extra", |volume| volume.disk(&disk).format(DiskImageFormat::Raw).readonly())
            .create().await.err().expect("duplicate disk attachment succeeded");
        assert!(error.to_string().contains("more than once per sandbox"), "{error}");
        Sandbox::remove(&names[3]).await.unwrap();

        // CLI creation returns only after detachment. Its SDK process is gone at this point.
        let output = tokio::process::Command::new(&binary)
            .args(["create", "mirror.gcr.io/library/alpine", "--name", &names[4], "--memory", "256M", "--cpus", "1", "--root-disk"])
            .arg(format!("{}:format=raw,fstype=ext4", disk.display())).output().await.unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        assert_conflict(&names[3], &disk).await;
        Sandbox::get(&names[4]).await.unwrap().stop().await.unwrap();
        assert!(!disk_is_attached(&disk), "detached stop returned before releasing the OCI upper");
        println!("PASS duplicate mount rollback and detached ownership after CLI exit");

        let (_progress, task) = builder(&names[6], &disk).create_with_progress().unwrap();
        // Cold boots need not emit snapshot startup progress. Observe admission itself,
        // then cancel before creation completes; the process-level tests cover handoff.
        wait_for_disk_admission(&disk).await;
        task.abort();
        assert!(task.await.err().expect("creation completed before cancellation").is_cancelled());
        // Cleanup is asynchronous. Observe release with a bounded deadline; never unlock a
        // lock held by another process. Reuse a new name to avoid testing catalog-name reuse.
        let recovered = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                match builder(&names[3], &disk).create().await {
                    Ok(sandbox) => break sandbox,
                    Err(error) if error.to_string().contains("incompatible disk mode") => {
                        Sandbox::remove(&names[3]).await.unwrap();
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    Err(error) => panic!("unexpected post-cancellation error: {error}"),
                }
            }
        }).await.expect("cancelled startup retained the upper lock");
        assert_running(&recovered).await;
        recovered.stop().await.unwrap();
        assert!(!disk_is_attached(&disk), "stop returned before releasing the OCI upper");
        // Force an actual guest mount failure after host admission, then reuse the
        // unchanged valid ext4 disk with the correct filesystem configuration.
        let (_progress, failed) = builder(&names[7], &disk)
            .root_disk_with(|root| root.disk_image(&disk).format(DiskImageFormat::Raw).fstype("msb_missing_fs"))
            .create_with_progress().unwrap();
        wait_for_disk_admission(&disk).await;
        let error = failed.await.unwrap().err().expect("invalid guest filesystem unexpectedly booted");
        // Admission rejection is not a failed guest boot and must never count as
        // coverage of post-launch rollback.
        assert!(matches!(&error, microsandbox::MicrosandboxError::BootStart { .. }), "expected guest boot failure after admission, got {error}");
        println!("Observed expected startup failure: {error}");
        let recovered = builder(&names[8], &disk).create().await.unwrap();
        assert_running(&recovered).await;
        recovered.stop().await.unwrap();
        assert!(!disk_is_attached(&disk), "stop returned before releasing the OCI upper");
        sibling.stop().await.unwrap();
        assert!(!disk_is_attached(&sibling_disk), "sibling stop returned before releasing its upper");
        println!("PASS startup cancellation and failed boot release upper ownership");
        // Make retention explicit through the final successful reattachment.
        assert!(!owner.name().is_empty() && !next.name().is_empty() && !after.name().is_empty());
    }).await.expect("OCI upper live matrix timed out");
    }).await;

    // Yield during cleanup so cancelled creation tasks can release transition
    // ownership. Blocking CLI calls in Drop would starve those tasks after panic.
    for name in &cleanup.names {
        let _ = tokio::process::Command::new(&cleanup.binary)
            .args(["stop", "--force", name])
            .output()
            .await;
        let _ = tokio::process::Command::new(&cleanup.binary)
            .args(["remove", name])
            .output()
            .await;
    }
    cleanup.names.clear();
    result.expect("OCI upper lifecycle assertions failed");
}

#[test]
fn cleanup_does_not_panic_if_the_binary_disappears() {
    let directory = tempfile::tempdir().unwrap();
    let result = std::panic::catch_unwind(|| {
        let _cleanup = Cleanup {
            binary: directory.path().join("missing-msb"),
            names: vec!["unused-test-name".into()],
        };
        panic!("original assertion failure");
    });
    // A second panic from Drop would abort this process instead of reaching here.
    assert!(result.is_err());
}
